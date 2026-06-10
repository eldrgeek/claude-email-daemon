#!/usr/bin/env python3
"""
Claude Email Daemon
===================
Polls Claude's inbox and Mike's drafts, routes via local LLM, takes action.

Logs every decision in structured JSONL for later evaluation.

Usage:
    python3 daemon.py                    # Run once
    python3 daemon.py --loop             # Run continuously
    python3 daemon.py --replay <logfile> # Replay logged emails through a different model
"""

import imaplib
import smtplib
import email
import json
import os
import re
import shlex
import subprocess
import sys
import time
import yaml
import argparse
import hashlib
import requests
import logging
from datetime import datetime
from email.header import decode_header
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

def load_config(path=None):
    if path is None:
        path = Path(__file__).parent / "config.yaml"
    with open(path) as f:
        return yaml.safe_load(f)


def get_password(label, env_var, memory_section=None):
    """Get password from env var or memory file.

    memory_section: a string that identifies the section in email.md.
    The password is expected on a line containing 'App Password:' within
    that section.
    """
    pw = os.environ.get(env_var)
    if pw:
        return pw
    # Check new canonical path first, fall back to old retired path
    for candidate in [
        "~/Projects/second-brain/Resources/email-config.md",
        "~/Projects/memory/context/email.md",
    ]:
        memory_path = os.path.expanduser(candidate)
        if os.path.exists(memory_path):
            break
    if memory_section and os.path.exists(memory_path):
        with open(memory_path) as f:
            lines = f.readlines()
        in_section = False
        for line in lines:
            # Detect section headers (## headings)
            if line.startswith("##"):
                in_section = memory_section.lower() in line.lower()
                continue
            if in_section and "App Password:" in line:
                pw = line.split("App Password:")[1].strip()
                pw = pw.replace("**", "").strip("`").strip()
                return pw
    raise RuntimeError(f"No password for {label}. Set {env_var} or update memory/context/email.md")


# ---------------------------------------------------------------------------
# Dispatch routing — [DISPATCH:Mac|VPS|Hermes] subject pattern
# ---------------------------------------------------------------------------

DISPATCH_SUBJECT_RE = re.compile(r'^\[DISPATCH:(Mac|VPS|Hermes)\]\s*(.*)', re.IGNORECASE)

PLATFORM_NORMALIZE = {'mac': 'Mac', 'vps': 'VPS', 'hermes': 'Hermes'}


def _load_rate_data(state_dir):
    path = Path(os.path.expanduser(state_dir)) / 'dispatch-rate.json'
    if path.exists():
        with open(path) as f:
            return json.load(f)
    return {}


def _save_rate_data(state_dir, data):
    path = Path(os.path.expanduser(state_dir)) / 'dispatch-rate.json'
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)


def _check_rate_limit(state_dir, sender_email, limit_per_hour):
    """Returns (allowed: bool). If allowed, records this dispatch timestamp."""
    now = time.time()
    cutoff = now - 3600
    data = _load_rate_data(state_dir)
    key = sender_email.lower()
    recent = [t for t in data.get(key, []) if t > cutoff]
    if len(recent) >= limit_per_hour:
        return False
    recent.append(now)
    data[key] = recent
    _save_rate_data(state_dir, data)
    return True


def _ssh_host_from_target(ssh_target):
    target_host = ssh_target.rsplit('@', 1)[-1]
    if target_host.startswith('['):
        return target_host.split(']', 1)[0].lstrip('[')
    return target_host.split(':', 1)[0]


def _vps_known_hosts_file(vps_cfg, ssh_target, state_dir):
    host_key = (
        vps_cfg.get('host_key')
        or vps_cfg.get('accepted_host_key')
        or vps_cfg.get('AcceptedHostKeys')
    )
    if host_key:
        known_hosts_line = host_key.strip()
        first_field = known_hosts_line.split(maxsplit=1)[0]
        key_only_prefixes = ('ssh-', 'ecdsa-', 'sk-')
        if first_field.startswith(key_only_prefixes):
            known_hosts_line = f'{_ssh_host_from_target(ssh_target)} {known_hosts_line}'

        path = Path(os.path.expanduser(state_dir)) / 'dispatch-vps-known-hosts'
        path.parent.mkdir(parents=True, exist_ok=True)
        expected = f'{known_hosts_line}\n'
        if not path.exists() or path.read_text() != expected:
            path.write_text(expected)
            path.chmod(0o600)
        return path

    known_hosts_file = Path(os.path.expanduser(vps_cfg.get('known_hosts_file', '~/.ssh/known_hosts')))
    if known_hosts_file.exists():
        return known_hosts_file

    raise RuntimeError(
        'VPS SSH host key is not pinned. Set dispatch.platforms.VPS.host_key '
        'to the expected known_hosts entry, or configure known_hosts_file with '
        'a pre-populated known_hosts file.'
    )


def handle_dispatch_email(email_data, config, logger):
    """
    Handle [DISPATCH:Mac|VPS|Hermes] emails.
    Returns a dispatch log dict, or None if subject doesn't match.
    Called before LLM routing — short-circuits normal flow on match.
    """
    dispatch_cfg = config.get('dispatch', {})
    if not dispatch_cfg.get('enabled', False):
        return None

    subject = email_data.get('subject', '')
    m = DISPATCH_SUBJECT_RE.match(subject)
    if not m:
        return None

    platform = PLATFORM_NORMALIZE.get(m.group(1).lower(), m.group(1))
    task_name_raw = m.group(2).strip()
    if not task_name_raw:
        task_name_raw = f"task-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    task_name = re.sub(r'[^\w\-]', '-', task_name_raw).strip('-') or 'task'

    iso_now = datetime.now().strftime('%Y%m%dT%H%M%S')
    log_dir = Path(os.path.expanduser(config['log_dir']))
    state_dir = str(Path(os.path.expanduser(config['state_file'])).parent)

    sender_raw = email_data.get('from', '')
    # Extract bare address from "Name <addr>" format
    m_addr = re.search(r'<([^>]+)>', sender_raw)
    sender_email = m_addr.group(1).strip().lower() if m_addr else sender_raw.strip().lower()

    allowed = [s.lower() for s in dispatch_cfg.get('allowed_senders', [])]

    def _reject(reason, reply_body):
        reject_log = {
            'type': 'dispatch_rejected',
            'from': sender_raw,
            'sender_email': sender_email,
            'subject': subject,
            'platform': platform,
            'task_name': task_name,
            'reason': reason,
            'timestamp': datetime.now().isoformat(),
        }
        logging.warning(f"Dispatch rejected ({reason}): {sender_email}")
        with open(log_dir / f'dispatch-rejected-{iso_now}.json', 'w') as f:
            json.dump(reject_log, f, indent=2)
        try:
            send_email(config, sender_raw, f'Re: {subject}', reply_body,
                       in_reply_to=email_data.get('message_id'),
                       references=email_data.get('references'))
        except Exception as e:
            logging.error(f"Failed to send rejection reply: {e}")
        return reject_log

    # Security: sender allowlist
    if sender_email not in allowed:
        return _reject('sender_not_allowlisted',
                        'Dispatch refused: sender not on allowlist.')

    body = email_data.get('body', '')

    # Security: body size limit
    body_max = dispatch_cfg.get('body_max_bytes', 51200)
    if len(body.encode('utf-8')) > body_max:
        return _reject('body_too_large',
                        f'Dispatch refused: body too large for dispatch (limit {body_max} bytes).')

    # Security: rate limit
    rate_limit = dispatch_cfg.get('rate_limit_per_hour', 5)
    if not _check_rate_limit(state_dir, sender_email, rate_limit):
        return _reject('rate_limit_exceeded',
                        f'Dispatch refused: rate limit exceeded ({rate_limit} dispatches/hour).')

    body_hash = hashlib.sha256(body.encode()).hexdigest()[:16]
    audit_path = f'~/Projects/SOMA/audits/{iso_now}-{task_name}.md'

    dispatch_log = {
        'type': 'dispatch',
        'from': sender_raw,
        'sender_email': sender_email,
        'subject': subject,
        'platform': platform,
        'task_name': task_name,
        'body_hash': body_hash,
        'timestamp': datetime.now().isoformat(),
    }

    platforms_cfg = dispatch_cfg.get('platforms', {})

    if platform == 'Mac':
        mac_cmd = os.path.expanduser(
            platforms_cfg.get('Mac', {}).get('command', '~/.local/bin/cc-dispatch')
        )
        if not os.path.exists(mac_cmd):
            logging.error(f"cc-dispatch not found at {mac_cmd}")
            dispatch_log['result'] = 'error:cc-dispatch_not_found'
            try:
                send_email(config, sender_raw, f'Re: {subject}',
                           f'Dispatch failed: cc-dispatch not found at {mac_cmd}. '
                           'Install cc-dispatch to enable Mac dispatch.',
                           in_reply_to=email_data.get('message_id'),
                           references=email_data.get('references'))
            except Exception as e:
                logging.error(f"Failed to send error reply: {e}")
        else:
            proc = subprocess.Popen(
                [mac_cmd, task_name, body],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            dispatch_log['dispatch_pid'] = proc.pid
            logging.info(f"[DISPATCH:Mac] task={task_name} pid={proc.pid}")
            try:
                send_email(
                    config, sender_raw, f'Re: {subject}',
                    f"Dispatch confirmed.\n\n"
                    f"Platform: Mac\n"
                    f"Task: {task_name}\n"
                    f"Report: {audit_path}\n\n"
                    f"Check status: ls ~/Projects/SOMA/audits/ | grep {task_name}",
                    in_reply_to=email_data.get('message_id'),
                    references=email_data.get('references'),
                )
            except Exception as e:
                logging.error(f"Failed to send confirmation reply: {e}")

    elif platform == 'VPS':
        vps_cfg = platforms_cfg.get('VPS', {})
        ssh_target = vps_cfg.get('ssh_target', 'dev@vpsmikewolf.duckdns.org')
        vps_cmd = vps_cfg.get('command', '~/.local/bin/cc-dispatch')
        try:
            known_hosts_file = _vps_known_hosts_file(vps_cfg, ssh_target, state_dir)
            ssh_cmd = [
                'ssh',
                '-T',
                '-o', 'StrictHostKeyChecking=yes',
                '-o', f'UserKnownHostsFile={known_hosts_file}',
                '-o', 'UpdateHostKeys=no',
                '-o', 'ConnectTimeout=15',
                ssh_target,
                f'exec {vps_cmd} {shlex.quote(task_name)}',
            ]
            result = subprocess.run(
                ssh_cmd,
                input=body.encode('utf-8'),
                capture_output=True,
                timeout=30,
            )
            stderr = result.stderr.decode('utf-8', errors='replace')
            dispatch_log['ssh_exit'] = result.returncode
            dispatch_log['ssh_stderr'] = stderr[:500]
            stderr_lc = stderr.lower()
            if result.returncode != 0 and ('command not found' in stderr_lc or 'no such file' in stderr_lc):
                err = f'VPS dispatch failed: cc-dispatch not found on VPS.\n{stderr[:300]}'
                logging.error(err)
                send_email(config, sender_raw, f'Re: {subject}', err,
                           in_reply_to=email_data.get('message_id'),
                           references=email_data.get('references'))
            elif result.returncode != 0 and (
                'host key verification failed' in stderr_lc
                or 'strict host key checking' in stderr_lc
                or 'no hostkey alg' in stderr_lc
            ):
                err = (
                    'VPS dispatch failed: SSH host key verification failed. '
                    'Confirm dispatch.platforms.VPS.host_key or known_hosts_file before retrying.\n'
                    f'{stderr[:300]}'
                )
                logging.error(err)
                send_email(config, sender_raw, f'Re: {subject}', err,
                           in_reply_to=email_data.get('message_id'),
                           references=email_data.get('references'))
            elif result.returncode != 0:
                err = f'VPS dispatch failed (exit {result.returncode}):\n{stderr[:300]}'
                logging.error(err)
                send_email(config, sender_raw, f'Re: {subject}', err,
                           in_reply_to=email_data.get('message_id'),
                           references=email_data.get('references'))
            else:
                logging.info(f"[DISPATCH:VPS] task={task_name} exit=0")
                send_email(
                    config, sender_raw, f'Re: {subject}',
                    f"Dispatch confirmed.\n\n"
                    f"Platform: VPS\n"
                    f"Task: {task_name}\n"
                    f"Report: {audit_path} (on VPS)\n\n"
                    f"Check: ssh {ssh_target} 'ls ~/Projects/SOMA/audits/ | grep {task_name}'",
                    in_reply_to=email_data.get('message_id'),
                    references=email_data.get('references'),
                )
        except subprocess.TimeoutExpired:
            dispatch_log['ssh_exit'] = -1
            dispatch_log['result'] = 'error:ssh_timeout'
            logging.error(f"VPS SSH timed out for task={task_name}")
        except RuntimeError as e:
            dispatch_log['result'] = 'error:ssh_host_key_not_pinned'
            logging.error(f"VPS dispatch refused: {e}")
            send_email(config, sender_raw, f'Re: {subject}', f'Dispatch refused: {e}',
                       in_reply_to=email_data.get('message_id'),
                       references=email_data.get('references'))
        except Exception as e:
            dispatch_log['result'] = f'error:{e}'
            logging.error(f"VPS dispatch error: {e}")

    elif platform == 'Hermes':
        # TODO: Hermes dispatch — not yet installed on VPS
        logging.info(f"[DISPATCH:Hermes] not yet implemented, notifying sender")
        dispatch_log['result'] = 'hermes_not_available'
        try:
            send_email(
                config, sender_raw, f'Re: {subject}',
                "Hermes Agent not yet installed on VPS — falling back to VPS dispatch.\n\n"
                f"To dispatch via VPS instead, resend with subject: [DISPATCH:VPS] {task_name_raw}",
                in_reply_to=email_data.get('message_id'),
                references=email_data.get('references'),
            )
        except Exception as e:
            logging.error(f"Failed to send Hermes fallback reply: {e}")

    # Write structured dispatch log
    log_path = log_dir / f'dispatch-{iso_now}.json'
    with open(log_path, 'w') as f:
        json.dump(dispatch_log, f, indent=2)
    logging.info(f"Dispatch log: {log_path}")

    return dispatch_log


# ---------------------------------------------------------------------------
# State tracking — never process the same message twice
# ---------------------------------------------------------------------------

class StateTracker:
    def __init__(self, state_file):
        self.path = Path(os.path.expanduser(state_file))
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.processed = self._load()

    def _load(self):
        if self.path.exists():
            with open(self.path) as f:
                return json.load(f)
        return {"inbox": [], "drafts": []}

    def save(self):
        with open(self.path, "w") as f:
            json.dump(self.processed, f, indent=2)

    def is_processed(self, source, msg_id):
        return msg_id in self.processed.get(source, [])

    def mark_processed(self, source, msg_id):
        if source not in self.processed:
            self.processed[source] = []
        self.processed[source].append(msg_id)
        self.save()


# ---------------------------------------------------------------------------
# Structured logger — every decision logged for eval
# ---------------------------------------------------------------------------

class DecisionLogger:
    """Writes one JSON line per routing decision. This is the eval dataset."""

    def __init__(self, log_dir):
        self.log_dir = Path(os.path.expanduser(log_dir))
        self.log_dir.mkdir(parents=True, exist_ok=True)
        today = datetime.now().strftime("%Y-%m-%d")
        self.log_file = self.log_dir / f"decisions_{today}.jsonl"

    def log(self, entry):
        entry["logged_at"] = datetime.now().isoformat()
        with open(self.log_file, "a") as f:
            f.write(json.dumps(entry) + "\n")

    def read_all(self, path=None):
        """Read all entries from a log file (for replay)."""
        target = Path(path) if path else self.log_file
        entries = []
        with open(target) as f:
            for line in f:
                if line.strip():
                    entries.append(json.loads(line))
        return entries


# ---------------------------------------------------------------------------
# Email operations
# ---------------------------------------------------------------------------

def decode_subject(subject):
    if not subject:
        return "(no subject)"
    decoded_parts = decode_header(subject)
    return "".join(
        part.decode(enc or "utf-8") if isinstance(part, bytes) else part
        for part, enc in decoded_parts
    )


def extract_body(msg):
    """Extract plain text body from email message."""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                payload = part.get_payload(decode=True)
                if payload:
                    return payload.decode("utf-8", errors="replace")
        # Fallback to HTML if no plain text
        for part in msg.walk():
            if part.get_content_type() == "text/html":
                payload = part.get_payload(decode=True)
                if payload:
                    return payload.decode("utf-8", errors="replace")
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            return payload.decode("utf-8", errors="replace")
    return ""


def fetch_new_emails(imap_server, address, password, state, source="inbox"):
    """Fetch unprocessed emails from an IMAP mailbox."""
    mail = imaplib.IMAP4_SSL(imap_server)
    mail.login(address, password)
    mail.select("inbox")

    status, messages = mail.search(None, "UNSEEN")
    mail_ids = messages[0].split()

    new_emails = []
    for mid in mail_ids:
        mid_str = mid.decode()
        # Build a stable ID from message content (IMAP UIDs can change)
        status, msg_data = mail.fetch(mid, "(RFC822)")
        msg = email.message_from_bytes(msg_data[0][1])

        message_id = msg.get("Message-ID", "")
        stable_id = message_id or hashlib.sha256(
            f"{msg['From']}{msg['Subject']}{msg['Date']}".encode()
        ).hexdigest()[:16]

        if state.is_processed(source, stable_id):
            continue

        new_emails.append({
            "imap_id": mid_str,
            "stable_id": stable_id,
            "message_id": message_id,
            "from": msg["From"] or "",
            "to": msg["To"] or "",
            "subject": decode_subject(msg["Subject"]),
            "date": msg["Date"] or "",
            "body": extract_body(msg)[:2000],  # Truncate long bodies
            "references": msg.get("References", ""),
            "authentication_results": msg.get("Authentication-Results", ""),
        })

    mail.logout()
    return new_emails


def fetch_claude_drafts(imap_server, address, password, draft_prefix, state):
    """Fetch drafts from Mike's Gmail that match the Claude prefix."""
    mail = imaplib.IMAP4_SSL(imap_server)
    mail.login(address, password)
    mail.select("[Gmail]/Drafts")

    status, messages = mail.search(None, "ALL")
    mail_ids = messages[0].split()

    drafts = []
    for mid in mail_ids:
        mid_str = mid.decode()
        status, msg_data = mail.fetch(mid, "(RFC822)")
        msg = email.message_from_bytes(msg_data[0][1])

        subject = decode_subject(msg["Subject"])
        if not subject.startswith(draft_prefix):
            continue

        stable_id = hashlib.sha256(
            f"draft:{subject}:{msg['Date']}:{extract_body(msg)[:100]}".encode()
        ).hexdigest()[:16]

        if state.is_processed("drafts", stable_id):
            continue

        drafts.append({
            "imap_id": mid_str,
            "stable_id": stable_id,
            "subject": subject,
            "body": extract_body(msg)[:2000],
            "date": msg["Date"] or "",
            "source": "draft",
        })

    mail.logout()
    return drafts


def send_email(config, to, subject, body, in_reply_to=None, references=None, cc=None):
    """Send an email from Claude's account. cc is an optional list of addresses."""
    password = get_password("claude", "CLAUDE_EMAIL_PW", "Account")
    cfg = config["claude_email"]

    msg = MIMEMultipart()
    msg["From"] = f"Claude <{cfg['address']}>"
    msg["To"] = to
    msg["Subject"] = subject
    if in_reply_to:
        msg["In-Reply-To"] = in_reply_to
    if references:
        msg["References"] = references
    if cc:
        msg["Cc"] = ", ".join(cc) if isinstance(cc, list) else cc
    msg.attach(MIMEText(body, "plain"))

    recipients = [to]
    if cc:
        recipients += (cc if isinstance(cc, list) else [cc])

    with smtplib.SMTP(cfg["smtp_server"], cfg["smtp_port"]) as server:
        server.starttls()
        server.login(cfg["address"], password)
        server.sendmail(cfg["address"], recipients, msg.as_string())

    return True


# ---------------------------------------------------------------------------
# Greg Foster pipeline — autonomous Legends Member Services email handling
# ---------------------------------------------------------------------------

GREG_CLASSIFY_PROMPT = """You are classifying an email from Greg Foster (Legends Member Services Committee) to determine safe routing.

Classify into exactly one category. Respond with valid JSON only.

Categories:
- "on_site_build": Request to build, modify, or fix something on the Legends website
- "proposal_with_cost": Request that explicitly mentions a cost or budget amount
- "off_site_research": Research, data gathering, or work not directly on the Legends website
- "destructive": Requests to delete, drop, wipe, remove, or irreversibly change data or systems
- "access_control": Requests about passwords, credentials, permissions, or account access
- "ambiguous": Unclear intent, insufficient context, or multiple conflicting categories

Extract any explicitly mentioned dollar amounts.

Respond ONLY with JSON:
{"category": "<category>", "reason": "<one sentence>", "cost_usd": <number or null>, "summary": "<2-3 sentence summary>"}
"""


def _check_dkim_spf(email_data):
    """
    Parse Authentication-Results header for explicit DKIM/SPF failures.
    Returns False if an explicit fail is found (treat as spoofed), None otherwise.
    """
    auth_results = email_data.get("authentication_results", "").lower()
    if not auth_results:
        return None
    if "dkim=fail" in auth_results or "spf=fail" in auth_results:
        return False
    return None


def _parse_classify_json(raw):
    """Extract and parse JSON from a classifier response string."""
    json_str = raw
    if "```" in json_str:
        json_str = json_str.split("```")[1]
        if json_str.startswith("json"):
            json_str = json_str[4:]
    # Find the first '{' in case there's leading prose
    brace = json_str.find("{")
    if brace > 0:
        json_str = json_str[brace:]
    return json.loads(json_str.strip())


def _classify_via_vps_fallback(email_text):
    """Classify Greg email via VPS Haiku endpoint. Returns classification dict or raises."""
    vps_url = "https://vpsmikewolf.duckdns.org/infer/ask"
    question = (
        GREG_CLASSIFY_PROMPT
        + "\n\nEmail:\n" + email_text
        + "\n\nRespond with valid JSON only — no other text."
    )
    resp = requests.post(vps_url, json={"question": question, "context": ""}, timeout=45)
    raw = resp.json().get("answer", "").strip()
    result = _parse_classify_json(raw)
    result["classifier"] = "vps_haiku_fallback"
    return result


def classify_greg_email(config, email_data):
    """Ask the local LLM to classify a Greg email. Falls back to VPS Haiku if Ollama is down."""
    llm = config["llm"]
    email_text = (
        f"Subject: {email_data.get('subject', '')}\n\n"
        f"Body: {email_data.get('body', '')}"
    )
    ollama_error = None
    try:
        resp = requests.post(llm["endpoint"], json={
            "model": llm["model"],
            "prompt": f"{GREG_CLASSIFY_PROMPT}\n\nEmail:\n{email_text}",
            "stream": False,
            "options": {
                "temperature": llm.get("temperature", 0.1),
                "num_predict": llm.get("max_tokens", 200),
            }
        }, timeout=30)
        raw = resp.json().get("response", "").strip()
        result = _parse_classify_json(raw)
        result["classifier"] = "ollama"
        return result
    except Exception as e:
        ollama_error = e
        logging.warning(f"Ollama classifier failed ({e}), trying VPS fallback")

    try:
        return _classify_via_vps_fallback(email_text)
    except Exception as e2:
        logging.error(f"VPS fallback classifier also failed: {e2}")
        return {
            "category": "ambiguous",
            "reason": f"Classification error (ollama: {ollama_error}; vps: {e2})",
            "cost_usd": None,
            "summary": "Could not classify — routing to Mike as precaution",
            "error": str(e2),
            "classifier": "none",
        }


def handle_greg_email(email_data, config, logger):
    """
    Handle emails from Greg Foster (Legends Member Services Committee).
    Returns a routing result dict, or None if sender is not Greg.

    Safety model:
    - Explicit DKIM/SPF fail → escalate (spoofed sender)
    - Wrong sender email → return None (not Greg, let normal routing handle it)
    - Category destructive/access_control → always escalate regardless of auto_dispatch
    - Category off_site_research/ambiguous → escalate
    - Cost above cost_threshold_usd → escalate
    - auto_dispatch disabled → escalate
    - on_site_build or proposal_with_cost under threshold → auto-dispatch + reply Greg + cc Mike
    """
    greg_cfg = config.get("greg_pipeline", {})
    if not greg_cfg.get("enabled", False):
        return None

    greg_email_addr = greg_cfg.get("email", "").lower().strip()

    sender_raw = email_data.get("from", "")
    m_addr = re.search(r'<([^>]+)>', sender_raw)
    sender_email = m_addr.group(1).strip().lower() if m_addr else sender_raw.strip().lower()

    if sender_email != greg_email_addr:
        return None  # Not Greg — fall through to normal routing

    iso_now = datetime.now().strftime('%Y%m%dT%H%M%S')
    log_dir = Path(os.path.expanduser(config['log_dir']))
    log_dir.mkdir(parents=True, exist_ok=True)
    forward_to = config["forward_to"]

    def _escalate_to_mike(reason, classification=None):
        subject = f"[Greg/Legends] {email_data.get('subject', '')}"
        body_parts = [
            "Email from Greg Foster requires your attention.",
            "",
            f"Reason not auto-dispatched: {reason}",
            "",
        ]
        if classification:
            body_parts += [
                f"Classification: {classification.get('category', 'unknown')}",
                f"Summary: {classification.get('summary', '')}",
                "",
            ]
        body_parts += [
            "---",
            f"From: {email_data.get('from', '')}",
            f"Date: {email_data.get('date', '')}",
            f"Subject: {email_data.get('subject', '')}",
            "",
            email_data.get("body", ""),
        ]
        result = {
            "type": "greg_escalated",
            "from": sender_raw,
            "sender_email": sender_email,
            "subject": email_data.get("subject", ""),
            "escalation_reason": reason,
            "classification": classification,
            "timestamp": datetime.now().isoformat(),
        }
        try:
            send_email(config, forward_to, subject, "\n".join(body_parts))
            result["action_result"] = "escalated_to_mike"
        except Exception as e:
            result["action_result"] = f"escalation_send_error: {e}"
            logging.error(f"Failed to escalate Greg email to Mike: {e}")
        log_path = log_dir / f"greg-escalated-{iso_now}.json"
        with open(log_path, "w") as f:
            json.dump(result, f, indent=2)
        logging.info(f"Greg email escalated to Mike: {reason}")
        return result

    # SENDER VERIFICATION: explicit DKIM/SPF failure → treat as spoofed
    auth_ok = _check_dkim_spf(email_data)
    if auth_ok is False:
        return _escalate_to_mike("DKIM/SPF authentication failed — possible spoofed sender")

    # Classify the email
    classification = classify_greg_email(config, email_data)
    category = classification.get("category", "ambiguous")
    cost_usd = classification.get("cost_usd")

    # SAFETY GUARDS: destructive and access_control are never auto-dispatched
    if category in ("destructive", "access_control"):
        return _escalate_to_mike(
            f"Safety guard: '{category}' requests require Mike approval",
            classification,
        )

    # Off-site or ambiguous → Mike
    if category in ("off_site_research", "ambiguous"):
        return _escalate_to_mike(
            f"Category '{category}' requires Mike review",
            classification,
        )

    # Cost threshold check
    cost_threshold = greg_cfg.get("cost_threshold_usd", 100)
    if cost_usd is not None and cost_usd > cost_threshold:
        return _escalate_to_mike(
            f"Cost ${cost_usd} exceeds threshold ${cost_threshold}",
            classification,
        )

    # auto_dispatch gate
    auto_dispatch = greg_cfg.get("auto_dispatch", False)
    if not auto_dispatch:
        return _escalate_to_mike(
            "auto_dispatch is disabled — routing to Mike for manual approval",
            classification,
        )

    # AUTO-DISPATCH path
    task_name_raw = email_data.get("subject", "greg-legends-task")
    task_name = re.sub(r'[^\w\-]', '-', task_name_raw).strip('-') or 'greg-task'
    task_name = task_name[:40]
    audit_path = f"~/Projects/SOMA/audits/{iso_now}-{task_name}.md"

    prompt = (
        "## Context\n"
        f"Email from Greg Foster ({greg_email_addr}), Legends Member Services Committee.\n"
        f"Subject: {email_data.get('subject', '')}\n\n"
        f"## Email Body\n{email_data.get('body', '')}\n\n"
        "## Task\n"
        f"Handle this Legends website work request from Greg. "
        f"Category: {category}. "
        "Complete the requested work and report back.\n\n"
        "## Done criteria\n"
        f"Changes complete, tested, and a summary written to {audit_path}"
    )

    dispatch_result = {
        "type": "greg_dispatched",
        "from": sender_raw,
        "sender_email": sender_email,
        "subject": email_data.get("subject", ""),
        "classification": classification,
        "task_name": task_name,
        "timestamp": datetime.now().isoformat(),
    }

    mac_cmd = os.path.expanduser(
        config.get("dispatch", {}).get("platforms", {}).get("Mac", {}).get(
            "command", "~/.local/bin/cc-dispatch"
        )
    )
    if not os.path.exists(mac_cmd):
        logging.error(f"cc-dispatch not found at {mac_cmd}")
        dispatch_result["action_result"] = "error:cc-dispatch_not_found"
        return _escalate_to_mike(f"cc-dispatch not found at {mac_cmd}", classification)

    try:
        proc = subprocess.Popen(
            [mac_cmd, task_name, prompt],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        dispatch_result["dispatch_pid"] = proc.pid
        dispatch_result["action_result"] = "dispatched"
        logging.info(f"[GREG/dispatch] task={task_name} pid={proc.pid}")
    except Exception as e:
        dispatch_result["action_result"] = f"dispatch_error: {e}"
        logging.error(f"Failed to dispatch Greg task: {e}")
        return _escalate_to_mike(f"Dispatch failed: {e}", classification)

    # Reply to Greg + optionally CC Mike
    reply_body = (
        f"Hi Greg,\n\n"
        f"I've received your request and started working on it.\n\n"
        f"Task: {task_name}\n"
        f"Report: {audit_path}\n\n"
        f"I'll follow up when complete.\n\n"
        "Best,\nClaude\n(AI assistant for the Legends website)"
    )
    cc_list = []
    if greg_cfg.get("cc_mike_on_dispatch", True):
        cc_list.append(forward_to)

    try:
        send_email(
            config,
            sender_raw,
            f"Re: {email_data.get('subject', '')}",
            reply_body,
            in_reply_to=email_data.get("message_id"),
            references=email_data.get("references"),
            cc=cc_list if cc_list else None,
        )
        dispatch_result["reply_sent"] = True
    except Exception as e:
        dispatch_result["reply_sent"] = False
        dispatch_result["reply_error"] = str(e)
        logging.error(f"Failed to send reply to Greg: {e}")

    log_path = log_dir / f"greg-dispatched-{iso_now}.json"
    with open(log_path, "w") as f:
        json.dump(dispatch_result, f, indent=2)

    return dispatch_result


# ---------------------------------------------------------------------------
# LLM router
# ---------------------------------------------------------------------------

ROUTING_PROMPT = """You are an email routing agent for Claude (claude@mike-wolf.com), an AI assistant working for Mike Wolf.

Given an email, classify it into exactly one action. Respond with valid JSON only.

Actions:
- "forward_urgent": Time-sensitive or important — forward to Mike immediately
- "forward_summary": Interesting but not urgent — summarize and forward to Mike
- "auto_reply": Routine message that can be acknowledged automatically (e.g., "Thanks, I'll pass this along to Mike")
- "ignore": Spam, marketing, automated notifications — no action needed
- "execute_draft": This is a draft instruction from Claude Web/Mobile — parse and execute the instruction

Respond ONLY with JSON:
{"action": "<action>", "reason": "<one sentence>", "summary": "<2-3 sentence summary of the email>"}
"""


def route_email(config, email_text):
    """Ask the local LLM to classify an email. Returns dict with action + metadata."""
    llm = config["llm"]
    start = time.time()

    try:
        resp = requests.post(llm["endpoint"], json={
            "model": llm["model"],
            "prompt": f"{ROUTING_PROMPT}\n\nEmail:\n{email_text}",
            "stream": False,
            "options": {
                "temperature": llm.get("temperature", 0.1),
                "num_predict": llm.get("max_tokens", 200),
            }
        }, timeout=30)
        elapsed = time.time() - start
        raw = resp.json().get("response", "").strip()

        # Parse JSON from response (handle markdown code blocks)
        json_str = raw
        if "```" in json_str:
            json_str = json_str.split("```")[1]
            if json_str.startswith("json"):
                json_str = json_str[4:]
        result = json.loads(json_str.strip())
        result["llm_time_seconds"] = round(elapsed, 2)
        result["raw_response"] = raw
        result["model"] = llm["model"]
        return result

    except (json.JSONDecodeError, requests.RequestException, KeyError) as e:
        elapsed = time.time() - start
        return {
            "action": "forward_urgent",  # Fail safe: forward to Mike
            "reason": f"LLM error: {e}",
            "summary": "Could not classify — forwarding to Mike as precaution",
            "llm_time_seconds": round(elapsed, 2),
            "raw_response": raw if 'raw' in dir() else str(e),
            "model": llm["model"],
            "error": str(e),
        }


def apply_policy_overrides(config, email_data, llm_decision):
    """Override LLM decisions based on configured policies."""
    policies = config.get("policies", {})
    sender = email_data.get("from", "").lower()

    for pattern in policies.get("always_forward", []):
        if pattern.lower() in sender:
            return {
                **llm_decision,
                "action": "forward_urgent",
                "reason": f"Policy override: always forward from {pattern}",
                "policy_override": True,
            }

    for pattern in policies.get("always_ignore", []):
        if pattern.lower() in sender:
            return {
                **llm_decision,
                "action": "ignore",
                "reason": f"Policy override: always ignore from {pattern}",
                "policy_override": True,
            }

    return llm_decision


# ---------------------------------------------------------------------------
# Action executors
# ---------------------------------------------------------------------------

def execute_action(config, email_data, decision, logger, dry_run=False):
    """Execute the routing decision and log everything."""
    action = decision["action"]
    forward_to = config["forward_to"]

    log_entry = {
        "source": email_data.get("source", "inbox"),
        "stable_id": email_data.get("stable_id"),
        "email": {
            "from": email_data.get("from", ""),
            "to": email_data.get("to", ""),
            "subject": email_data.get("subject", ""),
            "date": email_data.get("date", ""),
            "body_preview": email_data.get("body", "")[:500],
        },
        "decision": {
            "action": action,
            "reason": decision.get("reason", ""),
            "summary": decision.get("summary", ""),
            "model": decision.get("model", ""),
            "llm_time_seconds": decision.get("llm_time_seconds", 0),
            "policy_override": decision.get("policy_override", False),
            "raw_response": decision.get("raw_response", ""),
        },
        "dry_run": dry_run,
        "action_result": None,
    }

    if dry_run:
        log_entry["action_result"] = "skipped (dry run)"
        logger.log(log_entry)
        return log_entry

    try:
        if action == "forward_urgent":
            subject = f"[URGENT] {email_data['subject']}"
            body = (
                f"Forwarded by Claude — flagged as urgent.\n\n"
                f"From: {email_data['from']}\n"
                f"Date: {email_data['date']}\n"
                f"Subject: {email_data['subject']}\n\n"
                f"---\n\n{email_data.get('body', '')}"
            )
            send_email(config, forward_to, subject, body)
            log_entry["action_result"] = "forwarded_urgent"

        elif action == "forward_summary":
            summary = decision.get("summary", "No summary available.")
            subject = f"[FYI] {email_data['subject']}"
            body = (
                f"Summary from Claude:\n{summary}\n\n"
                f"---\nOriginal from: {email_data['from']}\n"
                f"Date: {email_data['date']}\n\n"
                f"{email_data.get('body', '')}"
            )
            send_email(config, forward_to, subject, body)
            log_entry["action_result"] = "forwarded_summary"

        elif action == "auto_reply":
            reply_body = (
                f"Hi,\n\nThank you for your message. I'll make sure Mike sees this.\n\n"
                f"Best,\nClaude\n(AI assistant for Mike Wolf)"
            )
            send_email(
                config,
                email_data["from"],
                f"Re: {email_data['subject']}",
                reply_body,
                in_reply_to=email_data.get("message_id"),
                references=email_data.get("references"),
            )
            log_entry["action_result"] = "auto_replied"

        elif action == "ignore":
            log_entry["action_result"] = "ignored"

        elif action == "execute_draft":
            # For now, log it — execution of draft instructions is Phase 2
            log_entry["action_result"] = "draft_logged_for_execution"

        else:
            log_entry["action_result"] = f"unknown_action: {action}"

    except Exception as e:
        log_entry["action_result"] = f"error: {e}"

    logger.log(log_entry)
    return log_entry


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def run_cycle(config, state, logger, dry_run=False):
    """Run one check cycle: fetch new emails + drafts, route, act."""
    results = []

    # 1. Check Claude's inbox
    try:
        claude_pw = get_password("claude", "CLAUDE_EMAIL_PW", "Account")
        cfg = config["claude_email"]
        new_emails = fetch_new_emails(
            cfg["imap_server"], cfg["address"], claude_pw, state, source="inbox"
        )
        logging.info(f"Found {len(new_emails)} new email(s) in Claude's inbox")

        for em in new_emails:
            # Dispatch emails short-circuit LLM routing entirely
            if DISPATCH_SUBJECT_RE.match(em.get('subject', '')):
                if not dry_run:
                    dispatch_result = handle_dispatch_email(em, config, logger)
                    results.append(dispatch_result or {})
                    logging.info(f"  [dispatch] {em['subject'][:60]}")
                else:
                    logging.info(f"  [dispatch/dry-run] {em['subject'][:60]}")
                    results.append({"action": "dispatch_dry_run", "subject": em["subject"]})
                state.mark_processed("inbox", em["stable_id"])
                continue

            # Greg pipeline: check before general LLM routing
            greg_result = handle_greg_email(em, config, logger) if not dry_run else None
            if greg_result is not None:
                results.append(greg_result)
                state.mark_processed("inbox", em["stable_id"])
                logging.info(f"  [greg/{greg_result.get('type', '?')}] {em['subject'][:60]}")
                continue
            if dry_run and config.get("greg_pipeline", {}).get("enabled"):
                _from_raw = em.get("from", "")
                _m = re.search(r'<([^>]+)>', _from_raw)
                _sender = _m.group(1).strip().lower() if _m else _from_raw.strip().lower()
                if _sender == config["greg_pipeline"].get("email", "").lower():
                    logging.info(f"  [greg/dry-run] {em['subject'][:60]}")
                    results.append({"action": "greg_dry_run", "subject": em["subject"]})
                    state.mark_processed("inbox", em["stable_id"])
                    continue

            email_text = f"From: {em['from']}\nSubject: {em['subject']}\n\n{em['body']}"
            decision = route_email(config, email_text)
            decision = apply_policy_overrides(config, em, decision)
            result = execute_action(config, em, decision, logger, dry_run=dry_run)
            state.mark_processed("inbox", em["stable_id"])
            results.append(result)
            logging.info(
                f"  [{decision['action']}] {em['subject'][:60]} "
                f"({decision.get('llm_time_seconds', 0):.1f}s)"
            )

    except Exception as e:
        logging.error(f"Error checking Claude's inbox: {e}")

    # 2. Check Mike's drafts (if configured)
    _auth_alert_path = Path(os.path.expanduser("~/Projects/SOMA/state/email-daemon-auth-alert.json"))
    try:
        mike_pw = get_password("mikeai", "MIKE_EMAIL_PW", "Mike's AI Account")
    except RuntimeError:
        mike_pw = None
    if mike_pw:
        try:
            mike_cfg = config["mike_email"]
            drafts = fetch_claude_drafts(
                mike_cfg["imap_server"],
                mike_cfg["address"],
                mike_pw,
                config["draft_prefix"],
                state,
            )
            logging.info(f"Found {len(drafts)} new Claude draft(s)")
            # Clear any stale auth-alert since credentials are now working
            if _auth_alert_path.exists():
                _auth_alert_path.unlink()

            for draft in drafts:
                email_text = f"Subject: {draft['subject']}\n\n{draft['body']}"
                decision = route_email(config, email_text)
                decision["action"] = "execute_draft"  # Override — drafts are always instructions
                result = execute_action(config, draft, decision, logger, dry_run=dry_run)
                state.mark_processed("drafts", draft["stable_id"])
                results.append(result)
                logging.info(f"  [draft] {draft['subject'][:60]}")

        except Exception as e:
            err_str = str(e)
            is_auth = "AUTHENTICATIONFAILED" in err_str or "Invalid credentials" in err_str
            if is_auth:
                # Rate-limit the log line to once per hour; always update health state file
                _auth_last_log = Path(os.path.expanduser("~/Projects/SOMA/state/email-daemon-auth-last-log"))
                now_ts = time.time()
                last_log = float(_auth_last_log.read_text()) if _auth_last_log.exists() else 0
                if now_ts - last_log > 3600:
                    logging.error(f"mikeai@ AUTHENTICATIONFAILED — stale app password; needs Mike to regenerate")
                    _auth_last_log.write_text(str(now_ts))
                _auth_alert_path.parent.mkdir(parents=True, exist_ok=True)
                _auth_alert_path.write_text(json.dumps({
                    "ts": datetime.now().isoformat(),
                    "msg": "mikeai@ AUTHENTICATIONFAILED — stale app password, needs Mike to regenerate in Google Account",
                }))
            else:
                logging.error(f"Error checking Mike's drafts: {e}")
    else:
        logging.debug("Skipping draft check — MIKE_EMAIL_PW not set")

    return results


def replay_log(config, log_path, model_override=None):
    """Replay logged emails through a (possibly different) model for comparison."""
    logger = DecisionLogger(config["log_dir"])
    entries = logger.read_all(log_path)

    if model_override:
        config["llm"]["model"] = model_override

    replay_logger = DecisionLogger(config["log_dir"])
    # Write to a separate replay file
    model_name = config["llm"]["model"].replace(":", "-").replace("/", "-")
    replay_logger.log_file = (
        replay_logger.log_dir / f"replay_{model_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jsonl"
    )

    print(f"Replaying {len(entries)} entries through {config['llm']['model']}")
    print(f"Output: {replay_logger.log_file}")

    for i, entry in enumerate(entries):
        em = entry.get("email", {})
        email_text = f"From: {em.get('from', '')}\nSubject: {em.get('subject', '')}\n\n{em.get('body_preview', '')}"
        decision = route_email(config, email_text)

        replay_entry = {
            "source": entry.get("source", "replay"),
            "stable_id": entry.get("stable_id"),
            "email": em,
            "original_decision": entry.get("decision", {}),
            "replay_decision": {
                "action": decision.get("action"),
                "reason": decision.get("reason"),
                "summary": decision.get("summary"),
                "model": decision.get("model"),
                "llm_time_seconds": decision.get("llm_time_seconds"),
                "raw_response": decision.get("raw_response"),
            },
            "match": decision.get("action") == entry.get("decision", {}).get("action"),
        }
        replay_logger.log(replay_entry)

        match_str = "✓" if replay_entry["match"] else "✗"
        orig = entry.get("decision", {}).get("action", "?")
        new = decision.get("action", "?")
        print(f"  {match_str} [{i+1}/{len(entries)}] {em.get('subject', '?')[:50]} | {orig} → {new}")

    print(f"\nDone. Results in: {replay_logger.log_file}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Claude Email Daemon")
    parser.add_argument("--loop", action="store_true", help="Run continuously")
    parser.add_argument("--dry-run", action="store_true", help="Route but don't send emails")
    parser.add_argument("--config", default=None, help="Config file path")
    parser.add_argument("--replay", default=None, help="Replay a log file through current model")
    parser.add_argument("--model", default=None, help="Override model (for replay)")
    args = parser.parse_args()

    config = load_config(args.config)

    # Set up console logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    # Replay mode
    if args.replay:
        replay_log(config, args.replay, model_override=args.model)
        return

    state = StateTracker(config["state_file"])
    logger = DecisionLogger(config["log_dir"])

    logging.info(f"Claude Email Daemon starting (model: {config['llm']['model']})")
    logging.info(f"Logging to: {logger.log_file}")

    if args.loop:
        interval = config["poll_interval_seconds"]
        logging.info(f"Polling every {interval}s. Ctrl+C to stop.")
        while True:
            try:
                run_cycle(config, state, logger, dry_run=args.dry_run)
            except KeyboardInterrupt:
                logging.info("Shutting down.")
                break
            except Exception as e:
                logging.error(f"Cycle error: {e}")
            time.sleep(interval)
    else:
        run_cycle(config, state, logger, dry_run=args.dry_run)
        logging.info("Single cycle complete.")


if __name__ == "__main__":
    main()
