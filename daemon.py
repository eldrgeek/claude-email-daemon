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


def _get_trusted_requesters(config):
    """
    Return {email_lower: requester_config} for all trusted senders.

    Reads from trusted_requesters config (new style).  Falls back to
    greg_pipeline for backward compatibility with old configs.
    """
    requesters = {}
    for addr, cfg in config.get("trusted_requesters", {}).items():
        requesters[addr.lower().strip()] = cfg
    # Backward compat: auto-populate from greg_pipeline if not already present
    greg_cfg = config.get("greg_pipeline", {})
    if greg_cfg.get("enabled") and greg_cfg.get("email"):
        greg_addr = greg_cfg["email"].lower().strip()
        if greg_addr not in requesters:
            requesters[greg_addr] = {
                "name": "Greg Foster",
                "tier": "member_services",
                "auto_dispatch": greg_cfg.get("auto_dispatch", True),
                "cc_dispatch_to": ([config["forward_to"]] if greg_cfg.get("cc_mike_on_dispatch") else []),
                "cost_threshold_usd": greg_cfg.get("cost_threshold_usd", 100),
                "completion_timeout_hours": greg_cfg.get("completion_timeout_hours", 4),
                "escalate_to": config["forward_to"],
                "ack_greeting": "Hi Greg,",
                "ack_signature": "Claude\n(AI assistant for the Legends website)",
            }
    return requesters


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
            "cc": msg.get("Cc") or "",
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
# Trusted-requester pipeline — autonomous email handling for site requesters
# ---------------------------------------------------------------------------

def _build_classify_prompt(requester):
    """Build a per-requester classifier prompt from their config fields."""
    req_name   = requester.get("name", "the requester")
    site_label = requester.get("site_label", "the website")
    site_desc  = requester.get("site_description", "")
    desc_clause = f"\n{site_desc}" if site_desc else ""
    return (
        f"You are classifying an email from {req_name} to determine safe routing.{desc_clause}\n\n"
        "Classify into exactly one category. Respond with valid JSON only.\n\n"
        "Categories:\n"
        f'- "on_site_build": Request to build, modify, or fix something on {site_label}\n'
        '- "proposal_with_cost": Request that explicitly mentions a cost or budget amount\n'
        f'- "off_site_research": Research, data gathering, or work not directly on {site_label}\n'
        '- "destructive": Requests to delete, drop, wipe, remove, or irreversibly change data or systems\n'
        '- "access_control": Requests about passwords, credentials, permissions, or account access\n'
        '- "ambiguous": Unclear intent, insufficient context, or multiple conflicting categories\n\n'
        "Extract any explicitly mentioned dollar amounts.\n\n"
        "Respond ONLY with JSON:\n"
        '{"category": "<category>", "reason": "<one sentence>", "cost_usd": <number or null>, "summary": "<2-3 sentence summary>"}'
    )


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


def _classify_via_vps_fallback(classify_prompt, email_text):
    """Classify email via VPS Haiku endpoint. Returns classification dict or raises."""
    vps_url = "https://vpsmikewolf.duckdns.org/infer/ask"
    question = (
        classify_prompt
        + "\n\nEmail:\n" + email_text
        + "\n\nRespond with valid JSON only — no other text."
    )
    resp = requests.post(vps_url, json={"question": question, "context": ""}, timeout=45)
    raw = resp.json().get("answer", "").strip()
    result = _parse_classify_json(raw)
    result["classifier"] = "vps_haiku_fallback"
    return result


def classify_trusted_email(config, email_data, requester):
    """Ask the local LLM to classify a trusted-requester email. Falls back to VPS Haiku if Ollama is down."""
    llm = config["llm"]
    email_text = (
        f"Subject: {email_data.get('subject', '')}\n\n"
        f"Body: {email_data.get('body', '')}"
    )
    classify_prompt = _build_classify_prompt(requester)
    ollama_error = None
    try:
        resp = requests.post(llm["endpoint"], json={
            "model": llm["model"],
            "prompt": f"{classify_prompt}\n\nEmail:\n{email_text}",
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
        return _classify_via_vps_fallback(classify_prompt, email_text)
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


def classify_greg_email(config, email_data):
    """Backward-compat alias — classifies using Greg's site context from trusted_requesters."""
    requesters = _get_trusted_requesters(config)
    greg_cfg = config.get("greg_pipeline", {})
    greg_addr = greg_cfg.get("email", "").lower().strip() if greg_cfg else ""
    requester = requesters.get(greg_addr) or {
        "name": "Greg Foster",
        "site_label": "the Legends website",
    }
    return classify_trusted_email(config, email_data, requester)


def _pending_path(config):
    return Path(os.path.expanduser(config["state_file"])).parent / "greg-pending.json"


def _load_pending(config):
    path = _pending_path(config)
    if path.exists():
        with open(path) as f:
            tasks = json.load(f)
        # Normalize old-style records that use greg_from / greg_email
        for task in tasks:
            if "requester_from" not in task:
                task["requester_from"] = task.get("greg_from", "")
            if "requester_email" not in task:
                task["requester_email"] = task.get("greg_email", "")
            if "extra_cc" not in task:
                task["extra_cc"] = []
        return tasks
    return []


def _save_pending_list(config, tasks):
    path = _pending_path(config)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(tasks, f, indent=2)


def _save_pending(config, task):
    tasks = _load_pending(config)
    tasks.append(task)
    _save_pending_list(config, tasks)


# Keep old names as aliases so any external scripts that import them still work.
_greg_pending_path = _pending_path
_load_greg_pending = _load_pending
_save_greg_pending_list = _save_pending_list
_save_greg_pending = _save_pending


def _extract_report_summary(report_text, max_chars=3000):
    """Extract a human-readable summary from an audit report for the completion email."""
    if not report_text:
        return "(no report content)"
    # Try to find a meaningful section: ## Result, ## What Was Done, ## Final assistant text
    for section_header in ("## Result", "## What Was Done", "## Changes Made", "## Final assistant text"):
        idx = report_text.find(section_header)
        if idx != -1:
            snippet = report_text[idx:idx + max_chars].strip()
            # Trim at the next ## heading if it's long
            next_section = snippet.find("\n## ", 3)
            if next_section != -1 and next_section > 200:
                snippet = snippet[:next_section].strip()
            return snippet
    # Fall back to first max_chars chars, skip the header line
    lines = report_text.strip().splitlines()
    body_lines = [l for l in lines if not l.startswith("# cc-dispatch report")]
    return "\n".join(body_lines)[:max_chars].strip()


def check_pending_completions(config, logger):
    """
    Check whether any pending trusted-requester tasks have completed (audit report on disk).
    Send completion emails when reports land; time out after completion_timeout_hours.
    Called every daemon cycle.  Handles both Greg-style and owner-tier tasks.
    """
    requesters = _get_trusted_requesters(config)
    if not requesters:
        return

    pending = _load_pending(config)
    if not pending:
        return

    audits_dir = Path(os.path.expanduser("~/Projects/SOMA/audits"))
    forward_to = config["forward_to"]
    updated = False

    for task in pending:
        if task.get("notified"):
            continue

        task_name = task["task_name"]
        dispatched_at = task.get("dispatched_at", "")
        requester_from = task.get("requester_from") or task.get("greg_from", "")
        requester_email = (task.get("requester_email") or task.get("greg_email", "")).lower()
        extra_cc = task.get("extra_cc", [])
        subject = task.get("subject", "")

        # Requester config for personalised email text
        req_cfg = requesters.get(requester_email, {})
        ack_greeting = req_cfg.get("ack_greeting", "Hi,")
        ack_signature = req_cfg.get("ack_signature", "Claude")
        req_name = req_cfg.get("name", requester_email)
        timeout_hours = req_cfg.get("completion_timeout_hours", 4)
        tier = req_cfg.get("tier", "member_services")

        # Look for a matching report: *-{task_name}.md in audits dir
        matching = sorted(audits_dir.glob(f"*-{task_name}.md"))
        report_path = None
        report_text = ""
        if matching:
            report_path = matching[-1]
            try:
                report_text = report_path.read_text(errors="replace")
            except OSError as e:
                logging.warning(f"[completion] could not read report {report_path}: {e}")

        # Check timeout
        timed_out = False
        if dispatched_at:
            try:
                dispatched_dt = datetime.fromisoformat(dispatched_at)
                age_hours = (datetime.now() - dispatched_dt).total_seconds() / 3600
                if age_hours > timeout_hours:
                    timed_out = True
            except ValueError:
                pass

        if report_path or timed_out:
            if report_path and report_text:
                summary = _extract_report_summary(report_text)
                email_body = (
                    f"{ack_greeting}\n\n"
                    f"Your request has been completed.\n\n"
                    f"Task: {task_name}\n\n"
                    f"---\n\n"
                    f"{summary}\n\n"
                    f"---\n\n"
                    f"Full report: {report_path}\n\n"
                    f"Best,\n{ack_signature}"
                )
                email_subject = f"Re: {subject} — Done"
                log_type = "completion_sent"
            else:
                if tier == "owner":
                    followup_note = "Please check the task status manually."
                else:
                    followup_note = "Mike has been notified and will follow up."
                email_body = (
                    f"{ack_greeting}\n\n"
                    f"Your request is taking longer than expected. "
                    f"{followup_note}\n\n"
                    f"Task: {task_name}\n\n"
                    f"Best,\n{ack_signature}"
                )
                email_subject = f"Re: {subject} — In Progress"
                log_type = "completion_timeout"
                # Alert forward_to about timeout unless requester IS forward_to
                if requester_email != forward_to.lower():
                    try:
                        send_email(
                            config, forward_to,
                            f"[{req_name}/Task] Timeout: {task_name}",
                            f"Task '{task_name}' for {req_name} has been pending for >{timeout_hours}h with no audit report.\n"
                            f"Dispatched at: {dispatched_at}\n"
                            f"Expected report in: {audits_dir}/*-{task_name}.md\n\n"
                            f"Original request from: {requester_from}\nSubject: {subject}",
                        )
                    except Exception as e:
                        logging.error(f"[completion] failed to alert {forward_to} about timeout: {e}")

            cc_list = extra_cc if extra_cc else None
            try:
                send_email(
                    config,
                    requester_from,
                    email_subject,
                    email_body,
                    in_reply_to=task.get("message_id") or None,
                    references=task.get("references") or None,
                    cc=cc_list,
                )
                task["notified"] = True
                task["notified_at"] = datetime.now().isoformat()
                task["report_path"] = str(report_path) if report_path else None
                task["notify_type"] = log_type
                updated = True
                logging.info(f"[completion] sent {log_type} for task={task_name} to {requester_from}")
            except Exception as e:
                logging.error(f"[completion] failed to send completion for task={task_name}: {e}")

    if updated:
        _save_pending_list(config, pending)
        # Prune fully-notified tasks older than 7 days
        cutoff = datetime.now().timestamp() - 7 * 86400
        pruned = []
        for task in pending:
            if task.get("notified"):
                notified_at = task.get("notified_at", "")
                try:
                    if datetime.fromisoformat(notified_at).timestamp() < cutoff:
                        continue
                except ValueError:
                    pass
            pruned.append(task)
        if len(pruned) != len(pending):
            _save_pending_list(config, pruned)


# Keep old name as an alias so any external scripts still work.
check_greg_completions = check_pending_completions


def handle_trusted_email(email_data, config, logger):
    """
    Handle emails from trusted requesters (configured in trusted_requesters).
    Returns a routing result dict, or None if the sender is not a trusted requester.

    Tiers:
      member_services (e.g. Greg Foster)
        - Auto-dispatch: on_site_build, proposal_with_cost under cost_threshold_usd
        - Escalate to escalate_to: destructive, access_control, off_site_research,
          ambiguous, over-threshold costs, auto_dispatch=false
      owner (e.g. Mike Wolf)
        - Auto-dispatch: ALL categories EXCEPT hard stops
        - No cost cap; no escalation path (owner is self)
        - Hard stops (destructive, access_control) are SURFACED to the owner as a
          manual-action notice — never auto-executed regardless of tier

    SENDER VERIFICATION:
      - owner tier: explicit DKIM/SPF fail → fall through to normal routing (return None)
      - member_services tier: explicit DKIM/SPF fail → escalate as possible spoof
    """
    requesters = _get_trusted_requesters(config)

    sender_raw = email_data.get("from", "")
    m_addr = re.search(r'<([^>]+)>', sender_raw)
    sender_email = m_addr.group(1).strip().lower() if m_addr else sender_raw.strip().lower()

    requester = requesters.get(sender_email)
    if requester is None:
        return None  # Not a trusted sender — fall through to normal routing

    tier = requester.get("tier", "member_services")
    req_name = requester.get("name", sender_email)
    iso_now = datetime.now().strftime('%Y%m%dT%H%M%S')
    log_dir = Path(os.path.expanduser(config['log_dir']))
    log_dir.mkdir(parents=True, exist_ok=True)
    forward_to = config["forward_to"]
    ack_greeting = requester.get("ack_greeting", f"Hi {req_name},")
    ack_signature = requester.get("ack_signature", "Claude")

    def _escalate(reason, classification=None):
        """Forward to the designated escalation address with full context."""
        escalate_to = requester.get("escalate_to", forward_to)
        subj = f"[{req_name}/Request] {email_data.get('subject', '')}"
        body_parts = [
            f"Email from {req_name} requires your attention.",
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
            "type": "trusted_escalated",
            "requester": req_name,
            "tier": tier,
            "from": sender_raw,
            "sender_email": sender_email,
            "subject": email_data.get("subject", ""),
            "escalation_reason": reason,
            "escalated_to": escalate_to,
            "classification": classification,
            "timestamp": datetime.now().isoformat(),
        }
        try:
            send_email(config, escalate_to, subj, "\n".join(body_parts))
            result["action_result"] = "escalated"
        except Exception as e:
            result["action_result"] = f"escalation_send_error: {e}"
            logging.error(f"[trusted/{req_name}] failed to escalate: {e}")
        log_path = log_dir / f"trusted-escalated-{iso_now}.json"
        with open(log_path, "w") as f:
            json.dump(result, f, indent=2)
        logging.info(f"[trusted/{req_name}] escalated: {reason}")
        return result

    def _surface_hard_stop(classification, category):
        """
        Notify the owner-tier requester that a hard stop was triggered.
        The request is NOT dispatched; they must act manually.
        """
        subj = f"[Hard Stop] {email_data.get('subject', '')} — manual action required"
        body_parts = [
            ack_greeting,
            "",
            "Your request contained a safety hard stop and was NOT auto-executed.",
            "",
            f"Hard stop: {category}",
            f"Reason: {classification.get('reason', '')}",
            "",
            "Requests involving destructive operations, access-control changes, or",
            "money movement are never auto-executed regardless of sender.",
            "Please handle this manually.",
            "",
            f"Summary: {classification.get('summary', '')}",
            "",
            "---",
            f"Original subject: {email_data.get('subject', '')}",
            "",
            email_data.get("body", ""),
            "",
            f"—{ack_signature}",
        ]
        result = {
            "type": "hard_stop_surfaced",
            "requester": req_name,
            "tier": tier,
            "from": sender_raw,
            "sender_email": sender_email,
            "subject": email_data.get("subject", ""),
            "hard_stop_category": category,
            "classification": classification,
            "timestamp": datetime.now().isoformat(),
        }
        try:
            send_email(config, sender_raw, subj, "\n".join(body_parts))
            result["action_result"] = "hard_stop_notified"
        except Exception as e:
            result["action_result"] = f"notify_error: {e}"
            logging.error(f"[trusted/{req_name}] failed to surface hard stop: {e}")
        log_path = log_dir / f"trusted-hard-stop-{iso_now}.json"
        with open(log_path, "w") as f:
            json.dump(result, f, indent=2)
        logging.info(f"[trusted/{req_name}] hard stop surfaced: {category}")
        return result

    # ----------------------------------------------------------------
    # SENDER VERIFICATION: explicit DKIM/SPF failure
    # ----------------------------------------------------------------
    auth_ok = _check_dkim_spf(email_data)
    if auth_ok is False:
        if tier == "owner":
            # A DKIM/SPF failure on an owner-address email is a spoof signal.
            # Fall through to normal routing rather than granting owner privileges.
            logging.warning(
                f"[trusted/{req_name}] DKIM/SPF fail on {sender_email} — "
                "possible spoof; falling through to normal routing"
            )
            return None
        return _escalate("DKIM/SPF authentication failed — possible spoofed sender")

    # ----------------------------------------------------------------
    # Classify the email
    # ----------------------------------------------------------------
    classification = classify_trusted_email(config, email_data, requester)
    category = classification.get("category", "ambiguous")
    cost_usd = classification.get("cost_usd")

    # ----------------------------------------------------------------
    # HARD STOPS — apply to ALL tiers, including owner
    # ----------------------------------------------------------------
    if category in ("destructive", "access_control"):
        if tier == "owner":
            return _surface_hard_stop(classification, category)
        return _escalate(
            f"Safety guard: '{category}' requests require manual approval",
            classification,
        )

    # ----------------------------------------------------------------
    # Tier-specific routing
    # ----------------------------------------------------------------
    if tier == "owner":
        auto_dispatch = requester.get("auto_dispatch", True)
        if not auto_dispatch:
            return _surface_hard_stop(
                {"category": "auto_dispatch_disabled",
                 "reason": "auto_dispatch is disabled for owner tier",
                 "summary": "auto_dispatch disabled"},
                "auto_dispatch_disabled",
            )
        # Determine dynamic CC: include any member_services-tier trusted sender
        # who was on the original thread (To or Cc headers).
        extra_cc = list(requester.get("cc_dispatch_to", []))
        to_lc = (email_data.get("to") or "").lower()
        cc_lc = (email_data.get("cc") or "").lower()
        for raddr, rcfg in requesters.items():
            if raddr != sender_email and rcfg.get("tier") == "member_services":
                if raddr in to_lc or raddr in cc_lc:
                    if raddr not in [e.lower() for e in extra_cc]:
                        extra_cc.append(raddr)

    else:
        # member_services tier
        if category in ("off_site_research", "ambiguous"):
            return _escalate(f"Category '{category}' requires review", classification)

        cost_threshold = requester.get("cost_threshold_usd", 100)
        if cost_threshold is not None and cost_usd is not None and cost_usd > cost_threshold:
            return _escalate(
                f"Cost ${cost_usd} exceeds threshold ${cost_threshold}", classification
            )

        auto_dispatch = requester.get("auto_dispatch", False)
        if not auto_dispatch:
            return _escalate(
                "auto_dispatch is disabled — routing for manual approval", classification
            )

        extra_cc = list(requester.get("cc_dispatch_to", []))

    # ----------------------------------------------------------------
    # AUTO-DISPATCH path (reached when all gates pass)
    # ----------------------------------------------------------------
    task_name_raw = email_data.get("subject", "task")
    task_name = re.sub(r'[^\w\-]', '-', task_name_raw).strip('-') or 'task'
    task_name = task_name[:40]
    audit_path = f"~/Projects/SOMA/audits/{iso_now}-{task_name}.md"

    prompt = (
        "## Context\n"
        f"Email from {req_name} ({sender_email}).\n"
        f"Subject: {email_data.get('subject', '')}\n\n"
        f"## Email Body\n{email_data.get('body', '')}\n\n"
        "## Task\n"
        f"Handle this work request. Category: {category}. "
        "Complete the requested work and report back.\n\n"
        "## Done criteria\n"
        f"Changes complete, tested, and a summary written to {audit_path}"
    )

    # Resolve repo workdir for this requester (used as --workdir arg to cc-dispatch)
    repo_raw = requester.get("repo")
    repo_path = os.path.expanduser(repo_raw) if repo_raw else None
    if repo_path and not os.path.isdir(repo_path):
        logging.warning(f"[trusted/{req_name}] repo path not found: {repo_path} — dispatching without workdir")
        repo_path = None

    dispatch_result = {
        "type": "trusted_dispatched",
        "requester": req_name,
        "tier": tier,
        "from": sender_raw,
        "sender_email": sender_email,
        "subject": email_data.get("subject", ""),
        "classification": classification,
        "task_name": task_name,
        "extra_cc": extra_cc,
        "repo": repo_path,
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
        if tier == "owner":
            return _surface_hard_stop(
                {"category": "dispatch_error",
                 "reason": f"cc-dispatch not found at {mac_cmd}",
                 "summary": "cc-dispatch binary missing"},
                "dispatch_error",
            )
        return _escalate(f"cc-dispatch not found at {mac_cmd}", classification)

    try:
        cmd_args = [mac_cmd]
        if repo_path:
            cmd_args += ["--workdir", repo_path]
        cmd_args += [task_name, prompt]

        proc = subprocess.Popen(
            cmd_args,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        dispatch_result["dispatch_pid"] = proc.pid
        dispatch_result["action_result"] = "dispatched"
        repo_note = f" workdir={repo_path}" if repo_path else ""
        logging.info(f"[trusted/{req_name}] dispatch task={task_name} pid={proc.pid}{repo_note}")
    except Exception as e:
        dispatch_result["action_result"] = f"dispatch_error: {e}"
        logging.error(f"[trusted/{req_name}] failed to dispatch: {e}")
        if tier == "owner":
            return _surface_hard_stop(
                {"category": "dispatch_error", "reason": str(e),
                 "summary": f"Dispatch failed: {e}"},
                "dispatch_error",
            )
        return _escalate(f"Dispatch failed: {e}", classification)

    # Ack to requester (CC any extra recipients)
    reply_body = (
        f"{ack_greeting}\n\n"
        f"I've received your request and started working on it.\n\n"
        f"Task: {task_name}\n"
        f"Report: {audit_path}\n\n"
        f"I'll follow up when complete.\n\n"
        f"Best,\n{ack_signature}"
    )
    try:
        send_email(
            config,
            sender_raw,
            f"Re: {email_data.get('subject', '')}",
            reply_body,
            in_reply_to=email_data.get("message_id"),
            references=email_data.get("references"),
            cc=extra_cc if extra_cc else None,
        )
        dispatch_result["reply_sent"] = True
    except Exception as e:
        dispatch_result["reply_sent"] = False
        dispatch_result["reply_error"] = str(e)
        logging.error(f"[trusted/{req_name}] failed to send ack: {e}")

    log_path = log_dir / f"trusted-dispatched-{iso_now}.json"
    with open(log_path, "w") as f:
        json.dump(dispatch_result, f, indent=2)

    # Register pending completion notification
    _save_pending(config, {
        "task_name": task_name,
        "requester_from": sender_raw,
        "requester_email": sender_email,
        "extra_cc": extra_cc,
        "subject": email_data.get("subject", ""),
        "message_id": email_data.get("message_id", ""),
        "references": email_data.get("references", ""),
        "dispatched_at": datetime.now().isoformat(),
        "notified": False,
    })

    return dispatch_result


# Keep old name as an alias so external callers still work.
handle_greg_email = handle_trusted_email


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

            # Trusted-requester pipeline: check before general LLM routing
            trusted_result = handle_trusted_email(em, config, logger) if not dry_run else None
            if trusted_result is not None:
                results.append(trusted_result)
                state.mark_processed("inbox", em["stable_id"])
                logging.info(f"  [trusted/{trusted_result.get('type', '?')}] {em['subject'][:60]}")
                continue
            if dry_run:
                _requesters = _get_trusted_requesters(config)
                _from_raw = em.get("from", "")
                _m = re.search(r'<([^>]+)>', _from_raw)
                _sender = _m.group(1).strip().lower() if _m else _from_raw.strip().lower()
                if _sender in _requesters:
                    logging.info(f"  [trusted/dry-run] {em['subject'][:60]}")
                    results.append({"action": "trusted_dry_run", "subject": em["subject"]})
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

    # 3. Check pending completions — send "done" emails when dispatched tasks land
    if not dry_run:
        check_pending_completions(config, logger)

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
