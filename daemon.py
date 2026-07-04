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
import shutil
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


def _load_env():
    """Load KEY=VALUE lines from the daemon's local .env (gitignored) into the
    environment — used for the Supabase service key / URL for the change queue."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if not os.path.exists(path):
        return
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())
    except Exception:
        pass


def _supa(method, path, body=None, prefer=None):
    """Supabase REST call with the service-role key (bypasses RLS). Returns the
    response, or None if not configured."""
    url = os.environ.get("SUPABASE_URL")
    key = os.environ.get("SUPABASE_SERVICE_ROLE_KEY")
    if not url or not key:
        return None
    headers = {"apikey": key, "Authorization": "Bearer " + key, "Content-Type": "application/json"}
    if prefer:
        headers["Prefer"] = prefer
    return requests.request(method, url + path, headers=headers, json=body, timeout=30)


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
# Board routing — [BOARD] subject pattern
# ---------------------------------------------------------------------------
# Cross-surface intake into the SOMA board (~/Projects/SOMA/board/inbox/).
# Any allowlisted sender (same allowlist as dispatch) can file a board card by
# email — this is how claude.ai web/mobile/CDC/CCw sessions without local
# filesystem access get an item onto the board. Unlike dispatch, this is pure
# file-write + confirmation: no shell-out, no cc-dispatch, no LLM routing.

BOARD_SUBJECT_RE = re.compile(r'^\[BOARD\]\s*(.*)', re.IGNORECASE)

# Self-generated confirmation replies (WQ-123/WQ-128 bug): handle_board_email
# sends "Re: [BOARD] <title>" back to the submitting sender. When that sender
# IS claude@mike-wolf.com (soma-feedback's self-send-to-itself pattern —
# SOMA-APP-STANDARD.md §8), the confirmation lands back in the SAME inbox
# this loop just polled, doesn't match BOARD_SUBJECT_RE (its anchor requires
# the subject to *start* with "[BOARD]", and "Re: " breaks that), and falls
# through to the general LLM classifier — which the routing prompt's own
# "always forward mail from @mike-wolf.com" policy override then flags as
# forward_urgent. Observed firing twice in one evening (2026-07-04) per the
# Playmaker feedback-pipeline dogfood session. Recognize and skip it here,
# BEFORE the general BOARD_SUBJECT_RE check, so it never reaches routing.
BOARD_SELF_REPLY_RE = re.compile(r'^(?:re:\s*)+\[board\]', re.IGNORECASE)


def _is_board_self_reply(email_data, config):
    """True if this looks like the daemon's own 'Re: [BOARD] ...' confirmation
    bouncing back into claude@'s inbox from a self-send (soma-feedback and any
    future self-emailing board producer). Matched on subject shape + sender
    identity, not just subject, so a legitimate human "Re: [BOARD] ..." reply
    (e.g. Mike replying to a card confirmation with a follow-up) is NOT
    swallowed — only mail whose sender is the daemon's own claude@ address
    gets treated as noise here."""
    subject = email_data.get('subject', '')
    if not BOARD_SELF_REPLY_RE.match(subject):
        return False
    sender_raw = email_data.get('from', '')
    m_addr = re.search(r'<([^>]+)>', sender_raw)
    sender_email = (m_addr.group(1).strip().lower() if m_addr else sender_raw.strip().lower())
    claude_address = config.get('claude_email', {}).get('address', '').strip().lower()
    return bool(claude_address) and sender_email == claude_address


BOARD_INBOX_DIR = '~/Projects/SOMA/board/inbox'

# Structured-meta lift (added 2026-07-04 for soma-feedback, SOMA-APP-STANDARD
# §8): a producer that can't write real YAML frontmatter (e.g. a JS string
# built inside a Netlify function, no yaml lib available) can instead embed
# an HTML-comment block at the top of the email body:
#
#   <!--SOMA-CARD-META
#   key: value
#   key2: value2
#   SOMA-CARD-META-->
#
# handle_board_email lifts every `key: value` line in that block into the
# card's real frontmatter (in addition to the standard source-surface /
# source-sender / received-at / needs-mike fields) and strips the block from
# the visible body. This is how a public, unauthenticated widget endpoint
# gets `auto-dispatch: true` / `app:` / `page:` etc. onto the actual card
# without the daemon trusting arbitrary body content as code — it's a
# plain key:value line parse, not YAML-eval, and only fires inside a block
# with this exact marker.
SOMA_CARD_META_RE = re.compile(
    r'<!--SOMA-CARD-META\s*\n(.*?)\nSOMA-CARD-META-->\s*\n?', re.DOTALL
)


def _extract_card_meta(body):
    """Returns (extra_frontmatter_dict, body_with_block_removed)."""
    m = SOMA_CARD_META_RE.search(body)
    if not m:
        return {}, body
    block = m.group(1)
    extra = {}
    for line in block.splitlines():
        line = line.strip()
        if not line or ':' not in line:
            continue
        key, _, val = line.partition(':')
        key = key.strip()
        val = val.strip()
        # Only allow a small known-safe key set onto the card — a public
        # endpoint must not be able to inject arbitrary frontmatter fields
        # (e.g. spoofing source-surface/source-sender).
        if key in (
            'needs-mike', 'auto-dispatch', 'tags', 'app', 'page',
            'reporter-name', 'reporter-email', 'area',
        ):
            extra[key] = val
    cleaned_body = body[:m.start()] + body[m.end():]
    return extra, cleaned_body

# ---------------------------------------------------------------------------
# Fathom meeting-summary short-circuit
# ---------------------------------------------------------------------------
# Fathom (fathom.video/.ai) emails a meeting summary after every call. Mike's
# tier has no API/webhook (Enterprise-only); the v0 ingestion path forwards
# those emails from mw@ to claude@mike-wolf.com (Gmail filter — see
# second-brain/docs/FATHOM-SETUP.md) and a separate poller
# (second-brain/scripts/fathom_import.py, its own cron/launchd job and state
# file) writes them into the vault. That import is unrelated to this daemon's
# LLM-routing loop — this short-circuit exists purely so Fathom mail doesn't
# fall through to route_email() and waste an LLM call / risk a nonsense
# "action" on a meeting summary that isn't an instruction to Claude at all.
FATHOM_SENDER_RE = re.compile(r'@fathom\.(video|ai)', re.IGNORECASE)


def _slugify(text, max_len=60):
    slug = re.sub(r'[^a-z0-9]+', '-', text.lower()).strip('-')
    return (slug or 'untitled')[:max_len].strip('-')


def handle_board_email(email_data, config, logger, trusted=False):
    """
    Handle [BOARD] emails: file the body as a card in the SOMA board inbox.
    Returns a board log dict, or None if subject doesn't match.
    Called before LLM routing — short-circuits normal flow on match, same as
    handle_dispatch_email. Reuses dispatch.allowed_senders (same trust surface)
    for the inbox channel. `trusted=True` skips the allowlist check — used for
    Mike's own already-authenticated drafts folder (mikeai@), which isn't on
    the inbox sender allowlist but is inherently trusted (password-gated Gmail
    account, not an arbitrary inbound sender).
    """
    dispatch_cfg = config.get('dispatch', {})
    subject = email_data.get('subject', '')
    m = BOARD_SUBJECT_RE.match(subject)
    if not m:
        return None

    title_raw = m.group(1).strip() or 'untitled'

    sender_raw = email_data.get('from', '')
    m_addr = re.search(r'<([^>]+)>', sender_raw)
    sender_email = m_addr.group(1).strip().lower() if m_addr else sender_raw.strip().lower()

    allowed = [s.lower() for s in dispatch_cfg.get('allowed_senders', [])]
    board_log = {
        'type': 'board',
        'from': sender_raw,
        'sender_email': sender_email,
        'subject': subject,
        'title': title_raw,
        'timestamp': datetime.now().isoformat(),
    }

    if not trusted and sender_email not in allowed:
        board_log['result'] = 'rejected:sender_not_allowlisted'
        logging.warning(f"Board card rejected (sender_not_allowlisted): {sender_email}")
        try:
            send_email(config, sender_raw, f'Re: {subject}',
                       'Board card refused: sender not on allowlist.',
                       in_reply_to=email_data.get('message_id'),
                       references=email_data.get('references'))
        except Exception as e:
            logging.error(f"Failed to send board rejection reply: {e}")
        return board_log

    inbox_dir = Path(os.path.expanduser(BOARD_INBOX_DIR))
    (inbox_dir / 'processed').mkdir(parents=True, exist_ok=True)

    now = datetime.now()
    slug = _slugify(title_raw)
    filename = f"{now.strftime('%Y-%m-%d')}-{slug}.md"
    card_path = inbox_dir / filename
    # Avoid clobbering same-day/same-slug cards from a prior email.
    suffix = 2
    while card_path.exists():
        card_path = inbox_dir / f"{now.strftime('%Y-%m-%d')}-{slug}-{suffix}.md"
        suffix += 1

    body = email_data.get('body', '')
    extra_meta, body = _extract_card_meta(body)
    # extra_meta may override needs-mike (e.g. soma-feedback sets it per
    # submitBuild); everything else is appended after the standard fields.
    needs_mike = extra_meta.pop('needs-mike', 'false')
    frontmatter_lines = [
        "source-surface: email",
        f"source-sender: {sender_email}",
        f"received-at: {now.isoformat()}",
        f"needs-mike: {needs_mike}",
    ]
    for k, v in extra_meta.items():
        frontmatter_lines.append(f"{k}: {v}")
    card = (
        "---\n"
        + "\n".join(frontmatter_lines)
        + "\n---\n\n"
        f"# {title_raw}\n\n"
        f"{body}\n"
    )
    card_path.write_text(card)
    logging.info(f"[board] card filed: {card_path}")

    board_log['result'] = 'filed'
    board_log['card_path'] = str(card_path)

    # For the drafts channel (trusted=True), sender_raw is Mike's own mikeai@
    # account — replying there is inert since nobody reads that inbox. Confirm
    # to forward_to (Mike's real inbox) instead. For the normal inbox channel,
    # reply directly to the sender as usual.
    confirm_to = config.get('forward_to') if trusted else sender_raw
    try:
        send_email(config, confirm_to, f'Re: {subject}',
                   f'Board card filed: {title_raw}',
                   in_reply_to=email_data.get('message_id'),
                   references=email_data.get('references'))
    except Exception as e:
        logging.error(f"Failed to send board confirmation reply: {e}")

    return board_log


# ---------------------------------------------------------------------------
# Provider data-export ingestion — zero-touch email→zip (2026-07-03)
# ---------------------------------------------------------------------------
# All three chat providers (Anthropic claude.ai, OpenAI ChatGPT, Google
# Takeout/Gemini) now deliver conversation exports as an emailed download link
# (Anthropic's expires in 24h). A Gmail filter on mw@ forwards those emails to
# claude@ (same pattern as Fathom — see second-brain/docs/EXPORT-FORWARD-SETUP.md)
# and this handler downloads the zip immediately on receipt, into the location
# the nightly import watches. Closes the last manual click in the export loop
# (second-brain/docs/AUTOMATION-STATUS-2026-07-01.md follow-up #1 / WQ-44).
#
# SECURITY: this is an email-triggered downloader, so it is an attack surface.
# The sender/subject match only selects candidates; the REAL gate is the
# hard-coded URL allowlist below (per-provider legitimate download hosts,
# https only, every redirect hop re-validated). It deliberately lives in code,
# not config, so a config edit can't silently widen it. A zip magic-byte check
# and a size cap guard the payload; downloads stream to disk (never held in
# memory) and land as .part until complete.
#
# Two download strategies:
#   1. direct  — streamed HTTPS GET. Works for signed one-shot URLs (OpenAI's
#                Azure SAS link; possibly Anthropic's).
#   2. chrome  — open the link in Mike's logged-in Chrome via CDP (:9222, the
#                same Chrome the nightly export job drives) and wait for the
#                zip to land in ~/Downloads. Needed for auth-gated links
#                (Google Takeout requires the logged-in session) and used as
#                fallback whenever the direct fetch doesn't yield a zip.

EXPORT_DOWNLOADS_DIR = "~/Downloads"
EXPORT_DROP_DIR = "~/Downloads/chat-exports"

# Verified sender/subject/domain facts (2026-07-03):
# - OpenAI: From "OpenAI <noreply@tm.openai.com>", subject
#   "ChatGPT - Your data export is ready", direct signed link on
#   proddatamgmtqueue.blob.core.windows.net (real archived email sample).
# - Anthropic: subject "Your data is ready for download", link on claude.ai
#   (from a working third-party ingester; exact sender local-part unverified —
#   matched by domain).
# - Google Takeout: From noreply@google.com, subject
#   "Your Google data is ready to download", links via takeout.google.com
#   (auth-gated → chrome strategy first).
PROVIDER_EXPORTS = {
    "claude": {
        "label": "Claude.ai (Anthropic)",
        "sender_domains": ("anthropic.com", "claude.ai", "claude.com"),
        "subject_res": (
            re.compile(r"your data .{0,30}ready", re.IGNORECASE),
            re.compile(r"data export", re.IGNORECASE),
        ),
        "allowed_hosts": ("claude.ai", "claude.com", "anthropic.com"),
        # 2026-07-04: the emailed link lands on an authenticated claude.ai PAGE
        # (not a signed one-shot zip URL) that needs a UI click to start the
        # download — a raw GET (direct strategy) always hits the app shell/auth
        # wall, and a passive CDP tab-open never triggers anything. Route
        # through Yeshie (which clicks) and gate to the overnight window since
        # it's a visible-tab action in Mike's real Chrome. See
        # yeshie/sites/claude.ai/tasks/export-download.payload.json.
        "needs_click_download": True,
        # Phase A of nightly_claude_export.sh scans this dir (content check:
        # zip contains conversations.json) and imports at 03:10.
        "dest_dir": EXPORT_DROP_DIR,
        "prefix": "claude-export",
        "next_step": ("tonight's 03:10 nightly import (Phase A of "
                      "nightly_claude_export.sh) picks it up automatically"),
    },
    "chatgpt": {
        "label": "ChatGPT (OpenAI)",
        "sender_domains": ("openai.com", "tm.openai.com", "chatgpt.com"),
        "subject_res": (
            re.compile(r"data export is ready", re.IGNORECASE),
            re.compile(r"your data export", re.IGNORECASE),
        ),
        "allowed_hosts": ("proddatamgmtqueue.blob.core.windows.net",),
        # NOT the chat-exports root: a ChatGPT export also contains
        # conversations.json, so Phase A's content check would misimport it as
        # a Claude export. Subdirs are outside Phase A's -maxdepth 1 scan.
        "dest_dir": EXPORT_DROP_DIR + "/chatgpt",
        "prefix": "chatgpt-export",
        # Legacy importer entry point (import-all.py) expects this exact path.
        "stage_copy": "~/Projects/second-brain/imports/ChatGPT Export.zip",
        "next_step": ("staged at second-brain/imports/ChatGPT Export.zip for "
                      "the ChatGPT importer (import wiring is the remaining "
                      "follow-up; the email→zip link was the blocker)"),
    },
    "gemini": {
        "label": "Gemini (Google Takeout)",
        "sender_domains": ("google.com",),
        "subject_res": (
            re.compile(r"google data .{0,30}(ready|download)", re.IGNORECASE),
            re.compile(r"takeout", re.IGNORECASE),
        ),
        "allowed_hosts": (
            "takeout.google.com",
            "takeout-download.usercontent.google.com",
            "apidata.googleusercontent.com",
        ),
        "dest_dir": EXPORT_DROP_DIR + "/gemini",
        "prefix": "gemini-takeout",
        # Takeout links are auth-gated: a bare GET bounces to accounts.google.com
        # (off-allowlist → direct correctly hard-fails) so go via Chrome.
        "prefer_chrome": True,
        "next_step": ("saved for the Gemini/Takeout importer "
                      "(canonical_import.py handles Gemini content)"),
    },
}

_URL_ANGLE_RE = re.compile(r"<\s*(https?://[^>]+?)\s*>", re.S)
_URL_HREF_RE = re.compile(r"""href\s*=\s*["']([^"']+)["']""", re.IGNORECASE)
_URL_BARE_RE = re.compile(r"https?://[^\s<>\"']+")


def _unwrap_redirector(url):
    """Unwrap common forwarding/safelink redirectors (e.g. google.com/url?q=...).
    Gmail auto-forward doesn't rewrite links, but manual forwards and some
    clients do — always resolve to the innermost target before allowlisting."""
    from urllib.parse import urlparse, parse_qs, unquote
    for _ in range(3):
        p = urlparse(url)
        host = (p.hostname or "").lower()
        if host in ("www.google.com", "google.com") and p.path == "/url":
            q = parse_qs(p.query)
            target = (q.get("q") or q.get("url") or [""])[0]
            if target.startswith("http"):
                url = unquote(target)
                continue
        break
    return url


def _extract_candidate_urls(email_data):
    """Pull every plausible URL out of the email (plain + HTML bodies).
    Handles angle-bracket-wrapped links that span lines (as in real provider
    mail), HTML entities (&amp; inside the SAS query string), and redirector
    wrapping. Returns deduped, cleaned URLs in discovery order."""
    import html as _html
    texts = [
        email_data.get("body_full") or email_data.get("body") or "",
        email_data.get("body_html") or "",
    ]
    raw = []
    for text in texts:
        if not text:
            continue
        for m in _URL_ANGLE_RE.finditer(text):
            raw.append(re.sub(r"\s+", "", m.group(1)))
        for m in _URL_HREF_RE.finditer(text):
            raw.append(m.group(1))
        for m in _URL_BARE_RE.finditer(text):
            raw.append(m.group(0))
    cleaned, seen = [], set()
    for u in raw:
        u = _html.unescape(u).strip().rstrip(">),.];'\"")
        u = _unwrap_redirector(u)
        if u.startswith("http") and u not in seen:
            seen.add(u)
            cleaned.append(u)
    return cleaned


def _export_host_allowed(url, allowed_hosts):
    """True iff url is https and its host is (a subdomain of) an allowlisted
    host. EXPORT_INGEST_EXTRA_ALLOWED_HOSTS (comma-sep, env) is a TEST-ONLY
    seam — hosts listed there are accepted with any scheme so tests can run a
    local http server; it is never set in the live launchd environment."""
    from urllib.parse import urlparse
    try:
        p = urlparse(url)
    except ValueError:
        return False
    host = (p.hostname or "").lower()
    if not host:
        return False
    extra = tuple(
        h.strip().lower()
        for h in os.environ.get("EXPORT_INGEST_EXTRA_ALLOWED_HOSTS", "").split(",")
        if h.strip()
    )
    if host in extra:
        return True
    if p.scheme != "https":
        return False
    return any(host == a or host.endswith("." + a) for a in allowed_hosts)


def _pick_export_url(urls, provider_cfg):
    """Choose the actual download link among allowlisted candidates (provider
    emails also contain help-center/manage links). Highest score wins."""
    allowed = [u for u in urls if _export_host_allowed(u, provider_cfg["allowed_hosts"])]
    if not allowed:
        return None

    def score(u):
        ul = u.lower()
        s = 0
        if ".zip" in ul:
            s += 4
        for kw in ("export", "download", "takeout"):
            if kw in ul:
                s += 1
        return s

    return max(allowed, key=score)


def _match_provider_export(email_data, config):
    """Return a PROVIDER_EXPORTS key if this email is a provider data-export
    notification, else None.

    Primary match: sender domain + subject. Fallback (manual forwards, where
    From: becomes Mike's own address): allowlisted sender + subject match +
    at least one URL on that provider's download allowlist. The URL allowlist
    stays the real gate either way."""
    sender_raw = email_data.get("from", "")
    m = re.search(r"<([^>]+)>", sender_raw)
    sender = (m.group(1) if m else sender_raw).strip().lower()
    domain = sender.rsplit("@", 1)[-1]
    subject = email_data.get("subject", "") or ""

    for key, cfg in PROVIDER_EXPORTS.items():
        dom_ok = any(domain == d or domain.endswith("." + d) for d in cfg["sender_domains"])
        if dom_ok and any(r.search(subject) for r in cfg["subject_res"]):
            return key

    trusted = [s.lower() for s in config.get("dispatch", {}).get("allowed_senders", [])]
    if sender in trusted:
        urls = _extract_candidate_urls(email_data)
        for key, cfg in PROVIDER_EXPORTS.items():
            if any(r.search(subject) for r in cfg["subject_res"]):
                if any(_export_host_allowed(u, cfg["allowed_hosts"]) for u in urls):
                    return key
    return None


def _stream_export_download(url, dest_path, allowed_hosts, max_bytes):
    """Streamed download with per-hop redirect validation and zip sniffing.
    Returns (bytes_written, None) on success or (None, reason) on failure.
    Never buffers the payload in memory; writes to <dest>.part then renames."""
    from urllib.parse import urljoin
    current = url
    part = dest_path + ".part"
    try:
        for _ in range(5):
            resp = requests.get(
                current, stream=True, allow_redirects=False, timeout=(15, 120),
                headers={"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"},
            )
            if resp.status_code in (301, 302, 303, 307, 308):
                loc = urljoin(current, resp.headers.get("Location", ""))
                if not _export_host_allowed(loc, allowed_hosts):
                    return None, f"redirect to non-allowlisted URL: {loc[:160]}"
                current = loc
                continue
            if resp.status_code != 200:
                return None, f"HTTP {resp.status_code} from {current[:120]}"
            written = 0
            first_bytes = b""
            with open(part, "wb") as fh:
                for chunk in resp.iter_content(chunk_size=1024 * 1024):
                    if not chunk:
                        continue
                    if not first_bytes:
                        first_bytes = chunk[:4]
                    written += len(chunk)
                    if written > max_bytes:
                        return None, f"size cap exceeded ({max_bytes} bytes)"
                    fh.write(chunk)
            if written == 0 or not first_bytes.startswith(b"PK"):
                return None, "response is not a zip (auth wall or error page?)"
            os.replace(part, dest_path)
            return written, None
        return None, "too many redirects"
    except requests.RequestException as e:
        return None, f"download error: {e}"
    finally:
        if os.path.exists(part):
            try:
                os.remove(part)
            except OSError:
                pass


def _in_overnight_window(pe_cfg):
    """True iff local time is inside the configured overnight window (default
    03:00-04:00, matching nightly_claude_export.sh's 03:10 Phase B slot).
    EXPORT_INGEST_FORCE_WINDOW=1 (env, test-only) bypasses the gate so the
    fix can be verified without waiting for the real window."""
    if os.environ.get("EXPORT_INGEST_FORCE_WINDOW") == "1":
        return True
    start_h = int(pe_cfg.get("overnight_window_start_hour", 3))
    end_h = int(pe_cfg.get("overnight_window_end_hour", 4))
    hour = datetime.now().hour
    if start_h <= end_h:
        return start_h <= hour < end_h
    return hour >= start_h or hour < end_h  # wraps midnight


def _pending_exports_path(config):
    state_dir = Path(os.path.expanduser(config["state_file"])).parent
    state_dir.mkdir(parents=True, exist_ok=True)
    return state_dir / "export-pending-queue.json"


def _load_pending_exports(config):
    path = _pending_exports_path(config)
    if path.exists():
        try:
            with open(path) as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return []
    return []


def _save_pending_exports(config, items):
    path = _pending_exports_path(config)
    with open(path, "w") as f:
        json.dump(items, f, indent=2)


def _queue_export_for_overnight(config, provider, url, cfg, email_subject):
    """Persist a Chrome/Yeshie-needing export so it survives past this poll
    cycle. Called when the export arrives outside the overnight window —
    the daemon does NOT try to drive Mike's daytime Chrome. Anthropic links
    expire in 24h, well outside any single day/night gap, so one overnight
    window is always reachable before expiry."""
    items = _load_pending_exports(config)
    entry = {
        "provider": provider,
        "url": url,
        "queued_at": datetime.now().isoformat(),
        "subject": email_subject,
        "attempts": 0,
    }
    items.append(entry)
    _save_pending_exports(config, items)
    return entry


def _yeshie_download_export(url, config, pe_cfg, dest_dir, prefix):
    """Drive the export-ready link through the Yeshie relay (the same
    extension-driven mechanism that already requests the export unattended
    every night) instead of a passive CDP tab-open + poll. Anthropic's link
    lands on an authenticated claude.ai PAGE that requires a UI click to
    start the actual browser download — see
    yeshie/sites/claude.ai/tasks/export-download.payload.json _meta for the
    root-cause note. Returns (zip_path, None) or (None, reason)."""
    relay = pe_cfg.get("yeshie_relay", "http://localhost:3333")
    payload_path = os.path.expanduser(pe_cfg.get(
        "yeshie_download_payload",
        "~/Projects/yeshie/sites/claude.ai/tasks/export-download.payload.json"))
    if not os.path.exists(payload_path):
        return None, f"yeshie payload not found at {payload_path}"

    try:
        status = requests.get(f"{relay}/status", timeout=5).json()
    except Exception as e:
        return None, f"yeshie relay unreachable: {e}"
    if not (status.get("ok") and status.get("extensionConnected")):
        return None, f"yeshie relay not ready: {status}"

    try:
        with open(payload_path) as f:
            payload = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        return None, f"could not read yeshie payload: {e}"

    downloads = os.path.expanduser(EXPORT_DOWNLOADS_DIR)
    start_ts = time.time()
    timeout_s = int(pe_cfg.get("yeshie_run_timeout_seconds", 60))
    try:
        resp = requests.post(
            f"{relay}/run",
            json={"payload": payload, "params": {"export_url": url}, "tabId": None,
                  "timeoutMs": timeout_s * 1000},
            timeout=timeout_s + 15,
        )
    except requests.RequestException as e:
        return None, f"yeshie /run request failed: {e}"
    if resp.status_code != 200:
        return None, f"yeshie /run HTTP {resp.status_code}: {resp.text[:200]}"
    result = resp.json() if resp.content else {}
    if result.get("success") is False:
        return None, f"yeshie chain failed: {str(result.get('error') or result)[:200]}"

    # The chain's job was to trigger the browser download; confirm it landed
    # the same way the pre-fix Chrome fallback confirmed (poll ~/Downloads
    # for a new, stable, non-partial zip since the chain started).
    deadline = start_ts + max(30, pe_cfg.get("chrome_wait_seconds", 180))
    found = None
    while time.time() < deadline:
        for name in os.listdir(downloads):
            if not name.lower().endswith(".zip"):
                continue
            p = os.path.join(downloads, name)
            try:
                if os.path.getmtime(p) < start_ts - 2:
                    continue
            except OSError:
                continue
            if os.path.exists(p + ".crdownload"):
                continue
            s1 = os.path.getsize(p)
            time.sleep(2)
            try:
                if os.path.getsize(p) != s1:
                    continue
            except OSError:
                continue
            found = p
            break
        if found:
            break
        time.sleep(3)

    if not found:
        return None, ("yeshie chain ran (result: "
                       f"{str(result)[:160]}) but no zip landed in ~/Downloads")
    return found, None


def _chrome_download_export(url, cdp_base, timeout_s=180):
    """Open url in Mike's logged-in Chrome (CDP) and wait for a new zip to
    finish landing in ~/Downloads. Returns the zip path, or None. Used for
    auth-gated links (Google Takeout) and as fallback for the direct path.
    The URL passed here has ALREADY passed the allowlist.

    NOTE (2026-07-04): kept as a fallback for providers whose page DOES
    auto-download on load (e.g. a future Anthropic flow change, or Takeout
    if it ever stops needing a click). For claude.ai's current click-required
    page, prefer _yeshie_download_export() — see its docstring for why this
    passive approach silently failed the one real test (07-03 14:09)."""
    from urllib.parse import quote
    downloads = os.path.expanduser(EXPORT_DOWNLOADS_DIR)
    start_ts = time.time()
    tab_id = None
    try:
        endpoint = f"{cdp_base}/json/new?{'url=' + quote(url, safe='')}"
        resp = requests.put(endpoint, timeout=10)
        if resp.status_code == 405:  # older Chrome wants GET
            resp = requests.get(endpoint, timeout=10)
        if resp.ok:
            tab_id = resp.json().get("id")
    except Exception as e:
        logging.warning(f"[export-ingest] Chrome CDP unavailable: {e}")
        return None

    found = None
    try:
        deadline = start_ts + timeout_s
        while time.time() < deadline:
            for name in os.listdir(downloads):
                if not name.lower().endswith(".zip"):
                    continue
                p = os.path.join(downloads, name)
                try:
                    if os.path.getmtime(p) < start_ts - 2:
                        continue
                except OSError:
                    continue
                if os.path.exists(p + ".crdownload") or os.path.exists(
                        os.path.join(downloads, name + ".crdownload")):
                    continue
                # size-stable check: still being written?
                s1 = os.path.getsize(p)
                time.sleep(2)
                if os.path.getsize(p) != s1:
                    continue
                found = p
                break
            if found:
                break
            time.sleep(3)
    finally:
        if tab_id:
            try:
                requests.get(f"{cdp_base}/json/close/{tab_id}", timeout=5)
            except Exception:
                pass
    return found


def handle_provider_export_email(email_data, config, logger):
    """Handle a provider data-export email: extract the download link, verify
    it against the hard allowlist, fetch the zip (direct stream or logged-in
    Chrome), place it where the import pipeline watches, and confirm to Mike.
    Returns a result dict, or None if this isn't a provider-export email.
    Called before LLM routing — short-circuits like dispatch/board/Fathom."""
    pe_cfg = config.get("provider_exports", {}) or {}
    if not pe_cfg.get("enabled", True):
        return None
    provider = _match_provider_export(email_data, config)
    if provider is None:
        return None

    cfg = PROVIDER_EXPORTS[provider]
    iso_now = datetime.now().strftime("%Y%m%dT%H%M%S")
    log_dir = Path(os.path.expanduser(config["log_dir"]))
    log_dir.mkdir(parents=True, exist_ok=True)
    forward_to = config["forward_to"]
    max_bytes = int(float(pe_cfg.get("max_download_gb", 6)) * 1024 ** 3)
    cdp_base = pe_cfg.get("chrome_cdp", "http://localhost:9222")

    result = {
        "type": "provider_export",
        "provider": provider,
        "from": email_data.get("from", ""),
        "subject": email_data.get("subject", ""),
        "timestamp": datetime.now().isoformat(),
    }

    def _finish(status, detail, zip_path=None, notify_subject=None, notify_body=None):
        result["result"] = status
        result["detail"] = detail
        if zip_path:
            result["zip_path"] = str(zip_path)
        log_path = log_dir / f"export-ingest-{iso_now}-{provider}.json"
        with open(log_path, "w") as f:
            json.dump(result, f, indent=2)
        if notify_subject:
            try:
                send_email(config, forward_to, notify_subject, notify_body)
            except Exception as e:
                logging.error(f"[export-ingest] failed to send notification: {e}")
        logging.info(f"[export-ingest] {provider}: {status} — {detail[:160]}")
        return result

    urls = _extract_candidate_urls(email_data)
    url = _pick_export_url(urls, cfg)
    if url is None:
        from urllib.parse import urlparse
        hosts = sorted({(urlparse(u).hostname or "?") for u in urls})
        return _finish(
            "no_allowlisted_link",
            f"candidate hosts: {', '.join(hosts) or '(none)'}",
            notify_subject=f"[export-ingest] {cfg['label']}: no allowlisted download link",
            notify_body=(
                f"A {cfg['label']} export email arrived but none of its links matched the "
                f"download allowlist {cfg['allowed_hosts']}.\n\n"
                f"Candidate link hosts found: {', '.join(hosts) or '(none)'}\n\n"
                "If one of those is the provider's real download host, extend "
                "PROVIDER_EXPORTS in claude-email-daemon/daemon.py. Original subject: "
                f"{email_data.get('subject', '')}"
            ),
        )
    result["url_host"] = url.split("/")[2] if "://" in url else ""

    dest_dir = os.path.expanduser(cfg["dest_dir"])
    os.makedirs(dest_dir, exist_ok=True)
    dest_path = os.path.join(dest_dir, f"{cfg['prefix']}-{iso_now}.zip")

    size, err = (None, "skipped (auth-gated provider — going via Chrome)")
    strategy = None
    if not cfg.get("prefer_chrome"):
        size, err = _stream_export_download(url, dest_path, cfg["allowed_hosts"], max_bytes)
        if size:
            strategy = "direct"

    # needs_click_download: the provider's link lands on an authenticated
    # PAGE that requires a UI click to start the browser download (true for
    # claude.ai as of 2026-07 — see export-download.payload.json _meta).
    # Driving that click opens a visible tab in Mike's real Chrome, so it's
    # gated to the overnight window; outside it, queue rather than attempt
    # against his daytime browser or silently drop the one-shot link.
    if not strategy and cfg.get("needs_click_download"):
        if not _in_overnight_window(pe_cfg):
            _queue_export_for_overnight(config, provider, url, cfg, email_data.get("subject", ""))
            return _finish(
                "queued_for_overnight",
                f"direct: {err}; deferred to overnight window "
                f"({pe_cfg.get('overnight_window_start_hour', 3):02d}:00-"
                f"{pe_cfg.get('overnight_window_end_hour', 4):02d}:00) — "
                "not driving Chrome during the day",
                notify_subject=f"[export-ingest] {cfg['label']}: queued for tonight's overnight window",
                notify_body=(
                    f"A {cfg['label']} export email arrived. Direct fetch failed ({err}), "
                    "as expected — this provider's link needs a logged-in browser click, not "
                    "just a raw HTTP GET.\n\n"
                    "Rather than pop a tab into your Chrome during the day, the download is "
                    f"queued and will run automatically in tonight's "
                    f"{pe_cfg.get('overnight_window_start_hour', 3):02d}:00-"
                    f"{pe_cfg.get('overnight_window_end_hour', 4):02d}:00 window "
                    "(same window nightly_claude_export.sh already uses). No action needed — "
                    f"the link is good for 24h from send. Queue file: {_pending_exports_path(config)}"
                ),
            )
        got, yerr = _yeshie_download_export(url, config, pe_cfg, dest_dir, cfg["prefix"])
        if got:
            try:
                shutil.move(got, dest_path)
                size = os.path.getsize(dest_path)
                strategy = "yeshie"
            except OSError as e:
                return _finish("move_failed", f"downloaded to {got} but move failed: {e}")
        else:
            err = f"{err}; yeshie: {yerr}"

    if not strategy and not cfg.get("needs_click_download"):
        if err:
            logging.info(f"[export-ingest] {provider}: direct fetch — {err}; trying Chrome")
        got = _chrome_download_export(url, cdp_base,
                                      timeout_s=int(pe_cfg.get("chrome_wait_seconds", 180)))
        if got:
            try:
                shutil.move(got, dest_path)
                size = os.path.getsize(dest_path)
                strategy = "chrome"
            except OSError as e:
                return _finish("move_failed", f"downloaded to {got} but move failed: {e}")
        elif err:
            err = f"{err}; chrome: no zip landed"

    if not strategy:
        return _finish(
            "download_failed", err or "download failed (no strategy succeeded)",
            notify_subject=f"[export-ingest] {cfg['label']}: download FAILED",
            notify_body=(
                f"A {cfg['label']} export email arrived but the automatic download failed.\n\n"
                f"{err}\n\n"
                f"Manual fallback — the (allowlisted) link from the email:\n{url}\n\n"
                "Anthropic links expire 24h after the export email."
            ),
        )

    # Staging copy for importers that expect a fixed path (ChatGPT legacy importer).
    stage = cfg.get("stage_copy")
    if stage:
        try:
            stage_path = os.path.expanduser(stage)
            os.makedirs(os.path.dirname(stage_path), exist_ok=True)
            shutil.copy2(dest_path, stage_path)
            result["stage_copy"] = stage_path
        except OSError as e:
            logging.warning(f"[export-ingest] stage copy failed: {e}")

    size_mb = round(size / (1024 * 1024), 1)
    return _finish(
        "downloaded", f"{dest_path} ({size_mb} MB, via {strategy})", zip_path=dest_path,
        notify_subject=f"[export-ingest] {cfg['label']} export downloaded ({size_mb} MB)",
        notify_body=(
            f"Zero-touch export ingestion succeeded.\n\n"
            f"Provider: {cfg['label']}\n"
            f"Saved to: {dest_path}\n"
            f"Size: {size_mb} MB (via {strategy})\n\n"
            f"Next: {cfg['next_step']}.\n\n"
            "No action needed."
        ),
    )


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


def extract_html_body(msg):
    """Extract the text/html body from an email message (or '' if none).

    The provider-export handler needs this: some providers put the download
    link only in the HTML part, and extract_body() prefers text/plain."""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/html":
                payload = part.get_payload(decode=True)
                if payload:
                    return payload.decode("utf-8", errors="replace")
    elif msg.get_content_type() == "text/html":
        payload = msg.get_payload(decode=True)
        if payload:
            return payload.decode("utf-8", errors="replace")
    return ""


def _extract_attachment_text(filename, content_type, data):
    """Best-effort plain-text extraction from an attachment's bytes.

    Returns extracted text, or '' if the type isn't text-extractable here (the
    worker still gets the saved file path so it can open the file itself)."""
    name = (filename or "").lower()
    ctype = (content_type or "").lower()

    # Plain-text-ish formats: decode directly.
    if (ctype.startswith("text/") or
            name.endswith((".txt", ".md", ".markdown", ".csv", ".tsv", ".log",
                           ".json", ".html", ".htm", ".rtf"))):
        try:
            return data.decode("utf-8", errors="replace")
        except Exception:
            return ""

    # PDF: try pdfminer, then pypdf/PyPDF2 — all optional.
    if ctype == "application/pdf" or name.endswith(".pdf"):
        import io
        try:
            from pdfminer.high_level import extract_text  # type: ignore
            return extract_text(io.BytesIO(data)) or ""
        except Exception:
            pass
        for mod in ("pypdf", "PyPDF2"):
            try:
                reader_mod = __import__(mod)
                reader = reader_mod.PdfReader(io.BytesIO(data))
                return "\n".join((p.extract_text() or "") for p in reader.pages)
            except Exception:
                continue
        return ""

    # DOCX: a zip of XML — pull text from word/document.xml without extra deps.
    if (name.endswith(".docx") or
            ctype == "application/vnd.openxmlformats-officedocument.wordprocessingml.document"):
        import io, zipfile, re as _re
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                xml = z.read("word/document.xml").decode("utf-8", errors="replace")
            xml = xml.replace("</w:p>", "\n")
            return _re.sub(r"<[^>]+>", "", xml)
        except Exception:
            return ""

    return ""


def extract_attachments(msg, save_dir):
    """Walk an email, save each attachment to save_dir, and extract text where we can.

    Returns a list of dicts: {filename, content_type, path, size, text}.
    Inline images / signatures with no filename are skipped."""
    attachments = []
    if not msg.is_multipart():
        return attachments

    for part in msg.walk():
        if part.get_content_maintype() == "multipart":
            continue
        filename = part.get_filename()
        disposition = (part.get("Content-Disposition") or "").lower()
        # Only real attachments (named, or explicitly disposition=attachment).
        if not filename and "attachment" not in disposition:
            continue
        try:
            data = part.get_payload(decode=True)
        except Exception:
            data = None
        if not data:
            continue

        if filename:
            decoded = decode_header(filename)
            filename = "".join(
                p.decode(enc or "utf-8", errors="replace") if isinstance(p, bytes) else p
                for p, enc in decoded
            )
        else:
            ext = (part.get_content_subtype() or "bin")
            filename = f"attachment-{len(attachments) + 1}.{ext}"
        # Sanitize so we never write outside save_dir.
        safe_name = re.sub(r"[^\w.\- ]", "_", os.path.basename(filename)).strip() or "attachment"

        content_type = part.get_content_type()
        saved_path = ""
        try:
            os.makedirs(save_dir, exist_ok=True)
            saved_path = os.path.join(save_dir, safe_name)
            with open(saved_path, "wb") as fh:
                fh.write(data)
        except Exception as e:
            logging.warning(f"[attachments] could not save {safe_name}: {e}")
            saved_path = ""

        text = ""
        try:
            text = _extract_attachment_text(safe_name, content_type, data)
        except Exception as e:
            logging.warning(f"[attachments] text extraction failed for {safe_name}: {e}")

        attachments.append({
            "filename": safe_name,
            "content_type": content_type,
            "path": saved_path,
            "size": len(data),
            "text": text,
        })

    return attachments


def _format_attachments_section(attachments, per_file_chars=6000):
    """Render an '## Attachments' block for the worker prompt.

    Includes each attachment's filename, saved absolute path (so the worker can
    open it directly with its own tools), and any extracted text inline."""
    if not attachments:
        return ""
    lines = ["## Attachments",
             "This email included the following attachment(s). Use their content to "
             "complete the request — do NOT report the request as missing material.",
             ""]
    for i, a in enumerate(attachments, 1):
        header = f"### Attachment {i}: {a.get('filename', '(unnamed)')}"
        meta = f"- Type: {a.get('content_type', 'unknown')}; Size: {a.get('size', 0)} bytes"
        if a.get("path"):
            meta += f"\n- Saved at: {a['path']} (open this file directly if you need the original)"
        lines.append(header)
        lines.append(meta)
        text = (a.get("text") or "").strip()
        if text:
            if len(text) > per_file_chars:
                text = text[:per_file_chars] + "\n…[truncated — read the full file at the path above]"
            lines.append("")
            lines.append("Extracted content:")
            lines.append("```")
            lines.append(text)
            lines.append("```")
        else:
            lines.append("- (No text extracted automatically — open the saved file at the path above to read it.)")
        lines.append("")
    return "\n".join(lines) + "\n"


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

        # Pull any attachments (e.g. a blueprint doc) so the worker can actually
        # see them — previously only the text body was read, so attachment-only
        # requests came back blocked.
        attach_dir = os.path.expanduser(
            f"~/Projects/claude-email-daemon/state/attachments/{re.sub(r'[^A-Za-z0-9]', '_', stable_id)}"
        )
        try:
            attachments = extract_attachments(msg, attach_dir)
        except Exception as e:
            logging.warning(f"[attachments] extraction error for {stable_id}: {e}")
            attachments = []

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
            # Untruncated bodies for handlers that need the whole thing (the
            # provider-export download link is routinely past the 2000-char cut,
            # or present only in the HTML part).
            "body_full": extract_body(msg),
            "body_html": extract_html_body(msg),
            "attachments": attachments,
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
    """Build a per-requester classifier prompt from their config fields.

    The classifier triages on REVERSIBILITY and blast radius — NOT on whether the
    email happens to contain words like "delete" or "remove". The site's content
    lives in version control (git) and is deployed via Netlify, so ordinary content
    edits — even ones that remove a section, page, or block — can be reverted in one
    step and are therefore NOT destructive. The "destructive" category is reserved
    for genuinely irreversible, high-blast-radius operations with no easy undo.
    """
    req_name   = requester.get("name", "the requester")
    site_label = requester.get("site_label", "the website")
    site_desc  = requester.get("site_description", "")
    desc_clause = f"\n{site_desc}" if site_desc else ""
    return (
        f"You are classifying an email from {req_name} to determine safe routing.{desc_clause}\n\n"
        f"{site_label} is kept in version control (git) and deployed via Netlify, so any change "
        "to page content can be reverted with a single step. Judge each request by whether it is "
        "REVERSIBLE and by its blast radius — do NOT classify something as destructive merely "
        "because it contains a word like 'delete', 'remove', or 'drop'.\n\n"
        "Classify into exactly one category. Respond with valid JSON only.\n\n"
        "Categories:\n"
        f'- "on_site_build": Build, modify, fix, OR remove content on {site_label}. This INCLUDES '
        "deleting, removing, hiding, or reordering a section, page, block, image, or text — those "
        "are reversible content edits and belong here, not under 'destructive'.\n"
        '- "proposal_with_cost": Request that explicitly mentions a cost or budget amount\n'
        f'- "off_site_research": Research, data gathering, or work not directly on {site_label}\n'
        '- "destructive": ONLY irreversible, high-blast-radius operations with no easy undo — e.g. '
        "dropping or wiping a database, deleting all records or every user account, deleting backups, "
        "deleting the entire site or repository, bulk-erasing data, or a factory reset. A request to "
        "remove ordinary page content is NOT destructive.\n"
        '- "access_control": Requests about passwords, credentials, permissions, or account access\n'
        '- "ambiguous": Unclear intent, insufficient context, or multiple conflicting categories\n\n'
        "Extract any explicitly mentioned dollar amounts.\n\n"
        "Respond ONLY with JSON:\n"
        '{"category": "<category>", "reversible": <true|false>, "risk": "<low|medium|high>", '
        '"reason": "<one sentence>", "cost_usd": <number or null>, "summary": "<2-3 sentence summary>"}'
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


def _resolve_claude_bin():
    """Locate the Claude Code CLI the same way cc-dispatch's runner does."""
    override = os.environ.get("CC_DISPATCH_CLAUDE_BIN")
    if override:
        return override
    for p in [Path.home() / ".local/bin/claude", Path("/opt/homebrew/bin/claude")]:
        if p.exists():
            return str(p)
    return shutil.which("claude") or "claude"


def _second_opinion(config, email_data, requester, first_pass):
    """Borderline-case adjudicator — a stronger model rules on reversibility.

    The fast first-pass classifier (local Ollama / VPS Haiku) is deliberately
    cautious. Before we hard-stop a 'destructive' request or bounce an 'ambiguous'
    one back to a human, we ask a stronger reasoning model (default: Opus, via the
    local `claude` CLI — the same binary cc-dispatch uses) to judge whether the
    requested action is REVERSIBLE and its blast radius.

    Returns a refined classification dict, or None when the second opinion is
    disabled or unavailable — in which case the caller keeps the conservative
    first-pass decision (fail safe, not fail open).
    """
    cfg = config.get("second_opinion", {}) or {}
    if not cfg.get("enabled", True):
        return None
    model = cfg.get("model", "opus")
    timeout = cfg.get("timeout_seconds", 120)

    site_label = requester.get("site_label", "the website")
    rubric = (
        "You are the senior reviewer for an automated website-maintenance assistant.\n"
        f"A fast first-pass classifier flagged the email below as '{first_pass.get('category')}'.\n"
        f"{site_label} is kept in version control (git) and deployed via Netlify, so any change "
        "to page content can be reverted with a single step.\n\n"
        "Decide whether the requested action is REVERSIBLE and what its blast radius is, so we "
        "know whether it is safe to auto-execute or must be escalated to a human.\n\n"
        "SAFE to auto-execute -> category 'on_site_build': any change captured in version control "
        "— editing, adding, removing, hiding, or reordering a section, page, block, image, or text "
        "— even when the request literally says 'delete' or 'remove'.\n\n"
        "ESCALATE (NOT safe to auto-execute): irreversible or high-blast-radius actions with no "
        "easy undo — dropping or wiping a database, deleting all records or every user account, "
        "deleting backups, deleting the entire repository or site, bulk-erasing data, changing "
        "credentials / permissions / access, or moving money.\n\n"
        "If — and ONLY if — you conclude the request is genuinely 'ambiguous', do not guess "
        "silently. Spell out the confusion so the requester can resolve it in a single reply: "
        "set 'confusion' to exactly what is unclear or missing, 'assumptions' to the most "
        "reasonable working assumptions you would make, and 'interpretation' to the concrete "
        "task you would carry out under those assumptions. Leave those three fields as empty "
        "strings for any non-ambiguous category.\n\n"
        "Respond with STRICT JSON only, no other text:\n"
        '{"category": "on_site_build|destructive|access_control|off_site_research|ambiguous", '
        '"reversible": true|false, "risk": "low|medium|high", "reason": "<one sentence>", '
        '"summary": "<2-3 sentences>", "confusion": "<if ambiguous: what is unclear, else \\"\\">", '
        '"assumptions": "<if ambiguous: your working assumptions, else \\"\\">", '
        '"interpretation": "<if ambiguous: the task you would do under those assumptions, else \\"\\">"}'
    )
    email_text = (
        f"Subject: {email_data.get('subject', '')}\n\n"
        f"Body: {email_data.get('body', '')}"
    )
    prompt = rubric + "\n\nEmail:\n" + email_text

    claude_bin = _resolve_claude_bin()
    try:
        proc = subprocess.run(
            [claude_bin, "-p", "--output-format", "json", "--model", model],
            input=prompt,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if proc.returncode != 0:
            logging.warning(
                f"second_opinion: claude exited {proc.returncode}: {proc.stderr[:200]}"
            )
            return None
        # `claude -p --output-format json` wraps the answer as {"result": "...", ...}
        try:
            outer = json.loads(proc.stdout.strip())
            answer = outer.get("result", proc.stdout) if isinstance(outer, dict) else proc.stdout
        except json.JSONDecodeError:
            answer = proc.stdout
        refined = _parse_classify_json(answer)
        refined["classifier"] = f"second_opinion:{model}"
        return refined
    except Exception as e:
        logging.warning(f"second_opinion unavailable ({e}); keeping first-pass classification")
        return None


def decompose_email_tasks(config, email_data, requester, classification):
    """Split a trusted-requester email into independently-fated tasks.

    A task is a unit of work that SHARES A FATE: split only when outcomes can
    diverge (one part ships while another blocks) or inputs differ (one part needs
    material another doesn't). Do NOT split for atomicity — several edits to one
    page are ONE task.

    Returns a list of normalized task dicts, or None to mean "treat the whole email
    as a single task" (the caller's safe fallback). Each task:
      {"title": str, "targets": [str], "kind": "build|verify|diagnose",
       "needs": [str], "ready": bool}

    Gated: requester['decompose_tasks'] overrides config['decompose_tasks'] (default
    False). Uses the same `claude` CLI as _second_opinion; any error -> None.
    """
    enabled = requester.get("decompose_tasks")
    if enabled is None:
        enabled = config.get("decompose_tasks", False)
    if not enabled:
        return None

    model = ((config.get("decompose") or {}).get("model")
             or (config.get("second_opinion") or {}).get("model", "opus"))
    timeout = (config.get("decompose") or {}).get("timeout_seconds", 180)

    attachments = email_data.get("attachments") or []
    if attachments:
        manifest_lines = []
        for a in attachments:
            has_text = bool((a.get("text") or "").strip())
            state = "text extracted" if has_text else "NO text extracted"
            manifest_lines.append(f"- {a.get('filename', '(unnamed)')} ({state})")
        manifest = "\n".join(manifest_lines)
    else:
        manifest = "(none)"

    rubric = (
        "You are the work-planner for an automated website-maintenance assistant.\n"
        "Split the email below into independently-fated TASKS. A task is a unit of "
        "work that SHARES A FATE: split only when outcomes can diverge (one part can "
        "ship while another blocks) or inputs differ (one part needs material another "
        "doesn't). Do NOT split for atomicity — several edits to one page are ONE "
        "task.\n\n"
        "Litmus test for whether two items belong in the same task: if item B were "
        "blocked, would it make sense for item A to ship anyway? If yes -> separate "
        "tasks. If no -> same task.\n\n"
        "For each task set:\n"
        "- title: a short imperative description of the work.\n"
        "- targets: the page(s), section(s), file(s) or member(s) the task touches "
        "(may be empty).\n"
        "- kind: one of 'build' (make/edit/remove content or code), 'verify' (check "
        "or confirm something is correct), 'diagnose' (figure out why something is "
        "wrong before any fix can happen).\n"
        "- needs: material or information that is REQUIRED to do this task but is NOT "
        "present in the email body or its attachments (e.g. a photo that wasn't "
        "attached, a spreadsheet, a missing URL). Leave empty if everything needed is "
        "already here.\n"
        "- ready: true only when kind is 'build' AND needs is empty (i.e. it can be "
        "dispatched and completed right now).\n\n"
        f"Attachment manifest:\n{manifest}\n\n"
        f"{_format_attachments_section(attachments)}"
        f"Subject: {email_data.get('subject', '')}\n\n"
        f"Body: {email_data.get('body', '')}\n\n"
        "Respond with STRICT JSON only, no other text:\n"
        '{"tasks": [{"title": "<str>", "targets": ["<str>"], '
        '"kind": "build|verify|diagnose", "needs": ["<str>"], "ready": true|false}]}'
    )

    claude_bin = _resolve_claude_bin()
    try:
        proc = subprocess.run(
            [claude_bin, "-p", "--output-format", "json", "--model", model],
            input=rubric,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if proc.returncode != 0:
            logging.warning(
                f"decompose: claude exited {proc.returncode}: {proc.stderr[:200]}"
            )
            return None
        # `claude -p --output-format json` wraps the answer as {"result": "...", ...}
        try:
            outer = json.loads(proc.stdout.strip())
            answer = outer.get("result", proc.stdout) if isinstance(outer, dict) else proc.stdout
        except json.JSONDecodeError:
            answer = proc.stdout
        parsed = _parse_classify_json(answer)
    except Exception as e:
        logging.warning(f"decompose unavailable ({e}); treating email as a single task")
        return None

    raw_tasks = parsed.get("tasks")
    if not isinstance(raw_tasks, list):
        return None

    normalized = []
    for t in raw_tasks:
        if not isinstance(t, dict):
            continue
        title = (t.get("title") or "").strip()
        if not title:
            continue
        kind = (t.get("kind") or "build").strip().lower()
        if kind not in ("build", "verify", "diagnose"):
            kind = "build"
        needs = [n.strip() for n in (t.get("needs") or []) if isinstance(n, str) and n.strip()]
        ready = bool(t.get("ready")) and kind == "build" and not needs
        targets = [tg.strip() for tg in (t.get("targets") or []) if isinstance(tg, str) and tg.strip()]
        normalized.append({
            "title": title,
            "targets": targets,
            "kind": kind,
            "needs": needs,
            "ready": ready,
        })

    return normalized or None


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


def _detect_blocked(report_text):
    """If an audit report indicates the worker couldn't complete the task, return a
    short human-readable reason; otherwise ''. Used to mark a change_request 'blocked'
    rather than 'awaiting-review' when no work actually shipped."""
    if not report_text:
        return ""
    low = report_text.lower()
    markers = [
        "blocked — incomplete", "blocked - incomplete", "blocked—incomplete",
        "**blocked", "blocked:", "incomplete request", "could not complete",
        "unable to complete", "no blueprint", "no attachment", "missing attachment",
        "nothing to add", "cannot proceed", "needs more information", "need more information",
    ]
    if not any(m in low for m in markers):
        return ""
    # Prefer the worker's own one-line explanation from the final-assistant section.
    idx = report_text.find("## Final assistant text")
    snippet = report_text[idx:] if idx != -1 else report_text
    for line in snippet.splitlines():
        s = line.strip().lstrip("*# ").strip()
        if len(s) > 25 and ("block" in s.lower() or "incomplete" in s.lower()
                            or "missing" in s.lower() or "could not" in s.lower()
                            or "unable" in s.lower()):
            return s[:240]
    return "The automated worker reported it could not complete this request."


def _merge_change_request_context(request_id, extra):
    """Read-modify-write the change_requests.context jsonb so we add keys (e.g. a
    'blocked' reason) without clobbering existing context. Best-effort."""
    try:
        res = _supa("GET", "/rest/v1/change_requests?select=context&id=eq." + str(request_id))
        ctx = {}
        if res is not None and res.ok:
            rows = res.json()
            if rows and isinstance(rows[0].get("context"), dict):
                ctx = rows[0]["context"]
        ctx.update(extra or {})
        _supa("PATCH", "/rest/v1/change_requests?id=eq." + str(request_id),
              {"context": ctx}, prefer="return=minimal")
    except Exception as e:
        logging.warning(f"[completion] could not merge context for {request_id}: {e}")


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
                # If this came from the change-request queue, update its status.
                if task.get("change_request_id") and log_type == "completion_sent":
                    try:
                        # Capture the commit the build produced (HEAD moved) so the
                        # Change Log can offer a one-click Revert targeting that SHA.
                        commit_sha = None
                        repo = task.get("repo_path")
                        if repo:
                            head_after = _git_head(repo)
                            if head_after and head_after != task.get("head_before"):
                                commit_sha = head_after

                        # Did the worker actually do the work, or report itself blocked?
                        # A "Blocked"/incomplete report with no commit means nothing
                        # shipped — mark it 'blocked' (not 'awaiting-review') so the
                        # Change Log shows WHY instead of an empty review preview.
                        blocked_reason = _detect_blocked(report_text)
                        if blocked_reason and not commit_sha:
                            patch = {"status": "blocked",
                                     "updated_at": datetime.utcnow().isoformat() + "Z"}
                            _supa("PATCH", "/rest/v1/change_requests?id=eq." + str(task["change_request_id"]),
                                  patch, prefer="return=minimal")
                            _merge_change_request_context(
                                task["change_request_id"], {"blocked": blocked_reason})
                            logging.info(f"[completion] change_request {task['change_request_id']} -> blocked "
                                         f"({blocked_reason[:60]})")
                        else:
                            patch = {"status": "awaiting-review",
                                     "updated_at": datetime.utcnow().isoformat() + "Z"}
                            if commit_sha:
                                patch["commit_sha"] = commit_sha
                            _supa("PATCH", "/rest/v1/change_requests?id=eq." + str(task["change_request_id"]),
                                  patch, prefer="return=minimal")
                            logging.info(f"[completion] change_request {task['change_request_id']} -> awaiting-review"
                                         + (f" (commit {commit_sha[:8]})" if commit_sha else ""))
                    except Exception as e:
                        logging.error(f"[completion] failed to mark change_request: {e}")
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

    Classification is two-stage: a fast first-pass classifier (local Ollama / VPS
    Haiku), then — only for borderline 'destructive' or 'ambiguous' calls — a
    stronger-model SECOND OPINION (_second_opinion) that re-judges the request on
    reversibility and blast radius. Reversible content edits (e.g. removing a
    duplicated section, which git can revert) are reclassified to on_site_build and
    proceed; only genuinely irreversible, high-blast-radius work stays a hard stop.
    If the second opinion is unavailable, the conservative first-pass call stands.

    AMBIGUOUS requests (all tiers) are never guessed at: the stronger model
    articulates what's unclear, what it would assume, and what it would do under
    those assumptions, and that is sent to the REQUESTER (manager CC'd) as a
    clarification they can confirm or correct in a one-line reply — instead of a
    bare "requires review" bounce to a manager.

    Tiers:
      member_services (e.g. Greg Foster)
        - Auto-dispatch: on_site_build, proposal_with_cost under cost_threshold_usd
        - Clarify with requester: ambiguous
        - Escalate to escalate_to: destructive, access_control, off_site_research,
          over-threshold costs, auto_dispatch=false
      owner (e.g. Mike Wolf)
        - Auto-dispatch: ALL categories EXCEPT hard stops and ambiguous
        - Clarify with owner: ambiguous (asked rather than guessed)
        - No cost cap; no escalation path (owner is self)
        - Hard stops (destructive, access_control) are SURFACED to the owner as a
          manual-action notice — never auto-executed regardless of tier

    HARD STOPS reflect IRREVERSIBILITY, not the presence of words like "delete":
    irreversible data loss (dropping a database, deleting all records/backups) and
    access-control / money movement are never auto-executed regardless of tier.

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

    def _request_clarification(classification):
        """Ask the requester to confirm or correct, rather than guessing or silently
        bouncing the request to a manager.

        For genuinely ambiguous requests, the stronger model has already articulated
        what's unclear, what it would assume, and what it would do under those
        assumptions. We relay that to the requester and invite a one-line reply —
        which the daemon will pick up on the next poll and re-route. The manager
        (escalate_to) is CC'd for visibility but doesn't have to act.
        """
        confusion       = (classification.get("confusion") or "").strip()
        assumptions     = (classification.get("assumptions") or "").strip()
        interpretation  = (classification.get("interpretation") or "").strip()
        summary         = (classification.get("summary") or "").strip()

        subj = f"Re: {email_data.get('subject', '')} — quick check before I start"
        lines = [ack_greeting, "", "I want to make sure I get this right before I start."]
        lines.append("")
        lines += ["What's unclear:", confusion or summary or
                  "I couldn't tell exactly what you'd like changed.", ""]
        if assumptions:
            lines += ["What I'm assuming:", assumptions, ""]
        if interpretation:
            lines += ["What I'd do based on that:", interpretation, ""]
        lines += [
            'If that\'s right, just reply "go ahead" and I\'ll take care of it.',
            "If not, reply with the correction and I'll adjust.",
            "",
            f"—{ack_signature}",
        ]

        cc = list(requester.get("cc_dispatch_to", []))
        escalate_to = requester.get("escalate_to")
        if (escalate_to and escalate_to.lower() != sender_email
                and escalate_to.lower() not in [c.lower() for c in cc]):
            cc.append(escalate_to)

        result = {
            "type": "trusted_clarification",
            "requester": req_name,
            "tier": tier,
            "from": sender_raw,
            "sender_email": sender_email,
            "subject": email_data.get("subject", ""),
            "classification": classification,
            "cc": cc,
            "timestamp": datetime.now().isoformat(),
        }
        try:
            send_email(
                config, sender_raw, subj, "\n".join(lines),
                in_reply_to=email_data.get("message_id"),
                references=email_data.get("references"),
                cc=cc if cc else None,
            )
            result["action_result"] = "clarification_sent"
        except Exception as e:
            result["action_result"] = f"clarification_send_error: {e}"
            logging.error(f"[trusted/{req_name}] failed to send clarification: {e}")
        log_path = log_dir / f"trusted-clarification-{iso_now}.json"
        with open(log_path, "w") as f:
            json.dump(result, f, indent=2)
        logging.info(f"[trusted/{req_name}] clarification requested")
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
    # SECOND OPINION — borderline first-pass calls get a stronger model
    # ----------------------------------------------------------------
    # The fast classifier is tuned to be cautious, so it tends to over-flag any
    # email containing words like "delete" or "remove" as destructive. Before we
    # hard-stop such a request — or bounce an 'ambiguous' one to a human — ask a
    # stronger reasoning model to rule on reversibility and blast radius. Reversible
    # content edits (e.g. "remove the duplicated section") get reclassified to
    # on_site_build and proceed; only genuinely irreversible work is stopped.
    if category in ("destructive", "ambiguous"):
        refined = _second_opinion(config, email_data, requester, classification)
        if refined:
            classification["first_pass"] = {
                "category": category,
                "classifier": classification.get("classifier"),
            }
            classification.update({k: v for k, v in refined.items() if k != "cost_usd"})
            category = classification.get("category", category)
            # Safety belt: never auto-run something the reviewer marked irreversible,
            # even if it labeled the category as a benign one.
            if refined.get("reversible") is False and category not in ("destructive", "access_control"):
                category = "destructive"
                classification["category"] = "destructive"
            logging.info(
                f"[trusted/{req_name}] second opinion: "
                f"{classification['first_pass']['category']} -> {category} "
                f"(reversible={refined.get('reversible')}, risk={refined.get('risk')})"
            )

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
    # AMBIGUOUS — never guess, and never bounce a bare "requires review" to a
    # manager. The stronger model has spelled out the confusion + assumptions;
    # relay that to the requester (CC the manager) so a one-line reply resolves it.
    # ----------------------------------------------------------------
    if category == "ambiguous":
        return _request_clarification(classification)

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
        # (ambiguous is handled above via _request_clarification, for all tiers)
        if category == "off_site_research":
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
    def _dispatch_one(task_label, task_instructions):
        """Dispatch a single unit of work. Reproduces the original single-dispatch
        block exactly, parameterized by a label (used to build the task_name slug)
        and the '## Task' instructions block slotted into the worker prompt.

        Returns the dispatch_result dict (or the _escalate / _surface_hard_stop
        result on a dispatch error, same as the original inline path).
        """
        task_name = re.sub(r'[^\w\-]', '-', task_label).strip('-') or 'task'
        task_name = task_name[:48]
        disp_iso = datetime.now().strftime('%Y%m%dT%H%M%S')
        audit_path = f"~/Projects/SOMA/audits/{disp_iso}-{task_name}.md"

        prompt = (
            "## Context\n"
            f"Email from {req_name} ({sender_email}).\n"
            f"Subject: {email_data.get('subject', '')}\n\n"
            f"## Email Body\n{email_data.get('body', '')}\n\n"
            f"{_format_attachments_section(email_data.get('attachments'))}"
            f"{task_instructions}"
            "## Deploy policy\n"
            "This repo auto-deploys to production (Netlify) on push to `master`. "
            "First classify your change:\n"
            "- NON-BREAKING (content/text edits, copy, adding or updating a member or section, "
            "image swaps, minor styling that can't break navigation, the build, or existing "
            "functionality): commit and push to `master` so it deploys live.\n"
            "- BREAKING (removing/renaming/moving a page, changing site navigation or structure, "
            "JS/logic changes that could error, data-shape changes, layout overhauls, edits to "
            "shared includes/templates, or anything you are unsure about): DO NOT push the change "
            "to master. Push it to a branch named `preview/<task>` so Netlify builds a preview at "
            "`https://preview-<task>--legends-membership.netlify.app`; leave production untouched. "
            "It goes live only after a human clicks Accept in the change log. When in doubt, treat "
            "the change as breaking.\n"
            "Record where the change was made in the change-log entry (in admin-changelog.html, "
            "committed to master so it shows in the queue as awaiting approval): for non-breaking "
            "changes set `page` to the production path; for breaking changes set `page` to the "
            "preview URL and `branch` to the `preview/<task>` branch name (the Accept button uses "
            "`branch` to merge it live). A request to merge/publish an already-approved preview "
            "branch into master is itself non-breaking — just do it and push.\n\n"
            "## Done criteria\n"
            f"Changes complete, tested, deployed per the policy above, and a summary written to {audit_path}"
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

        head_before = _git_head(repo_path) if repo_path else None
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

        # Ack to requester — gated. Default: NO separate ack; the single completion
        # email carries the explanation + summary. Set send_ack: true per requester to restore.
        if requester.get("send_ack", False):
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
        else:
            dispatch_result["reply_sent"] = False
            dispatch_result["ack_skipped"] = True

        # Per-dispatch log filename includes task_name so multiple decomposed
        # dispatches within the same iso_now second don't overwrite each other.
        log_path = log_dir / f"trusted-dispatched-{disp_iso}-{task_name}.json"
        with open(log_path, "w") as f:
            json.dump(dispatch_result, f, indent=2)

        # Unified queue: mirror this email-originated dispatch into change_requests so it
        # shows up in the Change Log alongside Bill intake and gets the same Review / Accept
        # / Revert lifecycle. Visibility only — the proven email dispatch/ack/CC path above
        # is untouched. Best-effort: a failure here never blocks the dispatch.
        crid = _mirror_email_to_change_request(
            config, email_data, requester, tier, classification, repo_path, task_name, sender_email
        )
        if crid:
            dispatch_result["change_request_id"] = crid

        # Register pending completion notification
        _save_pending(config, {
            "task_name": task_name,
            "requester_from": sender_raw,
            "requester_email": sender_email,
            "extra_cc": extra_cc,
            "subject": email_data.get("subject", ""),
            "message_id": email_data.get("message_id", ""),
            "references": email_data.get("references", ""),
            "change_request_id": crid,
            "repo_path": repo_path,
            "head_before": head_before,
            "dispatched_at": datetime.now().isoformat(),
            "notified": False,
        })

        return dispatch_result

    def _request_missing_material(blocked):
        """Email the requester (CC their cc_dispatch_to + escalate_to) about the
        parts of their email I could NOT start, because material or diagnostic
        detail is missing. One threaded reply; modeled on _request_clarification.
        """
        cc = list(requester.get("cc_dispatch_to", []))
        escalate_to = requester.get("escalate_to")
        if (escalate_to and escalate_to.lower() != sender_email
                and escalate_to.lower() not in [c.lower() for c in cc]):
            cc.append(escalate_to)

        items = []
        for n, t in enumerate(blocked, 1):
            title = t.get("title", "")
            needs = t.get("needs") or []
            if t.get("kind") == "diagnose":
                detail = "; ".join(needs) if needs else "more detail on what's going wrong"
                items.append(f"{n}. {title} — I need {detail}.")
            else:
                detail = "; ".join(needs) if needs else "the material"
                items.append(
                    f"{n}. {title} — please reply to this email with {detail} attached. "
                    "If you sent it before, just tell me you're re-attaching it and I'll "
                    "find out what went wrong the first time."
                )

        subj = f"Re: {email_data.get('subject', '')} — a few things I need to finish the rest"
        lines = [
            ack_greeting,
            "",
            "I've started on the parts of your email I can complete now. Before I can "
            "finish the rest, I need a few things from you:",
            "",
            "\n".join(items),
            "",
            f"—{ack_signature}",
        ]

        result = {
            "type": "trusted_missing_material",
            "requester": req_name,
            "tier": tier,
            "from": sender_raw,
            "sender_email": sender_email,
            "subject": email_data.get("subject", ""),
            "blocked": [t.get("title", "") for t in blocked],
            "cc": cc,
            "timestamp": datetime.now().isoformat(),
        }
        try:
            send_email(
                config, sender_raw, subj, "\n".join(lines),
                in_reply_to=email_data.get("message_id"),
                references=email_data.get("references"),
                cc=cc if cc else None,
            )
            result["action_result"] = "missing_material_sent"
        except Exception as e:
            result["action_result"] = f"missing_material_send_error: {e}"
            logging.error(f"[trusted/{req_name}] failed to send missing-material request: {e}")
        log_path = log_dir / f"trusted-missing-material-{iso_now}.json"
        with open(log_path, "w") as f:
            json.dump(result, f, indent=2)
        logging.info(f"[trusted/{req_name}] missing-material request sent for {len(blocked)} blocked task(s)")
        return result

    tasks = decompose_email_tasks(config, email_data, requester, classification)
    if not tasks or len(tasks) <= 1:
        # Unchanged single-task behavior (flag off, decomposition failed, or 1 task).
        return _dispatch_one(
            email_data.get("subject", "task"),
            f"## Task\nHandle this work request. Category: {category}. "
            "Complete the requested work and report back.\n\n",
        )

    # Decomposed: dispatch ready build tasks independently; collect the rest.
    dispatched, blocked = [], []
    for t in tasks:
        if t["ready"]:
            targ = f" (targets: {', '.join(t['targets'])})" if t.get("targets") else ""
            instr = (
                "## Task\n"
                "This email contains several requests, handled separately. Do ONLY this one:\n"
                f"**{t['title']}**{targ}.\n"
                "The full email is included above for context; do NOT do the other parts.\n"
                f"Category: {category}. Complete this part and report back.\n\n"
            )
            label = f"{email_data.get('subject','task')} - {t['title']}"
            dispatched.append((t, _dispatch_one(label, instr)))
        else:
            blocked.append(t)

    result = {
        "type": "trusted_decomposed",
        "requester": req_name, "tier": tier, "from": sender_raw,
        "sender_email": sender_email, "subject": email_data.get("subject", ""),
        "task_count": len(tasks),
        "dispatched": [d[0]["title"] for d in dispatched],
        "blocked": [{"title": t["title"], "needs": t["needs"], "kind": t["kind"]} for t in blocked],
        "timestamp": datetime.now().isoformat(),
    }
    if blocked:
        mm = _request_missing_material(blocked)
        result["missing_material_result"] = mm.get("action_result")
    mlog = log_dir / f"trusted-decomposed-{iso_now}.json"
    with open(mlog, "w") as f:
        json.dump(result, f, indent=2)
    logging.info(f"[trusted/{req_name}] decomposed into {len(tasks)} tasks: "
                 f"{len(dispatched)} dispatched, {len(blocked)} blocked")
    return result


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

def process_change_queue(config, logger):
    """Process new rows in the unified change_requests queue (Bill intake + email).
    Vet each via the reversibility second opinion, then route by requester role:
      - owner/admin → auto-proceed (status 'approved'; build-firing is the next step)
      - others      → reversibility-gated: reversible+low-risk auto-proceeds,
                      otherwise → 'awaiting-approval' + a DEEP-LINKED email to the
                      manager (admin-changelog.html#req-<id>).
    """
    _load_env()
    if not os.environ.get("SUPABASE_SERVICE_ROLE_KEY"):
        return
    changelog_url = config.get("changelog_url", "")
    forward_to = config.get("forward_to")
    # SAFETY: the live daemon never dispatches source='test' rows (left behind by
    # the test suite). Tests set DAEMON_ALLOW_TEST_ROWS=1 to exercise the pipeline.
    test_filter = "" if os.environ.get("DAEMON_ALLOW_TEST_ROWS") == "1" else "&source=neq.test"
    try:
        resp = _supa("GET", "/rest/v1/change_requests?status=eq.new" + test_filter + "&order=created_at.asc&limit=10")
        if not resp or not resp.ok:
            return
        rows = resp.json()
    except Exception as e:
        logging.warning(f"[queue] poll failed: {e}")
        return
    if not isinstance(rows, list):
        rows = []
    if rows:
        logging.info(f"[queue] {len(rows)} new change request(s)")
        for r in rows:
            try:
                _process_one_request(config, r, changelog_url, forward_to)
            except Exception as e:
                logging.error(f"[queue] error on {r.get('id')}: {e}")

    # Build-firing: dispatch APPROVED requests to a dev worker (cc-dispatch).
    try:
        ar = _supa("GET", "/rest/v1/change_requests?status=eq.approved" + test_filter + "&order=created_at.asc&limit=5")
        approved = ar.json() if (ar and ar.ok) else []
    except Exception:
        approved = []
    for r in approved:
        try:
            pid = _dispatch_change_request(config, r)
            if pid is not None:
                _supa("PATCH", "/rest/v1/change_requests?id=eq." + str(r["id"]),
                      {"status": "in-progress", "updated_at": datetime.utcnow().isoformat() + "Z"},
                      prefer="return=minimal")
        except Exception as e:
            logging.error(f"[queue] dispatch error on {r.get('id')}: {e}")


def _mirror_email_to_change_request(config, email_data, requester, tier, classification, repo_path, task_name, sender_email=None):
    """Insert an email-originated dispatch into change_requests (status in-progress) so
    it appears in the unified Change Log and shares the Review/Accept/Revert lifecycle.
    Returns the new row id, or None on any failure (never blocks the email path)."""
    try:
        _load_env()
        cat = (classification or {}).get("category", "on_site_build")
        reversible = cat not in ("destructive", "access_control")
        risk = "high" if not reversible else "low"
        subject = email_data.get("subject") or task_name or "change"
        body = (email_data.get("body") or "").strip()
        row = {
            "source": "email",
            "requester_name": requester.get("name") or requester.get("ack_greeting", "").replace("Hi", "").strip(", "),
            "requester_email": (sender_email or requester.get("email") or "").lower() or None,
            "requester_role": "owner" if tier == "owner" else "member",
            "type": "change",
            "title": subject[:200],
            "description": (body[:5000] or subject),
            "status": "in-progress",
            "vet": {"category": cat, "reversible": reversible, "risk": risk,
                    "reason": (classification or {}).get("reason") or "Classified by the email pipeline."},
            "context": {"source": "email", "message_id": email_data.get("message_id", ""), "task_name": task_name},
            "updated_at": datetime.utcnow().isoformat() + "Z",
        }
        resp = _supa("POST", "/rest/v1/change_requests", row, prefer="return=representation")
        if resp is not None and getattr(resp, "ok", False):
            data = resp.json()
            rid = data[0]["id"] if data else None
            if rid:
                logging.info(f"[unify] mirrored email dispatch into change_request {rid}")
            return rid
    except Exception as e:
        logging.warning(f"[unify] could not mirror email to change_requests: {e}")
    return None


def _git_head(repo_path):
    """Return the current HEAD commit SHA of repo_path, or None."""
    try:
        out = subprocess.run(["git", "-C", repo_path, "rev-parse", "HEAD"],
                             capture_output=True, text=True, timeout=10)
        sha = (out.stdout or "").strip()
        return sha or None
    except Exception:
        return None


def _dispatch_change_request(config, r):
    """Dispatch an approved change request to a dev worker (cc-dispatch), with the
    breaking/non-breaking deploy policy. Registers a pending completion carrying the
    change_request_id so the completion pass flips it to 'awaiting-review' + notifies."""
    import re as _re
    rid = r["id"]
    title = r.get("title") or "change"
    desc = r.get("description") or ""
    repo_path = os.path.expanduser(config.get("change_repo", "~/Projects/legends-membership-site"))
    iso_now = datetime.now().strftime("%Y%m%dT%H%M%S")
    task_name = (_re.sub(r"[^\w\-]", "-", title).strip("-") or "change")[:40]
    audit_path = f"~/Projects/SOMA/audits/{iso_now}-{task_name}.md"
    prompt = (
        "## Context\n"
        f"Change request from {r.get('requester_name') or r.get('requester_email') or 'a requester'}.\n"
        f"Page: {r.get('page', '')}\n\n"
        f"## Request\n{desc}\n\n"
        "## Task\nHandle this change request. Complete the work and report back.\n\n"
        "## Deploy policy\n"
        "This repo auto-deploys to production (Netlify) on push to `master`. NON-BREAKING "
        "(content/text/styling that can't break navigation, the build, or existing "
        "functionality): commit and push to master. BREAKING (removing/renaming/moving a page, "
        "nav/structure changes, JS/logic that could error, layout overhauls, or anything you "
        "are unsure about): push to a `preview/<task>` branch so Netlify builds a preview, leave "
        "production untouched, and report the preview URL — it goes live only after a human "
        "Accepts it. When in doubt, treat the change as breaking.\n\n"
        "## Done criteria\n"
        f"Changes complete, tested, deployed per the policy above, and a summary written to {audit_path}"
    )
    mac_cmd = os.path.expanduser(
        config.get("dispatch", {}).get("platforms", {}).get("Mac", {}).get("command", "~/.local/bin/cc-dispatch")
    )
    if not os.path.exists(mac_cmd):
        logging.error(f"[queue] cc-dispatch not found at {mac_cmd}")
        return None
    head_before = _git_head(repo_path)
    proc = subprocess.Popen(
        [mac_cmd, "--workdir", repo_path, task_name, prompt],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    _save_pending(config, {
        "task_name": task_name,
        "change_request_id": rid,
        "requester_from": r.get("requester_email") or config.get("forward_to"),
        "requester_email": (r.get("requester_email") or "").lower(),
        "extra_cc": [],
        "subject": title,
        "repo_path": repo_path,
        "head_before": head_before,
        "dispatched_at": datetime.now().isoformat(),
        "notified": False,
    })
    logging.info(f"[queue] dispatched change request {rid} task={task_name} pid={proc.pid}")
    return proc.pid


def _process_one_request(config, r, changelog_url, forward_to):
    rid = r.get("id")
    role = (r.get("requester_role") or "member").lower()
    desc = r.get("description") or ""
    title = r.get("title") or desc[:80]

    # Reversibility vet (reuse the second-opinion rubric).
    email_data = {"subject": title, "body": desc}
    requester = {"name": r.get("requester_name") or "requester", "site_label": "the website"}
    first_pass = {"category": "destructive" if r.get("type") == "change" else "on_site_build"}
    vet = None
    try:
        vet = _second_opinion(config, email_data, requester, first_pass)
    except Exception:
        vet = None
    if not vet:
        vet = {"reversible": False, "risk": "medium",
               "reason": "Could not auto-vet — routing to a human for approval.",
               "category": "ambiguous"}

    reversible = vet.get("reversible") is True
    risk = vet.get("risk", "medium")
    is_owner = role in ("owner", "admin")
    needs_approval = (not is_owner) and ((not reversible) or risk == "high")
    vet_store = {"reversible": reversible, "risk": risk,
                 "reason": vet.get("reason", ""), "needs_approval": needs_approval}
    new_status = "awaiting-approval" if needs_approval else "approved"

    _supa("PATCH", "/rest/v1/change_requests?id=eq." + str(rid),
          {"status": new_status, "vet": vet_store, "updated_at": datetime.utcnow().isoformat() + "Z"},
          prefer="return=minimal")
    logging.info(f"[queue] {rid} role={role} reversible={reversible} risk={risk} -> {new_status}")

    if needs_approval and forward_to:
        link = (changelog_url + "#req-" + str(rid)) if changelog_url else ""
        who = r.get("requester_name") or r.get("requester_email") or "a member"
        body = "\n".join([
            f"{who} submitted a change request that needs your approval.",
            "",
            f"Request: {title}",
            f"Details: {desc}",
            "",
            "Vet: " + (vet_store["reason"] or "—") + " (" +
            ("reversible" if reversible else "IRREVERSIBLE") + f", risk {risk})",
            "",
            (f"Review and approve here: {link}" if link else "Open the Site Change Log to review it."),
        ])
        try:
            send_email(config, forward_to, f"[Approve] {title}", body)
            logging.info(f"[queue] approval email sent for {rid} -> {forward_to}")
        except Exception as e:
            logging.error(f"[queue] approval email failed for {rid}: {e}")


FATHOM_IMPORT_SCRIPT = os.path.expanduser(
    "~/Projects/second-brain/scripts/fathom_import.py"
)
FATHOM_IMPORT_PYTHON = "/opt/homebrew/bin/python3"


def run_fathom_import(logger, dry_run=False):
    """Fold the Fathom meeting-summary importer into this daemon's existing
    5-minute poll loop (~/Projects/second-brain/scripts/fathom_import.py).
    Runs once per cycle, before the inbox scan below, so its own IMAP search
    + state-file dedup always sees mail before the inbox loop's FETCH calls
    flip the \\Seen flag. No LLM call — pure IMAP search + file write, cheap
    enough to run every cycle."""
    if dry_run:
        return
    try:
        args = [FATHOM_IMPORT_PYTHON, FATHOM_IMPORT_SCRIPT]
        proc = subprocess.run(args, capture_output=True, text=True, timeout=60)
        if proc.returncode != 0:
            logging.error(f"[fathom-import] exit {proc.returncode}: {proc.stderr[-500:]}")
        else:
            last_line = (proc.stdout or "").strip().splitlines()[-1] if proc.stdout.strip() else ""
            logging.info(f"[fathom-import] {last_line}")
    except Exception as e:
        logging.error(f"[fathom-import] failed to run: {e}")


def run_pending_exports(config, logger, dry_run=False):
    """Retry any provider-export downloads that were queued for the overnight
    window (see _queue_export_for_overnight). Runs every poll cycle but only
    ACTS once _in_overnight_window() is true — outside the window this is a
    cheap no-op read of the queue file, so it's safe to call unconditionally
    from the main loop rather than needing its own launchd job."""
    if dry_run:
        return
    pe_cfg = config.get("provider_exports", {}) or {}
    if not pe_cfg.get("enabled", True):
        return
    items = _load_pending_exports(config)
    if not items:
        return
    if not _in_overnight_window(pe_cfg):
        return

    remaining = []
    for entry in items:
        provider = entry.get("provider")
        cfg = PROVIDER_EXPORTS.get(provider)
        if not cfg:
            logging.warning(f"[export-ingest/pending] unknown provider '{provider}', dropping entry")
            continue
        entry["attempts"] = entry.get("attempts", 0) + 1
        url = entry["url"]
        iso_now = datetime.now().strftime("%Y%m%dT%H%M%S")
        log_dir = Path(os.path.expanduser(config["log_dir"]))
        log_dir.mkdir(parents=True, exist_ok=True)
        dest_dir = os.path.expanduser(cfg["dest_dir"])
        os.makedirs(dest_dir, exist_ok=True)
        dest_path = os.path.join(dest_dir, f"{cfg['prefix']}-{iso_now}.zip")

        got, yerr = _yeshie_download_export(url, config, pe_cfg, dest_dir, cfg["prefix"])
        result = {
            "type": "provider_export_pending_retry",
            "provider": provider,
            "queued_at": entry.get("queued_at"),
            "attempts": entry["attempts"],
            "timestamp": datetime.now().isoformat(),
        }
        if got:
            try:
                shutil.move(got, dest_path)
                size_mb = round(os.path.getsize(dest_path) / (1024 * 1024), 1)
                result["result"] = "downloaded"
                result["zip_path"] = dest_path
                logging.info(f"[export-ingest/pending] {provider}: downloaded {dest_path} ({size_mb} MB)")
                stage = cfg.get("stage_copy")
                if stage:
                    try:
                        stage_path = os.path.expanduser(stage)
                        os.makedirs(os.path.dirname(stage_path), exist_ok=True)
                        shutil.copy2(dest_path, stage_path)
                    except OSError as e:
                        logging.warning(f"[export-ingest/pending] stage copy failed: {e}")
                try:
                    send_email(
                        config, config["forward_to"],
                        f"[export-ingest] {cfg['label']} export downloaded ({size_mb} MB, overnight)",
                        f"Zero-touch export ingestion succeeded (queued earlier, ran in the "
                        f"overnight window).\n\nSaved to: {dest_path}\nSize: {size_mb} MB\n\n"
                        f"Next: {cfg['next_step']}.\n\nNo action needed.",
                    )
                except Exception as e:
                    logging.error(f"[export-ingest/pending] failed to send notification: {e}")
            except OSError as e:
                result["result"] = "move_failed"
                result["detail"] = str(e)
                remaining.append(entry)
        else:
            result["result"] = "retry_failed"
            result["detail"] = yerr
            logging.info(f"[export-ingest/pending] {provider}: attempt {entry['attempts']} failed — {yerr}")
            # Drop after 3 overnight attempts (link is 24h-expiring; further
            # retries past that are pointless) rather than growing forever.
            if entry["attempts"] < 3:
                remaining.append(entry)
            else:
                logging.warning(f"[export-ingest/pending] {provider}: giving up after 3 attempts (link likely expired)")

        log_path = log_dir / f"export-ingest-pending-{iso_now}-{provider}.json"
        with open(log_path, "w") as f:
            json.dump(result, f, indent=2)

    _save_pending_exports(config, remaining)


def run_cycle(config, state, logger, dry_run=False):
    """Run one check cycle: fetch new emails + drafts, route, act."""
    results = []

    # -1. Retry any provider-exports queued for the overnight window (no-op
    #     outside the window — see run_pending_exports docstring).
    run_pending_exports(config, logger, dry_run=dry_run)

    # 0. Fathom meeting-summary import — own poller, own state file, run
    #    first so it always sees mail before this cycle's inbox FETCH below
    #    can flip \Seen on the same message.
    run_fathom_import(logger, dry_run=dry_run)

    # 1. Check Claude's inbox
    try:
        claude_pw = get_password("claude", "CLAUDE_EMAIL_PW", "Account")
        cfg = config["claude_email"]
        new_emails = fetch_new_emails(
            cfg["imap_server"], cfg["address"], claude_pw, state, source="inbox"
        )
        logging.info(f"Found {len(new_emails)} new email(s) in Claude's inbox")

        for em in new_emails:
            # Fathom meeting summaries short-circuit LLM routing entirely —
            # the dedicated fathom_import.py poller (own cron job, own state
            # file) owns turning these into vault notes. Here we just avoid
            # burning an LLM routing call / risking a nonsense action on mail
            # that isn't an instruction to Claude.
            if FATHOM_SENDER_RE.search(em.get('from', '')):
                logging.info(f"  [fathom/skip-routing] {em['subject'][:60]}")
                results.append({"action": "fathom_skip_routing", "subject": em["subject"]})
                state.mark_processed("inbox", em["stable_id"])
                continue

            # Self-generated "Re: [BOARD] ..." confirmation bouncing back into
            # claude@'s own inbox (soma-feedback's self-send pattern) — skip
            # before it can fall through to general routing and get flagged
            # forward_urgent by the @mike-wolf.com policy override. See
            # BOARD_SELF_REPLY_RE / _is_board_self_reply above (WQ-128 fix).
            if _is_board_self_reply(em, config):
                logging.info(f"  [board/self-reply-skip] {em['subject'][:60]}")
                results.append({"action": "board_self_reply_skip", "subject": em["subject"]})
                state.mark_processed("inbox", em["stable_id"])
                continue

            # Provider data-export emails (Anthropic / OpenAI / Google Takeout,
            # forwarded from mw@ by Gmail filter) short-circuit LLM routing —
            # download the zip immediately (Anthropic links expire in 24h).
            if _match_provider_export(em, config):
                if not dry_run:
                    export_result = handle_provider_export_email(em, config, logger)
                    results.append(export_result or {})
                    logging.info(f"  [export-ingest] {em['subject'][:60]}")
                else:
                    logging.info(f"  [export-ingest/dry-run] {em['subject'][:60]}")
                    results.append({"action": "export_ingest_dry_run", "subject": em["subject"]})
                state.mark_processed("inbox", em["stable_id"])
                continue

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

            # Board emails short-circuit LLM routing entirely — file a card, confirm, done
            if BOARD_SUBJECT_RE.match(em.get('subject', '')):
                if not dry_run:
                    board_result = handle_board_email(em, config, logger)
                    results.append(board_result or {})
                    logging.info(f"  [board] {em['subject'][:60]}")
                else:
                    logging.info(f"  [board/dry-run] {em['subject'][:60]}")
                    results.append({"action": "board_dry_run", "subject": em["subject"]})
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
                # Board drafts short-circuit like board inbox emails: file a card, no LLM routing.
                # Covers a CCw/CDC session composing a draft in Mike's Gmail as a board note.
                if BOARD_SUBJECT_RE.match(draft.get('subject', '')):
                    draft.setdefault('from', mike_cfg.get('address', 'mikeai'))
                    board_result = handle_board_email(draft, config, logger, trusted=True) if not dry_run else None
                    if not dry_run:
                        results.append(board_result or {})
                        logging.info(f"  [board/draft] {draft['subject'][:60]}")
                    else:
                        results.append({"action": "board_dry_run", "subject": draft["subject"]})
                        logging.info(f"  [board/draft/dry-run] {draft['subject'][:60]}")
                    state.mark_processed("drafts", draft["stable_id"])
                    continue

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

    # 3. Process the unified change-request queue (Bill intake + email)
    if not dry_run:
        try:
            process_change_queue(config, logger)
        except Exception as e:
            logging.error(f"Error processing change queue: {e}")

    # 4. Check pending completions — send "done" emails when dispatched tasks land
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
