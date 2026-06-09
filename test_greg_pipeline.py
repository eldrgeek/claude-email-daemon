#!/usr/bin/env python3
"""
Simulation test for the Greg Foster email pipeline.

Tests the classifier + router WITHOUT sending real emails or dispatching real tasks.
Patches out send_email and cc-dispatch so nothing leaves the machine.

Run: python3 test_greg_pipeline.py
"""

import json
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Import daemon module
# ---------------------------------------------------------------------------
sys.path.insert(0, str(Path(__file__).parent))
import daemon as D


# ---------------------------------------------------------------------------
# Minimal config (no real credentials needed for routing logic)
# ---------------------------------------------------------------------------
TEST_CONFIG = {
    "claude_email": {
        "address": "claude@mike-wolf.com",
        "imap_server": "imap.gmail.com",
        "smtp_server": "smtp.gmail.com",
        "smtp_port": 587,
    },
    "llm": {
        "endpoint": "http://localhost:11434/api/generate",
        "model": "qwen2.5:7b",
        "temperature": 0.1,
        "max_tokens": 200,
    },
    "forward_to": "mw@mike-wolf.com",
    "log_dir": "/tmp/test-greg-pipeline/logs",
    "state_file": "/tmp/test-greg-pipeline/state/processed.json",
    "dispatch": {
        "enabled": True,
        "allowed_senders": ["mw@mike-wolf.com", "claude@mike-wolf.com"],
        "rate_limit_per_hour": 5,
        "body_max_bytes": 51200,
        "platforms": {
            "Mac": {
                "command": "/usr/bin/true",  # dummy — won't be called in send-blocked tests
            },
        },
    },
    "greg_pipeline": {
        "enabled": True,
        "email": "gfos44@gmail.com",
        "auto_dispatch": True,
        "cc_mike_on_dispatch": True,
        "cost_threshold_usd": 100,
    },
    "policies": {
        "always_forward": [],
        "always_ignore": [],
    },
}

# ---------------------------------------------------------------------------
# Synthetic email factories
# ---------------------------------------------------------------------------

def _make_email(subject, body, from_addr="gfos44@gmail.com", auth_results=""):
    """Build a minimal email_data dict for handle_greg_email."""
    return {
        "stable_id": "test-" + subject[:8].replace(" ", "-"),
        "message_id": "<test@localhost>",
        "from": f"Greg Foster <{from_addr}>",
        "to": "claude@mike-wolf.com",
        "subject": subject,
        "date": "Mon, 09 Jun 2026 12:00:00 -0600",
        "body": body,
        "references": "",
        "authentication_results": auth_results,
    }


CASE_A_ON_SITE = _make_email(
    subject="Update the Legends member directory page",
    body=(
        "Hi Claude,\n\n"
        "Please update the member directory on our website to add the new board "
        "members we approved last meeting. Names and bios are attached below.\n\n"
        "Jim Smith — Board President\nJane Doe — Treasurer\n\n"
        "Thanks, Greg"
    ),
)

CASE_B_OFF_SITE = _make_email(
    subject="Research competing golf club websites",
    body=(
        "Hi Claude,\n\n"
        "Can you do some research on what features competing golf club websites "
        "have that we don't? I want a comparison report for the committee.\n\n"
        "Thanks, Greg"
    ),
)

CASE_C_SPOOFED = _make_email(
    subject="Update the Legends member directory page",
    body="Please update the site.",
    from_addr="attacker@evil.com",  # Wrong sender
)

CASE_D_DKIM_FAIL = _make_email(
    subject="Add event to calendar page",
    body="Please add our June 15 tournament to the events page.",
    auth_results="dkim=fail header.d=gmail.com; spf=pass",
)

CASE_E_DESTRUCTIVE = _make_email(
    subject="Delete all old event posts",
    body="Please delete all event posts from before 2024 from the website.",
)

CASE_F_HIGH_COST = _make_email(
    subject="Website redesign proposal",
    body=(
        "Hi Claude,\n\n"
        "I'd like you to do a full website redesign. Budget is $500.\n\n"
        "Thanks, Greg"
    ),
)

CASE_G_AUTO_DISPATCH_OFF = _make_email(
    subject="Update the event schedule page",
    body="Please update the event schedule on the website with our July tournament.",
)


# ---------------------------------------------------------------------------
# LLM mock: classify based on keywords so tests run without Ollama
# ---------------------------------------------------------------------------

def _mock_classify(config, email_data):
    """Keyword-based classifier stub — no real LLM needed."""
    body = email_data.get("body", "").lower()
    subject = email_data.get("subject", "").lower()
    text = subject + " " + body

    if any(w in text for w in ("delete", "drop", "wipe", "remove all", "destroy")):
        return {"category": "destructive", "reason": "Destructive keyword", "cost_usd": None,
                "summary": "Wants to delete content."}
    if any(w in text for w in ("password", "credential", "access", "permission", "login")):
        return {"category": "access_control", "reason": "Access keyword", "cost_usd": None,
                "summary": "Mentions access control."}
    if any(w in text for w in ("research", "compare", "report", "competing", "analysis")):
        return {"category": "off_site_research", "reason": "Research keyword", "cost_usd": None,
                "summary": "Research request."}
    if "$" in text or "budget" in text or "cost" in text or "redesign" in text:
        # extract a dollar amount
        import re
        m = re.search(r'\$(\d+)', text)
        cost = int(m.group(1)) if m else None
        return {"category": "proposal_with_cost", "reason": "Cost mentioned", "cost_usd": cost,
                "summary": "Proposal with cost."}
    if any(w in text for w in ("update", "add", "fix", "build", "create", "page", "website", "site")):
        return {"category": "on_site_build", "reason": "On-site work", "cost_usd": None,
                "summary": "On-site website work request."}
    return {"category": "ambiguous", "reason": "No clear category", "cost_usd": None,
            "summary": "Unclear request."}


# ---------------------------------------------------------------------------
# Test runner
# ---------------------------------------------------------------------------

def run_simulation():
    print("=" * 70)
    print("Greg Foster Pipeline — Routing Simulation")
    print("=" * 70)

    sent_emails = []
    dispatched_tasks = []

    # Patch send_email and subprocess.Popen globally
    original_send = D.send_email
    original_popen = __import__("subprocess").Popen
    original_classify = D.classify_greg_email

    def mock_send(config, to, subject, body, **kwargs):
        sent_emails.append({"to": to, "subject": subject, "cc": kwargs.get("cc")})
        return True

    def mock_popen(cmd, **kwargs):
        dispatched_tasks.append(cmd)
        m = MagicMock()
        m.pid = 99999
        return m

    D.send_email = mock_send
    D.classify_greg_email = _mock_classify
    __import__("subprocess").Popen = mock_popen

    CASES = [
        ("A", CASE_A_ON_SITE,      "greg_dispatched", "On-site build request from Greg"),
        ("B", CASE_B_OFF_SITE,     "greg_escalated",  "Off-site research request"),
        ("C", CASE_C_SPOOFED,      None,              "Wrong sender — not Greg, falls through"),
        ("D", CASE_D_DKIM_FAIL,    "greg_escalated",  "DKIM fail → escalate (possible spoof)"),
        ("E", CASE_E_DESTRUCTIVE,  "greg_escalated",  "Destructive request → escalate"),
        ("F", CASE_F_HIGH_COST,    "greg_escalated",  "Cost over threshold → escalate"),
    ]

    # Case G: auto_dispatch=false variant
    cfg_no_dispatch = {**TEST_CONFIG, "greg_pipeline": {**TEST_CONFIG["greg_pipeline"], "auto_dispatch": False}}

    all_passed = True
    results_log = []

    for case_id, email_data, expected_type, description in CASES:
        sent_emails.clear()
        dispatched_tasks.clear()
        result = D.handle_greg_email(email_data, TEST_CONFIG, MagicMock())

        actual_type = result.get("type") if result else None
        passed = actual_type == expected_type
        all_passed = all_passed and passed

        status = "PASS" if passed else "FAIL"
        print(f"\n[{status}] Case {case_id}: {description}")
        print(f"  Subject  : {email_data['subject']}")
        print(f"  From     : {email_data['from']}")
        print(f"  Expected : {expected_type}")
        print(f"  Got      : {actual_type}")
        if result:
            if result.get("type") == "greg_dispatched":
                print(f"  Task     : {result.get('task_name')}")
                print(f"  Category : {result.get('classification', {}).get('category')}")
                print(f"  Emails sent: {[e['to'] + (' CC:' + str(e['cc']) if e.get('cc') else '') for e in sent_emails]}")
            elif result.get("type") == "greg_escalated":
                print(f"  Reason   : {result.get('escalation_reason')}")
                print(f"  Escalated to: {[e['to'] for e in sent_emails]}")

        results_log.append({
            "case": case_id,
            "description": description,
            "subject": email_data["subject"],
            "from": email_data["from"],
            "expected_type": expected_type,
            "actual_type": actual_type,
            "passed": passed,
            "escalation_reason": result.get("escalation_reason") if result else None,
            "classification": result.get("classification") if result else None,
            "task_name": result.get("task_name") if result else None,
        })

    # Case G: auto_dispatch=false
    sent_emails.clear()
    dispatched_tasks.clear()
    result_g = D.handle_greg_email(CASE_G_AUTO_DISPATCH_OFF, cfg_no_dispatch, MagicMock())
    actual_g = result_g.get("type") if result_g else None
    passed_g = actual_g == "greg_escalated"
    all_passed = all_passed and passed_g
    print(f"\n[{'PASS' if passed_g else 'FAIL'}] Case G: auto_dispatch=false → escalate even for on-site")
    print(f"  Expected : greg_escalated")
    print(f"  Got      : {actual_g}")
    if result_g:
        print(f"  Reason   : {result_g.get('escalation_reason')}")
    results_log.append({
        "case": "G",
        "description": "auto_dispatch disabled",
        "expected_type": "greg_escalated",
        "actual_type": actual_g,
        "passed": passed_g,
    })

    print("\n" + "=" * 70)
    print(f"Result: {'ALL PASSED' if all_passed else 'SOME FAILURES'} ({sum(r['passed'] for r in results_log)}/{len(results_log)})")
    print("=" * 70)

    # Restore
    D.send_email = original_send
    D.classify_greg_email = original_classify
    __import__("subprocess").Popen = original_popen

    return all_passed, results_log


if __name__ == "__main__":
    passed, results = run_simulation()
    sys.exit(0 if passed else 1)
