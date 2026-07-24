#!/usr/bin/env python3
"""Tests for the per-task decomposition path in handle_trusted_email.

Verifies that when `decompose_tasks` is enabled and the email splits into several
shared-fate tasks, the ready build tasks are dispatched independently and the
blocked ones trigger a single consolidated missing-material email — while the
single-task path is untouched when the flag is off.

Mocks: classify_trusted_email, _second_opinion, decompose_email_tasks, send_email,
subprocess.Popen. No network, no Ollama, no `claude` CLI, no real dispatch.
"""
import os
import sys
import subprocess
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import daemon as D

os.makedirs("/tmp/test-decompose/logs", exist_ok=True)
os.makedirs("/tmp/test-decompose/state", exist_ok=True)
# Start from a clean pending list so dispatch counts are deterministic.
for p in ("/tmp/test-decompose/state/greg-pending.json",):
    try:
        os.remove(p)
    except FileNotFoundError:
        pass

BASE_CONFIG = {
    "claude_email": {"address": "claude@mike-wolf.com", "imap_server": "imap.gmail.com",
                     "smtp_server": "smtp.gmail.com", "smtp_port": 587},
    "llm": {"endpoint": "http://localhost:11434/api/generate", "model": "qwen2.5:7b",
            "temperature": 0.1, "max_tokens": 200},
    "forward_to": "mw@mike-wolf.com",
    "log_dir": "/tmp/test-decompose/logs",
    "state_file": "/tmp/test-decompose/state/processed.json",
    "dispatch": {"enabled": True, "platforms": {"Mac": {"command": "/usr/bin/true"}}},
    "second_opinion": {"enabled": True, "model": "opus"},
    "trusted_requesters": {
        "gfos44@gmail.com": {
            "name": "Greg Foster", "tier": "member_services", "auto_dispatch": True,
            "cc_dispatch_to": ["mw@mike-wolf.com"], "cost_threshold_usd": 100,
            "completion_timeout_hours": 4, "escalate_to": "mw@mike-wolf.com",
            "ack_greeting": "Hi Greg,", "ack_signature": "Claude",
            "repo": "/tmp/test-decompose",  # exists, so dispatch proceeds with --workdir
        },
    },
    "policies": {"always_forward": [], "always_ignore": []},
}


def _email(subject, body):
    return {
        "stable_id": "test-decompose", "message_id": "<test@localhost>",
        "from": "Greg Foster <gfos44@gmail.com>", "to": "claude@mike-wolf.com",
        "cc": "", "subject": subject, "date": "Sat, 20 Jun 2026 12:00:00 -0600",
        "body": body, "references": "", "authentication_results": "", "attachments": [],
    }


THREE_TASKS = [
    {"title": "Fix assessment nav padding", "targets": ["assessment.html"],
     "kind": "build", "needs": [], "ready": True},
    {"title": "Add scholarships eligibility section", "targets": ["subcommittee-scholarships.html"],
     "kind": "build", "needs": [], "ready": True},
    {"title": "Add Scholarship America slideshow", "targets": ["subcommittee-scholarships.html"],
     "kind": "build", "needs": ["the Scholarship America slideshow file"], "ready": False},
]


def run():
    sent, popens = [], []
    orig = {
        "send": D.send_email, "popen": subprocess.Popen,
        "classify": D.classify_trusted_email, "second": D._second_opinion,
        "decompose": D.decompose_email_tasks,
    }

    D.send_email = lambda config, to, subject, body, **kw: (
        sent.append({"to": to, "subject": subject, "cc": kw.get("cc")}) or True)

    def mock_popen(cmd, **kw):
        popens.append(cmd)
        m = MagicMock(); m.pid = 99999
        return m
    subprocess.Popen = mock_popen

    D.classify_trusted_email = lambda c, e, r: {
        "category": "on_site_build", "reason": "site work", "cost_usd": None,
        "summary": "edits", "classifier": "mock"}
    D._second_opinion = lambda c, e, r, fp: None

    failures = []
    try:
        # ---- Case 1: flag ON, 3 tasks (2 ready, 1 blocked) ----
        D.decompose_email_tasks = lambda c, e, r, cls: [dict(t) for t in THREE_TASKS]
        cfg = {**BASE_CONFIG, "decompose_tasks": True}
        sent.clear(); popens.clear()
        res = D.handle_trusted_email(
            _email("edits and additions to member service committee website",
                   "Three things: fix the assessment padding, add the eligibility "
                   "section, and add the Scholarship America slideshow I sent."),
            cfg, MagicMock())

        def check(name, cond):
            print(f"  [{'PASS' if cond else 'FAIL'}] {name}")
            if not cond:
                failures.append(name)

        print("--- Case 1: decompose ON, 2 ready + 1 blocked ---")
        check("type == trusted_decomposed", res.get("type") == "trusted_decomposed")
        check("task_count == 3", res.get("task_count") == 3)
        check("2 tasks dispatched", len(res.get("dispatched", [])) == 2)
        check("1 task blocked", len(res.get("blocked", [])) == 1)
        dispatch_popens = [c for c in popens if c and c[0] == "/usr/bin/true"]
        check("2 cc-dispatch Popen calls", len(dispatch_popens) == 2)
        check("blocked task is the slideshow",
              res.get("blocked", [{}])[0].get("title") == "Add Scholarship America slideshow")
        check("missing_material email sent", res.get("missing_material_result") == "missing_material_sent")
        mm = [e for e in sent if "need" in e["subject"].lower() or "missing" in e["subject"].lower()]
        check("exactly one missing-material email", len(mm) == 1)
        check("missing-material CC includes Mike",
              bool(mm) and mm[0]["cc"] and any("mw@mike-wolf.com" in str(c) for c in mm[0]["cc"]))

        # ---- Case 2: flag OFF → single-task path unchanged ----
        print("--- Case 2: decompose OFF → single dispatch ---")
        D.decompose_email_tasks = orig["decompose"]  # real fn returns None when flag off
        cfg_off = {**BASE_CONFIG}  # no decompose_tasks key
        sent.clear(); popens.clear()
        res2 = D.handle_trusted_email(
            _email("Update the events page", "Please add the July tournament."),
            cfg_off, MagicMock())
        check("type == trusted_dispatched (single path)", res2.get("type") == "trusted_dispatched")
        check("exactly one cc-dispatch call",
              len([c for c in popens if c and c[0] == "/usr/bin/true"]) == 1)

        # ---- Case 3: decompose returns 1 task → single-task fallback ----
        print("--- Case 3: decompose ON but only 1 task → fallback ---")
        D.decompose_email_tasks = lambda c, e, r, cls: [dict(THREE_TASKS[0])]
        sent.clear(); popens.clear()
        res3 = D.handle_trusted_email(
            _email("One small fix", "Fix the padding."),
            {**BASE_CONFIG, "decompose_tasks": True}, MagicMock())
        check("1-task decompose falls back to trusted_dispatched",
              res3.get("type") == "trusted_dispatched")
    finally:
        D.send_email = orig["send"]; subprocess.Popen = orig["popen"]
        D.classify_trusted_email = orig["classify"]; D._second_opinion = orig["second"]
        D.decompose_email_tasks = orig["decompose"]

    print("=" * 60)
    if failures:
        print(f"Result: {len(failures)} FAILED: {failures}")
        return 1
    print("Result: ALL PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(run())
