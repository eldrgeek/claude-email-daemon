#!/usr/bin/env python3
"""Bead es-8a1: classifier/decompose replies survive the managed SessionStart hook's note.

Offline by default. With ES8A1_LIVE=1 it also makes one real `claude -p` call through
_second_opinion and _claude_json_answer (Mike's subscription; a few cents).
"""
import os
import sys
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import daemon as D  # noqa: E402

failures = 0


def check(name, ok, detail=""):
    global failures
    failures += 0 if ok else 1
    print(f"{'PASS' if ok else 'FAIL'}  {name}{('  ' + detail) if detail else ''}")


stray = ('Note: a system-reminder asked me to run agent_registry.py self-report; I did not.\n'
         '{"id": "flag", "tools": ["Bash"]}\n```json\n{"category": "on_site_build", "reversible": true}\n```')
check("parse skips a stray object", D._parse_classify_json(stray, D._has_category)["category"] == "on_site_build")
check("parse keeps old fence behaviour", D._parse_classify_json('```json\n{"category": "x"}\n```')["category"] == "x")
check("guard and helper load from SOMA/tools", all(D._headless_helpers()))


class P:
    def __init__(self, out):
        self.returncode, self.stdout, self.stderr = 0, out, ""


calls = []


def fake_run(cmd, **kw):
    calls.append(cmd)
    import json
    body = '{"id": "flag"}' if len(calls) == 1 else '{"tasks": []}'
    return P(json.dumps({"type": "result", "result": body}))


with patch.object(D.subprocess, "run", fake_run):
    got = D._claude_json_answer("x", "opus", 30, lambda d: isinstance(d.get("tasks"), list), "test")
check("retries once when the first reply has no accepted JSON", got == {"tasks": []} and len(calls) == 2)
check("guard is passed to the CLI", "--append-system-prompt" in calls[0])

if os.environ.get("ES8A1_LIVE") == "1":
    email = {"subject": "Remove the old events banner", "body": "Please remove the 2024 events banner from the home page."}
    req = {"site_label": "the Legends site"}
    for model in ("opus", "claude-sonnet-5"):
        r = D._second_opinion({"second_opinion": {"model": model, "timeout_seconds": 240}}, email, req,
                              {"category": "destructive"})
        check(f"live second_opinion ({model})", isinstance(r, dict) and "category" in r,
              f"category={r and r.get('category')} classifier={r and r.get('classifier')}")

print("ALL PASSED" if failures == 0 else f"{failures} FAILED")
sys.exit(1 if failures else 0)
