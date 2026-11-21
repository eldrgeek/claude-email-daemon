#!/usr/bin/env python3
"""[PLAN] intake: spooled for plan-coach, allowlist enforced, duplicates dropped.

Built 2026-11-21 by Claude Opus 5.5 for Mike Wolf (Mike Management, "Build Mac plan coach").
"""
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import daemon as D

ALLOWED = "assistant@example.org"
config = {"dispatch": {"allowed_senders": [ALLOWED]}}
fails = 0


def check(name, cond):
    global fails
    print(("ok   " if cond else "FAIL ") + name)
    fails += 0 if cond else 1


with tempfile.TemporaryDirectory() as d:
    em = {"subject": "[PLAN] change", "from": f"Dottie <{ALLOWED}>",
          "body": "change move SOMA Rooms to tomorrow because the appointment ran long",
          "message_id": "<abc@x>", "date": "Sat, 21 Nov 2026 09:00:00 -0500"}
    r = D.handle_plan_email(em, config, None, spool_dir=d)
    check("allowlisted [PLAN] change is spooled", r["result"] == "spooled")
    files = list(Path(d).glob("*.json"))
    check("one spool file", len(files) == 1)
    data = json.loads(files[0].read_text())
    check("kind parsed", data["kind"] == "change")
    check("body kept", "because the appointment" in data["body"])

    r2 = D.handle_plan_email(em, config, None, spool_dir=d)
    check("same message-id is a duplicate", r2["result"] == "duplicate")

    bad = dict(em, **{"from": "stranger@example.com", "message_id": "<zzz@x>"})
    r3 = D.handle_plan_email(bad, config, None, spool_dir=d)
    check("non-allowlisted sender rejected", r3["result"].startswith("rejected"))
    check("rejected mail not spooled", len(list(Path(d).glob("*.json"))) == 1)

    check("other subjects ignored", D.handle_plan_email({"subject": "[BOARD] x"}, config, None, spool_dir=d) is None)
    check("case-insensitive", D.PLAN_SUBJECT_RE.match("[plan] Commitment") is not None)

sys.exit(1 if fails else 0)
