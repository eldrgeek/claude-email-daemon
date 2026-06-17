#!/usr/bin/env python3
"""Verify process_change_queue routing WITHOUT sending real email.
Seeds 3 rows, patches send_email (capture) + _second_opinion (deterministic),
runs the processor, asserts statuses + the deep-linked approval email."""
import sys, json
from pathlib import Path
from unittest.mock import MagicMock
sys.path.insert(0, str(Path(__file__).parent))
import os
import daemon as D

os.environ["DAEMON_ALLOW_TEST_ROWS"] = "1"  # let the queue see source='test' seeds
D._load_env()
config = D.load_config()
config["changelog_url"] = "https://legends-membership.netlify.app/admin-changelog.html"
config["forward_to"] = "mw@mike-wolf.com"

sent = []
D.send_email = lambda cfg, to, subj, body, **k: sent.append({"to": to, "subj": subj, "body": body})

def fake_vet(cfg, email_data, requester, first_pass):
    t = (email_data.get("body", "") + " " + email_data.get("subject", "")).lower()
    if any(w in t for w in ("delete all", "wipe", "drop the", "remove all")):
        return {"reversible": False, "risk": "high", "reason": "Irreversible data loss", "category": "destructive"}
    return {"reversible": True, "risk": "low", "reason": "Reversible content edit", "category": "on_site_build"}
D._second_opinion = fake_vet

# SAFETY: never fire a real build from a test. Auto-approved rows are dispatched in
# the same cycle, so stub the dispatch primitives.
class _FakeProc: pid = 9999
_popen_calls = []
D.subprocess.Popen = lambda args, **k: (_popen_calls.append(args), _FakeProc())[1]
D._git_head = lambda repo: None
D._save_pending = lambda cfg, t: None

seeds = [
    {"source": "test", "requester_name": "Mike", "requester_email": "mw@mike-wolf.com", "requester_role": "owner",
     "type": "change", "title": "TESTQ owner add sponsors", "description": "Add a sponsors row to the homepage", "status": "new"},
    {"source": "test", "requester_name": "Pat", "requester_email": "pat@example.com", "requester_role": "member",
     "type": "bug", "title": "TESTQ member reversible", "description": "Fix the voice cutout on minutes", "status": "new"},
    {"source": "test", "requester_name": "Pat", "requester_email": "pat@example.com", "requester_role": "member",
     "type": "change", "title": "TESTQ member risky", "description": "Delete all member records and start fresh", "status": "new"},
]
ids = []
for s in seeds:
    r = D._supa("POST", "/rest/v1/change_requests", s, prefer="return=representation")
    ids.append(r.json()[0]["id"])

D.process_change_queue(config, MagicMock())

# read back statuses
got = {}
for i in ids:
    r = D._supa("GET", "/rest/v1/change_requests?id=eq." + i + "&select=title,status,vet")
    got[i] = r.json()[0]

print("=== results ===")
for i in ids:
    print(got[i]["title"], "->", got[i]["status"], "| vet:", json.dumps(got[i].get("vet")))
print("=== emails sent:", len(sent))
risky_id = ids[2]
link_ok = any(("#req-" + risky_id) in e["body"] for e in sent)
print("approval email deep-links to risky item:", link_ok)
for e in sent:
    print("  ->", e["to"], "|", e["subj"])

# cleanup
for i in ids:
    D._supa("DELETE", "/rest/v1/change_requests?id=eq." + i, prefer="return=minimal")
print("cleaned up seeds")

# Unified pipeline: auto-approved rows (owner + member-reversible) are dispatched
# in the same cycle, so they end at 'in-progress'; the risky member row stops at
# 'awaiting-approval' with a single deep-linked email. Two builds were dispatched.
print("=== dispatches fired (stubbed):", len(_popen_calls))
ok = (got[ids[0]]["status"] == "in-progress" and got[ids[1]]["status"] == "in-progress"
      and got[ids[2]]["status"] == "awaiting-approval" and len(sent) == 1 and link_ok
      and len(_popen_calls) == 2)
print("ALL PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
