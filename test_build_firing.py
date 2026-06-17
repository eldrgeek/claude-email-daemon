#!/usr/bin/env python3
"""Verify build-firing: approved -> dispatch -> in-progress -> (completion) -> awaiting-review.
Patches Popen (no real build), _second_opinion, send_email, and the pending store."""
import sys, os
from pathlib import Path
from unittest.mock import MagicMock
sys.path.insert(0, str(Path(__file__).parent))
import daemon as D

D._load_env()
cfg = D.load_config()
cfg["forward_to"] = "mw@mike-wolf.com"
cfg["changelog_url"] = "https://legends-membership.netlify.app/admin-changelog.html"

sent = []
D.send_email = lambda c, to, subj, body, **k: sent.append({"to": to, "subj": subj})
D._second_opinion = lambda c, e, r, f: {"reversible": True, "risk": "low", "reason": "reversible", "category": "on_site_build"}
popen_calls = []
class FakeProc:  pid = 4242
def fake_popen(args, **k): popen_calls.append(args); return FakeProc()
D.subprocess.Popen = fake_popen
pend = []
D._save_pending = lambda c, t: pend.append(t)
D._load_pending = lambda c: pend

# seed an APPROVED owner request
row = {"source": "test", "requester_name": "Mike", "requester_email": "mw@mike-wolf.com",
       "requester_role": "owner", "type": "change", "title": "BFQ build firing test",
       "description": "Tweak the homepage tagline wording", "status": "approved"}
rid = D._supa("POST", "/rest/v1/change_requests", row, prefer="return=representation").json()[0]["id"]

D.process_change_queue(cfg, MagicMock())
s1 = D._supa("GET", "/rest/v1/change_requests?id=eq." + rid + "&select=status").json()[0]["status"]
dispatched = any("cc-dispatch" in str(a) and "--workdir" in a for a in popen_calls)
pend_ok = any(p.get("change_request_id") == rid for p in pend)
print("after dispatch:", s1, "| popen calls:", len(popen_calls), "| pending has crid:", pend_ok)

# simulate completion: drop an audit report matching the task_name
task = [p for p in pend if p.get("change_request_id") == rid][0]
audits = Path(os.path.expanduser("~/Projects/SOMA/audits")); audits.mkdir(parents=True, exist_ok=True)
af = audits / ("20990101T000000-" + task["task_name"] + ".md")
af.write_text("## report\nDone — tagline updated and pushed to master.")
D.check_pending_completions(cfg, MagicMock())
s2 = D._supa("GET", "/rest/v1/change_requests?id=eq." + rid + "&select=status").json()[0]["status"]
print("after completion:", s2, "| completion emails:", len(sent))

af.unlink(missing_ok=True)
D._supa("DELETE", "/rest/v1/change_requests?id=eq." + rid, prefer="return=minimal")

ok = (s1 == "in-progress" and dispatched and pend_ok and s2 == "awaiting-review" and len(sent) >= 1)
print("ALL PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
