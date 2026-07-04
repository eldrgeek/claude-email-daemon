#!/usr/bin/env python3
"""Tests for the provider data-export ingestion path (email→zip).

Covers: URL extraction (real OpenAI email shape: angle-bracket-wrapped link
with &amp; entities), redirector unwrapping, the hard URL allowlist, provider
matching (direct + manual-forward fallback), and the full handler against a
local HTTP server via the EXPORT_INGEST_EXTRA_ALLOWED_HOSTS test seam:
zip success, non-zip rejection, off-allowlist redirect rejection, size cap.

No network beyond 127.0.0.1; send_email is stubbed. Safe to run anytime:
    python3 test_provider_exports.py
"""
import io
import json
import os
import sys
import tempfile
import threading
import zipfile
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).parent))
import daemon as D

PASS, FAIL = 0, 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  PASS {name}")
    else:
        FAIL += 1
        print(f"  FAIL {name} {detail}")


# ---------------------------------------------------------------------------
print("== URL extraction ==")
# Real shape from an archived OpenAI export email: angle-bracket wrapped,
# newline inside the URL, &amp; entities in the SAS query string.
OPENAI_BODY = """\
 Your data export is now ready. Please click on the link below to download
your data.

            Download data export
<https://proddatamgmtqueue.blob.core.windows.net/exportcontainer/7fc6cae1-2024-10-26.zip?se=2024-10-27T21%3A46%3A08Z&amp;sp=r&amp;sv=2024-08-04&amp;sr=b&amp;sig=abc%2Bdef%3D>
          If you have any questions please contact us through our help
center <https://help.openai.com/en/>.
"""
urls = D._extract_candidate_urls({"body_full": OPENAI_BODY})
target = [u for u in urls if "proddatamgmtqueue" in u]
check("finds azure link", len(target) == 1)
check("entities unescaped", target and "&sp=r&" in target[0] and "&amp;" not in target[0])
check("no whitespace in url", target and " " not in target[0] and "\n" not in target[0])
check("help link also found", any("help.openai.com" in u for u in urls))

html_body = '<a href="https://claude.ai/api/export/dl?sig=x&amp;y=1">Download</a>'
urls_h = D._extract_candidate_urls({"body_html": html_body})
check("html href extracted", any(u == "https://claude.ai/api/export/dl?sig=x&y=1" for u in urls_h))

wrapped = "https://www.google.com/url?q=https%3A%2F%2Ftakeout.google.com%2Fmanage%2Ftakeout%2Fdownloads%2F123&sa=D"
check("redirector unwrapped",
      D._unwrap_redirector(wrapped) == "https://takeout.google.com/manage/takeout/downloads/123")

# ---------------------------------------------------------------------------
print("== allowlist ==")
AZ = ("proddatamgmtqueue.blob.core.windows.net",)
check("azure exact host ok", D._export_host_allowed("https://proddatamgmtqueue.blob.core.windows.net/x.zip?sig=1", AZ))
check("http rejected", not D._export_host_allowed("http://proddatamgmtqueue.blob.core.windows.net/x.zip", AZ))
check("evil host rejected", not D._export_host_allowed("https://evil.com/x.zip", AZ))
check("prefix-spoof rejected", not D._export_host_allowed(
    "https://proddatamgmtqueue.blob.core.windows.net.evil.com/x.zip", AZ))
CL = ("claude.ai", "claude.com", "anthropic.com")
check("claude.ai ok", D._export_host_allowed("https://claude.ai/api/dl", CL))
check("subdomain ok", D._export_host_allowed("https://api.claude.ai/dl", CL))
check("notclaude.ai rejected", not D._export_host_allowed("https://notclaude.ai/dl", CL))
check("userinfo-spoof rejected", not D._export_host_allowed("https://claude.ai@evil.com/dl", CL))

# ---------------------------------------------------------------------------
print("== provider matching ==")
cfg = D.load_config()
# Keep test artifacts out of the live logs/ dir (the handler writes a JSON
# result file per event into config log_dir).
cfg["log_dir"] = tempfile.mkdtemp(prefix="export-ingest-test-logs-")

em_openai = {"from": "OpenAI <noreply@tm.openai.com>",
             "subject": "ChatGPT - Your data export is ready", "body_full": OPENAI_BODY}
check("openai matched", D._match_provider_export(em_openai, cfg) == "chatgpt")

em_claude = {"from": "Anthropic <noreply@anthropic.com>",
             "subject": "Your data is ready for download", "body_full": ""}
check("anthropic matched", D._match_provider_export(em_claude, cfg) == "claude")

em_google = {"from": "Google Takeout <noreply@google.com>",
             "subject": "Your Google data is ready to download", "body_full": ""}
check("google matched", D._match_provider_export(em_google, cfg) == "gemini")

# Manual forward: From becomes Mike, subject keeps provider phrasing, link intact.
em_fwd = {"from": "Mike Wolf <mw@mike-wolf.com>",
          "subject": "Fwd: Your data is ready for download",
          "body_full": "---------- Forwarded message ---------\n"
                       "<https://claude.ai/api/organizations/abc/export/download?sig=x>"}
check("manual forward matched", D._match_provider_export(em_fwd, cfg) == "claude")

em_fwd_bad = {"from": "Mike Wolf <mw@mike-wolf.com>",
              "subject": "Fwd: Your data is ready for download",
              "body_full": "<https://evil.com/fake.zip>"}
check("forward w/o allowlisted link NOT matched", D._match_provider_export(em_fwd_bad, cfg) is None)

em_spoof = {"from": "Attacker <noreply@google.com.evil.net>",
            "subject": "Your Google data is ready to download", "body_full": ""}
check("spoofed sender domain NOT matched", D._match_provider_export(em_spoof, cfg) is None)

em_random = {"from": "Greg <gfos44@gmail.com>", "subject": "add a new member", "body_full": ""}
check("normal email NOT matched", D._match_provider_export(em_random, cfg) is None)

# ---------------------------------------------------------------------------
print("== download path (local server via test seam) ==")

ZIP_BYTES = io.BytesIO()
with zipfile.ZipFile(ZIP_BYTES, "w") as z:
    z.writestr("conversations.json", json.dumps([{"uuid": "t", "name": "test"}]))
ZIP_BYTES = ZIP_BYTES.getvalue()


class Srv(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path == "/ok.zip":
            self.send_response(200)
            self.send_header("Content-Type", "application/zip")
            self.end_headers()
            self.wfile.write(ZIP_BYTES)
        elif self.path == "/loginpage":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"<html>please sign in</html>")
        elif self.path == "/evil-redirect":
            self.send_response(302)
            self.send_header("Location", "https://evil.com/x.zip")
            self.end_headers()
        elif self.path == "/big.zip":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"PK\x03\x04" + b"0" * (2 * 1024 * 1024))
        else:
            self.send_response(404)
            self.end_headers()


httpd = HTTPServer(("127.0.0.1", 0), Srv)
port = httpd.server_address[1]
threading.Thread(target=httpd.serve_forever, daemon=True).start()
os.environ["EXPORT_INGEST_EXTRA_ALLOWED_HOSTS"] = "127.0.0.1"
base = f"http://127.0.0.1:{port}"

tmp = tempfile.mkdtemp(prefix="export-ingest-test-")
dest = os.path.join(tmp, "out.zip")

size, err = D._stream_export_download(f"{base}/ok.zip", dest, ("127.0.0.1",), 10 * 1024 * 1024)
check("zip downloads", size == len(ZIP_BYTES) and err is None, f"err={err}")
check("zip valid on disk", os.path.exists(dest) and zipfile.is_zipfile(dest))
check("no .part left", not os.path.exists(dest + ".part"))

size, err = D._stream_export_download(f"{base}/loginpage", dest + "2", ("127.0.0.1",), 10 * 1024 * 1024)
check("non-zip rejected", size is None and "not a zip" in (err or ""), f"err={err}")

size, err = D._stream_export_download(f"{base}/evil-redirect", dest + "3", ("127.0.0.1",), 10 * 1024 * 1024)
check("off-allowlist redirect rejected", size is None and "non-allowlisted" in (err or ""), f"err={err}")

size, err = D._stream_export_download(f"{base}/big.zip", dest + "4", ("127.0.0.1",), 1024 * 1024)
check("size cap enforced", size is None and "size cap" in (err or ""), f"err={err}")
check("capped .part cleaned up", not os.path.exists(dest + "4.part"))

# ---------------------------------------------------------------------------
print("== full handler ==")
sent = []
orig_send = D.send_email
D.send_email = lambda c, to, subj, body, **k: sent.append({"to": to, "subj": subj, "body": body})

# Point the claude provider at the local server + tmp dest for the test.
orig_provider = dict(D.PROVIDER_EXPORTS["claude"])
D.PROVIDER_EXPORTS["claude"] = {**orig_provider,
                                "allowed_hosts": ("127.0.0.1",),
                                "dest_dir": tmp}
try:
    em = {"from": "Anthropic <noreply@anthropic.com>",
          "subject": "Your data is ready for download",
          "body_full": f"Download your data: <{base}/ok.zip>"}
    r = D.handle_provider_export_email(em, cfg, MagicMock())
    check("handler downloaded", r and r.get("result") == "downloaded", f"r={r}")
    check("zip in dest dir", r and os.path.exists(r.get("zip_path", "")))
    check("confirm email to Mike", sent and sent[-1]["to"] == cfg["forward_to"]
          and "downloaded" in sent[-1]["subj"])

    sent.clear()
    em_bad = {"from": "Anthropic <noreply@anthropic.com>",
              "subject": "Your data is ready for download",
              "body_full": "Download your data: <https://evil.com/x.zip>"}
    r = D.handle_provider_export_email(em_bad, cfg, MagicMock())
    check("off-allowlist link hard-fails", r and r.get("result") == "no_allowlisted_link", f"r={r}")
    check("failure notified", sent and "no allowlisted" in sent[-1]["subj"])

    r = D.handle_provider_export_email(em_random, cfg, MagicMock())
    check("non-export email returns None", r is None)
finally:
    D.PROVIDER_EXPORTS["claude"] = orig_provider
    D.send_email = orig_send
    del os.environ["EXPORT_INGEST_EXTRA_ALLOWED_HOSTS"]
    httpd.shutdown()

# ---------------------------------------------------------------------------
# 2026-07-04 fix: reconstruct the 07-03 14:09 failure mode (WQ export-ingest
# root cause) and prove the new needs_click_download / overnight-window /
# Yeshie-driven path. No real Anthropic email or Chrome needed — the auth
# wall is a local HTML page, and the Yeshie relay is mocked with a fake zip
# drop instead of a live extension.
print("== 2026-07-04 fix: click-required download + overnight gating ==")


class AuthWallSrv(BaseHTTPRequestHandler):
    """Serves an HTML page for the export link — reproduces the exact 07-03
    failure: direct GET gets HTML (not a zip), same as an auth wall/app shell."""
    def log_message(self, *a):
        pass

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body>claude.ai app shell (not a zip)</body></html>")


wall = HTTPServer(("127.0.0.1", 0), AuthWallSrv)
wall_port = wall.server_address[1]
threading.Thread(target=wall.serve_forever, daemon=True).start()
os.environ["EXPORT_INGEST_EXTRA_ALLOWED_HOSTS"] = "127.0.0.1"
wall_base = f"http://127.0.0.1:{wall_port}"

tmp2 = tempfile.mkdtemp(prefix="export-ingest-test2-")
downloads_dir = os.path.join(tmp2, "Downloads")
export_dir = os.path.join(tmp2, "chat-exports")
os.makedirs(downloads_dir, exist_ok=True)
os.makedirs(export_dir, exist_ok=True)

sent2 = []
D.send_email = lambda c, to, subj, body, **k: sent2.append({"to": to, "subj": subj, "body": body})

cfg2 = dict(cfg)
cfg2["log_dir"] = tempfile.mkdtemp(prefix="export-ingest-test2-logs-")
cfg2["state_file"] = os.path.join(tmp2, "state", "processed.json")
cfg2["provider_exports"] = dict(cfg.get("provider_exports", {}))
cfg2["provider_exports"]["overnight_window_start_hour"] = 3
cfg2["provider_exports"]["overnight_window_end_hour"] = 4

orig_provider2 = dict(D.PROVIDER_EXPORTS["claude"])
D.PROVIDER_EXPORTS["claude"] = {**orig_provider2,
                                 "allowed_hosts": ("127.0.0.1",),
                                 "dest_dir": export_dir,
                                 "needs_click_download": True}
orig_downloads_dir = D.EXPORT_DOWNLOADS_DIR

try:
    D.EXPORT_DOWNLOADS_DIR = downloads_dir

    em_claude_live = {"from": "Anthropic <noreply@anthropic.com>",
                      "subject": "Your data is ready for download",
                      "body_full": f"Download your data: <{wall_base}/export-link>"}

    # --- Daytime arrival: direct fails (auth-wall HTML), should QUEUE, not
    #     attempt Chrome/Yeshie against Mike's daytime browser. ---
    os.environ.pop("EXPORT_INGEST_FORCE_WINDOW", None)
    check("daytime: not in window by default",
          not D._in_overnight_window(cfg2["provider_exports"]))
    r = D.handle_provider_export_email(em_claude_live, cfg2, MagicMock())
    check("daytime: queued not failed", r and r.get("result") == "queued_for_overnight", f"r={r}")
    pending = D._load_pending_exports(cfg2)
    check("daytime: one item queued", len(pending) == 1, f"pending={pending}")
    check("daytime: queued url is the real link", pending and pending[0]["url"] == f"{wall_base}/export-link")
    check("daytime: notified Mike about queueing",
          sent2 and "queued" in sent2[-1]["subj"].lower())

    # --- Same email again outside the window shouldn't touch Chrome; confirm
    #     run_pending_exports() is a no-op outside the window (doesn't drop
    #     the queue, doesn't call Yeshie). ---
    sent2.clear()
    D.run_pending_exports(cfg2, MagicMock(), dry_run=False)
    check("pending retry no-op outside window", D._load_pending_exports(cfg2) == pending)

    # --- Force the overnight window (test seam) and mock the Yeshie relay
    #     call to simulate: relay reachable, chain runs, and the click
    #     "lands" a zip in ~/Downloads (what a real click-through would do). ---
    os.environ["EXPORT_INGEST_FORCE_WINDOW"] = "1"
    check("forced: in window", D._in_overnight_window(cfg2["provider_exports"]))

    def fake_yeshie_download(url, config, pe_cfg, dest_dir, prefix):
        # Simulate the Yeshie chain having clicked "Download" and the browser
        # finishing the file — write the zip directly to dest_dir, as
        # _yeshie_download_export would locate it in ~/Downloads and the
        # caller then shutil.move()s it. Returning a path in dest_dir here
        # (not Downloads) still proves the caller's move+size+notify logic.
        p = os.path.join(dest_dir, "simulated-yeshie-download.zip")
        with open(p, "wb") as f:
            f.write(ZIP_BYTES)
        return p, None

    orig_yeshie_fn = D._yeshie_download_export
    D._yeshie_download_export = fake_yeshie_download
    try:
        r2 = D.handle_provider_export_email(em_claude_live, cfg2, MagicMock())
        check("overnight: downloaded via yeshie", r2 and r2.get("result") == "downloaded", f"r2={r2}")
        check("overnight: zip landed in dest_dir", r2 and os.path.exists(r2.get("zip_path", "")))
        check("overnight: notified Mike of success",
              sent2 and "downloaded" in sent2[-1]["subj"].lower())

        # --- run_pending_exports(): drain the earlier-queued daytime entry
        #     now that we're "overnight". ---
        sent2.clear()
        D.run_pending_exports(cfg2, MagicMock(), dry_run=False)
        check("pending queue drained in window", D._load_pending_exports(cfg2) == [])
        check("pending retry notified Mike",
              sent2 and "downloaded" in sent2[-1]["subj"].lower() and "overnight" in sent2[-1]["subj"].lower())
    finally:
        D._yeshie_download_export = orig_yeshie_fn

    # --- Yeshie itself fails (relay unreachable / no zip): daytime-queued
    #     entry should retry up to 3x then drop, not grow forever. ---
    D._queue_export_for_overnight(cfg2, "claude", f"{wall_base}/export-link", D.PROVIDER_EXPORTS["claude"], "test")
    check("re-queued for drop test", len(D._load_pending_exports(cfg2)) == 1)

    def failing_yeshie_download(url, config, pe_cfg, dest_dir, prefix):
        return None, "simulated: relay unreachable"

    D._yeshie_download_export = failing_yeshie_download
    try:
        for i in range(3):
            D.run_pending_exports(cfg2, MagicMock(), dry_run=False)
        check("gives up after 3 failed overnight attempts", D._load_pending_exports(cfg2) == [],
              f"pending={D._load_pending_exports(cfg2)}")
    finally:
        D._yeshie_download_export = orig_yeshie_fn
finally:
    D.PROVIDER_EXPORTS["claude"] = orig_provider2
    D.EXPORT_DOWNLOADS_DIR = orig_downloads_dir
    D.send_email = orig_send
    os.environ.pop("EXPORT_INGEST_FORCE_WINDOW", None)
    os.environ.pop("EXPORT_INGEST_EXTRA_ALLOWED_HOSTS", None)
    wall.shutdown()

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
