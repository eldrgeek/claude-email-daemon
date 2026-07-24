# Spec — per-task decomposition + missing-material ask-back

**Where this lives:** `claude-email-daemon/daemon.py`, trusted-requester pipeline. This is intake/orchestration, so it's SOMA-owned — Legends (`legends-membership-site`) is only the build target. Generalizes to Eric and any future requester for free.

**Two changes:**
1. Decompose an inbound email into independently-fated tasks; dispatch the ready ones, isolate the blocked ones.
2. When a task is blocked because needed material is absent, send Greg a targeted "reply with X" email — and if he says he already sent it, investigate why it didn't land the first time.

---

## 1. Decomposition

### The grouping rule (the important part)

A **task = a unit of work that shares a fate.** Split only when:
- **outcomes can diverge** — one part can ship while another blocks, or
- **inputs differ** — one part needs material that another doesn't.

Do **not** split for atomicity's sake. Three cosmetic fixes on one page are one task. Eight content edits across pages that all ship in one commit are one task. The June 18 email was 10 listed items but 2 tasks (the edits batch + Ask Bill), because only Ask Bill had a separate fate.

Litmus: *"If item B turns out blocked, does it make sense for item A to ship anyway?"* Yes → separate tasks. No → same task.

### Mechanism

After `classify_trusted_email` returns a category, run one **decomposition pass** (reuse the second-opinion model — `_second_opinion`'s `claude` CLI path — since it already reasons over the full email + attachments; the local Ollama 7B is too weak for this). It returns:

```json
{
  "tasks": [
    {
      "title": "Page edits batch",
      "targets": ["assessment.html", "membership-offerings.html", "..."],
      "kind": "build",                // build | verify | diagnose
      "needs": [],                    // required inputs not present in the email
      "ready": true
    },
    {
      "title": "Ask Bill widget not responding",
      "targets": ["js/soma-guide.js"],
      "kind": "diagnose",
      "needs": ["browser console error from a page showing the widget"],
      "ready": false
    }
  ]
}
```

The prompt must carry the **shared-fate rule above** and the attachment manifest (filenames + whether text extracted), so it can tell "needs a file that isn't here" from "the file is attached."

### Routing each task

In `handle_trusted_email`, loop the tasks:
- `ready && kind in {build}` → existing dispatch path. **One `change_request_id` + one `greg-pending.json` entry per task** (the list + `_save_pending` append already support this). Each tracks and completes independently via `check_pending_completions`.
- `kind == verify` → confirm in code, no dispatch; fold into the reply.
- `!ready` → collect for the missing-material email (§2). Do **not** dispatch, do **not** silently defer.

### Replies, not spam

One inbound email → **one threaded reply**, itemized by task with per-task status — not N separate emails. This is the anti-didactic constraint applied to output too: Greg gets a single clear "here's where each thing landed," with blocked items called out, not a completion email that hides a blocker in paragraph nine.

---

## 2. Missing-material ask-back

New sibling to the existing `_request_clarification`. Different trigger: clarification = *intent unclear*; this = *intent clear, material absent*.

### The email (per Mike's spec)

One consolidated, threaded "need from you" email when ≥1 task is blocked on input. CC Mike (`cc_dispatch_to`). For each blocked item:

> **[task / page]** — I need **[X]** to finish this. Reply to this email with it attached.
>
> If you attached it before, just say so — tell me you're re-attaching it and I'll find out what went wrong the first time.

Concrete example for the two current *file* stragglers:

> Hi Greg,
>
> I've shipped the page edits — those are live. Two things I need from you before I can finish the rest:
>
> 1. **Committee contact directory** — reply with the contact list attached (or pasted inline). If you sent it before, say "re-attaching" and I'll trace why the first one didn't reach me.
> 2. **Scholarship America slideshow** — reply with the slideshow file attached. Same deal if you've sent it previously.
>
> —Claude (AI assistant for the Legends website)

**Ask Bill is NOT in this email.** Asking an untechnical committee member to open DevTools and paste a console error is a non-starter — see §3. Diagnostic input gets gathered by infrastructure, not by the user. The ask-back flow is only for material a human genuinely has to send (files, text).

### The re-attach investigation hook

When Greg replies in-thread (picked up next poll, already threaded), and the body matches a re-attach intent (`re-attach`, `attached it before`, `sent (it|this) (already|before|previously)`, `here it is again`), set `investigate_prior_attachment = true` and run `_investigate_attachment(original_msg, current_msg)`:

1. Re-walk the **original** message's MIME parts. Determine which actually happened:
   - **No attachment part existed** → Greg believed he attached but didn't (most common). Tell him gently, no bug.
   - **Attachment present but `extract_attachments` saved 0 bytes / `_extract_attachment_text` returned empty** → real extraction bug (scanned PDF, odd `.docx`, unusual encoding). Log the content-type + filename for the fix.
   - **It was a link, not a file** (Google Drive/Dropbox URL in body) → the daemon doesn't fetch links; flag for a decision on whether it should.
   - **Inline image / disposition=inline with no filename** → skipped by design (`extract_attachments` line 606); flag if it was actually the payload.
2. Write a finding to `logs/attachment-investigation-{iso}.json` and surface it to Mike (the CC, or a dedicated note). This closes the loop the audits kept hitting: "referenced but not readable."

The current reply's attachment is processed normally either way, so Greg's resend unblocks the task regardless of what the investigation finds.

---

---

## 3. Client telemetry channel (replaces "ask the user for a console error")

Untechnical users can't be relied on to open a console. SOMA apps should **self-instrument**: errors flow back to the dev team automatically over a feedback channel, so a `diagnose` task is answered by querying telemetry, not by emailing a human.

### Transport
A small `soma-telemetry.js`, loaded **first and synchronously in `<head>`** (before `soma-guide.js` or any component, or it misses early errors). It opens a WebSocket to the VPS relay (`wss://vpsmikewolf.duckdns.org`, the existing pm2 WS relay) and **buffers events until connected, then flushes** (capped buffer — never grow unbounded). Each event carries: timestamp, page URL, session/request id, source (script origin), level, message, stack.

### Two capture paths
- **Our own components** call a structured `soma.report(level, event, data)` directly. Richer and intentional — preferred over scraping log strings.
- **Components we don't own** (e.g. the CDN-loaded `soma-guide.js` Ask Bill widget) are covered by a **catch-all installed before they load.** `console.*` teeing alone is insufficient — it only catches what the component chooses to log. Install all four:
  1. `console.log/info/warn/error` → tee to channel **and call through to the original** (so anyone watching the real console still sees it).
  2. `window.addEventListener('error', …, true)` — uncaught exceptions + resource-load failures (capture phase).
  3. `window.addEventListener('unhandledrejection', …)` — swallowed promise rejections (how most `fetch` failures die).
  4. `window.fetch` / `XMLHttpRequest` wrapper — report any non-2xx or thrown request. Highest-value path for Ask Bill.

### The CORS-preflight blind spot → server correlation
A rejected CORS **preflight** is invisible even to the fetch wrapper: the browser returns an opaque "Failed to fetch" with no reason. Diagnose it by **correlation**, not client logs alone:
- client emits "attempting request id X to /infer/ask"
- the VPS `/infer/ask` endpoint logs every request id it receives
- **no server record of X** → died in preflight / CORS / network before arrival
- **server record + error** → server-side

This correlation is the actual diagnostic engine; the WebSocket is just transport. (For Ask Bill, the leading suspects — CORS preflight to the VPS, endpoint down — are exactly the cases this distinguishes.)

### Non-negotiable constraints
- **Fail-open & bulletproof.** Every proxy wrapped in try/catch, always calls through, never throws, never blocks render. If the WS is down, print locally and move on. Telemetry must never be able to crash the host page.
- **Don't tee everything.** This site has a member directory, contact info, and auth. Default to errors/warnings + network failures + explicit `soma.report()`; gate/scrub `info` logs; redact known PII fields; batch and rate-limit. Feature-flagged; scoped tightly on authed member sessions.
- **Tag by source** so telemetry is filterable to "errors from soma-guide.js" — that's what makes the don't-own-it case actionable.

### Daemon tie-in
A `diagnose`-kind task (e.g. Ask Bill) does **not** generate a missing-material email. Instead the daemon queries the VPS telemetry store for recent matching errors and feeds them into the diagnosis automatically. Human ask-back (§2) is reserved for material only a human can supply.

---

## Build order

1. Decomposition pass + the loop in `handle_trusted_email` (behind a flag; dry-run against `test_greg_pipeline.py`).
2. Threaded itemized reply.
3. `_request_missing_material` + the consolidated email.
4. Re-attach detection + `_investigate_attachment`.

Steps 1–2 deliver most of the value (blockers stop hiding). 3–4 are the ask-back loop. Each is independently testable against the existing Greg fixtures.

**§3 (telemetry) is a parallel workstream, not daemon code** — it ships in `legends-membership-site` (the `soma-telemetry.js` client) and on the VPS (relay consumer + request-id logging on `/infer/ask`). The daemon's `diagnose` path depends on it but doesn't block on it: until telemetry exists, `diagnose` tasks just route to Mike with the candidate-cause list. It's the cleaner long-term answer to the recurring Ask Bill dead-end.

## Decisions (locked)

- **Sequence:** daemon decomposition (§1–2) first — it's the original requirement, self-contained, testable against `test_greg_pipeline.py`, zero production blast radius. Telemetry (§3) second.
- **PII scope:** telemetry defaults to **anonymous / pre-login pages only.** The shim is built with a flag so authed-member capture (with scrubbing) can be enabled later after review. Never ship authed-session telemetry on the member site without an explicit policy pass.
- **Production safety:** decomposition ships behind a config flag (`decompose_tasks`, default off). Enable only after the test suite passes and a diff review.

## Not touched

- The 5/hr `dispatch.rate_limit_per_hour` cap is on the `[DISPATCH:Mac|VPS]` remote-exec channel only (`handle_dispatch_email`, line 289). It never touched Greg's pipeline. Leave it; it's unrelated blast-radius insurance on remote shell execution.
