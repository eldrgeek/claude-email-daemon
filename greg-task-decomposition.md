# Greg Foster requests — retroactive task decomposition

Each email from Greg (gfos44@gmail.com) was processed as **one** change request → one dispatch → one completion email. That bundled independent asks under a single status, so a "completed" email could quietly carry a sub-task that was actually blocked.

Below, each email is split by **shared fate** — a task is a unit of work that succeeds or blocks together. Cosmetic edits on the same page are one task; anything that depends on a *different missing input* is broken out, because that's the thing that can block while the rest ships.

Status key: ✅ done · ⛔ blocked (needs something) · ↪ blocked then resolved by a later email

---

## Email A — "Site changes and edits still needed" (Jun 17) — review pass

| Task | Status | Note |
|------|--------|------|
| **A1 · Verify prior items** (9 confirmations: contact directory, nav text, assessment embed, Scholarship America content, Membership Offerings page + bug, Workforce-delegation removal, Choo Smith / Hollins / Tinsley removals) | ✅ | All confirmed in code, one review |
| **A2 · NBRPA Transition Blueprint PDF** on Legends Life | ⛔→↪ | Needs the PDF (cl-027). Resolved in Email D |
| **A3 · Scholarship America PDF deck** on Membership Offerings | ⛔→↪ | Needs the PDF (cl-026). Resolved in Email C |

A2 and A3 are separate tasks only because they wait on *different files*.

---

## Email B — "Additions to … Transition Legends Life Page" (Jun 17)

| Task | Status | Note |
|------|--------|------|
| **B1 · Add "blueprint" to transition-services.html** | ⛔→↪ | Email referenced a blueprint with no attachment/content/URL. Resolved in Emails C & D |

---

## Email C — "Re-sending edits and additions…" (Jun 18) — 10 listed items

| Task | Status | Note |
|------|--------|------|
| **C1 · Page edits batch** (assessment nav-padding, Membership Offerings 6 cards + PDFs, Purvis Legends Life framework, Purvis contact on committee card, Chapter-Presidents board-reporting goal, Membership goals 7–8, Scholarships available-scholarships section, Bill knowledge-base update) | ✅ | All shipped together, commit 1929b69e (cl-029–034) |
| **C2 · Ask Bill widget broken** | ⛔ | No code defect found (cl-035). Needs a browser console error to diagnose |

The 8 edits in C1 share a fate — one build, one commit, one deploy. Splitting them further would be noise. Ask Bill is isolated because it can't ship without input Greg has to capture.

---

## Email D — "Edits and additions to member service committee website" (Jun 20) — latest

| Task | Status | Note |
|------|--------|------|
| **D1 · Page edits batch** (Chapter-President comms goals 6→8, Scholarships eligibility section, Legends Life goals overhaul + 4-phase roadmap, Purvis Short strategy PDF, changelog cl-036) | ✅ | One commit f13e1d6e |
| **D2 · Ask Bill not working** | ⛔ | Recurring (= C2). Needs browser console error |
| **D3 · Committee contact directory update** | ⛔ | The referenced contact email/attachment wasn't included |
| **D4 · Scholarship America slideshow** | ⛔ | Slideshow "emailed previously" but not attached |

---

## Still open (the stragglers)

1. **Ask Bill widget** (C2 / D2) — needs a client-side console error from a page with the widget. Two investigations found nothing server- or static-side. Candidates: VPS `/infer/ask` down, CORS preflight fail, ElevenLabs outage, runtime error in `soma-guide.js`.
2. **Committee contact directory** (D3) — needs Greg to resend the contact info.
3. **Scholarship America slideshow** (D4) — needs Greg to resend the file.

All three blockers are the same shape: **the request is clear, the needed material isn't present.** That's the case the daemon should turn into a targeted "reply with X" email instead of a buried line in a completion report.
