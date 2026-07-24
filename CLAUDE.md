---
district: soma-core
status: active
depends_on: [SOMA, soma-platform]
capabilities: [email, cc-dispatch, ollama]
last_reviewed: 2026-06-23
---

# claude-email-daemon — email-as-universal-channel: polls inboxes/drafts, classifies via local LLM, dispatches work

**Where work happens:** `daemon.py` (the whole pipeline: IMAP/SMTP poll → classify → decompose → dispatch). Run `python3 daemon.py --loop`. Config in `config.yaml`; tests are `test_*.py`.

**Key docs** (read in this order):
- [SPEC-decomposition-and-missing-material.md](SPEC-decomposition-and-missing-material.md) — per-task decomposition (shared-fate rule) + ask-back-for-missing-material; the current build spec.
- `greg-task-decomposition.md` — worked example of the decomposition pipeline.

**Skills**
- gap: a "email-daemon-operate" skill (start/stop loop, replay a logfile through a different model, read the JSONL decision log) is the obvious local skill.

**Depends on / used by:** Intake/orchestration layer for **SOMA**; dispatches build work to targets like `legends-membership-site` (in soma-platform) via the local `claude` CLI (same binary cc-dispatch uses). First-pass classify uses local Ollama (qwen2.5:7b); second opinion uses the `claude` CLI.

**Gotchas**
- App passwords are NOT in the repo — `config.yaml` reads them from a memory file (or `CLAUDE_EMAIL_PW`/`MIKE_EMAIL_PW` env). The hardcoded path `~/Projects/memory/context/email.md` is RETIRED; creds now live at `~/Projects/second-brain/Resources/email-config.md` (update `get_password()` if it breaks).
- Decomposition reuses the `claude` CLI second-opinion path, not the 7B local model (too weak); if the CLI is unreachable, the conservative first-pass call stands.
- `*.bak-*` files and `__pycache__/` are cruft, not reference material.
