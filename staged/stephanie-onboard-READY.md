# Stephanie Rincon — email-conversation onboarding (STAGED, awaiting her address)

Mike's grant, in-session 2026-08-13: "Dee, send Stephanie a message from you. And
wire up the Claude email watcher so that it can respond to messages back from her.
And give her an understanding of what you're capable of doing so she can have a
conversation with you as needed."

**Blocked on exactly one fact: her email address** — it is nowhere on file
(stephanie-hours-dashboard/README.md says so explicitly; contacts, vault, SOMA
Auth users, and Fathom recaps all came up empty; her Trello profile doesn't
expose it). Mike supplies it; everything below then executes in one pass.

## 1. config.yaml — trusted_requesters entry (insert with her real address)

```yaml
  STEPHANIE_EMAIL_HERE:
    name: "Stephanie Rincon"
    tier: "member_services"
    auto_dispatch: true
    cc_dispatch_to:
      - "mw@mike-wolf.com"
    cost_threshold_usd: 100
    completion_timeout_hours: 4
    escalate_to: "mw@mike-wolf.com"
    ack_greeting: "Hi Stephanie,"
    ack_signature: "Dee\n(Claude — Mike's AI chief of staff)"
    site_label: "the PlayMaker/ESR back office"
    site_description: "Stephanie leads web design for PlayMaker and runs ops (hours ledger, Stripe/bank wiring, Trello). Dee coordinates Mike's AI fleet: builds and fixes web things, digs up records, drafts documents, and routes anything Mike-gated onto his board."
    repo: "~/Projects/stephanie-hours-dashboard"
```

Then: `launchctl kickstart -k gui/501/$(launchctl list | grep -o 'com[.a-z]*claude-email[.a-z]*' | head -1)` and verify the reload in logs.

## 2. Also fix while we're there (her stalled 07-29 request)
- Add her email to `stephanie-hours-dashboard/config.js` `allowedEmails` + redeploy
  → answers her Trello #8 comment "let me know how to get access to this please".
- Add her to `~/.local/share/contact-lookup/CONTACTS.md`.

## 3. The intro email (send from claude@ via SOMA/tools/mail/send_from_claude.py)

Subject: Hi from Dee — Mike's AI chief of staff (and one quick Stripe question)

Body: see stephanie-intro-email.txt in this directory (final text, ready to send).

## 4. After send
- pulse-answer-write stripe-stephanie-status --note (delegated to Dee, sent, awaiting her reply)
- ESTATE.md changelog line (first external human in direct email conversation with Dee)
- Register her in the consent/comms sense: she's on the daemon allowlist for
  conversation, NOT on the [DISPATCH:*] allowlist — conversation ≠ code execution.
