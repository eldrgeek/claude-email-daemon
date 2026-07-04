#!/usr/bin/env python3
"""WQ-128 — regression test for the board self-reply misfire.

handle_board_email replies "Re: [BOARD] <title>" to the submitting sender.
When that sender is claude@mike-wolf.com (soma-feedback's self-send pattern,
SOMA-APP-STANDARD.md §8), the reply lands back in the same inbox this loop
just polled and used to fall through to the general LLM classifier — which
flagged it forward_urgent under the @mike-wolf.com policy override (observed
firing twice on 2026-07-04, flagged in WQ-123's receipts, not fixed there).

This asserts _is_board_self_reply() correctly distinguishes:
  1. A genuine self-generated confirmation reply (skip it — no LLM call).
  2. A real [BOARD] submission (not a reply — must NOT be treated as noise).
  3. A human's own "Re: [BOARD] ..." follow-up from a DIFFERENT sender
     (e.g. Mike replying to a card confirmation) — must NOT be swallowed,
     since it could carry real content.
  4. A doubled "Re: Re: [BOARD] ..." self-reply (thread chains) — still caught.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
import daemon as D

config = {"claude_email": {"address": "claude@mike-wolf.com"}}

cases = [
    (
        "self-send confirmation reply — must be skipped",
        {"subject": "Re: [BOARD] playmaker feedback: fix the thing",
         "from": "Claude <claude@mike-wolf.com>"},
        True,
    ),
    (
        "doubled Re: Re: chain from self — must still be skipped",
        {"subject": "Re: Re: [BOARD] playmaker feedback: fix the thing",
         "from": "claude@mike-wolf.com"},
        True,
    ),
    (
        "fresh [BOARD] submission (not a reply) — must NOT be skipped",
        {"subject": "[BOARD] playmaker feedback: fix the thing",
         "from": "claude@mike-wolf.com"},
        False,
    ),
    (
        "human reply to a board confirmation from mw@ — must NOT be skipped",
        {"subject": "Re: [BOARD] playmaker feedback: fix the thing",
         "from": "Mike Wolf <mw@mike-wolf.com>"},
        False,
    ),
    (
        "unrelated Re: subject — must NOT be skipped (doesn't match at all)",
        {"subject": "Re: dinner plans", "from": "claude@mike-wolf.com"},
        False,
    ),
]

failures = 0
for name, email_data, expected in cases:
    got = D._is_board_self_reply(email_data, config)
    status = "PASS" if got == expected else "FAIL"
    if got != expected:
        failures += 1
    print(f"[{status}] {name}: got={got} expected={expected}")

print(f"\n{len(cases) - failures}/{len(cases)} passed")
sys.exit(1 if failures else 0)
