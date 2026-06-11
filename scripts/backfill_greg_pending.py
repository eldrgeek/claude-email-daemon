#!/usr/bin/env python3
"""
Backfill greg-pending.json from existing dispatch logs.

Run this ONCE after deploying the completion-notification fix to register
previously-dispatched tasks so the next daemon cycle sends completion emails.

Usage:
    python3 scripts/backfill_greg_pending.py [--dry-run]

The daemon must NOT be running when you write greg-pending.json.
After running, restart the daemon — the next cycle will send completion emails.
"""

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
import daemon as d


def main():
    parser = argparse.ArgumentParser(description="Backfill greg-pending.json from dispatch logs")
    parser.add_argument("--dry-run", action="store_true", help="Print what would be written, don't write")
    args = parser.parse_args()

    config = d.load_config()
    log_dir = Path(os.path.expanduser(config["log_dir"]))

    # Load existing pending so we don't duplicate
    existing_pending = d._load_greg_pending(config)
    already_known = {t["task_name"] for t in existing_pending}

    # Find all greg-dispatched logs
    dispatch_logs = sorted(log_dir.glob("greg-dispatched-*.json"))
    print(f"Found {len(dispatch_logs)} dispatch logs")

    new_tasks = []
    for log_path in dispatch_logs:
        with open(log_path) as f:
            data = json.load(f)

        task_name = data.get("task_name", "")
        if not task_name or task_name in already_known:
            continue

        # Skip if already notified (check if any existing pending has it)
        task_entry = {
            "task_name": task_name,
            "greg_from": data.get("from", ""),
            "greg_email": data.get("sender_email", ""),
            "subject": data.get("subject", ""),
            "message_id": "",  # not in dispatch log
            "references": "",
            "dispatched_at": data.get("timestamp", ""),
            "notified": False,
        }
        new_tasks.append(task_entry)
        print(f"  + {task_name} (dispatched {data.get('timestamp', '?')[:19]})")

    if not new_tasks:
        print("Nothing to backfill — all dispatched tasks already in pending state.")
        return

    print(f"\n{len(new_tasks)} task(s) to backfill")
    if args.dry_run:
        print("(dry run — not writing)")
        return

    all_tasks = existing_pending + new_tasks
    d._save_greg_pending_list(config, all_tasks)
    print(f"Written {len(all_tasks)} total tasks to {d._greg_pending_path(config)}")
    print("\nNext daemon cycle will send completion emails for any tasks with existing reports.")
    print("Restart the daemon now: launchctl kickstart -k gui/$(id -u)/com.mikewolf.claude-email-daemon")


if __name__ == "__main__":
    main()
