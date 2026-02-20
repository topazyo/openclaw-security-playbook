#!/usr/bin/env python3
"""
verify_hash_chain.py — Validate openclaw-telemetry hash chain integrity

Usage:
    python3 verify_hash_chain.py --input ~/.openclaw/logs/telemetry.jsonl
    python3 verify_hash_chain.py --input telemetry.jsonl --output report.json

Exits with code 0 if chain is intact, code 1 if tampering detected.
Part of: https://github.com/topazyo/openclaw-security-playbook
"""

import json
import sys
import argparse
from pathlib import Path
from datetime import datetime


def verify_hash_chain(input_path: str, output_path: str | None = None) -> bool:
    events = []
    path = Path(input_path)

    if not path.exists():
        print(f"ERROR: File not found: {input_path}", file=sys.stderr)
        sys.exit(2)

    with open(path) as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError as e:
                print(f"WARNING: Line {i} is invalid JSON: {e}", file=sys.stderr)
                continue

    if not events:
        print("WARNING: No events found in telemetry file", file=sys.stderr)
        return True

    results = {
        "total_events": len(events),
        "chain_intact": True,
        "breaks": [],
        "checked_at": datetime.utcnow().isoformat() + "Z",
        "first_event": events[0].get("timestamp"),
        "last_event": events[-1].get("timestamp"),
    }

    prev_hash = None

    for i, event in enumerate(events):
        current_hash = event.get("chain_hash")
        event_prev_hash = event.get("prev_hash")

        if i == 0:
            prev_hash = current_hash
            continue

        if prev_hash is not None and event_prev_hash != prev_hash:
            break_info = {
                "position": i,
                "timestamp": event.get("timestamp"),
                "expected_prev_hash": prev_hash,
                "actual_prev_hash": event_prev_hash,
                "event_type": event.get("event_type"),
            }
            results["breaks"].append(break_info)
            results["chain_intact"] = False
            print(
                f"BREAK at position {i} ({event.get('timestamp')}): "
                f"expected prev_hash={prev_hash}, got={event_prev_hash}",
                file=sys.stderr,
            )

        prev_hash = current_hash

    if output_path:
        with open(output_path, "w") as f:
            json.dump(results, f, indent=2)

    if results["chain_intact"]:
        print(
            f"OK: Hash chain intact. {results['total_events']} events verified. "
            f"Range: {results['first_event']} to {results['last_event']}"
        )
    else:
        print(
            f"CRITICAL: Hash chain broken at {len(results['breaks'])} position(s). "
            f"Log tampering possible. Review {output_path or 'stderr output'} for details.",
            file=sys.stderr,
        )

    return results["chain_intact"]


def main():
    parser = argparse.ArgumentParser(
        description="Verify openclaw-telemetry hash chain integrity"
    )
    parser.add_argument("--input", required=True, help="Path to telemetry.jsonl file")
    parser.add_argument("--output", help="Path to write JSON report (optional)")
    args = parser.parse_args()

    intact = verify_hash_chain(args.input, args.output)
    sys.exit(0 if intact else 1)


if __name__ == "__main__":
    main()
