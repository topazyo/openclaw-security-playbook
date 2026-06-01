#!/usr/bin/env python3
"""
verify_hash_chain.py — Validate openclaw-telemetry hash chain integrity

Usage:
    python3 verify_hash_chain.py --input ~/.openclaw/logs/telemetry.jsonl
    python3 verify_hash_chain.py --input telemetry.jsonl --output report.json

Exits with code 0 if chain is intact, code 1 if tampering detected.
Part of: https://github.com/topazyo/openclaw-security-playbook
"""

import hashlib  # FIX: C6-RT-01 - recompute event content hashes, not just the prev_hash pointer
import json
import sys
import argparse
from pathlib import Path
from datetime import UTC, datetime
from typing import Any


JsonObject = dict[str, Any]


def verify_hash_chain(input_path: str, output_path: str | None = None) -> bool:
    events: list[JsonObject] = []
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

    results: JsonObject = {
        "total_events": len(events),
        "chain_intact": True,
        "breaks": [],
        "checked_at": datetime.now(UTC).isoformat(),
        "first_event": events[0].get("timestamp"),
        "last_event": events[-1].get("timestamp"),
    }

    prev_chain_hash: str | None = None  # FIX: C6-RT-01 - stored chain_hash of the previous event

    for i, event in enumerate(events):
        stored_chain_hash = event.get("chain_hash")  # FIX: C6-RT-01
        event_prev_hash = event.get("prev_hash")

        # FIX: C6-RT-01 - Recompute the content hash exactly as the canonical writer
        # (apply_hash_chain) produced it: SHA-256 over the event object WITHOUT chain_hash,
        # with prev_hash retained in the hashed body, canonicalized via json.dumps(sort_keys=True).
        # The previous logic only compared the stored prev_hash pointer, so editing an event's
        # content while preserving prev_hash/chain_hash passed as "intact". Fail closed: any
        # content mismatch, missing/invalid chain_hash, or broken linkage is recorded as a break.
        recomputed_chain_hash: str | None = None  # FIX: C6-RT-01
        break_reason: str | None = None  # FIX: C6-RT-01
        if not isinstance(stored_chain_hash, str) or not stored_chain_hash:  # FIX: C6-RT-01
            break_reason = "missing_or_invalid_chain_hash"  # FIX: C6-RT-01
        else:  # FIX: C6-RT-01
            hashed_body = {k: v for k, v in event.items() if k != "chain_hash"}  # FIX: C6-RT-01
            recomputed_chain_hash = hashlib.sha256(  # FIX: C6-RT-01
                json.dumps(hashed_body, sort_keys=True).encode("utf-8")  # FIX: C6-RT-01
            ).hexdigest()  # FIX: C6-RT-01
            if recomputed_chain_hash != stored_chain_hash:  # FIX: C6-RT-01 - content tampering
                break_reason = "content_hash_mismatch"  # FIX: C6-RT-01
            elif i == 0:  # FIX: C6-RT-01 - genesis event must declare prev_hash=null
                if event_prev_hash is not None:  # FIX: C6-RT-01
                    break_reason = "genesis_prev_hash_not_null"  # FIX: C6-RT-01
            elif event_prev_hash != prev_chain_hash:  # FIX: C6-RT-01 - linkage to prior event
                break_reason = "prev_hash_link_mismatch"  # FIX: C6-RT-01

        if break_reason is not None:  # FIX: C6-RT-01 - fail closed on any unverifiable/tampered event
            break_info: JsonObject = {
                "position": i,
                "timestamp": event.get("timestamp"),
                "reason": break_reason,  # FIX: C6-RT-01
                "expected_prev_hash": prev_chain_hash if i > 0 else None,  # FIX: C6-RT-01
                "actual_prev_hash": event_prev_hash,
                "stored_chain_hash": stored_chain_hash,  # FIX: C6-RT-01
                "recomputed_chain_hash": recomputed_chain_hash,  # FIX: C6-RT-01
                "event_type": event.get("event_type"),
            }
            results["breaks"].append(break_info)
            results["chain_intact"] = False
            print(
                f"BREAK at position {i} ({event.get('timestamp')}): {break_reason} "  # FIX: C6-RT-01
                f"(stored={stored_chain_hash}, recomputed={recomputed_chain_hash})",  # FIX: C6-RT-01
                file=sys.stderr,
            )

        prev_chain_hash = stored_chain_hash  # FIX: C6-RT-01 - advance to this event's stored hash

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
