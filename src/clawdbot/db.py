"""Minimal database command surface expected by the gateway entrypoint."""

import argparse


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Minimal ClawdBot database command shim")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("migrate", help="Run no-op database migrations")
    args = parser.parse_args(argv)

    if args.command == "migrate":
        print("[db] No-op migration completed")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())