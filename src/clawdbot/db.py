"""
Database command surface expected by the gateway entrypoint.

Migration contract (NOT YET IMPLEMENTED):
  - Command: ``clawdbot db migrate``
  - Pre-condition: a live relational database reachable via ``DATABASE_URL``
  - Action: apply all pending schema migrations in dependency order
  - Success: print ``[db] migrations applied: <N>`` and return 0
  - No-op (schema already current): print ``[db] no pending migrations`` and return 0
  - Failure: print ``[db] migration failed: <reason>`` to stderr and return 2

Until a real migration engine is wired, callers MUST handle ``NotImplementedError``
and treat the migration path as unavailable.
"""

import argparse
import sys


def _run_migrate() -> int:  # FIX: C5-M-03
    """
    Apply pending database schema migrations.

    NOT IMPLEMENTED — raises ``NotImplementedError`` until a migration engine
    (e.g. Alembic, Flyway) is wired to a live ``DATABASE_URL``.

    Contract when implemented:
      - Returns 0 and prints ``[db] migrations applied: <N>`` on success.
      - Returns 0 and prints ``[db] no pending migrations`` when schema is current.
      - Returns 2 and prints ``[db] migration failed: <reason>`` to stderr on error.

    Raises:
        NotImplementedError: Always, until real migration wiring is present.
    """
    raise NotImplementedError(  # FIX: C5-M-03
        "Database migration is not implemented. "
        "Wire a migration engine to DATABASE_URL and replace this stub before calling migrate."
    )


def main(argv: list[str] | None = None) -> int:  # FIX: C5-M-03
    parser = argparse.ArgumentParser(description="ClawdBot database command")  # FIX: C5-M-03
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("migrate", help="Apply pending database schema migrations")  # FIX: C5-M-03
    args = parser.parse_args(argv)

    if args.command == "migrate":  # FIX: C5-M-03
        try:  # FIX: C5-M-03
            return _run_migrate()  # FIX: C5-M-03
        except NotImplementedError as exc:  # FIX: C5-M-03
            print(f"[db] migration failed: {exc}", file=sys.stderr)  # FIX: C5-M-03
            return 2  # FIX: C5-M-03
    return 1  # FIX: C5-M-03


if __name__ == "__main__":
    raise SystemExit(main())