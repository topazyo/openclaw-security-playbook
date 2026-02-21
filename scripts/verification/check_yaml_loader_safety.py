#!/usr/bin/env python3
"""Fail if unsafe PyYAML loaders are used in workspace Python files."""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
UNSAFE_PATTERN = re.compile(r"\byaml\.load\s*\(")
EXCLUDED_DIRS = {".git", ".venv", "node_modules", "archive", "tmp"}


def iter_python_files(root: Path):
    for path in root.rglob("*.py"):
        if any(part in EXCLUDED_DIRS for part in path.parts):
            continue
        yield path


def main() -> int:
    violations: list[tuple[Path, int, str]] = []

    for file_path in iter_python_files(ROOT):
        try:
            text = file_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue

        for line_number, line in enumerate(text.splitlines(), start=1):
            if UNSAFE_PATTERN.search(line):
                violations.append((file_path, line_number, line.strip()))

    if violations:
        print("ERROR: Unsafe yaml.load usage detected. Use yaml.safe_load instead.")
        for file_path, line_number, line in violations:
            rel = file_path.relative_to(ROOT)
            print(f"  - {rel}:{line_number}: {line}")
        return 1

    print("OK: No unsafe yaml.load usage detected.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
