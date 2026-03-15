#!/usr/bin/env python3
"""Validate OpenClaw detection content.

Runs Sigma validation for all OpenClaw Sigma rules and compiles the YARA IOC
rule set using `yarac` when available.
"""

from __future__ import annotations

import shutil
import subprocess  # nosec B404
import sys
import tempfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SIGMA_DIR = REPO_ROOT / "detections" / "sigma"
YARA_RULE = REPO_ROOT / "detections" / "ioc" / "ioc-openclaw.yar"


def _run(command: list[str], description: str) -> None:
    print(f"[*] {description}")
    result = subprocess.run(command, capture_output=True, text=True)  # nosec B603
    if result.stdout:
        print(result.stdout.rstrip())
    if result.stderr:
        print(result.stderr.rstrip(), file=sys.stderr)
    if result.returncode != 0:
        raise RuntimeError(f"{description} failed with exit code {result.returncode}")


def _require_command(name: str) -> str:
    path = shutil.which(name)
    if not path:
        raise RuntimeError(f"Required command not found in PATH: {name}")
    return path


def validate_sigma() -> None:
    sigma = _require_command("sigma")
    rule_files = sorted(SIGMA_DIR.glob("openclaw-*.yml"))
    if not rule_files:
        raise RuntimeError("No OpenClaw Sigma rules found to validate")

    for rule_file in rule_files:
        _run([sigma, "check", str(rule_file)], f"Validate Sigma rule {rule_file.name}")


def validate_yara() -> None:
    yarac = _require_command("yarac")
    if not YARA_RULE.exists():
        raise RuntimeError(f"YARA rule file not found: {YARA_RULE}")

    with tempfile.TemporaryDirectory() as temp_dir:
        compiled_output = Path(temp_dir) / "ioc-openclaw.yarc"
        _run([yarac, str(YARA_RULE), str(compiled_output)], f"Compile YARA rule {YARA_RULE.name}")


def main() -> int:
    try:
        validate_sigma()
        validate_yara()
    except RuntimeError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2

    print("[✓] Detection rule validation completed successfully")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())