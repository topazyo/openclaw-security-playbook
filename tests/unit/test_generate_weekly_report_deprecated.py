"""C6-RT-07 regression tests — generate-weekly-report.py is a deprecation shim.

Claim made true: the legacy `scripts/vulnerability-scanning/generate-weekly-report.py`
previously died on `--help` with "ERROR: Missing dependencies" because it eagerly
imported matplotlib/pandas/reportlab/elasticsearch *before* argparse. The fix adds a
deprecation guard that runs BEFORE those imports, so:

  * `--help` exits 0 and prints a pointer to the canonical `openclaw-cli report weekly`
    EVEN WHEN the heavy deps are absent (proves the guard precedes the eager imports);
  * any other invocation exits non-zero and does NOT masquerade as a successful report
    run (it must not silently produce nothing, nor write a fabricated output file).

These drive the real script in a subprocess via ``sys.executable`` so the module-level
guard is exercised exactly as an operator would hit it.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_LEGACY_SCRIPT = _REPO_ROOT / "scripts" / "vulnerability-scanning" / "generate-weekly-report.py"


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(_LEGACY_SCRIPT), *args],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )


def test_help_exits_zero_and_points_to_canonical_cli():
    """--help prints the deprecation pointer and exits 0, before the eager imports."""
    proc = _run("--help")
    combined = proc.stdout + proc.stderr
    assert proc.returncode == 0, combined
    assert "DEPRECATED" in proc.stderr, combined  # pointer must go to stderr, not stdout
    assert "openclaw-cli report weekly" in combined, combined
    # The guard short-circuits BEFORE the matplotlib/pandas/reportlab/elasticsearch
    # import block, so the old missing-deps abort path must never be reached.
    assert "Missing dependencies" not in combined, combined


def test_real_invocation_fails_closed_and_writes_nothing(tmp_path):
    """A report-style invocation must not fake success nor write a fabricated file."""
    out = tmp_path / "weekly-report.json"
    proc = _run("--output", str(out))
    combined = proc.stdout + proc.stderr
    # Exit 2 (deprecated/usage), distinct from the OLD exit-1 missing-deps path — asserting
    # the exact code catches any future drift back toward that fail-open behavior.
    assert proc.returncode == 2, combined            # does not masquerade as success
    assert "DEPRECATED" in proc.stderr, combined      # surfaces the canonical pointer on stderr
    assert "Missing dependencies" not in combined, combined
    assert not out.exists(), "deprecated shim must not write an output file"
