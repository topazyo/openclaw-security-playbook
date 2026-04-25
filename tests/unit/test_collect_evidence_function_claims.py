from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest


_BASH_PATH = shutil.which("bash")
_SCRIPT_PATH = Path(__file__).resolve().parents[2] / "scripts" / "forensics" / "collect_evidence.sh"
_FUNCTION_BLOCK = _SCRIPT_PATH.read_bytes().replace(b"\r", b"").split(b"TIMESTAMP=", 1)[0]


def _run_function_block(commands: bytes) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [_BASH_PATH, "-s"],
        capture_output=True,
        input=_FUNCTION_BLOCK + b"\n" + commands,
        check=False,
    )


@pytest.mark.skipif(_BASH_PATH is None, reason="bash is required to execute collect_evidence.sh helpers")
def test_record_warning_claim_increments_warning_counter():
    result = _run_function_block(
        b'WARNINGS=0\nrecord_warning "missing ./config.json; rm -rf /"\nprintf "__WARNINGS__%s\\n" "$WARNINGS"\n'
    )
    output = (result.stdout + result.stderr).decode("utf-8", errors="replace")

    assert result.returncode == 0
    assert "missing ./config.json; rm -rf /" in output
    assert "__WARNINGS__1" in output


@pytest.mark.skipif(_BASH_PATH is None, reason="bash is required to execute collect_evidence.sh helpers")
def test_run_capture_claim_surfaces_failed_capture():
    result = _run_function_block(
        b'WARNINGS=0\nworkdir="$(mktemp -d)"\nrun_capture "capture active network connections" "$workdir/out.txt" bash -lc "exit 3"\nprintf "__WARNINGS__%s\\n" "$WARNINGS"\ncat "$workdir/out.txt"\n'
    )
    output = (result.stdout + result.stderr).decode("utf-8", errors="replace")

    assert result.returncode == 0
    assert "Failed to capture active network connections (exit 3)" in output
    assert "__WARNINGS__1" in output


@pytest.mark.skipif(_BASH_PATH is None, reason="bash is required to execute collect_evidence.sh helpers")
def test_run_append_capture_claim_appends_success_and_flags_failure():
    result = _run_function_block(
        b'WARNINGS=0\nworkdir="$(mktemp -d)"\nprintf "base\\n" > "$workdir/out.txt"\nrun_append_capture "append good data" "$workdir/out.txt" bash -lc "printf \'extra\\n\'"\nrun_append_capture "append bad data" "$workdir/out.txt" bash -lc "exit 4"\nprintf "__WARNINGS__%s\\n" "$WARNINGS"\ncat "$workdir/out.txt"\n'
    )
    output = (result.stdout + result.stderr).decode("utf-8", errors="replace")

    assert result.returncode == 0
    assert "Failed to append bad data (exit 4)" in output
    assert "__WARNINGS__1" in output
    assert "base" in output
    assert "extra" in output