from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest


_BASH_PATH = shutil.which("bash")
_SCRIPT_PATH = Path(__file__).resolve().parents[2] / "scripts" / "forensics" / "collect_evidence.sh"


@pytest.mark.skipif(_BASH_PATH is None, reason="bash is required to execute collect_evidence.sh")
def test_collect_evidence_surfaces_capture_command_failures(tmp_path):
    home_dir = tmp_path / "home"
    home_dir.mkdir()

    env = os.environ.copy()
    env["HOME"] = str(home_dir)

    script_input = b"ss() { return 3; }\n" + _SCRIPT_PATH.read_bytes().replace(b"\r", b"")

    result = subprocess.run(
        [_BASH_PATH, "-s"],
        capture_output=True,
        env=env,
        input=script_input,
        check=False,
    )

    output = (result.stdout + result.stderr).decode("utf-8", errors="replace")

    assert result.returncode != 0
    assert "Failed to capture active network connections" in output