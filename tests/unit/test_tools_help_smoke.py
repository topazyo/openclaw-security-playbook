import subprocess
import sys
from pathlib import Path

import pytest


TOOLS = [
    "certificate-manager.py",
    "compliance-reporter.py",
    "config-migrator.py",
    "incident-simulator.py",
    "openclaw-cli.py",
    "policy-validator.py",
]


@pytest.mark.parametrize("tool_name", TOOLS)
def test_tool_help_runs_without_error(tool_name):
    repo_root = Path(__file__).resolve().parents[2]
    tool_path = repo_root / "tools" / tool_name

    result = subprocess.run(
        [sys.executable, str(tool_path), "--help"],
        cwd=repo_root,
        capture_output=True,
        text=True,
    )

    if "No module named 'click'" in result.stderr and tool_name == "openclaw-cli.py":
        pytest.skip("click is not installed in this environment")

    assert result.returncode == 0, (
        f"{tool_name} --help failed with rc={result.returncode}\n"
        f"stdout:\n{result.stdout}\n"
        f"stderr:\n{result.stderr}"
    )
