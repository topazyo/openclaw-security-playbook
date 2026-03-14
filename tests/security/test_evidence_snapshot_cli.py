#!/usr/bin/env python3
"""Tests for the evidence snapshot CLI command."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys

from click.testing import CliRunner


MODULE_PATH = Path(__file__).resolve().parents[2] / "tools" / "openclaw-cli.py"
SPEC = importlib.util.spec_from_file_location("openclaw_cli", MODULE_PATH)
openclaw_cli = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = openclaw_cli
SPEC.loader.exec_module(openclaw_cli)


class _Result:
    def __init__(self, returncode: int = 0, stdout: str = "ok\n", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_evidence_snapshot_writes_manifest_and_logs(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(openclaw_cli, "_run_python_tool", lambda script, args: _Result())

    class _Reporter:
        @staticmethod
        def generate_report(framework: str):
            return {"framework": framework, "implemented_count": 1, "pending_count": 0, "compliance_percentage": 100.0}

    monkeypatch.setattr(openclaw_cli, "_load_tool_module", lambda filename, module_name: _Reporter())

    runner = CliRunner()
    result = runner.invoke(openclaw_cli.cli, ["report", "evidence-snapshot", "--output-dir", str(tmp_path), "--skip-yara"])

    assert result.exit_code == 0
    manifest = json.loads((tmp_path / "manifest.json").read_text(encoding="utf-8"))
    step_names = [step["name"] for step in manifest["steps"]]
    assert "runtime-regression" in step_names
    assert "detection-replay" in step_names
    assert "compliance-soc2" in step_names
    assert (tmp_path / "runtime" / "execution.log").exists()
    assert (tmp_path / "detection-replay" / "execution.log").exists()
    assert (tmp_path / "compliance" / "soc2-report.json").exists()


def test_evidence_snapshot_fails_when_subcommand_fails(tmp_path: Path, monkeypatch) -> None:
    def _run_tool(script: str, args: list[str]) -> _Result:
        if script.endswith("validate_detection_replay.py"):
            return _Result(returncode=1, stderr="replay failed")
        return _Result()

    monkeypatch.setattr(openclaw_cli, "_run_python_tool", _run_tool)

    class _Reporter:
        @staticmethod
        def generate_report(framework: str):
            return {"framework": framework, "implemented_count": 1, "pending_count": 0, "compliance_percentage": 100.0}

    monkeypatch.setattr(openclaw_cli, "_load_tool_module", lambda filename, module_name: _Reporter())

    runner = CliRunner()
    result = runner.invoke(openclaw_cli.cli, ["report", "evidence-snapshot", "--output-dir", str(tmp_path), "--skip-yara"])

    assert result.exit_code != 0
    assert "detection-replay" in result.output