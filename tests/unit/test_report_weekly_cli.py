"""CLI tests for ``openclaw-cli report weekly``.

These tests mock ``_load_clawdbot_module`` so no live tools are required.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from click.testing import CliRunner

# ---------------------------------------------------------------------------
# Load the CLI module directly
# ---------------------------------------------------------------------------
_CLI_PATH = Path(__file__).resolve().parents[2] / "tools" / "openclaw-cli.py"
_spec = importlib.util.spec_from_file_location("openclaw_cli_weekly_tests", _CLI_PATH)
assert _spec is not None and _spec.loader is not None
_cli_mod = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = _cli_mod
_spec.loader.exec_module(_cli_mod)
cli = _cli_mod.cli


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SAMPLE_RESULT_HEALTHY = {
    "command": "report weekly",
    "generated_at": "2026-03-21T00:00:00+00:00",
    "period": {"start": "2026-03-14", "end": "2026-03-21"},
    "sections": {
        "compliance_status": {
            "soc2": {"compliance_percentage": 98.5, "implemented_count": 65, "pending_count": 1},
            "iso27001": {"compliance_percentage": 97.0, "implemented_count": 113, "pending_count": 3},
        },
        "certificate_status": {"total": 3, "expiring_soon": 0, "certificates": []},
        "vulnerability_summary": None,
        "access_review_status": None,
    },
    "overall_status": "healthy",
    "missing_evidence": [
        "vulnerability_summary: run 'openclaw-cli scan vulnerability' ...",
        "access_review_status: run 'openclaw-cli scan access' ...",
    ],
    "warnings": [],
    "artifacts": {"json_report": None, "pdf_report": None},
}

_SAMPLE_RESULT_WARNING = {
    **_SAMPLE_RESULT_HEALTHY,
    "overall_status": "warning",
    "sections": {
        **_SAMPLE_RESULT_HEALTHY["sections"],
        "certificate_status": {"total": 3, "expiring_soon": 2, "certificates": []},
    },
}


def _mock_weekly_mod(result: dict):
    mod = SimpleNamespace()
    mod.generate_weekly_report = lambda **kw: result
    return mod


BASE_ARGS = ["report", "weekly", "--start", "2026-03-14", "--end", "2026-03-21"]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestReportWeeklyCommand:
    """Tests for `openclaw-cli report weekly`."""

    def test_happy_path_exits_zero(self, monkeypatch):
        monkeypatch.setattr(
            _cli_mod, "_load_clawdbot_module", lambda _n: _mock_weekly_mod(_SAMPLE_RESULT_HEALTHY)
        )
        runner = CliRunner()
        out = runner.invoke(cli, BASE_ARGS)
        assert out.exit_code == 0

    def test_output_shows_overall_status(self, monkeypatch):
        monkeypatch.setattr(
            _cli_mod, "_load_clawdbot_module", lambda _n: _mock_weekly_mod(_SAMPLE_RESULT_HEALTHY)
        )
        runner = CliRunner()
        out = runner.invoke(cli, BASE_ARGS)
        assert "HEALTHY" in out.output

    def test_output_shows_compliance_percentage(self, monkeypatch):
        monkeypatch.setattr(
            _cli_mod, "_load_clawdbot_module", lambda _n: _mock_weekly_mod(_SAMPLE_RESULT_HEALTHY)
        )
        runner = CliRunner()
        out = runner.invoke(cli, BASE_ARGS)
        # Both frameworks should appear
        assert "SOC2" in out.output or "soc2" in out.output.lower()
        assert "98" in out.output  # 98.5%

    def test_missing_evidence_shown(self, monkeypatch):
        monkeypatch.setattr(
            _cli_mod, "_load_clawdbot_module", lambda _n: _mock_weekly_mod(_SAMPLE_RESULT_HEALTHY)
        )
        runner = CliRunner()
        out = runner.invoke(cli, BASE_ARGS)
        assert "Missing evidence" in out.output or "vulnerability_summary" in out.output

    def test_warning_status_displayed(self, monkeypatch):
        monkeypatch.setattr(
            _cli_mod, "_load_clawdbot_module", lambda _n: _mock_weekly_mod(_SAMPLE_RESULT_WARNING)
        )
        runner = CliRunner()
        out = runner.invoke(cli, BASE_ARGS)
        assert out.exit_code == 0
        assert "WARNING" in out.output
        assert "2" in out.output  # 2 expiring certs

    def test_output_file_written(self, tmp_path, monkeypatch):
        out_path = tmp_path / "report.json"
        report = dict(_SAMPLE_RESULT_HEALTHY)

        def _gen(**kw):
            if kw.get("output_path"):
                Path(kw["output_path"]).write_text(json.dumps(report), encoding="utf-8")
                report["artifacts"] = {"json_report": kw["output_path"], "pdf_report": None}
            return report

        mod = SimpleNamespace(generate_weekly_report=_gen)
        monkeypatch.setattr(_cli_mod, "_load_clawdbot_module", lambda _n: mod)

        runner = CliRunner()
        out = runner.invoke(cli, [*BASE_ARGS, "--output", str(out_path)])
        assert out.exit_code == 0
        assert out_path.exists()

    def test_vulnerability_scan_arg_passed(self, tmp_path, monkeypatch):
        received: dict = {}

        def _gen(**kw):
            received.update(kw)
            return _SAMPLE_RESULT_HEALTHY

        mod = SimpleNamespace(generate_weekly_report=_gen)
        monkeypatch.setattr(_cli_mod, "_load_clawdbot_module", lambda _n: mod)

        vuln_path = tmp_path / "vuln.json"
        vuln_path.write_text("{}", encoding="utf-8")
        runner = CliRunner()
        runner.invoke(cli, [*BASE_ARGS, "--vulnerability-scan", str(vuln_path)])
        assert received.get("vulnerability_scan_path") == str(vuln_path)

    def test_access_scan_arg_passed(self, tmp_path, monkeypatch):
        received: dict = {}

        def _gen(**kw):
            received.update(kw)
            return _SAMPLE_RESULT_HEALTHY

        mod = SimpleNamespace(generate_weekly_report=_gen)
        monkeypatch.setattr(_cli_mod, "_load_clawdbot_module", lambda _n: mod)

        access_path = tmp_path / "access.json"
        access_path.write_text("{}", encoding="utf-8")
        runner = CliRunner()
        runner.invoke(cli, [*BASE_ARGS, "--access-scan", str(access_path)])
        assert received.get("access_scan_path") == str(access_path)

    def test_start_required(self, monkeypatch):
        monkeypatch.setattr(
            _cli_mod, "_load_clawdbot_module", lambda _n: _mock_weekly_mod(_SAMPLE_RESULT_HEALTHY)
        )
        runner = CliRunner()
        out = runner.invoke(cli, ["report", "weekly", "--end", "2026-03-21"])
        assert out.exit_code != 0
        assert "start" in out.output.lower() or "missing" in out.output.lower()

    def test_end_required(self, monkeypatch):
        monkeypatch.setattr(
            _cli_mod, "_load_clawdbot_module", lambda _n: _mock_weekly_mod(_SAMPLE_RESULT_HEALTHY)
        )
        runner = CliRunner()
        out = runner.invoke(cli, ["report", "weekly", "--start", "2026-03-14"])
        assert out.exit_code != 0
        assert "end" in out.output.lower() or "missing" in out.output.lower()
