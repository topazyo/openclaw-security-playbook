"""CLI tests for ``openclaw-cli scan access``.

These tests mock ``_load_clawdbot_module`` so no real IdP or CSV is required.
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
_spec = importlib.util.spec_from_file_location("openclaw_cli_access_tests", _CLI_PATH)
assert _spec is not None and _spec.loader is not None
_cli_mod = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = _cli_mod
_spec.loader.exec_module(_cli_mod)
cli = _cli_mod.cli


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_access_result(
    total_users: int = 10,
    inactive: int = 2,
    privilege_creep: int = 1,
    orphaned: int = 0,
) -> dict:
    return {
        "command": "scan access",
        "generated_at": "2026-03-21T00:00:00+00:00",
        "input_source": "csv",
        "days_threshold": 90,
        "findings": {
            "inactive_users": [{"user_id": f"u{i}"} for i in range(inactive)],
            "privilege_creep": [{"user_id": f"p{i}"} for i in range(privilege_creep)],
            "orphaned_approvers": [{"user_id": f"o{i}"} for i in range(orphaned)],
        },
        "summary": {
            "total_users": total_users,
            "inactive_count": inactive,
            "privilege_creep_count": privilege_creep,
            "orphaned_approver_count": orphaned,
        },
        "compliance": {
            "soc2_cc6_1": "warn" if inactive > 0 else "pass",
            "iso27001_a9_2_5": "warn" if privilege_creep > 0 else "pass",
        },
    }


def _mock_access_mod(result: dict):
    mod = SimpleNamespace()
    mod.run_access_review = lambda **kw: result
    return mod


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestScanAccessCommand:
    """Tests for `openclaw-cli scan access`."""

    def test_csv_source_exits_zero(self, tmp_path, monkeypatch):
        result = _build_access_result()
        monkeypatch.setattr(_cli_mod, "_load_clawdbot_module", lambda _n: _mock_access_mod(result))

        csv_file = tmp_path / "access.csv"
        csv_file.write_text("dummy", encoding="utf-8")
        runner = CliRunner()
        out = runner.invoke(cli, ["scan", "access", "--input-csv", str(csv_file)])
        assert out.exit_code == 0

    def test_output_shows_finding_counts(self, tmp_path, monkeypatch):
        result = _build_access_result(total_users=50, inactive=3, privilege_creep=1)
        monkeypatch.setattr(_cli_mod, "_load_clawdbot_module", lambda _n: _mock_access_mod(result))

        csv_file = tmp_path / "access.csv"
        csv_file.write_text("dummy", encoding="utf-8")
        runner = CliRunner()
        out = runner.invoke(cli, ["scan", "access", "--input-csv", str(csv_file)])
        assert out.exit_code == 0
        assert "50" in out.output
        assert "3" in out.output

    def test_compliance_block_shown(self, tmp_path, monkeypatch):
        result = _build_access_result(inactive=2)
        monkeypatch.setattr(_cli_mod, "_load_clawdbot_module", lambda _n: _mock_access_mod(result))

        csv_file = tmp_path / "access.csv"
        csv_file.write_text("dummy", encoding="utf-8")
        runner = CliRunner()
        out = runner.invoke(cli, ["scan", "access", "--input-csv", str(csv_file)])
        assert out.exit_code == 0
        assert "SOC2" in out.output.upper() or "CC6_1" in out.output.upper()

    def test_no_source_errors(self, monkeypatch):
        monkeypatch.setattr(_cli_mod, "_load_clawdbot_module", lambda _n: SimpleNamespace())
        runner = CliRunner()
        out = runner.invoke(cli, ["scan", "access"])
        assert out.exit_code != 0
        assert "input-csv" in out.output or "provider" in out.output

    def test_mutual_exclusion_csv_and_provider(self, tmp_path, monkeypatch):
        monkeypatch.setattr(_cli_mod, "_load_clawdbot_module", lambda _n: SimpleNamespace())
        csv_file = tmp_path / "access.csv"
        csv_file.write_text("dummy", encoding="utf-8")
        runner = CliRunner()
        out = runner.invoke(
            cli,
            ["scan", "access", "--input-csv", str(csv_file), "--provider", "azure-ad"],
        )
        assert out.exit_code != 0
        assert "mutually exclusive" in out.output.lower()

    def test_output_file_written(self, tmp_path, monkeypatch):
        out_path = tmp_path / "access.json"
        access_result = _build_access_result()

        def _run_access_review(**kw):
            if kw.get("output_path"):
                Path(kw["output_path"]).write_text(
                    json.dumps(access_result), encoding="utf-8"
                )
            return access_result

        mod = SimpleNamespace(run_access_review=_run_access_review)
        monkeypatch.setattr(_cli_mod, "_load_clawdbot_module", lambda _n: mod)

        csv_file = tmp_path / "access.csv"
        csv_file.write_text("dummy", encoding="utf-8")
        runner = CliRunner()
        out = runner.invoke(
            cli,
            ["scan", "access", "--input-csv", str(csv_file), "--output", str(out_path)],
        )
        assert out.exit_code == 0
        assert out_path.exists()

    def test_days_flag_passed_to_backend(self, tmp_path, monkeypatch):
        received: dict = {}

        def _run(**kw):
            received.update(kw)
            return _build_access_result()

        mod = SimpleNamespace(run_access_review=_run)
        monkeypatch.setattr(_cli_mod, "_load_clawdbot_module", lambda _n: mod)

        csv_file = tmp_path / "access.csv"
        csv_file.write_text("dummy", encoding="utf-8")
        runner = CliRunner()
        runner.invoke(cli, ["scan", "access", "--input-csv", str(csv_file), "--days", "60"])
        assert received.get("days_threshold") == 60

    def test_provider_azure_ad_accepted(self, monkeypatch):
        result = _build_access_result()
        received: dict = {}

        def _run(**kw):
            received.update(kw)
            return result

        mod = SimpleNamespace(run_access_review=_run)
        monkeypatch.setattr(_cli_mod, "_load_clawdbot_module", lambda _n: mod)

        runner = CliRunner()
        out = runner.invoke(cli, ["scan", "access", "--provider", "azure-ad"])
        assert out.exit_code == 0
        assert received.get("provider") == "azure-ad"
