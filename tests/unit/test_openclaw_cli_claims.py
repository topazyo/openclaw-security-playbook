from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import click
import pytest
from click.testing import CliRunner


_CLI_PATH = Path(__file__).resolve().parents[2] / "tools" / "openclaw-cli.py"
_SPEC = importlib.util.spec_from_file_location("openclaw_cli_claim_tests", _CLI_PATH)
assert _SPEC is not None and _SPEC.loader is not None
_CLI_MOD = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _CLI_MOD
_SPEC.loader.exec_module(_CLI_MOD)
cli = _CLI_MOD.cli


def _completed_process(stdout: str = "", stderr: str = "", returncode: int = 0) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=["pytest"], returncode=returncode, stdout=stdout, stderr=stderr)


def _recording_runner(
    recorded_commands: list[dict],
    *,
    ioc_report_payload: dict | None = None,
    impact_total_resources: int = 1,
):
    def _run(command_spec: dict) -> subprocess.CompletedProcess[str]:
        recorded_commands.append(
            {
                "phase": command_spec.get("phase"),
                "script": command_spec.get("script"),
                "args": list(command_spec.get("args", [])),
                "channel": command_spec.get("channel"),
            }
        )

        if command_spec.get("script") == "scripts/incident-response/ioc-scanner.py":
            output_path = Path(command_spec["output_path"])
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(
                json.dumps(
                    ioc_report_payload
                    or {
                        "scan_timestamp": "2026-04-24T00:00:00+00:00",
                        "iocs_found": [],
                        "threat_score": 0,
                        "overall_threat_level": "LOW",
                    }
                ),
                encoding="utf-8",
            )

        if command_spec.get("validation") == "impact_blast_radius":
            output_path = Path(command_spec["output_path"])
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(
                json.dumps({"blast_radius": {"total_resources": impact_total_resources}}),
                encoding="utf-8",
            )

        return _completed_process(stdout=f"ran {command_spec.get('script', 'unknown')}")

    return _run


def _simulator_module(incident_data: dict):
    def _create_incident(incident_type: str, severity: str = "P1") -> dict:
        payload = dict(incident_data)
        payload["severity"] = severity
        return payload

    return SimpleNamespace(create_incident=_create_incident)


def test__notification_severity_for_cli_severity_claim_maps_cli_severity_with_fallback():
    assert _CLI_MOD._notification_severity_for_cli_severity("P0", "HIGH") == "CRITICAL"
    assert _CLI_MOD._notification_severity_for_cli_severity("P9", "HIGH") == "HIGH"


def test__required_notification_channels_claim_requires_pagerduty_only_for_high_severity():
    assert _CLI_MOD._required_notification_channels("HIGH") == ["slack", "pagerduty", "jira"]
    assert _CLI_MOD._required_notification_channels("DROP TABLE") == ["slack", "jira"]


def test__select_detection_target_claim_selects_later_scannable_target(monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-token")
    monkeypatch.setattr(
        _CLI_MOD.socket,
        "gethostbyname",
        lambda resource: (_ for _ in ()).throw(_CLI_MOD.socket.gaierror("dns failed")) if resource == "broken.invalid" else "203.0.113.10",
    )

    target = _CLI_MOD._select_detection_target(
        {"affected_resources": ["broken.invalid", "203.0.113.10", "i-0abc123"]},
        require_real=True,
    )

    assert target == ("ip", "203.0.113.10")


def test__select_blast_radius_resource_claim_returns_supported_resource():
    resource = _CLI_MOD._select_blast_radius_resource(
        {"affected_resources": ["api-gateway", "i-0abc123"]},
        require_real=True,
    )

    assert resource == "i-0abc123"


def test__build_execution_profile_claim_applies_defaults_and_overrides():
    profile = _CLI_MOD._build_execution_profile(
        "playbook-unknown-case",
        overrides={"notification_message": "override payload", "impact_args": ["--users", "9"]},
    )

    assert profile["incident_slug"] == "unknown-case"
    assert profile["ioc_domain"] == "unknown-case.xyz"
    assert profile["notification_message"] == "override payload"
    assert profile["impact_args"] == ["--users", "9"]


def test__build_incident_artifact_paths_claim_creates_isolated_artifact_paths(tmp_path, monkeypatch):
    monkeypatch.setattr(_CLI_MOD, "REPO_ROOT", tmp_path)

    artifact_paths = _CLI_MOD._build_incident_artifact_paths("credential-theft", "INC 001", create=True)

    assert artifact_paths["root"].exists()
    assert artifact_paths["root"] == tmp_path / "tmp" / "cli-orchestration" / "credential-theft" / "INC 001"
    assert artifact_paths["ioc_report"].parent == artifact_paths["root"]


def test__build_phase_command_specs_claim_builds_validated_phase_commands(monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-token")

    command_specs = _CLI_MOD._build_phase_command_specs(
        "playbook-credential-theft",
        "P3",
        "INC-001",
        incident_data={"affected_resources": ["203.0.113.10", "i-0abc123"]},
        require_real_inputs=True,
    )

    detection_command = next(spec for spec in command_specs if spec["phase"] == "Detection")
    recovery_phase = next(spec for spec in command_specs if spec["phase"] == "Recovery")
    containment_command = next(spec for spec in command_specs if spec["phase"] == "Containment")
    eradication_command = next(spec for spec in command_specs if spec["phase"] == "Eradication")

    assert detection_command["validation"] == "ioc_report"
    assert detection_command["args"][:2] == ["--ip", "203.0.113.10"]
    assert containment_command["failure_markers"] == ["Failed to apply deny policy"]
    assert [command["channel"] for command in recovery_phase["commands"]] == ["slack", "jira"]
    assert eradication_command["args"][2:4] == ["--resource", "i-0abc123"]


def test__format_command_spec_claim_formats_literal_command_text(tmp_path):
    command = _CLI_MOD._format_command_spec(
        {
            "kind": "shell",
            "script": "scripts/forensics/collect_evidence.sh",
            "args": ["$(touch", str(tmp_path / "should-not-exist")],
        }
    )

    assert "scripts/forensics/collect_evidence.sh" in command
    assert "$(touch" in command
    assert not (tmp_path / "should-not-exist").exists()


def test__run_shell_tool_claim_requires_available_shell_interpreter(monkeypatch):
    monkeypatch.setattr(_CLI_MOD.shutil, "which", lambda _name: None)

    with pytest.raises(RuntimeError, match="No shell interpreter available"):
        _CLI_MOD._run_shell_tool("scripts/forensics/collect_evidence.sh", [])


def test__run_command_spec_claim_restores_environment(monkeypatch):
    monkeypatch.setenv("EVIDENCE_DIR", "original-dir")
    monkeypatch.setattr(
        _CLI_MOD,
        "_run_python_tool",
        lambda _script, _args: _completed_process(stdout=os.environ["EVIDENCE_DIR"]),
    )

    result = _CLI_MOD._run_command_spec(
        {
            "kind": "python",
            "script": "scripts/incident-response/forensics-collector.py",
            "args": [],
            "env": {"EVIDENCE_DIR": "malicious-override"},
        }
    )

    assert result.stdout == "malicious-override"
    assert os.environ["EVIDENCE_DIR"] == "original-dir"


def test__validate_command_result_claim_rejects_error_marked_ioc_report(tmp_path):
    report_path = tmp_path / "ioc-report.json"
    report_path.write_text(
        json.dumps(
            {
                "scan_timestamp": "2026-04-24T00:00:00+00:00",
                "iocs_found": [],
                "threat_score": 0,
                "overall_threat_level": "LOW",
                "scan_results": [{"status": "error", "error": "upstream timeout"}],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(click.ClickException, match="IOC report indicates scanner failure"):
        _CLI_MOD._validate_command_result(
            {
                "validation": "ioc_report",
                "output_path": str(report_path),
                "expected_output_fields": ["scan_timestamp", "iocs_found", "threat_score", "overall_threat_level"],
            },
            _completed_process(),
        )


def test__build_evidence_command_spec_claim_builds_fixed_shell_evidence_command(monkeypatch):
    monkeypatch.setenv("EVIDENCE_DIR", "malicious-override")

    command_spec = _CLI_MOD._build_evidence_command_spec()

    assert command_spec == {
        "phase": "Evidence",
        "kind": "shell",
        "script": "scripts/forensics/collect_evidence.sh",
        "args": [],
    }


def test__execute_playbook_orchestration_claim_fails_closed_on_error_ioc_report(tmp_path, monkeypatch):
    recorded_commands: list[dict] = []
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-token")
    playbook_path = tmp_path / "playbook-credential-theft.md"
    playbook_path.write_text("# playbook", encoding="utf-8")
    monkeypatch.setattr(_CLI_MOD, "_resolve_playbook", lambda _playbook_id: playbook_path)
    monkeypatch.setattr(
        _CLI_MOD,
        "_run_command_spec",
        _recording_runner(
            recorded_commands,
            ioc_report_payload={
                "scan_timestamp": "2026-04-24T00:00:00+00:00",
                "iocs_found": [],
                "threat_score": 0,
                "overall_threat_level": "LOW",
                "scan_results": [{"status": "error", "error": "timeout"}],
            },
        ),
    )

    with pytest.raises(click.ClickException, match="IOC report indicates scanner failure"):
        _CLI_MOD._execute_playbook_orchestration(
            click.Context(cli),
            playbook_id="playbook-credential-theft",
            severity="P1",
            dry_run=False,
            execute_flag=True,
            incident_id="INC-EXEC-001",
            incident_data={"affected_resources": ["203.0.113.10", "i-0abc123"]},
        )

    assert recorded_commands[0]["script"] == "scripts/incident-response/ioc-scanner.py"


def test_execute_claim_rejects_execute_without_real_incident_context():
    runner = CliRunner()

    result = runner.invoke(cli, ["playbook", "execute", "playbook-credential-theft", "--severity", "P0", "--execute"])

    assert result.exit_code != 0
    assert "Detection phase requires real incident data" in result.output


def test_incident_claim_routes_declared_scenario_to_matching_playbook(monkeypatch):
    recorded_commands: list[dict] = []
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-token")
    monkeypatch.setattr(
        _CLI_MOD,
        "_load_tool_module",
        lambda _filename, _module_name: _simulator_module(
            {
                "incident_id": "INC-MCP-001",
                "type": "MCP Server Compromise",
                "severity": "P1",
                "affected_resources": ["example.com", "i-0abc123"],
                "description": "MCP compromise simulation",
                "detected_at": "2026-04-24T00:00:00+00:00",
                "status": "active",
            }
        ),
    )
    monkeypatch.setattr(_CLI_MOD, "_run_command_spec", _recording_runner(recorded_commands))

    runner = CliRunner()
    result = runner.invoke(cli, ["simulate", "incident", "--type", "mcp-compromise", "--severity", "P1"])

    assert result.exit_code == 0
    assert "Routed playbook: playbook-data-breach" in result.output
    assert recorded_commands[0]["args"][:2] == ["--domain", "example.com"]