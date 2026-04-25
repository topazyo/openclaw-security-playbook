"""CLI tests for ``openclaw-cli playbook`` and ``simulate incident``.

These tests mock command execution so the orchestration logic can be verified
without invoking the real incident-response helpers.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest
from click.testing import CliRunner


_CLI_PATH = Path(__file__).resolve().parents[2] / "tools" / "openclaw-cli.py"
_SPEC = importlib.util.spec_from_file_location("openclaw_cli_playbook_tests", _CLI_PATH)
assert _SPEC is not None and _SPEC.loader is not None
_CLI_MOD = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _CLI_MOD
_SPEC.loader.exec_module(_CLI_MOD)
cli = _CLI_MOD.cli


def _completed_process(stdout: str = "", stderr: str = "", returncode: int = 0) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=["pytest"], returncode=returncode, stdout=stdout, stderr=stderr)


def _incident(incident_id: str, incident_type: str, resources: list[str], description: str) -> dict:
    return {
        "incident_id": incident_id,
        "type": incident_type,
        "severity": "P1",
        "affected_resources": resources,
        "description": description,
        "detected_at": "2026-04-24T00:00:00+00:00",
        "status": "active",
    }


_INCIDENT_FIXTURES = {
    "credential-theft": _incident(
        "INC-CT-001",
        "Credential Exfiltration",
        ["203.0.113.10", "i-0abc123"],
        "Credential theft simulation",
    ),
    "mcp-compromise": _incident(
        "INC-MCP-001",
        "MCP Server Compromise",
        ["example.com", "i-0abc123"],
        "MCP compromise simulation",
    ),
    "dos-attack": _incident(
        "INC-DOS-001",
        "Denial of Service",
        ["198.51.100.10", "i-0abc123"],
        "DoS simulation",
    ),
}


def _mock_incident_simulator_module():
    def _create_incident(incident_type: str, severity: str = "P1") -> dict:
        incident = deepcopy(_INCIDENT_FIXTURES[incident_type])
        incident["severity"] = severity
        return incident

    return SimpleNamespace(create_incident=_create_incident)


def _recording_runner(
    recorded_commands: list[dict],
    *,
    impact_total_resources: int = 1,
    containment_stderr: str = "",
    failing_channel: str | None = None,
    ioc_report_payload: object | None = None,
    write_ioc_report: bool = True,
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

        if command_spec.get("script") == "scripts/incident-response/ioc-scanner.py" and write_ioc_report:
            output_args = list(command_spec.get("args", []))
            output_path = Path(output_args[output_args.index("--output") + 1])
            output_path.parent.mkdir(parents=True, exist_ok=True)
            report_payload = ioc_report_payload
            if report_payload is None:
                report_payload = {
                    "scan_timestamp": "2026-04-24T00:00:00+00:00",
                    "iocs_found": [],
                    "threat_score": 0,
                    "overall_threat_level": "LOW",
                }
            output_path.write_text(json.dumps(report_payload), encoding="utf-8")

        if command_spec.get("validation") == "impact_blast_radius":
            output_path = Path(command_spec["output_path"])
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(
                json.dumps({"blast_radius": {"total_resources": impact_total_resources}}),
                encoding="utf-8",
            )

        if failing_channel is not None and command_spec.get("channel") == failing_channel:
            return _completed_process(stderr=f"{failing_channel} failed", returncode=1)

        if containment_stderr and command_spec.get("script") == "scripts/incident-response/auto-containment.py":
            return _completed_process(stdout="containment attempted", stderr=containment_stderr)

        return _completed_process(stdout=f"ran {command_spec.get('script', 'unknown')}")

    return _run


def test_playbook_execute_dry_run_only_prints_plan(monkeypatch):
    recorded_commands: list[dict] = []
    monkeypatch.setattr(_CLI_MOD, "_run_command_spec", _recording_runner(recorded_commands))

    runner = CliRunner()
    result = runner.invoke(cli, ["playbook", "execute", "playbook-credential-theft", "--severity", "P0", "--dry-run"])

    assert result.exit_code == 0
    assert recorded_commands == []
    assert "[DRY RUN] Would execute scripts/incident-response/ioc-scanner.py" in result.output
    assert "[DRY RUN] Would execute scripts/forensics/collect_evidence.sh" in result.output


def test_playbook_execute_fails_closed_without_real_incident_data():
    runner = CliRunner()
    result = runner.invoke(cli, ["playbook", "execute", "playbook-credential-theft", "--severity", "P0", "--execute"])

    assert result.exit_code != 0
    assert "Detection phase requires real incident data" in result.output


def test_simulate_credential_theft_dispatches_all_phase_commands(monkeypatch):
    recorded_commands: list[dict] = []
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-token")
    monkeypatch.setattr(_CLI_MOD, "_load_tool_module", lambda _filename, _module_name: _mock_incident_simulator_module())
    monkeypatch.setattr(_CLI_MOD, "_run_command_spec", _recording_runner(recorded_commands))

    runner = CliRunner()
    result = runner.invoke(cli, ["simulate", "incident", "--type", "credential-theft", "--severity", "P1"])

    assert result.exit_code == 0
    assert "Routed playbook: playbook-credential-theft" in result.output
    assert [command["script"] for command in recorded_commands] == [
        "scripts/incident-response/ioc-scanner.py",
        "scripts/incident-response/auto-containment.py",
        "scripts/incident-response/impact-analyzer.py",
        "scripts/incident-response/notification-manager.py",
        "scripts/incident-response/notification-manager.py",
        "scripts/incident-response/notification-manager.py",
        "scripts/incident-response/forensics-collector.py",
        "scripts/forensics/collect_evidence.sh",
    ]
    assert recorded_commands[0]["args"][:2] == ["--ip", "203.0.113.10"]
    assert "--resource" in recorded_commands[2]["args"]
    assert recorded_commands[3]["channel"] == "slack"
    assert recorded_commands[4]["channel"] == "pagerduty"
    assert recorded_commands[5]["channel"] == "jira"
    assert any("credential-theft-impact-report.json" in arg for arg in recorded_commands[2]["args"])


def test_simulate_mcp_compromise_routes_to_distinct_artifacts(monkeypatch):
    recorded_commands: list[dict] = []
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-token")
    monkeypatch.setattr(_CLI_MOD, "_load_tool_module", lambda _filename, _module_name: _mock_incident_simulator_module())
    monkeypatch.setattr(_CLI_MOD, "_run_command_spec", _recording_runner(recorded_commands))

    runner = CliRunner()
    result = runner.invoke(cli, ["simulate", "incident", "--type", "mcp-compromise", "--severity", "P1"])

    assert result.exit_code == 0
    assert "Routed playbook: playbook-data-breach" in result.output
    assert recorded_commands[0]["args"][:2] == ["--domain", "example.com"]
    assert recorded_commands[1]["args"][2:6] == ["--action", "block_domain", "--domain", "compromised-mcp-gateway.xyz"]
    assert any("mcp-compromise-impact-report.json" in arg for arg in recorded_commands[2]["args"])


def test_simulate_dos_attack_routes_to_distinct_playbook(monkeypatch):
    recorded_commands: list[dict] = []
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-token")
    monkeypatch.setattr(_CLI_MOD, "_load_tool_module", lambda _filename, _module_name: _mock_incident_simulator_module())
    monkeypatch.setattr(_CLI_MOD, "_run_command_spec", _recording_runner(recorded_commands))

    runner = CliRunner()
    result = runner.invoke(cli, ["simulate", "incident", "--type", "dos-attack", "--severity", "P1"])

    assert result.exit_code == 0
    assert "Routed playbook: playbook-denial-of-service" in result.output
    assert recorded_commands[0]["args"][:2] == ["--ip", "198.51.100.10"]
    assert recorded_commands[1]["args"][2:6] == ["--action", "update_rate_limits", "--mode", "aggressive"]
    assert any("dos-attack-impact-report.json" in arg for arg in recorded_commands[2]["args"])


def test_recovery_fails_when_required_notification_channel_fails(monkeypatch):
    recorded_commands: list[dict] = []
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-token")
    monkeypatch.setattr(_CLI_MOD, "_load_tool_module", lambda _filename, _module_name: _mock_incident_simulator_module())
    monkeypatch.setattr(_CLI_MOD, "_run_command_spec", _recording_runner(recorded_commands, failing_channel="pagerduty"))

    runner = CliRunner()
    result = runner.invoke(cli, ["simulate", "incident", "--type", "credential-theft", "--severity", "P1"])

    assert result.exit_code != 0
    assert "Recovery phase failed while running scripts/incident-response/notification-manager.py" in result.output


def test_revoke_credentials_deny_policy_warning_fails_orchestration(monkeypatch):
    recorded_commands: list[dict] = []
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-token")
    monkeypatch.setattr(_CLI_MOD, "_load_tool_module", lambda _filename, _module_name: _mock_incident_simulator_module())
    monkeypatch.setattr(
        _CLI_MOD,
        "_run_command_spec",
        _recording_runner(recorded_commands, containment_stderr="Failed to apply deny policy"),
    )

    runner = CliRunner()
    result = runner.invoke(cli, ["simulate", "incident", "--type", "credential-theft", "--severity", "P1"])

    assert result.exit_code != 0
    assert "Containment phase did not complete the deny policy step for revoke-credentials" in result.output


def test_detection_fails_when_ioc_report_contains_error_status(monkeypatch):
    recorded_commands: list[dict] = []
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-token")
    monkeypatch.setattr(_CLI_MOD, "_load_tool_module", lambda _filename, _module_name: _mock_incident_simulator_module())
    monkeypatch.setattr(
        _CLI_MOD,
        "_run_command_spec",
        _recording_runner(
            recorded_commands,
            ioc_report_payload={"status": "error", "error": "upstream timeout"},
        ),
    )

    runner = CliRunner()
    result = runner.invoke(cli, ["simulate", "incident", "--type", "credential-theft", "--severity", "P1"])

    assert result.exit_code != 0
    assert "Detection phase IOC report indicates scanner failure" in result.output


def test_detection_fails_when_ioc_report_is_missing(monkeypatch):
    recorded_commands: list[dict] = []
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-token")
    monkeypatch.setattr(_CLI_MOD, "_load_tool_module", lambda _filename, _module_name: _mock_incident_simulator_module())
    monkeypatch.setattr(
        _CLI_MOD,
        "_run_command_spec",
        _recording_runner(recorded_commands, write_ioc_report=False),
    )

    runner = CliRunner()
    result = runner.invoke(cli, ["simulate", "incident", "--type", "credential-theft", "--severity", "P1"])

    assert result.exit_code != 0
    assert "Detection phase did not produce the expected IOC report" in result.output


def test_requested_cli_severity_drives_notification_policy(monkeypatch):
    recorded_commands: list[dict] = []
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-token")
    monkeypatch.setattr(_CLI_MOD, "_load_tool_module", lambda _filename, _module_name: _mock_incident_simulator_module())
    monkeypatch.setattr(_CLI_MOD, "_run_command_spec", _recording_runner(recorded_commands))

    runner = CliRunner()
    result = runner.invoke(cli, ["simulate", "incident", "--type", "credential-theft", "--severity", "P3"])

    assert result.exit_code == 0
    recovery_commands = [
        command for command in recorded_commands if command["script"] == "scripts/incident-response/notification-manager.py"
    ]
    assert [command["channel"] for command in recovery_commands] == ["slack", "jira"]
    assert {
        command["args"][command["args"].index("--severity") + 1] for command in recovery_commands
    } == {"LOW"}


def test_detection_uses_later_scannable_target_when_earlier_domain_fails_dns(monkeypatch):
    recorded_commands: list[dict] = []
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-token")

    def _create_incident(incident_type: str, severity: str = "P1") -> dict:
        return {
            "incident_id": "INC-DNS-001",
            "type": "Credential Exfiltration",
            "severity": severity,
            "affected_resources": ["broken.invalid", "203.0.113.10", "i-0abc123"],
            "description": "DNS failure fallback simulation",
            "detected_at": "2026-04-24T00:00:00+00:00",
            "status": "active",
        }

    monkeypatch.setattr(_CLI_MOD, "_load_tool_module", lambda _filename, _module_name: SimpleNamespace(create_incident=_create_incident))
    monkeypatch.setattr(
        _CLI_MOD.socket,
        "gethostbyname",
        lambda resource: (_ for _ in ()).throw(_CLI_MOD.socket.gaierror("dns failed")) if resource == "broken.invalid" else "203.0.113.10",
    )
    monkeypatch.setattr(_CLI_MOD, "_run_command_spec", _recording_runner(recorded_commands))

    runner = CliRunner()
    result = runner.invoke(cli, ["simulate", "incident", "--type", "credential-theft", "--severity", "P1"])

    assert result.exit_code == 0
    assert recorded_commands[0]["args"][:2] == ["--ip", "203.0.113.10"]


@pytest.mark.parametrize("incident_type", ["credential-theft", "mcp-compromise", "dos-attack"])
def test_shipped_simulator_payloads_satisfy_hardened_orchestration(monkeypatch, incident_type):
    recorded_commands: list[dict] = []
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-token")
    monkeypatch.setattr(_CLI_MOD.socket, "gethostbyname", lambda _resource: "203.0.113.10")
    monkeypatch.setattr(_CLI_MOD, "_run_command_spec", _recording_runner(recorded_commands))

    runner = CliRunner()
    result = runner.invoke(cli, ["simulate", "incident", "--type", incident_type, "--severity", "P1"])

    assert result.exit_code == 0
    assert recorded_commands