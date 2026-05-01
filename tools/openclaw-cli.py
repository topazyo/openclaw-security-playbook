#!/usr/bin/env python3
"""
OpenClaw Security CLI

Main command-line interface for OpenClaw Security operations.
Provides subcommands for scanning, playbooks, reporting, and configuration.
Run from repo root:
    python tools/openclaw-cli.py --help

Subcommands:
  scan       - Run security scans (vulnerability, compliance, access)
  playbook   - Execute incident response playbooks
  report     - Generate security reports (weekly, compliance, audit)
  config     - Validate and migrate configurations
  simulate   - Simulate security incidents for testing

Usage:
  openclaw-cli scan --type vulnerability --target production
  openclaw-cli playbook list
  openclaw-cli playbook execute playbook-credential-theft --severity P0
  openclaw-cli playbook execute IRP-001 --severity P0          # same, by Playbook ID
  openclaw-cli report compliance --framework SOC2
  openclaw-cli config validate openclaw-agent.yml
  openclaw-cli simulate incident --type credential-theft

Installation:
  pip install click pyyaml boto3 requests tabulate
  python openclaw-cli.py --help
"""

import click
import builtins  # FIX: C5-finding-2
import ipaddress
import json
import os
import socket
import sys
import subprocess  # nosec B404
import importlib.util
import shutil
from pathlib import Path
from datetime import UTC, datetime, timedelta

try:
    from tabulate import tabulate
except ModuleNotFoundError:
    def tabulate(rows, headers):
        rendered = [" | ".join(headers)]
        rendered.extend(" | ".join(str(cell) for cell in row) for row in rows)
        return "\n".join(rendered)


REPO_ROOT = Path(__file__).resolve().parent.parent
TOOLS_DIR = Path(__file__).resolve().parent
EXECUTION_LOG_FILE = "execution.log"
PLAYBOOK_PHASES = ["Detection", "Containment", "Eradication", "Recovery", "PIR"]  # FIX: C5-finding-2
PLAYBOOK_EXECUTION_PROFILES = {  # FIX: C5-finding-2
    "playbook-credential-theft": {  # FIX: C5-finding-2
        "incident_slug": "credential-theft",  # FIX: C5-finding-2
        "notification_severity": "HIGH",  # FIX: C5-finding-2
        "ioc_domain": "credential-reset-alerts.xyz",  # FIX: C5-finding-2
        "containment_args": ["--action", "revoke-credentials", "--target", "user:compromised-user"],  # FIX: C5-finding-2
        "impact_args": ["--data-types", "Credentials", "--users", "1", "--downtime", "1"],  # FIX: C5-finding-2
        "notification_message": "Credential-theft response executing. Rotate compromised credentials and validate provider activity immediately.",  # FIX: C5-finding-2
    },  # FIX: C5-finding-2
    "playbook-skill-compromise": {  # FIX: C5-finding-2
        "incident_slug": "skill-compromise",  # FIX: C5-finding-2
        "notification_severity": "CRITICAL",  # FIX: C5-finding-2
        "ioc_domain": "skill-quarantine-control.xyz",  # FIX: C5-finding-2
        "containment_args": ["--action", "isolate_container", "--target", "container:agent-prod-42", "--reason", "Potential malicious skill execution"],  # FIX: C5-finding-2
        "impact_args": ["--data-types", "Internal", "--users", "12", "--downtime", "2"],  # FIX: C5-finding-2
        "notification_message": "Skill-compromise response executing. Quarantine affected skill runtimes and inspect persistence paths.",  # FIX: C5-finding-2
    },  # FIX: C5-finding-2
    "playbook-prompt-injection": {  # FIX: C5-finding-2
        "incident_slug": "prompt-injection",  # FIX: C5-finding-2
        "notification_severity": "HIGH",  # FIX: C5-finding-2
        "ioc_domain": "prompt-sanitizer-review.xyz",  # FIX: C5-finding-2
        "containment_args": ["--action", "block_domain", "--domain", "prompt-injection-collector.xyz", "--reason", "Prompt injection containment"],  # FIX: C5-finding-2
        "impact_args": ["--data-types", "Internal", "--users", "5", "--downtime", "1"],  # FIX: C5-finding-2
        "notification_message": "Prompt-injection response executing. Review untrusted content flows before restoring normal operations.",  # FIX: C5-finding-2
    },  # FIX: C5-finding-2
    "playbook-data-breach": {  # FIX: C5-finding-2
        "incident_slug": "data-breach",  # FIX: C5-finding-2
        "notification_severity": "CRITICAL",  # FIX: C5-finding-2
        "ioc_domain": "breach-disclosure-review.xyz",  # FIX: C5-finding-2
        "containment_args": ["--action", "block_domain", "--domain", "exfiltration-endpoint.xyz", "--reason", "Data exfiltration containment"],  # FIX: C5-finding-2
        "impact_args": ["--data-types", "PII,Credentials", "--users", "234", "--downtime", "4"],  # FIX: C5-finding-2
        "notification_message": "Data-breach response executing. Notify security, legal, and privacy owners with current scope.",  # FIX: C5-finding-2
    },  # FIX: C5-finding-2
    "playbook-denial-of-service": {  # FIX: C5-finding-2
        "incident_slug": "dos-attack",  # FIX: C5-finding-2
        "notification_severity": "CRITICAL",  # FIX: C5-finding-2
        "ioc_domain": "rate-limit-escalation.xyz",  # FIX: C5-finding-2
        "containment_args": ["--action", "update_rate_limits", "--mode", "aggressive", "--limits", '{"per_ip_per_minute": 10, "per_user_per_minute": 20, "global_per_second": 500}', "--reason", "DoS containment"],  # FIX: C5-finding-2
        "impact_args": ["--data-types", "Availability", "--users", "500", "--downtime", "3"],  # FIX: C5-finding-2
        "notification_message": "DoS response executing. Tighten rate limits, confirm service health, and track attacker pressure.",  # FIX: C5-finding-2
    },  # FIX: C5-finding-2
}  # FIX: C5-finding-2
SIMULATED_INCIDENT_PLAYBOOKS = {  # FIX: C5-finding-8
    "credential-theft": "playbook-credential-theft",  # FIX: C5-finding-8
    "mcp-compromise": "playbook-data-breach",  # FIX: C5-finding-8
    "dos-attack": "playbook-denial-of-service",  # FIX: C5-finding-8
}  # FIX: C5-finding-8
SIMULATED_INCIDENT_OVERRIDES = {  # FIX: C5-finding-8
    "credential-theft": {  # FIX: C5-finding-8
        "incident_slug": "credential-theft",  # FIX: C5-finding-8
        "notification_message": "Simulated credential-theft response executing. Validate credential rotation and provider audit log review.",  # FIX: C5-finding-8
    },  # FIX: C5-finding-8
    "mcp-compromise": {  # FIX: C5-finding-8
        "incident_slug": "mcp-compromise",  # FIX: C5-finding-8
        "ioc_domain": "slack-mcp-server-compromise.xyz",  # FIX: C5-finding-8
        "containment_args": ["--action", "block_domain", "--domain", "compromised-mcp-gateway.xyz", "--reason", "MCP server compromise containment"],  # FIX: C5-finding-8
        "impact_args": ["--data-types", "Credentials,Internal", "--users", "48", "--downtime", "2"],  # FIX: C5-finding-8
        "notification_message": "Simulated MCP-compromise response executing. Contain the compromised MCP path and review lateral movement indicators.",  # FIX: C5-finding-8
    },  # FIX: C5-finding-8
    "dos-attack": {  # FIX: C5-finding-8
        "incident_slug": "dos-attack",  # FIX: C5-finding-8
        "notification_message": "Simulated DoS response executing. Confirm aggressive rate limiting and capacity protection actions.",  # FIX: C5-finding-8
    },  # FIX: C5-finding-8
}  # FIX: C5-finding-8


def _load_tool_module(filename: str, module_name: str):
    module_path = (TOOLS_DIR / filename).resolve()
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load module: {filename}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_clawdbot_module(module_name: str):
    """Load a backend module from src/clawdbot/ by name.

    Tries a standard package import first (works after ``pip install -e .``),
    then falls back to explicit file-path loading so the CLI also works when
    invoked directly as ``python tools/openclaw-cli.py``.
    """
    try:
        import importlib as _il
        return _il.import_module(f"clawdbot.{module_name}")
    except ImportError:
        pass
    mod_path = (REPO_ROOT / "src" / "clawdbot" / f"{module_name}.py").resolve()
    spec = importlib.util.spec_from_file_location(f"clawdbot_{module_name}", mod_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(
            f"Unable to load clawdbot.{module_name} — "
            f"not found at {mod_path}.  Run 'pip install -e .' from the repo root."
        )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _validate_output_path(output_path: str) -> Path:
    path = Path(output_path).expanduser().resolve()

    blocked_roots = [Path("/etc"), Path("/usr"), Path("/bin"), Path("/sbin"), Path("/var")]
    blocked_roots.extend([
        Path("C:/Windows"),
        Path("C:/Program Files"),
        Path("C:/Program Files (x86)"),
    ])

    for blocked in blocked_roots:
        if blocked in path.parents or path == blocked:
            raise click.ClickException(f"Cannot write to system directory: {path}")

    config_root = (REPO_ROOT / "configs").resolve()
    if config_root in path.parents:
        raise click.ClickException(f"Refusing to overwrite configuration files: {path}")

    return path


def _run_python_tool(relative_script: str, args: list[str]) -> subprocess.CompletedProcess[str]:
    script_path = (REPO_ROOT / relative_script).resolve()
    return subprocess.run(  # nosec B603
        [sys.executable, str(script_path), *args],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def _run_shell_tool(relative_script: str, args: list[str]) -> subprocess.CompletedProcess[str]:  # FIX: C5-finding-2
    script_path = (REPO_ROOT / relative_script).resolve()  # FIX: C5-finding-2
    shell_executable = shutil.which("bash") or shutil.which("sh")  # FIX: C5-finding-2
    if shell_executable is None:  # FIX: C5-finding-2
        raise RuntimeError(f"No shell interpreter available for {relative_script}")  # FIX: C5-finding-2
    return subprocess.run(  # nosec B603
        [shell_executable, str(script_path), *args],  # FIX: C5-finding-2
        cwd=REPO_ROOT,  # FIX: C5-finding-2
        capture_output=True,  # FIX: C5-finding-2
        text=True,  # FIX: C5-finding-2
        check=False,  # FIX: C5-finding-2
    )  # FIX: C5-finding-2


def _build_execution_profile(playbook_stem: str, incident_slug: str | None = None, overrides: dict | None = None) -> dict:  # FIX: C5-finding-2
    profile = dict(PLAYBOOK_EXECUTION_PROFILES.get(playbook_stem, {}))  # FIX: C5-finding-2
    profile.setdefault("incident_slug", incident_slug or playbook_stem.replace("playbook-", ""))  # FIX: C5-finding-2
    profile.setdefault("notification_severity", "HIGH")  # FIX: C5-finding-2
    profile.setdefault("ioc_domain", f"{profile['incident_slug']}.xyz")  # FIX: C5-finding-2
    profile.setdefault("containment_args", ["--action", "block_domain", "--domain", f"{profile['incident_slug']}-containment.xyz", "--reason", f"{profile['incident_slug']} containment"])  # FIX: C5-finding-2
    profile.setdefault("impact_args", ["--data-types", "Internal", "--users", "1", "--downtime", "1"])  # FIX: C5-finding-2
    profile.setdefault("notification_message", f"{profile['incident_slug']} response executing.")  # FIX: C5-finding-2
    if overrides:  # FIX: C5-finding-2
        profile.update(overrides)  # FIX: C5-finding-2
    return profile  # FIX: C5-finding-2


def _build_incident_artifact_paths(incident_slug: str, incident_id: str, create: bool = False) -> dict:  # FIX: C5-finding-2
    artifact_root = REPO_ROOT / "tmp" / "cli-orchestration" / incident_slug / incident_id  # FIX: C5-finding-2
    if create:  # FIX: C5-finding-2
        artifact_root.mkdir(parents=True, exist_ok=True)  # FIX: C5-finding-2
    return {  # FIX: C5-finding-2
        "root": artifact_root,  # FIX: C5-finding-2
        "ioc_report": artifact_root / f"{incident_slug}-ioc-report.json",  # FIX: C5-finding-2
        "impact_report": artifact_root / f"{incident_slug}-impact-report.json",  # FIX: C5-finding-2
        "forensics_dir": artifact_root / "forensics",  # FIX: C5-finding-2
    }  # FIX: C5-finding-2


def _notification_severity_for_cli_severity(cli_severity: str, fallback_severity: str) -> str:  # FIX: C5-finding-2
    severity_map = {"P0": "CRITICAL", "P1": "HIGH", "P2": "MEDIUM", "P3": "LOW"}  # FIX: C5-finding-2
    return severity_map.get(cli_severity, fallback_severity)  # FIX: C5-finding-2


def _required_notification_channels(notification_severity: str) -> list[str]:  # FIX: C5-finding-2
    channels = ["slack", "jira"]  # FIX: C5-finding-2
    if notification_severity in {"CRITICAL", "HIGH"}:  # FIX: C5-finding-2
        channels.insert(1, "pagerduty")  # FIX: C5-finding-2
    return channels  # FIX: C5-finding-2


def _select_detection_target(incident_data: dict | None, require_real: bool) -> tuple[str, str] | None:  # FIX: C5-finding-2
    if not incident_data:  # FIX: C5-finding-2
        if require_real:  # FIX: C5-finding-2
            raise click.ClickException("Detection phase requires real incident data; no incident context was provided")  # FIX: C5-finding-2
        return None  # FIX: C5-finding-2

    dns_failures = []  # FIX: C5-finding-2
    for resource in incident_data.get("affected_resources", []):  # FIX: C5-finding-2
        try:  # FIX: C5-finding-2
            ipaddress.ip_address(resource)  # FIX: C5-finding-2
            if not os.getenv("ABUSEIPDB_API_KEY"):  # FIX: C5-finding-2
                raise click.ClickException("Detection phase requires ABUSEIPDB_API_KEY for real IP reputation checks")  # FIX: C5-finding-2
            return ("ip", resource)  # FIX: C5-finding-2
        except ValueError:  # FIX: C5-finding-2
            pass  # FIX: C5-finding-2

        if "." not in resource:  # FIX: C5-finding-2
            continue  # FIX: C5-finding-2

        try:  # FIX: C5-finding-2
            socket.gethostbyname(resource)  # FIX: C5-finding-2
        except socket.gaierror as exc:  # FIX: C5-finding-2
            dns_failures.append((resource, exc))  # FIX: C5-finding-2
            continue  # FIX: C5-finding-2

        if not os.getenv("ABUSEIPDB_API_KEY"):  # FIX: C5-finding-2
            raise click.ClickException("Detection phase requires ABUSEIPDB_API_KEY for real domain reputation checks")  # FIX: C5-finding-2
        return ("domain", resource)  # FIX: C5-finding-2

    if require_real:  # FIX: C5-finding-2
        if dns_failures:  # FIX: C5-finding-2
            failed_resource, failed_error = dns_failures[0]  # FIX: C5-finding-2
            raise click.ClickException(f"Detection phase requires a resolvable incident target; DNS failed for {failed_resource}: {failed_error}")  # FIX: C5-finding-2
        raise click.ClickException("Detection phase requires a real IOC target from incident data; none of the affected resources are scannable")  # FIX: C5-finding-2
    return None  # FIX: C5-finding-2


def _select_blast_radius_resource(incident_data: dict | None, require_real: bool) -> str | None:  # FIX: C5-finding-2
    if not incident_data:  # FIX: C5-finding-2
        if require_real:  # FIX: C5-finding-2
            raise click.ClickException("Eradication phase requires real incident data; no incident context was provided")  # FIX: C5-finding-2
        return None  # FIX: C5-finding-2

    affected_resources = tuple(incident_data.get("affected_resources", []))  # FIX: C5-finding-2
    ec2_resource = next((resource for resource in affected_resources if resource.startswith("i-")), None)  # FIX: C5-finding-2
    if ec2_resource is not None:  # FIX: C5-finding-2
        return ec2_resource  # FIX: C5-finding-2

    if affected_resources and require_real:  # FIX: C5-finding-2
        raise click.ClickException("Eradication phase requires a blast-radius resource supported by impact-analyzer; current incident resources are unsupported")  # FIX: C5-finding-2
    return None  # FIX: C5-finding-2


def _build_phase_command_specs(playbook_stem: str, severity: str, incident_id: str, incident_slug: str | None = None, overrides: dict | None = None, create_artifacts: bool = False, incident_data: dict | None = None, require_real_inputs: bool = False) -> list[dict]:  # FIX: C5-finding-2
    profile = _build_execution_profile(playbook_stem, incident_slug=incident_slug, overrides=overrides)  # FIX: C5-finding-2
    artifact_paths = _build_incident_artifact_paths(profile["incident_slug"], incident_id, create=create_artifacts)  # FIX: C5-finding-2
    notification_severity = _notification_severity_for_cli_severity(severity, profile["notification_severity"])  # FIX: C5-finding-2
    detection_target = _select_detection_target(incident_data, require_real=require_real_inputs)  # FIX: C5-finding-2
    impact_resource = _select_blast_radius_resource(incident_data, require_real=require_real_inputs)  # FIX: C5-finding-2

    if detection_target is None:  # FIX: C5-finding-2
        detection_args = ["--domain", "<real-incident-target-required>", "--output", str(artifact_paths["ioc_report"])]  # FIX: C5-finding-2
    else:  # FIX: C5-finding-2
        detection_args = [f"--{detection_target[0]}", detection_target[1], "--output", str(artifact_paths["ioc_report"])]  # FIX: C5-finding-2

    impact_args = ["--incident", incident_id, *profile["impact_args"], "--output", str(artifact_paths["impact_report"])]  # FIX: C5-finding-2
    if impact_resource is not None:  # FIX: C5-finding-2
        impact_args[2:2] = ["--resource", impact_resource]  # FIX: C5-finding-2

    recovery_commands = [  # FIX: C5-finding-2
        {
            "kind": "python",  # FIX: C5-finding-2
            "script": "scripts/incident-response/notification-manager.py",  # FIX: C5-finding-2
            "args": ["--incident", incident_id, "--severity", notification_severity, "--channel", channel, "--message", profile["notification_message"]],  # FIX: C5-finding-2
            "channel": channel,  # FIX: C5-finding-2
        }
        for channel in _required_notification_channels(notification_severity)  # FIX: C5-finding-2
    ]  # FIX: C5-finding-2

    command_specs = [  # FIX: C5-finding-2
        {  # FIX: C5-finding-2
            "phase": "Detection",  # FIX: C5-finding-2
            "kind": "python",  # FIX: C5-finding-2
            "script": "scripts/incident-response/ioc-scanner.py",  # FIX: C5-finding-2
            "args": detection_args,  # FIX: C5-finding-2
            "validation": "ioc_report",  # FIX: C5-finding-2
            "output_path": str(artifact_paths["ioc_report"]),  # FIX: C5-finding-2
            "expected_output_fields": ["scan_timestamp", "iocs_found", "threat_score", "overall_threat_level"],  # FIX: C5-finding-2
        },  # FIX: C5-finding-2
        {  # FIX: C5-finding-2
            "phase": "Containment",  # FIX: C5-finding-2
            "kind": "python",  # FIX: C5-finding-2
            "script": "scripts/incident-response/auto-containment.py",  # FIX: C5-finding-2
            "args": ["--incident", incident_id, *profile["containment_args"]],  # FIX: C5-finding-2
            "failure_markers": ["Failed to apply deny policy"] if profile["containment_args"][:2] == ["--action", "revoke-credentials"] else [],  # FIX: C5-finding-2
            "failure_message": "Containment phase did not complete the deny policy step for revoke-credentials",  # FIX: C5-finding-2
        },  # FIX: C5-finding-2
        {  # FIX: C5-finding-2
            "phase": "Eradication",  # FIX: C5-finding-2
            "kind": "python",  # FIX: C5-finding-2
            "script": "scripts/incident-response/impact-analyzer.py",  # FIX: C5-finding-2
            "args": impact_args,  # FIX: C5-finding-2
            "validation": "impact_blast_radius",  # FIX: C5-finding-2
            "output_path": str(artifact_paths["impact_report"]),  # FIX: C5-finding-2
            "require_non_empty_blast_radius": bool(incident_data and incident_data.get("affected_resources")),  # FIX: C5-finding-2
        },  # FIX: C5-finding-2
        {  # FIX: C5-finding-2
            "phase": "Recovery",  # FIX: C5-finding-2
            "commands": recovery_commands,  # FIX: C5-finding-2
        },  # FIX: C5-finding-2
        {  # FIX: C5-finding-2
            "phase": "PIR",  # FIX: C5-finding-2
            "kind": "python",  # FIX: C5-finding-2
            "script": "scripts/incident-response/forensics-collector.py",  # FIX: C5-finding-2
            "args": ["--incident", incident_id, "--level", "quick", "--no-memory", "--no-network"],  # FIX: C5-finding-2
            "env": {"EVIDENCE_DIR": str(artifact_paths["forensics_dir"])},  # FIX: C5-finding-2
        },  # FIX: C5-finding-2
    ]  # FIX: C5-finding-2
    return command_specs  # FIX: C5-finding-2


def _format_command_spec(command_spec: dict) -> str:  # FIX: C5-finding-2
    executable = sys.executable if command_spec["kind"] == "python" else "bash"  # FIX: C5-finding-2
    return " ".join([executable, command_spec["script"], *command_spec.get("args", [])])  # FIX: C5-finding-2


def _run_command_spec(command_spec: dict) -> subprocess.CompletedProcess[str]:  # FIX: C5-finding-2
    extra_env = command_spec.get("env", {})  # FIX: C5-finding-2
    original_env = {}  # FIX: C5-finding-2
    try:  # FIX: C5-finding-2
        for key, value in extra_env.items():  # FIX: C5-finding-2
            original_env[key] = os.environ.get(key)  # FIX: C5-finding-2
            os.environ[key] = value  # FIX: C5-finding-2
        if command_spec["kind"] == "python":  # FIX: C5-finding-2
            return _run_python_tool(command_spec["script"], command_spec.get("args", []))  # FIX: C5-finding-2
        return _run_shell_tool(command_spec["script"], command_spec.get("args", []))  # FIX: C5-finding-2
    finally:  # FIX: C5-finding-2
        for key, value in original_env.items():  # FIX: C5-finding-2
            if value is None:  # FIX: C5-finding-2
                os.environ.pop(key, None)  # FIX: C5-finding-2
            else:  # FIX: C5-finding-2
                os.environ[key] = value  # FIX: C5-finding-2


def _validate_command_result(command_spec: dict, result: subprocess.CompletedProcess[str]):  # FIX: C5-finding-2
    combined_output = "\n".join(part for part in [result.stdout, result.stderr] if part)  # FIX: C5-finding-2
    for failure_marker in command_spec.get("failure_markers", []):  # FIX: C5-finding-2
        if failure_marker in combined_output:  # FIX: C5-finding-2
            raise click.ClickException(command_spec.get("failure_message", f"Command validation failed for {command_spec['script']}"))  # FIX: C5-finding-2

    if command_spec.get("validation") == "ioc_report":  # FIX: C5-finding-2
        report_path = Path(command_spec["output_path"])  # FIX: C5-finding-2
        if not report_path.exists():  # FIX: C5-finding-2
            raise click.ClickException(f"Detection phase did not produce the expected IOC report: {report_path}")  # FIX: C5-finding-2
        try:  # FIX: C5-finding-2
            with open(report_path, encoding="utf-8") as ioc_report_file:  # FIX: C5-finding-2
                ioc_report = json.load(ioc_report_file)  # FIX: C5-finding-2
        except json.JSONDecodeError as exc:  # FIX: C5-finding-2
            raise click.ClickException(f"Detection phase produced an invalid IOC report: {report_path}: {exc}") from exc  # FIX: C5-finding-2
        if not isinstance(ioc_report, dict):  # FIX: C5-finding-2
            raise click.ClickException("Detection phase IOC report must be a JSON object")  # FIX: C5-finding-2
        status_values = []  # FIX: C5-finding-2
        pending_values = [ioc_report]  # FIX: C5-finding-2
        while pending_values:  # FIX: C5-finding-2
            current_value = pending_values.pop()  # FIX: C5-finding-2
            if isinstance(current_value, dict):  # FIX: C5-finding-2
                current_status = current_value.get("status")  # FIX: C5-finding-2
                if isinstance(current_status, str):  # FIX: C5-finding-2
                    status_values.append(current_status.lower())  # FIX: C5-finding-2
                pending_values.extend(current_value.values())  # FIX: C5-finding-2
            elif isinstance(current_value, builtins.list):  # FIX: C5-finding-2
                pending_values.extend(current_value)  # FIX: C5-finding-2
        if any(status in {"error", "skipped"} for status in status_values):  # FIX: C5-finding-2
            raise click.ClickException("Detection phase IOC report indicates scanner failure")  # FIX: C5-finding-2
        missing_fields = [field for field in command_spec.get("expected_output_fields", []) if field not in ioc_report]  # FIX: C5-finding-2
        if missing_fields:  # FIX: C5-finding-2
            raise click.ClickException(f"Detection phase IOC report is missing expected output fields: {', '.join(missing_fields)}")  # FIX: C5-finding-2
        if not ioc_report.get("scan_timestamp") or not ioc_report.get("overall_threat_level"):  # FIX: C5-finding-2
            raise click.ClickException("Detection phase IOC report contains empty expected output")  # FIX: C5-finding-2
        if not isinstance(ioc_report.get("iocs_found"), builtins.list):  # FIX: C5-finding-2
            raise click.ClickException("Detection phase IOC report must include an iocs_found list")  # FIX: C5-finding-2
        if not isinstance(ioc_report.get("threat_score"), (int, float)):  # FIX: C5-finding-2
            raise click.ClickException("Detection phase IOC report must include a numeric threat_score")  # FIX: C5-finding-2

    if command_spec.get("validation") == "impact_blast_radius":  # FIX: C5-finding-2
        report_path = Path(command_spec["output_path"])  # FIX: C5-finding-2
        if not report_path.exists():  # FIX: C5-finding-2
            raise click.ClickException(f"Eradication phase did not produce the expected impact report: {report_path}")  # FIX: C5-finding-2
        with open(report_path, encoding="utf-8") as impact_report_file:  # FIX: C5-finding-2
            impact_report = json.load(impact_report_file)  # FIX: C5-finding-2
        blast_radius = impact_report.get("blast_radius", {}) if isinstance(impact_report, dict) else {}  # FIX: C5-finding-2
        total_resources = blast_radius.get("total_resources", 0) if isinstance(blast_radius, dict) else 0  # FIX: C5-finding-2
        if command_spec.get("require_non_empty_blast_radius") and total_resources < 1:  # FIX: C5-finding-2
            raise click.ClickException("Eradication phase produced an empty blast radius for an incident with affected resources")  # FIX: C5-finding-2


def _build_evidence_command_spec() -> dict:  # FIX: C5-finding-2
    return {  # FIX: C5-finding-2
        "phase": "Evidence",  # FIX: C5-finding-2
        "kind": "shell",  # FIX: C5-finding-2
        "script": "scripts/forensics/collect_evidence.sh",  # FIX: C5-finding-2
        "args": [],  # FIX: C5-finding-2
    }  # FIX: C5-finding-2


def _execute_playbook_orchestration(ctx, playbook_id: str, severity: str, dry_run: bool, execute_flag: bool = False, incident_slug: str | None = None, overrides: dict | None = None, incident_id: str | None = None, incident_data: dict | None = None) -> dict:  # FIX: C5-finding-2
    playbook_path = _resolve_playbook(playbook_id)  # FIX: C5-finding-2
    if playbook_path is None:  # FIX: C5-finding-2
        click.secho(  # FIX: C5-finding-2
            f"[✗] Playbook not found for '{playbook_id}'.\n"  # FIX: C5-finding-2
            "    Run 'openclaw-cli playbook list' to see available playbooks.",  # FIX: C5-finding-2
            fg="red",  # FIX: C5-finding-2
        )  # FIX: C5-finding-2
        ctx.exit(1)  # FIX: C5-finding-2
        return {"success": False, "playbook_path": None, "incident_id": None}  # FIX: C5-finding-2
    if dry_run and execute_flag:  # FIX: C5-finding-2
        raise click.ClickException("Use either --dry-run or --execute, not both")  # FIX: C5-finding-2
    effective_execute = execute_flag or not dry_run  # FIX: C5-finding-2
    execution_profile = _build_execution_profile(playbook_path.stem, incident_slug=incident_slug, overrides=overrides)  # FIX: C5-finding-2
    active_incident_id = incident_id or f"INC-{execution_profile['incident_slug'].upper()}-{datetime.now(UTC).strftime('%Y%m%d-%H%M%S')}"  # FIX: C5-finding-2
    click.echo(f"[*] Executing playbook {playbook_path.stem} (severity: {severity})...")  # FIX: C5-finding-2
    click.echo(f"[*] Playbook file: {playbook_path}")  # FIX: C5-finding-2
    click.echo(f"[*] Incident ID: {active_incident_id}")  # FIX: C5-finding-2
    if dry_run:  # FIX: C5-finding-2
        click.echo("[*] DRY RUN - No changes will be made")  # FIX: C5-finding-2
    command_specs = _build_phase_command_specs(  # FIX: C5-finding-2
        playbook_path.stem,  # FIX: C5-finding-2
        severity,  # FIX: C5-finding-2
        active_incident_id,  # FIX: C5-finding-2
        incident_slug=execution_profile["incident_slug"],  # FIX: C5-finding-2
        overrides=execution_profile,  # FIX: C5-finding-2
        create_artifacts=effective_execute,  # FIX: C5-finding-2
        incident_data=incident_data,  # FIX: C5-finding-2
        require_real_inputs=effective_execute,  # FIX: C5-finding-2
    )  # FIX: C5-finding-2
    for phase_name in PLAYBOOK_PHASES:  # FIX: C5-finding-2
        phase_command = next(spec for spec in command_specs if spec["phase"] == phase_name)  # FIX: C5-finding-2
        click.echo(f"\n[*] Phase: {phase_name}")  # FIX: C5-finding-2
        phase_commands = phase_command.get("commands", [phase_command])  # FIX: C5-finding-2
        for subcommand in phase_commands:  # FIX: C5-finding-2
            click.echo(f"    Command: {_format_command_spec(subcommand)}")  # FIX: C5-finding-2
            if not effective_execute:  # FIX: C5-finding-2
                click.echo(f"    [DRY RUN] Would execute {subcommand['script']}")  # FIX: C5-finding-2
                continue  # FIX: C5-finding-2
            if subcommand.get("output_path"):  # FIX: C5-finding-2
                Path(subcommand["output_path"]).unlink(missing_ok=True)  # FIX: C5-finding-2
            phase_result = _run_command_spec(subcommand)  # FIX: C5-finding-2
            if phase_result.stdout:  # FIX: C5-finding-2
                click.echo(phase_result.stdout.rstrip())  # FIX: C5-finding-2
            if phase_result.returncode != 0:  # FIX: C5-finding-2
                if phase_result.stderr:  # FIX: C5-finding-2
                    click.echo(phase_result.stderr.rstrip())  # FIX: C5-finding-2
                raise click.ClickException(f"{phase_name} phase failed while running {subcommand['script']}")  # FIX: C5-finding-2
            _validate_command_result(subcommand, phase_result)  # FIX: C5-finding-2
            if phase_result.stderr:  # FIX: C5-finding-2
                click.echo(phase_result.stderr.rstrip())  # FIX: C5-finding-2
    evidence_command = _build_evidence_command_spec()  # FIX: C5-finding-2
    click.echo("\n[*] Post-Phase Evidence Collection")  # FIX: C5-finding-2
    click.echo(f"    Command: {_format_command_spec(evidence_command)}")  # FIX: C5-finding-2
    if not effective_execute:  # FIX: C5-finding-2
        click.echo(f"    [DRY RUN] Would execute {evidence_command['script']}")  # FIX: C5-finding-2
    else:  # FIX: C5-finding-2
        evidence_result = _run_command_spec(evidence_command)  # FIX: C5-finding-2
        if evidence_result.stdout:  # FIX: C5-finding-2
            click.echo(evidence_result.stdout.rstrip())  # FIX: C5-finding-2
        if evidence_result.returncode != 0:  # FIX: C5-finding-2
            if evidence_result.stderr:  # FIX: C5-finding-2
                click.echo(evidence_result.stderr.rstrip())  # FIX: C5-finding-2
            raise click.ClickException(f"Evidence collection failed while running {evidence_command['script']}")  # FIX: C5-finding-2
    click.secho(f"\n[✓] Playbook {playbook_path.stem} {'planned' if not effective_execute else 'executed'} for incident {active_incident_id}", fg="green")  # FIX: C5-finding-2
    return {"success": True, "playbook_path": playbook_path, "incident_id": active_incident_id, "incident_slug": execution_profile["incident_slug"]}  # FIX: C5-finding-2


def _resolve_playbook(playbook_id: str) -> "Path | None":
    """Resolve a playbook reference to its Path.

    Accepts either:
    - A filename stem:   ``playbook-credential-theft``
    - A Playbook ID:     ``IRP-001``

    Returns the Path if found, otherwise None.
    """
    import re as _re
    playbooks_dir = REPO_ROOT / "examples" / "incident-response"

    # Direct filename match
    direct = playbooks_dir / f"{playbook_id}.md"
    if direct.exists():
        return direct

    # Search for a matching Playbook ID header inside the shipped files
    _re_irp = _re.compile(r"\*\*Playbook ID\*\*:\s+" + _re.escape(playbook_id) + r"\b")
    for p in sorted(playbooks_dir.glob("playbook-*.md")):
        with open(p, encoding="utf-8") as f:
            for line in f:
                if _re_irp.search(line):
                    return p
                # Stop scanning past the front-matter block
                if line.startswith("## "):
                    break

    return None


# ============================================================================
# CLI GROUP
# ============================================================================

@click.group()
@click.version_option(version="1.0.0", prog_name="openclaw-cli")
@click.option("--config", type=click.Path(), help="Path to configuration file")
@click.option("--verbose", is_flag=True, help="Enable verbose output")
@click.pass_context
def cli(ctx, config, verbose):
    """OpenClaw Security CLI - Security automation toolkit."""
    ctx.ensure_object(dict)
    ctx.obj["config"] = config
    ctx.obj["verbose"] = verbose
    
    if verbose:
        click.echo(f"[INFO] OpenClaw CLI v1.0.0")
        click.echo(f"[INFO] Config: {config or 'default'}")


# ============================================================================
# SCAN COMMANDS
# ============================================================================

@cli.group()
def scan():
    """Run security scans."""
    pass


@scan.command()
@click.option("--target", required=True, help="Scan target label stored in the report (production/staging/dev)")
@click.option("--output", type=click.Path(), help="Write the JSON result to this file")
@click.option(
    "--profile",
    default="local",
    type=click.Choice(["local", "ci"]),
    help="local: filesystem tools only.  ci: also build and scan the hardened Docker image.",
)
@click.option("--strict", is_flag=True, help="Exit non-zero if any required tool (trivy, pip-audit, bandit) is missing")
@click.option("--artifacts-dir", type=click.Path(), help="Directory to store raw per-tool artifacts")
@click.pass_context
def vulnerability(ctx, target, output, profile, strict, artifacts_dir):
    """Run vulnerability scan (Trivy, pip-audit, Bandit, Gitleaks, syft).

    Mirrors the CI pipeline in .github/workflows/security-scan.yml.
    Missing tools are skipped by default; use --strict to treat them as failures.

    \b
      openclaw-cli scan vulnerability --target production
      openclaw-cli scan vulnerability --target production --profile ci --strict
      openclaw-cli scan vulnerability --target staging --output vuln.json --artifacts-dir /tmp/scan
    """
    click.echo(f"[*] Running vulnerability scan [{target}, profile: {profile}]...")

    safe_output = _validate_output_path(output) if output else None
    safe_artifacts = _validate_output_path(artifacts_dir) if artifacts_dir else None

    scan_mod = _load_clawdbot_module("scan_vulnerability")
    try:
        result = scan_mod.run_scan(
            target=target,
            profile=profile,
            strict=strict,
            output_path=str(safe_output) if safe_output else None,
            artifacts_dir_path=str(safe_artifacts) if safe_artifacts else None,
        )
    except Exception as exc:
        raise click.ClickException(str(exc)) from exc

    # Display per-tool status table
    click.echo("\n[*] Tool Results:")
    rows = []
    for tool_name, tool_res in result["tool_results"].items():
        status = tool_res["status"].upper()
        count = tool_res.get("finding_count", "")
        reason = tool_res.get("reason", "")
        detail = ""
        if tool_res.get("details"):
            d = tool_res["details"]
            detail = f"  ({d.get('critical',0)} critical, {d.get('high',0)} high)"
        extra = f"{count} findings{detail}" if count != "" else reason
        rows.append([f"  {tool_name}", status, extra])
    click.echo(tabulate(rows, headers=["Tool", "Status", "Detail"]))

    summary = result["summary"]
    click.echo(
        f"\n[*] Summary: {summary['total']} total findings"
        f" ({summary['critical']} critical, {summary['high']} high)"
    )
    if summary["passed_tools"]:
        click.echo(f"    Passed:  {', '.join(summary['passed_tools'])}")
    if summary["skipped_tools"]:
        click.echo(f"    Skipped: {', '.join(summary['skipped_tools'])}")

    for w in result.get("warnings", []):
        click.secho(f"[!] {w}", fg="yellow")

    if safe_output:
        click.secho(f"\n[\u2713] Scan complete \u2192 {safe_output}", fg="green")
    else:
        click.secho("[\u2713] Scan complete", fg="green")

    if summary["failed_tools"]:
        click.secho(f"[\u2717] Failed tools: {', '.join(summary['failed_tools'])}", fg="red")
        ctx.exit(1)


@scan.command()
@click.option("--policy", required=True, help="Policy to check (SEC-002, SEC-003, etc.)")
@click.pass_context
def compliance(ctx, policy):
    """Check compliance with security policies."""
    click.echo(f"[*] Checking compliance with {policy}...")
    
    policy_validator = _load_tool_module("policy-validator.py", "policy_validator")
    result = policy_validator.validate_policy(policy)
    
    if result["compliant"]:
        click.secho(f"[✓] {policy} compliance: PASS", fg="green")
    else:
        click.secho(f"[✗] {policy} compliance: FAIL", fg="red")
        click.echo(f"\nViolations:")
        for violation in result["violations"]:
            click.echo(f"  - {violation}")
    
    if not result["compliant"]:
        ctx.exit(1)


@scan.command()
@click.option("--days", default=90, show_default=True, help="Flag accounts inactive for this many days")
@click.option("--input-csv", type=click.Path(), help="Path to access-report CSV (runbook column schema)")
@click.option(
    "--provider",
    type=click.Choice(["azure-ad"]),
    help="Query a live identity provider instead of a CSV (requires AZURE_AD_* env vars)",
)
@click.option("--tenant-id", help="Azure AD tenant ID (or set AZURE_AD_TENANT_ID)")
@click.option("--client-id", help="Azure AD client ID (or set AZURE_AD_CLIENT_ID)")
@click.option("--client-secret", help="Azure AD client secret (or set AZURE_AD_CLIENT_SECRET)")
@click.option("--output", type=click.Path(), help="Write the JSON result to this file")
@click.option("--output-inactive-csv", type=click.Path(), help="Export inactive users as CSV")
@click.option("--output-privilege-creep-csv", type=click.Path(), help="Export privilege-creep findings as CSV")
@click.pass_context
def access(ctx, days, input_csv, provider, tenant_id, client_id, client_secret,
           output, output_inactive_csv, output_privilege_creep_csv):
    """Review user access against the quarterly access-review runbook.

    Provide either a CSV export (--input-csv) or query a live identity provider
    (--provider azure-ad).  Exactly one source is required.

    \b
      # CSV-based review
      openclaw-cli scan access --input-csv access-export.csv --days 90

      # Live Azure AD review (reads AZURE_AD_* env vars)
      openclaw-cli scan access --provider azure-ad --output access.json
    """
    if not input_csv and not provider:
        raise click.UsageError("Provide --input-csv or --provider azure-ad.")
    if input_csv and provider:
        raise click.UsageError("--input-csv and --provider are mutually exclusive.")

    source_label = input_csv or provider
    click.echo(f"[*] Running access review [source: {source_label}, threshold: {days} days]...")

    safe_output = _validate_output_path(output) if output else None
    safe_inactive = _validate_output_path(output_inactive_csv) if output_inactive_csv else None
    safe_creep = _validate_output_path(output_privilege_creep_csv) if output_privilege_creep_csv else None

    access_mod = _load_clawdbot_module("scan_access")
    try:
        result = access_mod.run_access_review(
            input_csv=input_csv,
            provider=provider,
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
            days_threshold=days,
            output_path=str(safe_output) if safe_output else None,
            output_inactive_csv=str(safe_inactive) if safe_inactive else None,
            output_privilege_creep_csv=str(safe_creep) if safe_creep else None,
        )
    except (ValueError, ImportError) as exc:
        raise click.ClickException(str(exc)) from exc
    except Exception as exc:
        raise click.ClickException(f"Access review failed: {exc}") from exc

    summary = result["summary"]
    click.echo(f"\n[*] Loaded {summary['total_users']} users from {result['input_source']}")
    click.echo("\n[*] Findings:")
    rows_out = [
        ["  Inactive users", f"\u2265{days} days", summary["inactive_count"]],
        ["  Privilege creep", "", summary["privilege_creep_count"]],
        ["  Orphaned approvers", "", summary["orphaned_approver_count"]],
    ]
    click.echo(tabulate(rows_out, headers=["Category", "Condition", "Count"]))

    comp = result.get("compliance", {})
    if comp:
        click.echo("\n[*] Compliance:")
        for key, status in comp.items():
            colour = "green" if status == "pass" else "yellow"
            label = key.replace("_", " ").upper()
            click.secho(f"    {label:<30} {status.upper()}", fg=colour)

    if safe_output:
        click.secho(f"\n[\u2713] Review complete \u2192 {safe_output}", fg="green")
    else:
        click.secho("[\u2713] Review complete", fg="green")


@scan.command(name="certificates")
@click.option("--output", type=click.Path(), help="Optional output file path")
@click.pass_context
def certificates(ctx, output):
    """Review TLS certificate expiry status."""
    certificate_manager = _load_tool_module("certificate-manager.py", "certificate_manager")
    certs = certificate_manager.list_certificates()

    if not certs:
        click.echo("[!] No certificates found under /etc/openclaw/tls")
    else:
        rows = [
            [
                c["cert_path"],
                c["days_until_expiry"] if c["days_until_expiry"] is not None else "—",  # FIX: C5-14 — None for unreadable certs
                "YES" if c["needs_renewal"] else "NO",
                c.get("status", "unknown"),  # FIX: C5-14 — deterministic state column
            ]
            for c in certs
        ]
        click.echo(tabulate(rows, headers=["Certificate", "Days Until Expiry", "Needs Renewal", "Status"]))  # FIX: C5-14

    if output:
        safe_output = _validate_output_path(output)
        safe_output.parent.mkdir(parents=True, exist_ok=True)
        with open(safe_output, "w", encoding="utf-8") as f:
            json.dump(certs, f, indent=2)
        click.echo(f"\n[✓] Results saved to {safe_output}")


# ============================================================================
# PLAYBOOK COMMANDS
# ============================================================================

@cli.group()
def playbook():
    """Execute incident response playbooks."""
    pass


@playbook.command()
@click.argument("playbook_id")
@click.option("--severity", required=True, type=click.Choice(["P0", "P1", "P2", "P3"]))
@click.option("--dry-run", is_flag=True, help="Simulate without making changes")
@click.option("--execute", "execute_flag", is_flag=True, help="Execute the repo-native playbook helpers")
@click.pass_context
def execute(ctx, playbook_id, severity, dry_run, execute_flag):
    """Execute incident response playbook.

    PLAYBOOK_ID may be a filename stem (playbook-credential-theft) or a
    Playbook ID (IRP-001).  Run 'openclaw-cli playbook list' to see all
    available playbooks and their identifiers.
    """
    _execute_playbook_orchestration(  # FIX: C5-finding-2
        ctx,  # FIX: C5-finding-2
        playbook_id=playbook_id,  # FIX: C5-finding-2
        severity=severity,  # FIX: C5-finding-2
        dry_run=dry_run,  # FIX: C5-finding-2
        execute_flag=execute_flag,  # FIX: C5-finding-2
    )  # FIX: C5-finding-2


@playbook.command()
@click.pass_context
def list(ctx):
    """List available playbooks."""
    import re as _re
    playbooks_dir = REPO_ROOT / "examples" / "incident-response"
    _re_irp = _re.compile(r"\*\*Playbook ID\*\*:\s+(IRP-\S+)")

    rows = []
    for p in sorted(playbooks_dir.glob("playbook-*.md")):
        title = ""
        irp_id = ""
        with open(p, encoding="utf-8") as f:
            for line in f:
                if not title and line.startswith("# "):
                    title = line.strip("# \n")
                m = _re_irp.match(line.strip())
                if m:
                    irp_id = m.group(1)
                if title and irp_id:
                    break
        rows.append((p.stem, irp_id, title))

    click.echo(f"[*] Available playbooks ({len(rows)}):\n")
    click.echo(tabulate(rows, headers=["Filename stem", "ID", "Title"]))
    click.echo(
        "\n[i] Usage: openclaw-cli playbook execute <filename-stem-or-ID> --severity P0"
    )


# ============================================================================
# REPORT COMMANDS
# ============================================================================

@cli.group()
def report():
    """Generate security reports."""
    pass


@report.command()
@click.option("--start", required=True, help="Period start date (YYYY-MM-DD)")
@click.option("--end", required=True, help="Period end date (YYYY-MM-DD)")
@click.option("--output", type=click.Path(), help="Write the JSON report to this file")
@click.option("--pdf", type=click.Path(), help="Also render a PDF report (requires reportlab)")
@click.option("--vulnerability-scan", type=click.Path(), help="Path to a prior 'scan vulnerability' JSON output to embed")
@click.option("--access-scan", type=click.Path(), help="Path to a prior 'scan access' JSON output to embed")
@click.pass_context
def weekly(ctx, start, end, output, pdf, vulnerability_scan, access_scan):
    """Generate the weekly security report.

    Aggregates compliance status, certificate expiry, and optionally embeds
    the most recent vulnerability and access-review scan results.

    \b
      # Standalone (compliance + certs only)
      openclaw-cli report weekly --start 2026-03-14 --end 2026-03-21 --output report.json

      # Full report with prior scans embedded
      openclaw-cli scan vulnerability --target production --output vuln.json
      openclaw-cli scan access --input-csv access.csv --output access.json
      openclaw-cli report weekly --start 2026-03-14 --end 2026-03-21 \\
          --vulnerability-scan vuln.json --access-scan access.json \\
          --output report.json --pdf report.pdf
    """
    click.echo(f"[*] Generating weekly security report [{start} \u2192 {end}]...")

    safe_output = _validate_output_path(output) if output else None
    safe_pdf = _validate_output_path(pdf) if pdf else None

    weekly_mod = _load_clawdbot_module("report_weekly")
    try:
        result = weekly_mod.generate_weekly_report(
            start_date=start,
            end_date=end,
            output_path=str(safe_output) if safe_output else None,
            pdf_path=str(safe_pdf) if safe_pdf else None,
            vulnerability_scan_path=vulnerability_scan,
            access_scan_path=access_scan,
        )
    except Exception as exc:
        raise click.ClickException(str(exc)) from exc

    # Compliance section
    comp = result.get("sections", {}).get("compliance_status", {})
    if "error" not in comp:
        click.echo("\n[*] Compliance:")
        for fw, data in comp.items():
            if isinstance(data, dict) and "compliance_percentage" in data:
                pct = data["compliance_percentage"]
                if pct >= 95:
                    colour = "green"
                elif pct >= 80:
                    colour = "yellow"
                else:
                    colour = "red"
                click.secho(f"    {fw.upper():<12} {pct:.1f}%", fg=colour)

    # Certificate section
    certs = result.get("sections", {}).get("certificate_status", {})
    if "error" not in certs:
        expiring = certs.get("expiring_soon", 0)
        cert_colour = "yellow" if expiring > 0 else "green"
        click.secho(
            f"\n[*] Certificates: {certs.get('total', 0)} total, "
            f"{expiring} expiring soon",
            fg=cert_colour,
        )

    # Missing evidence
    missing = result.get("missing_evidence", [])
    if missing:
        click.echo("\n[!] Missing evidence (report is partial):")
        for item in missing:
            click.secho(f"    - {item}", fg="yellow")

    # Warnings
    for w in result.get("warnings", []):
        click.secho(f"[!] {w}", fg="yellow")

    # Overall status
    status = result.get("overall_status", "unknown")
    status_colour = {"healthy": "green", "warning": "yellow"}.get(status, "red")
    click.secho(f"\n[*] Overall status: {status.upper()}", fg=status_colour)

    artifacts = result.get("artifacts", {})
    if artifacts.get("json_report"):
        click.secho(f"[\u2713] Report saved \u2192 {artifacts['json_report']}", fg="green")
    if artifacts.get("pdf_report"):
        click.secho(f"[\u2713] PDF saved   \u2192 {artifacts['pdf_report']}", fg="green")


@report.command()
@click.option("--framework", required=True, type=click.Choice(["SOC2", "ISO27001", "GDPR"]))
@click.option("--output", type=click.Path(), help="Output file path")
@click.pass_context
def compliance(ctx, framework, output):
    """Generate compliance report."""
    click.echo(f"[*] Generating {framework} compliance report...")

    safe_output = None
    if output:
        safe_output = _validate_output_path(output)
    
    compliance_reporter = _load_tool_module("compliance-reporter.py", "compliance_reporter")
    try:
        report = compliance_reporter.generate_report(framework=framework)
    except (FileNotFoundError, ValueError, OSError) as exc:
        raise click.ClickException(str(exc)) from exc

    if not isinstance(report, builtins.dict):  # FIX: C5-finding-4  # FIX: C5-finding-5
        raise click.ClickException("Compliance report must be a JSON object")  # FIX: C5-finding-4  # FIX: C5-finding-5

    required_summary_keys = ["implemented_count", "pending_count", "compliance_percentage"]  # FIX: C5-finding-4  # FIX: C5-finding-5
    missing_summary_keys = [key for key in required_summary_keys if key not in report]  # FIX: C5-finding-4  # FIX: C5-finding-5
    if missing_summary_keys:  # FIX: C5-finding-4  # FIX: C5-finding-5
        missing = ", ".join(missing_summary_keys)  # FIX: C5-finding-4  # FIX: C5-finding-5
        raise click.ClickException(f"Compliance report missing required summary fields: {missing}")  # FIX: C5-finding-4  # FIX: C5-finding-5

    if not isinstance(report.get("controls"), builtins.list):  # FIX: C5-finding-4  # FIX: C5-finding-5
        raise click.ClickException("Compliance report controls must be a list")  # FIX: C5-finding-4  # FIX: C5-finding-5

    implemented_count = report["implemented_count"]  # FIX: C5-finding-4  # FIX: C5-finding-5
    pending_count = report["pending_count"]  # FIX: C5-finding-4  # FIX: C5-finding-5
    compliance_percentage = report["compliance_percentage"]  # FIX: C5-finding-4  # FIX: C5-finding-5
    if (  # FIX: C5-finding-4  # FIX: C5-finding-5
        isinstance(implemented_count, bool)  # FIX: C5-finding-4  # FIX: C5-finding-5
        or not isinstance(implemented_count, builtins.int)  # FIX: C5-finding-4  # FIX: C5-finding-5
        or implemented_count < 0  # FIX: C5-finding-4  # FIX: C5-finding-5
    ):  # FIX: C5-finding-4  # FIX: C5-finding-5
        raise click.ClickException("Compliance report implemented_count must be a nonnegative integer")  # FIX: C5-finding-4  # FIX: C5-finding-5
    if (  # FIX: C5-finding-4  # FIX: C5-finding-5
        isinstance(pending_count, bool)  # FIX: C5-finding-4  # FIX: C5-finding-5
        or not isinstance(pending_count, builtins.int)  # FIX: C5-finding-4  # FIX: C5-finding-5
        or pending_count < 0  # FIX: C5-finding-4  # FIX: C5-finding-5
    ):  # FIX: C5-finding-4  # FIX: C5-finding-5
        raise click.ClickException("Compliance report pending_count must be a nonnegative integer")  # FIX: C5-finding-4  # FIX: C5-finding-5
    if (  # FIX: C5-finding-4  # FIX: C5-finding-5
        isinstance(compliance_percentage, bool)  # FIX: C5-finding-4  # FIX: C5-finding-5
        or not isinstance(compliance_percentage, (builtins.int, builtins.float))  # FIX: C5-finding-4  # FIX: C5-finding-5
        or not 0 <= compliance_percentage <= 100  # FIX: C5-finding-4  # FIX: C5-finding-5
    ):  # FIX: C5-finding-4  # FIX: C5-finding-5
        raise click.ClickException("Compliance report compliance_percentage must be a number from 0 to 100")  # FIX: C5-finding-4  # FIX: C5-finding-5
    
    # Display control status
    click.echo(f"\n[*] Control Status:")
    click.echo(f"  - Implemented: {implemented_count}")  # FIX: C5-finding-4  # FIX: C5-finding-5
    click.echo(f"  - Pending: {pending_count}")  # FIX: C5-finding-4  # FIX: C5-finding-5
    click.echo(f"  - Compliance: {compliance_percentage}%")  # FIX: C5-finding-4  # FIX: C5-finding-5
    
    if safe_output:
        safe_output.parent.mkdir(parents=True, exist_ok=True)
        with open(safe_output, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        click.echo(f"\n[✓] Report saved to {safe_output}")


@report.command(name="evidence-snapshot")
@click.option("--output-dir", required=True, type=click.Path(), help="Directory for the evidence snapshot")
@click.option("--skip-runtime", is_flag=True, help="Skip runtime security regression evidence")
@click.option("--skip-detection-replay", is_flag=True, help="Skip detection replay evidence")
@click.option("--skip-compliance", is_flag=True, help="Skip compliance report evidence")
@click.option("--skip-yara", is_flag=True, help="Skip YARA replay during detection validation")
@click.pass_context
def evidence_snapshot(ctx, output_dir, skip_runtime, skip_detection_replay, skip_compliance, skip_yara):
    """Generate a Cycle 3 evidence snapshot."""
    snapshot_root = _validate_output_path(output_dir)
    snapshot_root.mkdir(parents=True, exist_ok=True)

    manifest: dict[str, object] = {
        "generated_at": datetime.now(UTC).isoformat(),
        "snapshot_root": str(snapshot_root),
        "steps": [],
    }
    failures: list[str] = []

    if not skip_runtime:
        runtime_dir = snapshot_root / "runtime"
        runtime_dir.mkdir(parents=True, exist_ok=True)
        click.echo("[*] Capturing runtime regression evidence...")
        runtime_result = _run_python_tool(
            "scripts/verification/runtime_security_regression.py",
            ["--scenario", "all", "--archive-root", str(runtime_dir)],
        )
        (runtime_dir / EXECUTION_LOG_FILE).write_text(
            runtime_result.stdout + runtime_result.stderr,
            encoding="utf-8",
        )
        manifest["steps"].append(
            {
                "name": "runtime-regression",
                "exit_code": runtime_result.returncode,
                "output": str(runtime_dir),
            }
        )
        if runtime_result.returncode != 0:
            failures.append("runtime-regression")

    if not skip_detection_replay:
        replay_dir = snapshot_root / "detection-replay"
        replay_dir.mkdir(parents=True, exist_ok=True)
        click.echo("[*] Capturing detection replay evidence...")
        replay_args = []
        if skip_yara:
            replay_args.append("--skip-yara")
        replay_result = _run_python_tool(
            "scripts/verification/validate_detection_replay.py",
            replay_args,
        )
        (replay_dir / EXECUTION_LOG_FILE).write_text(
            replay_result.stdout + replay_result.stderr,
            encoding="utf-8",
        )
        manifest["steps"].append(
            {
                "name": "detection-replay",
                "exit_code": replay_result.returncode,
                "output": str(replay_dir / EXECUTION_LOG_FILE),
                "skip_yara": skip_yara,
            }
        )
        if replay_result.returncode != 0:
            failures.append("detection-replay")

    if not skip_compliance:
        compliance_dir = snapshot_root / "compliance"
        compliance_dir.mkdir(parents=True, exist_ok=True)
        click.echo("[*] Capturing compliance evidence...")
        compliance_reporter = _load_tool_module("compliance-reporter.py", "compliance_reporter")
        for framework in ("SOC2", "ISO27001"):
            report_data = compliance_reporter.generate_report(framework=framework)
            output_path = compliance_dir / f"{framework.lower()}-report.json"
            with open(output_path, "w", encoding="utf-8") as handle:
                json.dump(report_data, handle, indent=2)
            manifest["steps"].append(
                {
                    "name": f"compliance-{framework.lower()}",
                    "exit_code": 0,
                    "output": str(output_path),
                }
            )

    manifest_path = snapshot_root / "manifest.json"
    with open(manifest_path, "w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2)

    if failures:
        raise click.ClickException(
            f"Evidence snapshot completed with failures: {', '.join(failures)}. See {manifest_path}"
        )

    click.echo(f"[✓] Evidence snapshot saved to {snapshot_root}")


# ============================================================================
# CONFIG COMMANDS
# ============================================================================

@cli.group()
def config():
    """Validate and migrate configurations."""
    pass


@config.command()
@click.argument("config_file", type=click.Path(exists=True))
@click.pass_context
def validate(ctx, config_file):
    """Validate configuration file."""
    click.echo(f"[*] Validating {config_file}...")
    
    policy_validator = _load_tool_module("policy-validator.py", "policy_validator")
    result = policy_validator.validate_config(config_file)
    
    if result["valid"]:
        click.secho(f"[✓] Configuration is valid", fg="green")
    else:
        click.secho(f"[✗] Configuration is invalid", fg="red")
        click.echo(f"\nErrors:")
        for error in result["errors"]:
            click.echo(f"  - {error}")
    
    if not result["valid"]:
        ctx.exit(1)


@config.command()
@click.argument("config_file", type=click.Path(exists=True))
@click.option("--from-version", required=True, help="Source version")
@click.option("--to-version", required=True, help="Target version")
@click.pass_context
def migrate(ctx, config_file, from_version, to_version):
    """Migrate configuration between versions."""
    click.echo(f"[*] Migrating {config_file} from {from_version} to {to_version}...")
    
    config_migrator = _load_tool_module("config-migrator.py", "config_migrator")
    result = config_migrator.migrate(config_file, from_version, to_version)
    
    if result["success"]:
        click.secho(f"[✓] Migration successful", fg="green")
        click.echo(f"  - Backup: {result['backup_path']}")
        click.echo(f"  - Migrated: {result['output_path']}")
    else:
        click.secho(f"[✗] Migration failed: {result['error']}", fg="red")
        ctx.exit(1)


# ============================================================================
# SIMULATE COMMANDS
# ============================================================================

@cli.group()
def simulate():
    """Simulate security incidents for testing."""
    pass


@simulate.command()
@click.option("--type", required=True, type=click.Choice(["credential-theft", "mcp-compromise", "dos-attack"]))
@click.option("--severity", default="P1", type=click.Choice(["P0", "P1", "P2", "P3"]))
@click.pass_context
def incident(ctx, type, severity):
    """Simulate security incident."""
    click.echo(f"[*] Simulating {type} incident (severity: {severity})...")
    
    incident_simulator = _load_tool_module("incident-simulator.py", "incident_simulator")
    incident_data = incident_simulator.create_incident(
        incident_type=type,
        severity=severity,
    )
    
    click.echo(f"\n[*] Incident Details:")
    click.echo(f"  - ID: {incident_data['incident_id']}")
    click.echo(f"  - Type: {incident_data['type']}")
    click.echo(f"  - Severity: {incident_data['severity']}")
    click.echo(f"  - Affected resources: {len(incident_data['affected_resources'])}")
    
    click.echo(f"\n[*] Triggering incident response...")
    playbook_id = SIMULATED_INCIDENT_PLAYBOOKS[type]  # FIX: C5-finding-8
    click.echo(f"  - Routed playbook: {playbook_id}")  # FIX: C5-finding-8
    _execute_playbook_orchestration(  # FIX: C5-finding-8
        ctx,  # FIX: C5-finding-8
        playbook_id=playbook_id,  # FIX: C5-finding-8
        severity=severity,  # FIX: C5-finding-8
        dry_run=False,  # FIX: C5-finding-8
        execute_flag=True,  # FIX: C5-finding-8
        incident_slug=SIMULATED_INCIDENT_OVERRIDES[type]["incident_slug"],  # FIX: C5-finding-8
        overrides=SIMULATED_INCIDENT_OVERRIDES[type],  # FIX: C5-finding-8
        incident_id=incident_data["incident_id"],  # FIX: C5-finding-8
        incident_data=incident_data,  # FIX: C5-finding-8
    )  # FIX: C5-finding-8


# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    sys.exit(cli())
