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
  openclaw-cli playbook execute IRP-001 --severity P0
  openclaw-cli report weekly --start 2024-01-15 --end 2024-01-22
  openclaw-cli config validate openclaw-agent.yml
  openclaw-cli simulate incident --type credential-theft

Installation:
  pip install click pyyaml boto3 requests tabulate
  python openclaw-cli.py --help
"""

import click
import json
import sys
import importlib.util
from pathlib import Path
from datetime import datetime, timedelta

try:
    from tabulate import tabulate
except ModuleNotFoundError:
    def tabulate(rows, headers):
        rendered = [" | ".join(headers)]
        rendered.extend(" | ".join(str(cell) for cell in row) for row in rows)
        return "\n".join(rendered)


REPO_ROOT = Path(__file__).resolve().parent.parent
TOOLS_DIR = Path(__file__).resolve().parent


def _load_tool_module(filename: str, module_name: str):
    module_path = (TOOLS_DIR / filename).resolve()
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load module: {filename}")
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
@click.option("--target", required=True, help="Scan target (production, staging, dev)")
@click.option("--output", type=click.Path(), help="Output file path")
@click.pass_context
def vulnerability(ctx, target, output):
    """Run vulnerability scan using Trivy and dependency checkers."""
    click.echo(f"[*] Starting vulnerability scan on {target}...")
    
    # Import vulnerability scanner
    from scripts.discovery import os_scan, dependency_scan
    
    # Scan OS packages
    click.echo("[*] Scanning OS packages...")
    os_vulns = os_scan.scan_os_packages(target=target)
    
    # Scan dependencies
    click.echo("[*] Scanning dependencies...")
    dep_vulns = dependency_scan.scan_npm_packages()
    dep_vulns.extend(dependency_scan.scan_python_packages())
    
    all_vulns = os_vulns + dep_vulns
    
    # Display results
    if all_vulns:
        click.echo(f"\n[!] Found {len(all_vulns)} vulnerabilities:")
        
        # Group by severity
        critical = [v for v in all_vulns if v.get("severity") == "CRITICAL"]
        high = [v for v in all_vulns if v.get("severity") == "HIGH"]
        medium = [v for v in all_vulns if v.get("severity") == "MEDIUM"]
        low = [v for v in all_vulns if v.get("severity") == "LOW"]
        
        summary = [
            ["CRITICAL", len(critical), "🔴"],
            ["HIGH", len(high), "🟠"],
            ["MEDIUM", len(medium), "🟡"],
            ["LOW", len(low), "🟢"],
        ]
        
        click.echo(tabulate(summary, headers=["Severity", "Count", "Status"]))
        
        # Save to file if specified
        if output:
            safe_output = _validate_output_path(output)
            safe_output.parent.mkdir(parents=True, exist_ok=True)
            with open(safe_output, "w", encoding="utf-8") as f:
                json.dump(all_vulns, f, indent=2)
            click.echo(f"\n[✓] Results saved to {safe_output}")
    else:
        click.echo("[✓] No vulnerabilities found!")
    
    if len(critical) != 0:
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
@click.option("--days", default=90, help="Flag accounts inactive for X days")
@click.pass_context
def access(ctx, days):
    """Review user access and permissions."""
    click.echo(f"[*] Reviewing access (flagging accounts inactive >{days} days)...")
    
    from scripts.compliance import access_review
    
    # Enumerate users
    iam_users = access_review.enumerate_iam_users()
    jira_users = access_review.enumerate_jira_users()
    
    # Find inactive accounts
    inactive = access_review.find_inactive_accounts(days=days)
    
    click.echo(f"\n[*] User Summary:")
    click.echo(f"  - IAM users: {len(iam_users)}")
    click.echo(f"  - Jira users: {len(jira_users)}")
    click.echo(f"  - Inactive (>{ days}d): {len(inactive)}")
    
    if inactive:
        click.echo(f"\n[!] Inactive accounts:")
        for user in inactive:
            click.echo(f"  - {user['username']} (last active: {user['last_active']})")


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
            [c["cert_path"], c["days_until_expiry"], "YES" if c["needs_renewal"] else "NO"]
            for c in certs
        ]
        click.echo(tabulate(rows, headers=["Certificate", "Days Until Expiry", "Needs Renewal"]))

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
@click.pass_context
def execute(ctx, playbook_id, severity, dry_run):
    """Execute incident response playbook."""
    click.echo(f"[*] Executing playbook {playbook_id} (severity: {severity})...")
    
    if dry_run:
        click.echo("[*] DRY RUN - No changes will be made")
    
    # Load playbook
    playbook_path = Path(f"examples/incident-response/{playbook_id}.md")
    
    if not playbook_path.exists():
        click.secho(f"[✗] Playbook not found: {playbook_path}", fg="red")
        ctx.exit(1)
    
    # Execute phases
    phases = ["Detection", "Containment", "Eradication", "Recovery", "PIR"]
    
    for phase in phases:
        click.echo(f"\n[*] Phase: {phase}")
        
        if not dry_run:
            # Execute phase (implementation depends on playbook)
            if phase == "Containment":
                from scripts.incident_response import auto_containment
                auto_containment.isolate_resources()
            elif phase == "Detection":
                from scripts.incident_response import forensics_collector
                forensics_collector.collect()
        else:
            click.echo(f"    [DRY RUN] Would execute {phase} phase")
    
    click.secho(f"\n[✓] Playbook {playbook_id} executed successfully", fg="green")


@playbook.command()
@click.pass_context
def list(ctx):
    """List available playbooks."""
    playbooks_dir = Path("examples/incident-response")
    
    playbooks = list(playbooks_dir.glob("IRP-*.md"))
    
    click.echo(f"[*] Available playbooks ({len(playbooks)}):\n")
    
    for playbook in sorted(playbooks):
        # Extract title from markdown
        with open(playbook) as f:
            title = f.readline().strip("# \n")
        
        click.echo(f"  - {playbook.stem}: {title}")


# ============================================================================
# REPORT COMMANDS
# ============================================================================

@cli.group()
def report():
    """Generate security reports."""
    pass


@report.command()
@click.option("--start", required=True, help="Start date (YYYY-MM-DD)")
@click.option("--end", required=True, help="End date (YYYY-MM-DD)")
@click.option("--output", type=click.Path(), help="Output PDF path")
@click.pass_context
def weekly(ctx, start, end, output):
    """Generate weekly security report."""
    click.echo(f"[*] Generating weekly report ({start} to {end})...")
    
    from scripts.reporting import generate_weekly_report
    
    report_data = generate_weekly_report.generate(
        start_date=start,
        end_date=end,
    )
    
    # Display summary
    click.echo(f"\n[*] Report Summary:")
    click.echo(f"  - Vulnerabilities: {report_data['vulnerability_count']}")
    click.echo(f"  - Incidents: {report_data['incident_count']}")
    click.echo(f"  - Patching velocity: {report_data['patching_velocity']}%")
    
    if output:
        safe_output = _validate_output_path(output)
        safe_output.parent.mkdir(parents=True, exist_ok=True)
        generate_weekly_report.export_pdf(report_data, str(safe_output))
        click.echo(f"\n[✓] Report saved to {safe_output}")


@report.command()
@click.option("--framework", required=True, type=click.Choice(["SOC2", "ISO27001", "GDPR"]))
@click.option("--output", type=click.Path(), help="Output file path")
@click.pass_context
def compliance(ctx, framework, output):
    """Generate compliance report."""
    click.echo(f"[*] Generating {framework} compliance report...")
    
    compliance_reporter = _load_tool_module("compliance-reporter.py", "compliance_reporter")
    report = compliance_reporter.generate_report(framework=framework)
    
    # Display control status
    click.echo(f"\n[*] Control Status:")
    click.echo(f"  - Implemented: {report['implemented_count']}")
    click.echo(f"  -Pending: {report['pending_count']}")
    click.echo(f"  - Compliance: {report['compliance_percentage']}%")
    
    if output:
        safe_output = _validate_output_path(output)
        safe_output.parent.mkdir(parents=True, exist_ok=True)
        with open(safe_output, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        click.echo(f"\n[✓] Report saved to {safe_output}")


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
    
    # Execute playbook
    ctx.invoke(playbook.execute, playbook_id="IRP-001", severity=severity, dry_run=False)


# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    sys.exit(cli())
