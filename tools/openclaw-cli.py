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

Not yet implemented (placeholder modules absent):
  scan vulnerability, scan access, report weekly
  See scripts/README.md for placeholder status.

Installation:
  pip install click pyyaml boto3 requests tabulate
  python openclaw-cli.py --help
"""

import click
import json
import sys
import subprocess  # nosec B404
import importlib.util
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


def _run_python_tool(relative_script: str, args: list[str]) -> subprocess.CompletedProcess[str]:
    script_path = (REPO_ROOT / relative_script).resolve()
    return subprocess.run(  # nosec B603
        [sys.executable, str(script_path), *args],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


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
@click.option("--target", required=True, help="Scan target (production, staging, dev)")
@click.option("--output", type=click.Path(), help="Output file path")
@click.pass_context
def vulnerability(ctx, target, output):
    """Run vulnerability scan using Trivy and dependency checkers.

    NOTE: The automated scan pipeline (scripts.discovery) is not yet
    implemented in this repo.  Run the maintained CI tools directly:

    \b
      trivy fs .                                  # filesystem scan
      pip-audit --format json                     # Python dependency audit
      See .github/workflows/security-scan.yml for the full automated pipeline.
    """
    raise click.ClickException(
        "scan vulnerability requires scripts.discovery modules that are not yet "
        "implemented in this repo (see scripts/README.md, status: Placeholder).\n"
        "Run 'trivy fs .' and 'pip-audit' directly, or trigger the "
        ".github/workflows/security-scan.yml workflow for CI-backed scanning."
    )


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
    """Review user access and permissions.

    NOTE: The automated access-review pipeline (scripts.compliance) is not yet
    implemented in this repo.  Follow the manual procedure instead:

    \b
      docs/procedures/access-review.md
    """
    raise click.ClickException(
        "scan access requires scripts.compliance modules that are not yet "
        "implemented in this repo (see scripts/README.md, status: Placeholder).\n"
        "See docs/procedures/access-review.md for the manual quarterly "
        "access-review procedure."
    )


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
    """Execute incident response playbook.

    PLAYBOOK_ID may be a filename stem (playbook-credential-theft) or a
    Playbook ID (IRP-001).  Run 'openclaw-cli playbook list' to see all
    available playbooks and their identifiers.
    """
    playbook_path = _resolve_playbook(playbook_id)

    if playbook_path is None:
        click.secho(
            f"[✗] Playbook not found for '{playbook_id}'.\n"
            "    Run 'openclaw-cli playbook list' to see available playbooks.",
            fg="red",
        )
        ctx.exit(1)
        return

    click.echo(f"[*] Executing playbook {playbook_path.stem} (severity: {severity})...")

    if dry_run:
        click.echo("[*] DRY RUN - No changes will be made")

    click.echo(f"[*] Playbook file: {playbook_path}")

    # Walk the five standard IR phases
    phases = ["Detection", "Containment", "Eradication", "Recovery", "PIR"]
    for phase in phases:
        click.echo(f"\n[*] Phase: {phase}")
        if dry_run:
            click.echo(f"    [DRY RUN] Would execute {phase} phase")
        else:
            click.echo(
                f"    Follow the '{phase}' section in {playbook_path.name}. "
                "For automated helpers see scripts/incident-response/."
            )

    click.secho(f"\n[✓] Playbook {playbook_path.stem} ready for execution", fg="green")


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
@click.option("--start", required=True, help="Start date (YYYY-MM-DD)")
@click.option("--end", required=True, help="End date (YYYY-MM-DD)")
@click.option("--output", type=click.Path(), help="Output PDF path")
@click.pass_context
def weekly(ctx, start, end, output):
    """Generate weekly security report.

    NOTE: The automated reporting pipeline (scripts.reporting) is not yet
    implemented in this repo.  Use the compliance report command instead:

    \b
      openclaw-cli report compliance --framework SOC2
    """
    raise click.ClickException(
        "report weekly requires scripts.reporting modules that are not yet "
        "implemented in this repo (see scripts/README.md, status: Placeholder).\n"
        "Use 'openclaw-cli report compliance --framework SOC2' for a "
        "repo-backed compliance report."
    )


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
    except (FileNotFoundError, ValueError, json.JSONDecodeError, OSError) as exc:
        raise click.ClickException(str(exc)) from exc
    
    # Display control status
    click.echo(f"\n[*] Control Status:")
    click.echo(f"  - Implemented: {report['implemented_count']}")
    click.echo(f"  -Pending: {report['pending_count']}")
    click.echo(f"  - Compliance: {report['compliance_percentage']}%")
    
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
        (runtime_dir / "execution.log").write_text(
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
        (replay_dir / "execution.log").write_text(
            replay_result.stdout + replay_result.stderr,
            encoding="utf-8",
        )
        manifest["steps"].append(
            {
                "name": "detection-replay",
                "exit_code": replay_result.returncode,
                "output": str(replay_dir / "execution.log"),
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
    
    # Execute playbook
    ctx.invoke(playbook.execute, playbook_id="playbook-credential-theft", severity=severity, dry_run=False)


# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    sys.exit(cli())
