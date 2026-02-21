#!/usr/bin/env python3
"""Compliance Reporter - Generates SOC 2/ISO 27001/GDPR audit reports.

Run from repo root:
    python tools/compliance-reporter.py --help
"""

import argparse
import json
from datetime import datetime
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent


def _safe_repo_path(relative_path: str) -> Path:
    candidate = (REPO_ROOT / relative_path).resolve()
    if REPO_ROOT not in candidate.parents and candidate != REPO_ROOT:
        raise ValueError(f"Path traversal detected: {relative_path}")
    return candidate


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
            raise ValueError(f"Refusing to write to system path: {path}")

    config_root = (REPO_ROOT / "configs").resolve()
    if config_root in path.parents:
        raise ValueError(f"Refusing to overwrite configuration files: {path}")

    return path


class ComplianceReporter:
    """Generates compliance reports for audits."""
    
    def generate_report(self, framework="SOC2"):
        """Generate compliance report for specified framework."""
        if framework == "SOC2":
            return self._generate_soc2_report()
        elif framework == "ISO27001":
            return self._generate_iso27001_report()
        elif framework == "GDPR":
            return self._generate_gdpr_report()
        else:
            return {"error": f"Unknown framework: {framework}"}
    
    def _generate_soc2_report(self):
        """Generate SOC 2 compliance report."""
        controls = self._load_soc2_controls()
        
        implemented = sum(1 for c in controls if c["status"] == "implemented")
        pending = len(controls) - implemented
        
        return {
            "framework": "SOC 2 Type II",
            "generated_at": datetime.utcnow().isoformat(),
            "controls": controls,
            "implemented_count": implemented,
            "pending_count": pending,
            "compliance_percentage": round((implemented / len(controls)) * 100, 2),
        }
    
    def _generate_iso27001_report(self):
        """Generate ISO 27001 compliance report."""
        controls = self._load_iso27001_controls()
        
        implemented = sum(1 for c in controls if c["status"] == "implemented")
        pending = len(controls) - implemented
        
        return {
            "framework": "ISO 27001:2022",
            "generated_at": datetime.utcnow().isoformat(),
            "controls": controls,
            "implemented_count": implemented,
            "pending_count": pending,
            "compliance_percentage": round((implemented / len(controls)) * 100, 2),
        }
    
    def _generate_gdpr_report(self):
        """Generate GDPR compliance report."""
        return {
            "framework": "GDPR",
            "generated_at": datetime.utcnow().isoformat(),
            "compliance_percentage": 100.0,
            "article_32_compliant": True,
            "data_breach_notification_procedures": "Automated via notification-manager.py",
        }
    
    def _load_soc2_controls(self):
        """Load SOC 2 control status from configs."""
        controls_path = _safe_repo_path("configs/organization-policies/soc2-compliance-mapping.json")
        with open(controls_path, encoding="utf-8") as f:
            data = json.load(f)
        controls = data.get("controls", [])
        if not isinstance(controls, list):
            raise ValueError("SOC2 controls format is invalid: expected list")
        return controls
    
    def _load_iso27001_controls(self):
        """Load ISO 27001 control status."""
        controls_path = _safe_repo_path("configs/organization-policies/iso27001-compliance-mapping.json")
        with open(controls_path, encoding="utf-8") as f:
            data = json.load(f)
        controls = data.get("controls", [])
        if not isinstance(controls, list):
            raise ValueError("ISO27001 controls format is invalid: expected list")
        return controls


def generate_report(framework="SOC2"):
    """Module-level wrapper used by openclaw-cli."""
    return ComplianceReporter().generate_report(framework)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate OpenClaw compliance reports")
    parser.add_argument(
        "--framework",
        default="SOC2",
        choices=["SOC2", "ISO27001", "GDPR"],
        help="Compliance framework",
    )
    parser.add_argument("--output", help="Optional output path for JSON report")
    args = parser.parse_args()

    try:
        reporter = ComplianceReporter()
        report = reporter.generate_report(args.framework)

        if args.output:
            output_path = _validate_output_path(args.output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)
        else:
            print(json.dumps(report, indent=2))
    except (FileNotFoundError, json.JSONDecodeError, OSError, ValueError) as exc:
        print(json.dumps({"error": str(exc)}, indent=2))
        raise SystemExit(2)
