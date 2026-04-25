#!/usr/bin/env python3
"""Policy Validator - Validates agent configs against SEC-002/003/004/005 policies.

Run from repo root:
    python tools/policy-validator.py --help
"""

import argparse
import json  # FIX: C5-finding-1
import re
from pathlib import Path

try:
    import yaml
except ModuleNotFoundError:
    yaml = None


class PolicyValidator:
    """Validates configurations against security policies."""
    
    def __init__(self, repo_root=None):  # FIX: C5-finding-1
        self.repo_root = Path(repo_root) if repo_root else Path(__file__).resolve().parents[1]  # FIX: C5-finding-1
    
    def validate_policy(self, policy_name):
        """Validate specific policy compliance."""
        validators = {
            "SEC-002": self._validate_data_classification,
            "SEC-003": self._validate_vulnerability_mgmt,
            "SEC-004": self._validate_access_control,
            "SEC-005": self._validate_incident_response,
        }
        
        if policy_name not in validators:
            return {"compliant": False, "violations": [f"Unknown policy: {policy_name}"]}
        
        return validators[policy_name]()
    
    def _validate_data_classification(self):
        """Validate SEC-002 data classification policy."""
        violations = []
        
        # Check encryption enabled
        config = self._load_config("configs/agent-config/openclaw-agent.yml")
        
        if config.get("security_controls", {}).get("encryption", {}).get("algorithm") != "AES-256-GCM":
            violations.append("Encryption must use AES-256-GCM")
        
        return {"compliant": len(violations) == 0, "violations": violations}
    
    def _validate_vulnerability_mgmt(self):
        """Validate SEC-003 vulnerability management SLAs."""
        violations = []  # FIX: C5-finding-1
        policy = self._load_json_config("configs/organization-policies/security-policy.json")  # FIX: C5-finding-1
        rules = self._get_vulnerability_mgmt_rules(policy)  # FIX: C5-finding-1
        critical_patch_sla_days = self._coerce_duration_days(rules.get("critical_patch_sla_days"))  # FIX: C5-finding-1
        if critical_patch_sla_days is None or critical_patch_sla_days >= 7:  # FIX: C5-finding-1
            found = rules.get("critical_patch_sla_days", "missing")  # FIX: C5-finding-1
            violations.append(f"SEC-003.1: CRITICAL patch SLA must be less than 7 days (found: {found})")  # FIX: C5-finding-1
        dependency_audit_cadence_days = self._coerce_duration_days(rules.get("dependency_audit_cadence_days"))  # FIX: C5-finding-1
        if dependency_audit_cadence_days is None or dependency_audit_cadence_days <= 0:  # FIX: C5-finding-1
            found = rules.get("dependency_audit_cadence_days", "missing")  # FIX: C5-finding-1
            violations.append(f"SEC-003.2: Dependency audit cadence must be configured in days (found: {found})")  # FIX: C5-finding-1
        return {"compliant": len(violations) == 0, "violations": violations}  # FIX: C5-finding-1
    
    def _validate_access_control(self):
        """Validate SEC-004 access control (MFA, passwords)."""
        violations = []
        
        config = self._load_config("configs/agent-config/openclaw-agent.yml")
        
        if not config.get("security_controls", {}).get("authentication", {}).get("mfa_required"):
            violations.append("MFA must be required")
        
        return {"compliant": len(violations) == 0, "violations": violations}
    
    def _validate_incident_response(self):
        """Validate SEC-005 incident response SLAs."""
        violations = []  # FIX: C5-finding-1
        policy = self._load_json_config("configs/organization-policies/security-policy.json")  # FIX: C5-finding-1
        rules = self._get_incident_response_rules(policy)  # FIX: C5-finding-1
        missing_playbooks = [path for path in rules["required_playbooks"] if not self._resolve_repo_path(path).exists()]  # FIX: C5-finding-1
        if missing_playbooks:  # FIX: C5-finding-1
            violations.append(f"SEC-005.1: Required incident-response playbooks missing: {', '.join(missing_playbooks)}")  # FIX: C5-finding-1
        checklist = rules.get("checklist")  # FIX: C5-finding-1
        if not isinstance(checklist, dict):  # FIX: C5-finding-1
            violations.append("SEC-005.2: Incident checklist validation config must define a checklist mapping")  # FIX: C5-finding-1
        else:  # FIX: C5-finding-1
            violations.extend(self._validate_incident_checklist(checklist))  # FIX: C5-finding-1
        return {"compliant": len(violations) == 0, "violations": violations}  # FIX: C5-finding-1

    def _resolve_repo_path(self, path):  # FIX: C5-finding-1
        candidate = Path(path)  # FIX: C5-finding-1
        if candidate.is_absolute():  # FIX: C5-finding-1
            return candidate  # FIX: C5-finding-1
        return self.repo_root / candidate  # FIX: C5-finding-1

    def _load_json_config(self, path):  # FIX: C5-finding-1
        try:  # FIX: C5-finding-1
            with self._resolve_repo_path(path).open(encoding="utf-8") as handle:  # FIX: C5-finding-1
                return json.load(handle)  # FIX: C5-finding-1
        except Exception:  # FIX: C5-finding-1
            return {}  # FIX: C5-finding-1

    def _get_vulnerability_mgmt_rules(self, policy):  # FIX: C5-finding-1
        section = policy.get("policies", {}).get("vulnerability_management", {})  # FIX: C5-finding-1
        validation = section.get("validation", {}) if isinstance(section.get("validation", {}), dict) else {}  # FIX: C5-finding-1
        rules = dict(validation)  # FIX: C5-finding-1
        if "critical_patch_sla_days" not in rules and "critical_patch_sla" in rules:  # FIX: C5-finding-1
            rules["critical_patch_sla_days"] = rules["critical_patch_sla"]  # FIX: C5-finding-1
        if "dependency_audit_cadence_days" not in rules and "dependency_audit_cadence" in rules:  # FIX: C5-finding-1
            rules["dependency_audit_cadence_days"] = rules["dependency_audit_cadence"]  # FIX: C5-finding-1
        if "critical_patch_sla_days" not in rules:  # FIX: C5-finding-1
            rules["critical_patch_sla_days"] = self._extract_critical_patch_sla(section.get("requirements", []))  # FIX: C5-finding-1
        return rules  # FIX: C5-finding-1

    def _get_incident_response_rules(self, policy):  # FIX: C5-finding-1
        section = policy.get("policies", {}).get("incident_response", {})  # FIX: C5-finding-1
        validation = section.get("validation", {}) if isinstance(section.get("validation", {}), dict) else {}  # FIX: C5-finding-1
        required_playbooks = validation.get("required_playbooks") if isinstance(validation.get("required_playbooks"), list) else [  # FIX: C5-finding-1
            "examples/incident-response/playbook-credential-theft.md",  # FIX: C5-finding-1
            "examples/incident-response/playbook-data-breach.md",  # FIX: C5-finding-1
            "examples/incident-response/playbook-denial-of-service.md",  # FIX: C5-finding-1
            "examples/incident-response/playbook-prompt-injection.md",  # FIX: C5-finding-1
            "examples/incident-response/playbook-skill-compromise.md",  # FIX: C5-finding-1
        ]  # FIX: C5-finding-1
        return {"required_playbooks": required_playbooks, "checklist": validation.get("checklist")}  # FIX: C5-finding-1

    def _validate_incident_checklist(self, checklist):  # FIX: C5-finding-1
        checklist_path = checklist.get("path")  # FIX: C5-finding-1
        required_fields = checklist.get("required_fields") if isinstance(checklist.get("required_fields"), list) else None  # FIX: C5-finding-1
        forbidden_placeholders = checklist.get("forbidden_placeholders") if isinstance(checklist.get("forbidden_placeholders"), list) else []  # FIX: C5-finding-1
        if not checklist_path or not required_fields:  # FIX: C5-finding-1
            return ["SEC-005.2: Incident checklist config must define checklist.path and checklist.required_fields"]  # FIX: C5-finding-1
        checklist_file = self._resolve_repo_path(checklist_path)  # FIX: C5-finding-1
        if not checklist_file.exists():  # FIX: C5-finding-1
            return [f"SEC-005.2: Incident checklist file not found: {checklist_path}"]  # FIX: C5-finding-1
        checklist_text = checklist_file.read_text(encoding="utf-8")  # FIX: C5-finding-1
        violations = []  # FIX: C5-finding-1
        missing_fields = [field for field in required_fields if field not in checklist_text]  # FIX: C5-finding-1
        if missing_fields:  # FIX: C5-finding-1
            violations.append(f"SEC-005.2: Incident checklist missing required fields: {', '.join(missing_fields)}")  # FIX: C5-finding-1
        placeholder_hits = [placeholder for placeholder in forbidden_placeholders if placeholder in checklist_text]  # FIX: C5-finding-1
        if placeholder_hits:  # FIX: C5-finding-1
            violations.append(f"SEC-005.2: Incident checklist contains unpopulated placeholders: {', '.join(placeholder_hits)}")  # FIX: C5-finding-1
        return violations  # FIX: C5-finding-1

    def _extract_critical_patch_sla(self, requirements):  # FIX: C5-finding-1
        for requirement in requirements if isinstance(requirements, list) else []:  # FIX: C5-finding-1
            if not isinstance(requirement, str) or "critical" not in requirement.lower() or "patch" not in requirement.lower():  # FIX: C5-finding-1
                continue  # FIX: C5-finding-1
            return requirement  # FIX: C5-finding-1
        return None  # FIX: C5-finding-1

    def _coerce_duration_days(self, value):  # FIX: C5-finding-1
        if isinstance(value, (int, float)) and value > 0:  # FIX: C5-finding-1
            return float(value)  # FIX: C5-finding-1
        if not isinstance(value, str):  # FIX: C5-finding-1
            return None  # FIX: C5-finding-1
        normalized = value.strip().lower()  # FIX: C5-finding-1
        if normalized.isdigit():  # FIX: C5-finding-1
            return float(normalized)  # FIX: C5-finding-1
        day_match = re.search(r"(\d+)\s*day", normalized)  # FIX: C5-finding-1
        if day_match:  # FIX: C5-finding-1
            return float(day_match.group(1))  # FIX: C5-finding-1
        hour_match = re.search(r"(\d+)\s*hour", normalized)  # FIX: C5-finding-1
        if hour_match:  # FIX: C5-finding-1
            return float(hour_match.group(1)) / 24.0  # FIX: C5-finding-1
        return None  # FIX: C5-finding-1
    
    def validate_config(self, config_path):
        """Validate configuration file syntax and settings."""
        if yaml is None:
            return {"valid": False, "errors": ["Missing dependency: pyyaml"]}

        try:
            with open(config_path) as f:
                config = yaml.safe_load(f)
            
            errors = []
            
            # Validate required fields
            if "security_controls" not in config:
                errors.append("Missing security_controls section")
            
            return {"valid": len(errors) == 0, "errors": errors}
        except Exception as e:
            return {"valid": False, "errors": [str(e)]}
    
    def _load_config(self, path):
        """Load YAML configuration."""
        if yaml is None:
            return {}

        try:
            with open(path) as f:
                return yaml.safe_load(f)
        except Exception:
            return {}


def validate_policy(policy_name):
    """Module-level wrapper used by openclaw-cli."""
    return PolicyValidator().validate_policy(policy_name)


def validate_config(config_path):
    """Module-level wrapper used by openclaw-cli."""
    return PolicyValidator().validate_config(config_path)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Validate OpenClaw policy compliance")
    parser.add_argument("--policy", default="SEC-002", help="Policy to validate (default: SEC-002)")
    args = parser.parse_args()

    validator = PolicyValidator()  # FIX: C5-finding-1
    result = validator.validate_policy(args.policy)  # FIX: C5-finding-1
    print(result)  # FIX: C5-finding-1
    raise SystemExit(0 if result["compliant"] else 1)  # FIX: C5-finding-1
