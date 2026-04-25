from __future__ import annotations  # FIX: C5-finding-1

import importlib.util  # FIX: C5-finding-1
import json  # FIX: C5-finding-1
import shutil  # FIX: C5-finding-1
import subprocess  # FIX: C5-finding-1
import sys  # FIX: C5-finding-1
from pathlib import Path  # FIX: C5-finding-1

import pytest  # FIX: C5-finding-1


_POLICY_VALIDATOR_PATH = Path(__file__).resolve().parents[2] / "tools" / "policy-validator.py"  # FIX: C5-finding-1
_SPEC = importlib.util.spec_from_file_location("openclaw_policy_validator_tests", _POLICY_VALIDATOR_PATH)  # FIX: C5-finding-1
assert _SPEC is not None and _SPEC.loader is not None  # FIX: C5-finding-1
_POLICY_MOD = importlib.util.module_from_spec(_SPEC)  # FIX: C5-finding-1
sys.modules[_SPEC.name] = _POLICY_MOD  # FIX: C5-finding-1
_SPEC.loader.exec_module(_POLICY_MOD)  # FIX: C5-finding-1

_CHECKLIST_PATH = "configs/organization-policies/incident-response-checklist.json"  # FIX: C5-finding-1
_REQUIRED_PLAYBOOKS = [  # FIX: C5-finding-1
    "examples/incident-response/playbook-credential-theft.md",  # FIX: C5-finding-1
    "examples/incident-response/playbook-data-breach.md",  # FIX: C5-finding-1
    "examples/incident-response/playbook-denial-of-service.md",  # FIX: C5-finding-1
    "examples/incident-response/playbook-prompt-injection.md",  # FIX: C5-finding-1
    "examples/incident-response/playbook-skill-compromise.md",  # FIX: C5-finding-1
]  # FIX: C5-finding-1
_REQUIRED_CHECKLIST_FIELDS = [  # FIX: C5-finding-1
    "incident_type",  # FIX: C5-finding-1
    "severity_level",  # FIX: C5-finding-1
    "detection_summary",  # FIX: C5-finding-1
    "containment_actions",  # FIX: C5-finding-1
    "eradication_steps",  # FIX: C5-finding-1
    "recovery_validation",  # FIX: C5-finding-1
    "internal_communication",  # FIX: C5-finding-1
    "lessons_learned",  # FIX: C5-finding-1
]  # FIX: C5-finding-1


def _write_security_policy(repo_root: Path, critical_patch_sla_days: int | None, dependency_audit_cadence_days: int | None) -> None:  # FIX: C5-finding-1
    vulnerability_validation = {}  # FIX: C5-finding-1
    if critical_patch_sla_days is not None:  # FIX: C5-finding-1
        vulnerability_validation["critical_patch_sla_days"] = critical_patch_sla_days  # FIX: C5-finding-1
    if dependency_audit_cadence_days is not None:  # FIX: C5-finding-1
        vulnerability_validation["dependency_audit_cadence_days"] = dependency_audit_cadence_days  # FIX: C5-finding-1
    security_policy = {  # FIX: C5-finding-1
        "policies": {  # FIX: C5-finding-1
            "vulnerability_management": {  # FIX: C5-finding-1
                "validation": vulnerability_validation,  # FIX: C5-finding-1
            },  # FIX: C5-finding-1
            "incident_response": {  # FIX: C5-finding-1
                "validation": {  # FIX: C5-finding-1
                    "required_playbooks": list(_REQUIRED_PLAYBOOKS),  # FIX: C5-finding-1
                    "checklist": {  # FIX: C5-finding-1
                        "path": _CHECKLIST_PATH,  # FIX: C5-finding-1
                        "required_fields": list(_REQUIRED_CHECKLIST_FIELDS),  # FIX: C5-finding-1
                        "forbidden_placeholders": [  # FIX: C5-finding-1
                            "TBD",  # FIX: C5-finding-1
                            "TODO",  # FIX: C5-finding-1
                            "__REQUIRED__",  # FIX: C5-finding-1
                            "[Your Name]",  # FIX: C5-finding-1
                            "YYYY-MM-DD",  # FIX: C5-finding-1
                            "INC-YYYY-NNNN",  # FIX: C5-finding-1
                        ],  # FIX: C5-finding-1
                    },  # FIX: C5-finding-1
                },  # FIX: C5-finding-1
            },  # FIX: C5-finding-1
        },  # FIX: C5-finding-1
    }  # FIX: C5-finding-1
    policy_path = repo_root / "configs" / "organization-policies" / "security-policy.json"  # FIX: C5-finding-1
    policy_path.parent.mkdir(parents=True, exist_ok=True)  # FIX: C5-finding-1
    policy_path.write_text(json.dumps(security_policy, indent=2), encoding="utf-8")  # FIX: C5-finding-1


def _write_playbooks(repo_root: Path, missing_playbooks: set[str] | None = None) -> None:  # FIX: C5-finding-1
    missing = missing_playbooks or set()  # FIX: C5-finding-1
    for playbook_path_text in _REQUIRED_PLAYBOOKS:  # FIX: C5-finding-1
        if playbook_path_text in missing:  # FIX: C5-finding-1
            continue  # FIX: C5-finding-1
        playbook_path = repo_root / Path(playbook_path_text)  # FIX: C5-finding-1
        playbook_path.parent.mkdir(parents=True, exist_ok=True)  # FIX: C5-finding-1
        playbook_path.write_text("# Incident response playbook\n", encoding="utf-8")  # FIX: C5-finding-1


def _write_checklist(repo_root: Path, missing_fields: set[str] | None = None, empty_fields: set[str] | None = None) -> None:  # FIX: C5-finding-1
    checklist_payload = {  # FIX: C5-finding-1
        "incident_type": "Credential compromise",  # FIX: C5-finding-1
        "severity_level": "P0",  # FIX: C5-finding-1
        "detection_summary": "Security monitoring escalated the incident.",  # FIX: C5-finding-1
        "containment_actions": ["Revoked credentials", "Isolated the workload"],  # FIX: C5-finding-1
        "eradication_steps": ["Removed malicious access", "Patched the affected service"],  # FIX: C5-finding-1
        "recovery_validation": ["Monitoring verified", "Follow-up scan passed"],  # FIX: C5-finding-1
        "internal_communication": {  # FIX: C5-finding-1
            "incident_commander": "Security Lead",  # FIX: C5-finding-1
            "summary": "Stakeholders were notified through the approved channels.",  # FIX: C5-finding-1
        },  # FIX: C5-finding-1
        "lessons_learned": ["Credential rotation automation reduced containment time."],  # FIX: C5-finding-1
    }  # FIX: C5-finding-1
    for field_name in missing_fields or set():  # FIX: C5-finding-1
        checklist_payload.pop(field_name, None)  # FIX: C5-finding-1
    for field_name in empty_fields or set():  # FIX: C5-finding-1
        value = checklist_payload.get(field_name)  # FIX: C5-finding-1
        if isinstance(value, str):  # FIX: C5-finding-1
            checklist_payload[field_name] = ""  # FIX: C5-finding-1
        elif isinstance(value, list):  # FIX: C5-finding-1
            checklist_payload[field_name] = []  # FIX: C5-finding-1
        elif isinstance(value, dict):  # FIX: C5-finding-1
            checklist_payload[field_name] = {}  # FIX: C5-finding-1
        elif field_name in checklist_payload:  # FIX: C5-finding-1
            checklist_payload[field_name] = None  # FIX: C5-finding-1
    checklist_path = repo_root / Path(_CHECKLIST_PATH)  # FIX: C5-finding-1
    checklist_path.parent.mkdir(parents=True, exist_ok=True)  # FIX: C5-finding-1
    checklist_path.write_text(json.dumps(checklist_payload, indent=2), encoding="utf-8")  # FIX: C5-finding-1


def _seed_policy_repo(tmp_path: Path, critical_patch_sla_days: int | None = 1, dependency_audit_cadence_days: int | None = 7, missing_playbooks: set[str] | None = None, missing_checklist_fields: set[str] | None = None, empty_checklist_fields: set[str] | None = None) -> Path:  # FIX: C5-finding-1
    repo_root = tmp_path / "policy-repo"  # FIX: C5-finding-1
    _write_security_policy(repo_root, critical_patch_sla_days, dependency_audit_cadence_days)  # FIX: C5-finding-1
    _write_playbooks(repo_root, missing_playbooks=missing_playbooks)  # FIX: C5-finding-1
    _write_checklist(repo_root, missing_fields=missing_checklist_fields, empty_fields=empty_checklist_fields)  # FIX: C5-finding-1
    return repo_root  # FIX: C5-finding-1


def _copy_validator_script(repo_root: Path) -> Path:  # FIX: C5-finding-1
    validator_copy = repo_root / "tools" / "policy-validator.py"  # FIX: C5-finding-1
    validator_copy.parent.mkdir(parents=True, exist_ok=True)  # FIX: C5-finding-1
    shutil.copyfile(_POLICY_VALIDATOR_PATH, validator_copy)  # FIX: C5-finding-1
    return validator_copy  # FIX: C5-finding-1


def test_sec_003_passes_with_configured_sla_and_audit_cadence(tmp_path: Path) -> None:  # FIX: C5-finding-1
    repo_root = _seed_policy_repo(tmp_path, critical_patch_sla_days=1, dependency_audit_cadence_days=7)  # FIX: C5-finding-1
    result = _POLICY_MOD.PolicyValidator(repo_root=repo_root).validate_policy("SEC-003")  # FIX: C5-finding-1
    assert result == {"compliant": True, "violations": []}  # FIX: C5-finding-1


def test_sec_003_fails_with_overdue_sla_and_missing_audit_cadence(tmp_path: Path) -> None:  # FIX: C5-finding-1
    repo_root = _seed_policy_repo(tmp_path, critical_patch_sla_days=10, dependency_audit_cadence_days=None)  # FIX: C5-finding-1
    result = _POLICY_MOD.PolicyValidator(repo_root=repo_root).validate_policy("SEC-003")  # FIX: C5-finding-1
    assert result["compliant"] is False  # FIX: C5-finding-1
    assert any(violation.startswith("SEC-003.1") for violation in result["violations"])  # FIX: C5-finding-1
    assert any(violation.startswith("SEC-003.2") for violation in result["violations"])  # FIX: C5-finding-1


def test_sec_005_passes_with_required_playbooks_and_populated_checklist(tmp_path: Path) -> None:  # FIX: C5-finding-1
    repo_root = _seed_policy_repo(tmp_path)  # FIX: C5-finding-1
    result = _POLICY_MOD.PolicyValidator(repo_root=repo_root).validate_policy("SEC-005")  # FIX: C5-finding-1
    assert result == {"compliant": True, "violations": []}  # FIX: C5-finding-1


def test_sec_005_fails_with_missing_playbook_and_missing_checklist_field(tmp_path: Path) -> None:  # FIX: C5-finding-1
    repo_root = _seed_policy_repo(  # FIX: C5-finding-1
        tmp_path,  # FIX: C5-finding-1
        missing_playbooks={"examples/incident-response/playbook-skill-compromise.md"},  # FIX: C5-finding-1
        missing_checklist_fields={"lessons_learned"},  # FIX: C5-finding-1
    )  # FIX: C5-finding-1
    result = _POLICY_MOD.PolicyValidator(repo_root=repo_root).validate_policy("SEC-005")  # FIX: C5-finding-1
    assert result["compliant"] is False  # FIX: C5-finding-1
    assert any(violation.startswith("SEC-005.1") for violation in result["violations"])  # FIX: C5-finding-1
    assert any(violation.startswith("SEC-005.2") for violation in result["violations"])  # FIX: C5-finding-1


def test_sec_005_fails_with_unpopulated_checklist_field(tmp_path: Path) -> None:  # FIX: C5-finding-1
    repo_root = _seed_policy_repo(tmp_path, empty_checklist_fields={"lessons_learned"})  # FIX: C5-finding-1
    result = _POLICY_MOD.PolicyValidator(repo_root=repo_root).validate_policy("SEC-005")  # FIX: C5-finding-1
    assert result["compliant"] is False  # FIX: C5-finding-1
    assert "SEC-005.2: Incident checklist fields must be populated: lessons_learned" in result["violations"]  # FIX: C5-finding-1


def test_validator_script_returns_nonzero_for_seeded_noncompliant_repo(tmp_path: Path) -> None:  # FIX: C5-finding-1
    repo_root = _seed_policy_repo(tmp_path, critical_patch_sla_days=10, dependency_audit_cadence_days=None)  # FIX: C5-finding-1
    validator_copy = _copy_validator_script(repo_root)  # FIX: C5-finding-1
    completed = subprocess.run(  # FIX: C5-finding-1
        [sys.executable, str(validator_copy), "--policy", "SEC-003"],  # FIX: C5-finding-1
        cwd=repo_root,  # FIX: C5-finding-1
        capture_output=True,  # FIX: C5-finding-1
        text=True,  # FIX: C5-finding-1
        check=False,  # FIX: C5-finding-1
    )  # FIX: C5-finding-1
    assert completed.returncode == 1  # FIX: C5-finding-1
    assert "SEC-003.1" in completed.stdout  # FIX: C5-finding-1
    assert "SEC-003.2" in completed.stdout  # FIX: C5-finding-1


if __name__ == "__main__":  # FIX: C5-finding-1
    raise SystemExit(pytest.main([__file__, "-v"]))  # FIX: C5-finding-1
