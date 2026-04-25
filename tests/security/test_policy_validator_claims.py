from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


_POLICY_VALIDATOR_PATH = Path(__file__).resolve().parents[2] / "tools" / "policy-validator.py"
_SPEC = importlib.util.spec_from_file_location("openclaw_policy_validator_claim_tests", _POLICY_VALIDATOR_PATH)
assert _SPEC is not None and _SPEC.loader is not None
_POLICY_MOD = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _POLICY_MOD
_SPEC.loader.exec_module(_POLICY_MOD)

_REQUIRED_PLAYBOOKS = [
    "examples/incident-response/playbook-credential-theft.md",
    "examples/incident-response/playbook-data-breach.md",
    "examples/incident-response/playbook-denial-of-service.md",
    "examples/incident-response/playbook-prompt-injection.md",
    "examples/incident-response/playbook-skill-compromise.md",
]
_CHECKLIST_PATH = "configs/organization-policies/incident-response-checklist.json"


def _build_policy(vulnerability_validation=None, incident_validation=None):
    return {
        "policies": {
            "vulnerability_management": {
                "requirements": [
                    "Weekly vulnerability scans of all ClawdBot components",
                    "Critical vulnerabilities patched within 24 hours",
                ],
                "validation": vulnerability_validation or {},
            },
            "incident_response": {
                "validation": incident_validation
                or {
                    "required_playbooks": list(_REQUIRED_PLAYBOOKS),
                    "checklist": {
                        "path": _CHECKLIST_PATH,
                        "required_fields": [
                            "incident_type",
                            "severity_level",
                            "detection_summary",
                            "containment_actions",
                            "eradication_steps",
                            "recovery_validation",
                            "internal_communication",
                            "lessons_learned",
                        ],
                        "forbidden_placeholders": ["TBD", "TODO", "INC-YYYY-NNNN"],
                    },
                },
            },
        }
    }


def _write_json(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _seed_repo(repo_root: Path, *, policy_payload=None, checklist_payload=None, missing_playbooks=None) -> None:
    _write_json(
        repo_root / "configs" / "organization-policies" / "security-policy.json",
        policy_payload or _build_policy(),
    )
    for relative_path in _REQUIRED_PLAYBOOKS:
        if missing_playbooks and relative_path in missing_playbooks:
            continue
        playbook_path = repo_root / relative_path
        playbook_path.parent.mkdir(parents=True, exist_ok=True)
        playbook_path.write_text("# playbook\n", encoding="utf-8")
    if checklist_payload is not None:
        _write_json(repo_root / _CHECKLIST_PATH, checklist_payload)


def _valid_checklist_payload():
    return {
        "incident_type": "Credential compromise",
        "severity_level": "P0",
        "detection_summary": "SIEM alert escalated to the incident commander.",
        "containment_actions": ["Revoked credentials", "Isolated the workload"],
        "eradication_steps": ["Removed access path", "Patched the affected service"],
        "recovery_validation": ["Monitoring verified", "Follow-up scan passed"],
        "internal_communication": {
            "incident_commander": "Security Lead",
            "summary": "Stakeholders were notified through approved channels.",
        },
        "lessons_learned": ["Credential rotation automation reduced containment time."],
    }


def test___init___claim_uses_explicit_repo_root(tmp_path):
    repo_root = tmp_path / "repo with spaces"
    validator = _POLICY_MOD.PolicyValidator(repo_root=repo_root)

    assert validator.repo_root == repo_root
    assert validator._resolve_repo_path("configs/security-policy.json") == repo_root / "configs" / "security-policy.json"


def test__resolve_repo_path_claim_anchors_relative_and_preserves_absolute_paths(tmp_path):
    repo_root = tmp_path / "claim-root"
    validator = _POLICY_MOD.PolicyValidator(repo_root=repo_root)
    absolute_path = (tmp_path / "outside.json").resolve()

    assert validator._resolve_repo_path("configs/security-policy.json") == repo_root / "configs" / "security-policy.json"
    assert validator._resolve_repo_path(str(absolute_path)) == absolute_path


def test__load_json_config_claim_loads_valid_json_and_handles_malformed_input(tmp_path):
    repo_root = tmp_path / "repo"
    validator = _POLICY_MOD.PolicyValidator(repo_root=repo_root)
    valid_path = repo_root / "configs" / "organization-policies" / "security-policy.json"
    valid_path.parent.mkdir(parents=True, exist_ok=True)
    valid_path.write_text('{"mode": "valid"}', encoding="utf-8")
    malformed_path = repo_root / "configs" / "organization-policies" / "malformed.json"
    malformed_path.write_text('{"mode": ', encoding="utf-8")

    assert validator._load_json_config("configs/organization-policies/security-policy.json") == {"mode": "valid"}
    assert validator._load_json_config("configs/organization-policies/missing.json") == {}
    assert validator._load_json_config("configs/organization-policies/malformed.json") == {}


def test__get_vulnerability_mgmt_rules_claim_normalizes_aliases_and_requirement_fallback():
    validator = _POLICY_MOD.PolicyValidator(repo_root=Path("."))
    policy = {
        "policies": {
            "vulnerability_management": {
                "requirements": [
                    "Critical exploit attempt detected",
                    "Critical vulnerabilities patched within 24 hours",
                ],
                "validation": {
                    "critical_patch_sla": "24 hours",
                    "dependency_audit_cadence": "7 days",
                },
            }
        }
    }

    rules = validator._get_vulnerability_mgmt_rules(policy)

    assert rules["critical_patch_sla_days"] == "24 hours"
    assert rules["dependency_audit_cadence_days"] == "7 days"

    fallback_rules = validator._get_vulnerability_mgmt_rules(
        {"policies": {"vulnerability_management": {"requirements": policy["policies"]["vulnerability_management"]["requirements"]}}}
    )
    assert fallback_rules["critical_patch_sla_days"] == "Critical vulnerabilities patched within 24 hours"


def test__extract_critical_patch_sla_claim_finds_patch_requirement_and_ignores_non_patch_text():
    validator = _POLICY_MOD.PolicyValidator(repo_root=Path("."))
    requirements = [
        "Critical exploit attempt detected",
        "Patch Tuesday calendar review",
        "Critical vulnerabilities patched within 24 hours",
    ]

    assert validator._extract_critical_patch_sla(requirements) == "Critical vulnerabilities patched within 24 hours"


def test__coerce_duration_days_claim_normalizes_days_and_hours_and_rejects_malformed_input():
    validator = _POLICY_MOD.PolicyValidator(repo_root=Path("."))

    assert validator._coerce_duration_days(7) == 7.0
    assert validator._coerce_duration_days("24 hours") == 1.0
    assert validator._coerce_duration_days("7 days") == 7.0
    assert validator._coerce_duration_days("DROP TABLE policies") is None


def test__get_incident_response_rules_claim_returns_configured_rules_and_handles_malformed_playbook_input():
    validator = _POLICY_MOD.PolicyValidator(repo_root=Path("."))
    configured_policy = _build_policy(
        incident_validation={
            "required_playbooks": ["examples/incident-response/custom-playbook.md"],
            "checklist": {"path": _CHECKLIST_PATH, "required_fields": ["incident_type"], "forbidden_placeholders": ["TBD"]},
        }
    )
    rules = validator._get_incident_response_rules(configured_policy)

    assert rules["required_playbooks"] == ["examples/incident-response/custom-playbook.md"]
    assert rules["checklist"]["path"] == _CHECKLIST_PATH

    fallback_rules = validator._get_incident_response_rules(
        _build_policy(incident_validation={"required_playbooks": "../../etc/passwd", "checklist": None})
    )
    assert fallback_rules["required_playbooks"] == _REQUIRED_PLAYBOOKS
    assert fallback_rules["checklist"] is None


def test__load_checklist_data_claim_parses_json_and_rejects_malformed_payloads(tmp_path):
    validator = _POLICY_MOD.PolicyValidator(repo_root=tmp_path)
    checklist_path = tmp_path / "checklist.json"
    checklist_path.write_text('{"incident_type": "Credential compromise"}', encoding="utf-8")
    malformed_path = tmp_path / "malformed.json"
    malformed_path.write_text('{"incident_type": ', encoding="utf-8")

    assert validator._load_checklist_data(checklist_path, checklist_path.read_text(encoding="utf-8")) == {
        "incident_type": "Credential compromise"
    }
    assert validator._load_checklist_data(malformed_path, malformed_path.read_text(encoding="utf-8")) is None


def test__is_populated_checklist_value_claim_rejects_empty_scalars_and_structures():
    validator = _POLICY_MOD.PolicyValidator(repo_root=Path("."))

    assert validator._is_populated_checklist_value("Security Lead") is True
    assert validator._is_populated_checklist_value("") is False
    assert validator._is_populated_checklist_value([]) is False
    assert validator._is_populated_checklist_value({}) is False
    assert validator._is_populated_checklist_value({"summary": "   "}) is False
    assert validator._is_populated_checklist_value(["", "completed review"]) is True


def test__validate_incident_checklist_claim_rejects_unpopulated_and_placeholder_fields(tmp_path):
    repo_root = tmp_path / "repo"
    validator = _POLICY_MOD.PolicyValidator(repo_root=repo_root)
    checklist_payload = _valid_checklist_payload()
    checklist_payload["lessons_learned"] = []
    checklist_payload["detection_summary"] = "TBD"
    _write_json(repo_root / _CHECKLIST_PATH, checklist_payload)

    violations = validator._validate_incident_checklist(
        {
            "path": _CHECKLIST_PATH,
            "required_fields": ["incident_type", "detection_summary", "lessons_learned"],
            "forbidden_placeholders": ["TBD"],
        }
    )

    assert any("fields must be populated: lessons_learned" in violation for violation in violations)
    assert any("contains unpopulated placeholders: TBD" in violation for violation in violations)


def test__validate_vulnerability_mgmt_claim_rejects_noncompliant_sla_and_cadence(tmp_path):
    repo_root = tmp_path / "repo"
    _seed_repo(
        repo_root,
        policy_payload=_build_policy(vulnerability_validation={"critical_patch_sla_days": "30 days", "dependency_audit_cadence_days": 0}),
        checklist_payload=_valid_checklist_payload(),
    )
    validator = _POLICY_MOD.PolicyValidator(repo_root=repo_root)

    result = validator._validate_vulnerability_mgmt()

    assert result["compliant"] is False
    assert any(violation.startswith("SEC-003.1") for violation in result["violations"])
    assert any(violation.startswith("SEC-003.2") for violation in result["violations"])


def test__validate_incident_response_claim_rejects_missing_playbooks_and_unpopulated_checklist(tmp_path):
    repo_root = tmp_path / "repo"
    checklist_payload = _valid_checklist_payload()
    checklist_payload["internal_communication"] = {}
    _seed_repo(
        repo_root,
        checklist_payload=checklist_payload,
        missing_playbooks={"examples/incident-response/playbook-skill-compromise.md"},
    )
    validator = _POLICY_MOD.PolicyValidator(repo_root=repo_root)

    result = validator._validate_incident_response()

    assert result["compliant"] is False
    assert any(violation.startswith("SEC-005.1") for violation in result["violations"])
    assert any("fields must be populated: internal_communication" in violation for violation in result["violations"])