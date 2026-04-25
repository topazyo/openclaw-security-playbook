from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


_SIMULATOR_PATH = Path(__file__).resolve().parents[2] / "tools" / "incident-simulator.py"
_SPEC = importlib.util.spec_from_file_location("openclaw_incident_simulator_claim_tests", _SIMULATOR_PATH)
assert _SPEC is not None and _SPEC.loader is not None
_SIM_MOD = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _SIM_MOD
_SPEC.loader.exec_module(_SIM_MOD)


def test_create_incident_claim_returns_scannable_resources_for_known_and_fallback_scenarios():
    simulator = _SIM_MOD.IncidentSimulator()

    hardened_incident = simulator.create_incident("mcp-compromise", severity="P3")
    fallback_incident = simulator.create_incident("unexpected-scenario", severity="P2")

    assert hardened_incident["severity"] == "P3"
    assert "example.com" in hardened_incident["affected_resources"]
    assert any(resource.startswith("i-") for resource in hardened_incident["affected_resources"])
    assert fallback_incident["type"] == "Credential Exfiltration"
    assert any(resource.startswith("i-") for resource in fallback_incident["affected_resources"])
    assert any("." in resource for resource in fallback_incident["affected_resources"])