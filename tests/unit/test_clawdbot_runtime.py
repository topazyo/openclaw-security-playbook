from __future__ import annotations

import sys
from pathlib import Path


SRC_ROOT = Path(__file__).resolve().parents[2] / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from clawdbot.agent import build_status_payload
from clawdbot.config import load_config
from clawdbot.gateway import build_status_payload as build_gateway_status_payload


def test_load_config_expands_environment_variables(monkeypatch) -> None:
    monkeypatch.setenv("OPENCLAW_AGENT_ID", "agent-123")
    config = load_config(Path("configs/agent-config/openclaw-agent.yml"))
    assert config["agent"]["id"] == "agent-123"


def test_agent_status_payload_uses_runtime_inputs(monkeypatch) -> None:
    monkeypatch.setenv("OPENCLAW_AGENT_ID", "agent-123")
    payload = build_status_payload("configs/agent-config/openclaw-agent.yml", "https://gateway.internal", 7)
    assert payload["agent_name"] == "openclaw-agent-prod"
    assert payload["gateway_url"] == "https://gateway.internal"
    assert payload["effective_max_tasks"] == 7


def test_gateway_status_payload_reads_template_defaults() -> None:
    payload = build_gateway_status_payload("configs/templates/gateway.hardened.yml")
    assert payload["bind_address"] == "127.0.0.1"
    assert payload["bind_port"] == 18789
    assert payload["tls_enabled"] is False