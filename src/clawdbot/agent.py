"""Minimal agent runtime used by the hardened container assets."""

import argparse
import os

from .config import load_config
from .server import serve


def build_status_payload(config_path: str, gateway_url: str, max_tasks: int) -> dict[str, object]:
    config = load_config(config_path)
    agent_config = config.get("agent", {})
    capabilities = agent_config.get("capabilities", {})
    return {
        "agent_name": agent_config.get("name", "clawdbot-agent"),
        "environment": agent_config.get("environment", "production"),
        "gateway_url": gateway_url,
        "configured_max_tasks": capabilities.get("max_concurrent_tasks"),
        "effective_max_tasks": max_tasks,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the minimal ClawdBot agent runtime")
    parser.add_argument("--config", required=True, help="Path to the agent configuration file")
    parser.add_argument("--gateway-url", default="", help="Gateway URL used by the worker")
    parser.add_argument("--max-tasks", type=int, default=5, help="Maximum concurrent tasks")
    parser.add_argument("--host", default=os.environ.get("AGENT_HOST", "0.0.0.0"), help="Bind host")
    parser.add_argument("--port", type=int, default=int(os.environ.get("AGENT_PORT", "8000")), help="Bind port")
    args = parser.parse_args(argv)

    payload = build_status_payload(args.config, args.gateway_url, args.max_tasks)
    serve("agent", args.host, args.port, payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())