"""Minimal gateway runtime used by the hardened container assets."""

import argparse

from .config import load_config
from .server import serve


def build_status_payload(config_path: str) -> dict[str, object]:
    config = load_config(config_path)
    network = config.get("network", {})
    bind = network.get("bind", {})
    tls = config.get("tls", {})
    authentication = config.get("authentication", {})
    return {
        "bind_address": bind.get("address", "127.0.0.1"),
        "bind_port": bind.get("port", 18789),
        "tls_enabled": tls.get("enabled", False),
        "authentication_mode": authentication.get("mode", "optional"),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the minimal ClawdBot gateway runtime")
    parser.add_argument("--config", required=True, help="Path to the gateway configuration file")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host")
    parser.add_argument("--port", type=int, default=8443, help="Bind port")
    args = parser.parse_args(argv)

    payload = build_status_payload(args.config)
    serve("gateway", args.host, args.port, payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())