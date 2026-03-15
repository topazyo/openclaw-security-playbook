"""Shared HTTP server utilities for the minimal ClawdBot runtime."""

from __future__ import annotations

import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any


def _json_handler(component: str, status_payload: dict[str, Any]):
    class _Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            if self.path not in {"/health", "/healthz", "/ready"}:
                self.send_response(HTTPStatus.NOT_FOUND)
                self.end_headers()
                return

            body = json.dumps(
                {
                    "status": "ok",
                    "component": component,
                    **status_payload,
                }
            ).encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:  # noqa: A003
            return

    return _Handler


def serve(component: str, host: str, port: int, status_payload: dict[str, Any]) -> None:
    server = HTTPServer((host, port), _json_handler(component, status_payload))
    print(f"[{component}] listening on {host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()