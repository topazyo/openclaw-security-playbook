#!/usr/bin/env python3
"""Cycle 3 runtime security regression harness.

Builds controlled secure and insecure runtime states around
verify_openclaw_security.sh, captures the verifier output, and archives
evidence for future audit comparison.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import ssl
import subprocess  # nosec B404
import sys
import tempfile
import textwrap
import threading
import time
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
VERIFY_SCRIPT = REPO_ROOT / "scripts" / "verification" / "verify_openclaw_security.sh"
SECCOMP_PROFILE = REPO_ROOT / "scripts" / "hardening" / "docker" / "seccomp-profiles" / "clawdbot.json"
DEFAULT_ARCHIVE_ROOT = REPO_ROOT / "archive" / "audit-artifacts-2026-03-14" / "cycle-3-runtime"
DEFAULT_IMAGE = "alpine:3.19"
DEFAULT_CONTAINER_NAME = "clawdbot-production"
GATEWAY_PORT = 18789
TLS_PORT = 8443
GIT_WINDOWS_ROOTS = (
    Path("C:/Program Files/Git"),
    Path("C:/Program Files (x86)/Git"),
)


@dataclass(frozen=True)
class ScenarioDefinition:
    name: str
    bind_address: str
    tls_mode: str
    skills_auto_install: bool
    skills_auto_update: bool
    skills_require_signature: bool
    container_user: str | None
    read_only: bool
    cap_drop_all: bool
    cap_add: tuple[str, ...]
    security_opt: tuple[str, ...]
    tmpfs_mounts: tuple[str, ...]
    pids_limit: int | None
    expected_exit_code: int
    expected_markers: tuple[str, ...]
    expected_absent_markers: tuple[str, ...]


SCENARIOS: dict[str, ScenarioDefinition] = {
    "secure": ScenarioDefinition(
        name="secure",
        bind_address="127.0.0.1",
        tls_mode="tls1_3",
        skills_auto_install=False,
        skills_auto_update=False,
        skills_require_signature=True,
        container_user="1000:1000",
        read_only=True,
        cap_drop_all=True,
        cap_add=("NET_BIND_SERVICE",),
        security_opt=(f"seccomp={SECCOMP_PROFILE}", "no-new-privileges:true"),
        tmpfs_mounts=(
            "/tmp:rw,noexec,nosuid,nodev,size=100m",  # nosec
            "/var/run:rw,noexec,nosuid,nodev,size=10m",
        ),
        pids_limit=100,
        expected_exit_code=0,
        expected_markers=(
            "Gateway bound to localhost only",
            "TLS 1.3-only posture validated",
            "Runtime hardening checks passed (8/8 controls)",
            "Skill policy defaults are hardened",
            "All checks passed!",
        ),
        expected_absent_markers=("CRITICAL", "Warnings found"),
    ),
    "insecure": ScenarioDefinition(
        name="insecure",
        bind_address="0.0.0.0",  # nosec
        tls_mode="tls1_2",
        skills_auto_install=True,
        skills_auto_update=True,
        skills_require_signature=False,
        container_user=None,
        read_only=False,
        cap_drop_all=False,
        cap_add=("SYS_ADMIN",),
        security_opt=(),
        tmpfs_mounts=(),
        pids_limit=None,
        expected_exit_code=1,
        expected_markers=(
            "Gateway config contains wildcard bind",
            "Gateway exposed on all interfaces",
            "TLS 1.2 accepted",
            "Container is not running as 1000:1000",
            "Container root filesystem is not read-only",
            "cap_drop does not include ALL",
            "no-new-privileges is not enabled",
            "pids_limit not set",
            "tmpfs mounts not configured",
            "Skill policy defaults are not hardened",
            "CRITICAL ISSUES DETECTED",
        ),
        expected_absent_markers=("All checks passed!",),
    ),
}


class _HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, format: str, *args: object) -> None:  # noqa: A003
        return


class GatewayServer:
    def __init__(self, host: str, port: int) -> None:
        self._server = ThreadingHTTPServer((host, port), _HealthHandler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)


class TLSServer:
    def __init__(self, host: str, port: int, cert_path: Path, key_path: Path, tls_mode: str) -> None:
        self._host = host
        self._port = port
        self._stop_event = threading.Event()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((host, port))
        self._sock.listen(5)
        self._sock.settimeout(0.5)
        self._context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
        if tls_mode == "tls1_3":
            self._context.minimum_version = ssl.TLSVersion.TLSv1_3
            self._context.maximum_version = ssl.TLSVersion.TLSv1_3
        elif tls_mode == "tls1_2":
            self._context.minimum_version = ssl.TLSVersion.TLSv1_2
            self._context.maximum_version = ssl.TLSVersion.TLSv1_2
        else:
            raise ValueError(f"Unsupported TLS mode: {tls_mode}")
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def _serve(self) -> None:
        while not self._stop_event.is_set():
            try:
                client, _ = self._sock.accept()
            except TimeoutError:
                continue
            except OSError:
                break

            with client:
                try:
                    tls_client = self._context.wrap_socket(client, server_side=True)
                except ssl.SSLError:
                    continue

                with tls_client:
                    try:
                        tls_client.recv(1024)
                        tls_client.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
                    except OSError:
                        continue

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        self._sock.close()
        self._thread.join(timeout=5)


def ensure_command(name: str) -> str:
    path = shutil.which(name)
    if not path:
        raise RuntimeError(f"Required command not found in PATH: {name}")
    return path


def resolve_bash_executable() -> str:
    for git_root in GIT_WINDOWS_ROOTS:
        candidate = git_root / "bin" / "bash.exe"
        if candidate.exists():
            return str(candidate)
    return ensure_command("bash")


def resolve_git_bash_command(name: str) -> str | None:
    candidates = []
    for git_root in GIT_WINDOWS_ROOTS:
        candidates.extend(
            [
                git_root / "usr" / "bin" / f"{name}.exe",
                git_root / "mingw64" / "bin" / f"{name}.exe",
                git_root / "bin" / f"{name}.exe",
            ]
        )
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)
    return None


def run_command(command: list[str], *, env: dict[str, str] | None = None, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, env=env, cwd=cwd, capture_output=True, text=True, check=False)  # nosec B603


def scenario_names(selection: str) -> list[str]:
    if selection == "all":
        return ["secure", "insecure"]
    if selection not in SCENARIOS:
        raise ValueError(f"Unknown scenario: {selection}")
    return [selection]


def build_skills_config(scenario: ScenarioDefinition) -> str:
    auto_install = str(scenario.skills_auto_install).lower()
    auto_update = str(scenario.skills_auto_update).lower()
    require_signature = str(scenario.skills_require_signature).lower()
    return textwrap.dedent(
        f"""
        skills:
          autoInstall: {auto_install}
          autoUpdate: {auto_update}
          requireSignature: {require_signature}
        """
    ).strip() + "\n"


def write_fixture_home(home_dir: Path, scenario: ScenarioDefinition) -> None:
    config_dir = home_dir / ".openclaw" / "config"
    shield_dir = config_dir / "shield"
    telemetry_dir = config_dir / "telemetry"
    logs_dir = home_dir / ".openclaw" / "logs"
    for path in (config_dir, shield_dir, telemetry_dir, logs_dir):
        path.mkdir(parents=True, exist_ok=True)

    (config_dir / "gateway.yml").write_text(
        textwrap.dedent(
            f"""
            network:
              bind:
                address: {scenario.bind_address}
                port: {GATEWAY_PORT}
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )
    (config_dir / "skills.yml").write_text(build_skills_config(scenario), encoding="utf-8")
    (shield_dir / "config.yml").write_text("enabled: true\n", encoding="utf-8")
    (telemetry_dir / "config.yml").write_text("enabled: true\n", encoding="utf-8")


def generate_certificate(cert_dir: Path) -> tuple[Path, Path]:
    cert_path = cert_dir / "server.crt"
    key_path = cert_dir / "server.key"
    openssl = shutil.which("openssl") or resolve_git_bash_command("openssl")
    args = [
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-keyout",
        str(key_path),
        "-out",
        str(cert_path),
        "-days",
        "1",
        "-nodes",
        "-subj",
        "/CN=localhost",
    ]
    if openssl:
        result = run_command([openssl, *args])
    else:
        raise RuntimeError("Failed to locate openssl in PATH or Git Bash")
    if result.returncode != 0:
        raise RuntimeError(f"Failed to generate TLS certificate: {result.stderr.strip()}")
    return cert_path, key_path


def build_docker_command(scenario: ScenarioDefinition, image: str, container_name: str) -> list[str]:
    command = ["docker", "run", "-d", "--name", container_name]
    if scenario.container_user:
        command.extend(["--user", scenario.container_user])
    if scenario.cap_drop_all:
        command.extend(["--cap-drop", "ALL"])
    for cap in scenario.cap_add:
        command.extend(["--cap-add", cap])
    for security_opt in scenario.security_opt:
        command.extend(["--security-opt", security_opt])
    if scenario.read_only:
        command.append("--read-only")
    if scenario.pids_limit is not None:
        command.extend(["--pids-limit", str(scenario.pids_limit)])
    for mount in scenario.tmpfs_mounts:
        command.extend(["--tmpfs", mount])
    command.extend([image, "sleep", "600"])
    return command


def ensure_docker_daemon() -> None:
    result = run_command(["docker", "info", "--format", "{{.ServerVersion}}"])
    if result.returncode != 0:
        message = result.stderr.strip() or result.stdout.strip() or "unknown docker error"
        raise RuntimeError(f"Docker daemon is unavailable: {message}")


def remove_container(container_name: str) -> None:
    run_command(["docker", "rm", "-f", container_name])


def wait_for_port(host: str, port: int, timeout_seconds: float = 10.0) -> None:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5)
            if sock.connect_ex((host, port)) == 0:
                return
        time.sleep(0.1)
    raise RuntimeError(f"Timed out waiting for {host}:{port}")


def verify_output(scenario: ScenarioDefinition, output: str, exit_code: int) -> list[str]:
    errors: list[str] = []
    if exit_code != scenario.expected_exit_code:
        errors.append(
            f"Expected exit code {scenario.expected_exit_code} for {scenario.name}, got {exit_code}"
        )
    for marker in scenario.expected_markers:
        if marker not in output:
            errors.append(f"Missing expected marker for {scenario.name}: {marker}")
    for marker in scenario.expected_absent_markers:
        if marker in output:
            errors.append(f"Unexpected marker for {scenario.name}: {marker}")
    return errors


def archive_result(
    archive_root: Path,
    scenario: ScenarioDefinition,
    combined_output: str,
    exit_code: int,
    verification_errors: list[str],
    fixture_home: Path,
    container_name: str,
) -> None:
    scenario_dir = archive_root / scenario.name
    scenario_dir.mkdir(parents=True, exist_ok=True)
    (scenario_dir / "verifier-output.txt").write_text(combined_output, encoding="utf-8")
    gateway_config = fixture_home / ".openclaw" / "config" / "gateway.yml"
    skills_config = fixture_home / ".openclaw" / "config" / "skills.yml"
    shutil.copy2(gateway_config, scenario_dir / "gateway.yml")
    shutil.copy2(skills_config, scenario_dir / "skills.yml")

    inspect_output = run_command(["docker", "inspect", container_name])
    if inspect_output.returncode == 0:
        (scenario_dir / "docker-inspect.json").write_text(inspect_output.stdout, encoding="utf-8")

    manifest = {
        "scenario": asdict(scenario),
        "verifier_exit_code": exit_code,
        "verification_errors": verification_errors,
        "recorded_at": datetime.now(UTC).isoformat(),
    }
    (scenario_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")


def execute_scenario(scenario: ScenarioDefinition, archive_root: Path, image: str, container_name: str) -> dict[str, Any]:
    bash = resolve_bash_executable()
    ensure_command("docker")
    ensure_docker_daemon()
    remove_container(container_name)

    with tempfile.TemporaryDirectory(prefix=f"openclaw-{scenario.name}-") as temp_dir:
        temp_path = Path(temp_dir)
        home_dir = temp_path / "home"
        cert_dir = temp_path / "certs"
        cert_dir.mkdir(parents=True, exist_ok=True)
        write_fixture_home(home_dir, scenario)
        cert_path, key_path = generate_certificate(cert_dir)

        gateway_server = GatewayServer(scenario.bind_address, GATEWAY_PORT)
        tls_server = TLSServer("127.0.0.1", TLS_PORT, cert_path, key_path, scenario.tls_mode)

        try:
            gateway_server.start()
            tls_server.start()
            wait_for_port("127.0.0.1", GATEWAY_PORT)
            wait_for_port("127.0.0.1", TLS_PORT)

            docker_result = run_command(build_docker_command(scenario, image, container_name))
            if docker_result.returncode != 0:
                raise RuntimeError(
                    f"Failed to start {scenario.name} container: {docker_result.stderr.strip()}"
                )

            env = os.environ.copy()
            env["HOME"] = str(home_dir)
            env["OPENCLAW_VERIFIER_CONTAINER_NAME"] = container_name
            env["OPENCLAW_VERIFIER_GATEWAY_PORT"] = str(GATEWAY_PORT)
            env["OPENCLAW_VERIFIER_TLS_HOST"] = "127.0.0.1"
            env["OPENCLAW_VERIFIER_TLS_PORT"] = str(TLS_PORT)

            verifier_result = run_command([bash, str(VERIFY_SCRIPT)], env=env, cwd=REPO_ROOT)
            combined_output = verifier_result.stdout + verifier_result.stderr
            verification_errors = verify_output(scenario, combined_output, verifier_result.returncode)
            archive_result(
                archive_root,
                scenario,
                combined_output,
                verifier_result.returncode,
                verification_errors,
                home_dir,
                container_name,
            )
            return {
                "scenario": scenario.name,
                "exit_code": verifier_result.returncode,
                "verification_errors": verification_errors,
            }
        finally:
            tls_server.stop()
            gateway_server.stop()
            remove_container(container_name)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run Cycle 3 runtime security regression scenarios")
    parser.add_argument(
        "--scenario",
        choices=["secure", "insecure", "all"],
        default="all",
        help="Which runtime scenario to execute",
    )
    parser.add_argument(
        "--archive-root",
        default=str(DEFAULT_ARCHIVE_ROOT),
        help="Directory where runtime evidence should be written",
    )
    parser.add_argument(
        "--image",
        default=DEFAULT_IMAGE,
        help="Container image to use for runtime hardening inspection",
    )
    parser.add_argument(
        "--container-name",
        default=DEFAULT_CONTAINER_NAME,
        help="Container name passed through to the verifier",
    )
    args = parser.parse_args(argv)

    archive_root = Path(args.archive_root).resolve()
    archive_root.mkdir(parents=True, exist_ok=True)

    summary: dict[str, Any] = {
        "created_at": datetime.now(UTC).isoformat(),
        "scenario_selection": args.scenario,
        "results": [],
    }

    for name in scenario_names(args.scenario):
        result = execute_scenario(SCENARIOS[name], archive_root, args.image, args.container_name)
        summary["results"].append(result)

    (archive_root / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

    failures = [result for result in summary["results"] if result["verification_errors"]]
    if failures:
        for failure in failures:
            for error in failure["verification_errors"]:
                print(f"[!] {error}", file=sys.stderr)
        return 1

    print(f"[OK] Runtime regression pack completed successfully: {archive_root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())