#!/usr/bin/env python3
"""Capture a small runner-environment snapshot for hosted CI evidence."""

import argparse
import json
import platform
import shutil
import subprocess  # nosec B404
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast  # pylance: cast/Any used to narrow object-typed snapshot dicts


INTERESTING_ENV_VARS = (
    "CI",
    "GITHUB_ACTIONS",
    "GITHUB_ACTOR",
    "GITHUB_REF",
    "GITHUB_REPOSITORY",
    "GITHUB_RUN_ATTEMPT",
    "GITHUB_RUN_ID",
    "GITHUB_RUN_NUMBER",
    "GITHUB_SHA",
    "ImageOS",
    "ImageVersion",
    "RUNNER_ARCH",
    "RUNNER_NAME",
    "RUNNER_OS",
    "RUNNER_TEMP",
    "RUNNER_TOOL_CACHE",
)


def run_command(command: list[str]) -> dict[str, object]:
    result = subprocess.run(command, capture_output=True, text=True, check=False)  # nosec B603
    return {
        "command": command,
        "returncode": result.returncode,
        "stdout": result.stdout.strip(),
        "stderr": result.stderr.strip(),
    }


def command_snapshot(name: str, version_args: list[str] | None = None) -> dict[str, object]:
    resolved = shutil.which(name)
    snapshot: dict[str, object] = {
        "name": name,
        "path": resolved,
        "available": resolved is not None,
    }
    if resolved and version_args:
        snapshot["version"] = run_command([resolved, *version_args])
    return snapshot


def gather_snapshot() -> dict[str, object]:
    docker_path = shutil.which("docker")
    if docker_path:  # pylance: only run docker subprocess when binary resolved (str, not None)
        docker_info: dict[str, object] = run_command(  # pylance: typed dict for downstream narrowing
            [docker_path, "info", "--format", "{{json .SecurityOptions}}"]
        )
        docker_version: dict[str, object] = run_command(  # pylance: typed dict for downstream narrowing
            [docker_path, "version", "--format", "{{json .}}"]
        )
    else:
        docker_info = {
            "command": ["docker", "info", "--format", "{{json .SecurityOptions}}"],
            "returncode": 127,
            "stdout": "",
            "stderr": "docker command not available",
        }
        docker_version = {
            "command": ["docker", "version", "--format", "{{json .}}"],
            "returncode": 127,
            "stdout": "",
            "stderr": "docker command not available",
        }

    snapshot = {
        "captured_at": datetime.now(UTC).isoformat(),
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "python_version": sys.version,
        },
        "environment": {name: __import__("os").environ.get(name, "") for name in INTERESTING_ENV_VARS},
        "commands": {
            "python": command_snapshot("python", ["--version"]),
            "bash": command_snapshot("bash", ["--version"]),
            "openssl": command_snapshot("openssl", ["version"]),
            "yara": command_snapshot("yara", ["--version"]),
            "yara64": command_snapshot("yara64", ["--version"]),
            "docker": {
                "name": "docker",
                "path": docker_path,
                "available": docker_path is not None,
                "version": docker_version,
                "security_options": docker_info,
            },
        },
    }
    return snapshot


def render_markdown(snapshot: dict[str, object]) -> str:
    environment = cast(dict[str, Any], snapshot["environment"])  # pylance: snapshot dict values are object; narrow for indexing
    commands = cast(dict[str, Any], snapshot["commands"])  # pylance: narrow nested dict for indexing
    docker = cast(dict[str, Any], commands["docker"])  # pylance: narrow nested dict for indexing
    platform_info = cast(dict[str, Any], snapshot["platform"])  # pylance: narrow nested dict for indexing
    return "\n".join(
        [
            "# Runner Delta Snapshot",
            "",
            f"- Captured: {snapshot['captured_at']}",
            f"- Runner OS: {environment.get('RUNNER_OS') or platform_info['system']}",  # pylance: use narrowed local
            f"- Image: {environment.get('ImageOS', 'unknown')} {environment.get('ImageVersion', '').strip()}",
            f"- Python: {commands['python'].get('version', {}).get('stdout', '') or commands['python'].get('version', {}).get('stderr', '')}",
            f"- Docker available: {docker['available']}",
            f"- YARA available: {commands['yara']['available'] or commands['yara64']['available']}",
            "",
            "## Hosted Checks",
            "",
            f"- Docker security options: {docker.get('security_options', {}).get('stdout', '') or docker.get('security_options', {}).get('stderr', '')}",
            f"- Bash path: {commands['bash'].get('path') or 'missing'}",
            f"- OpenSSL path: {commands['openssl'].get('path') or 'missing'}",
            f"- YARA path: {commands['yara'].get('path') or commands['yara64'].get('path') or 'missing'}",
            "",
            "## GitHub Context",
            "",
            f"- Repository: {environment.get('GITHUB_REPOSITORY', '')}",
            f"- Ref: {environment.get('GITHUB_REF', '')}",
            f"- Run ID: {environment.get('GITHUB_RUN_ID', '')}",
            f"- Attempt: {environment.get('GITHUB_RUN_ATTEMPT', '')}",
        ]
    ) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Capture runner environment details for CI evidence")
    parser.add_argument("--output-dir", required=True, help="Directory where runner snapshot files are written")
    args = parser.parse_args(argv)

    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    snapshot = gather_snapshot()
    (output_dir / "runner-delta.json").write_text(json.dumps(snapshot, indent=2), encoding="utf-8")
    (output_dir / "runner-delta.md").write_text(render_markdown(snapshot), encoding="utf-8")
    print(f"[OK] Runner delta written to {output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())