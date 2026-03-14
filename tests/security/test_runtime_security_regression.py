#!/usr/bin/env python3
"""Unit tests for the Cycle 3 runtime security regression harness."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys


MODULE_PATH = Path(__file__).resolve().parents[2] / "scripts" / "verification" / "runtime_security_regression.py"
SPEC = importlib.util.spec_from_file_location("runtime_security_regression", MODULE_PATH)
runtime_security_regression = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = runtime_security_regression
SPEC.loader.exec_module(runtime_security_regression)


def test_scenario_selection_all_returns_both_paths() -> None:
    assert runtime_security_regression.scenario_names("all") == ["secure", "insecure"]


def test_secure_skills_config_is_hardened() -> None:
    config = runtime_security_regression.build_skills_config(
        runtime_security_regression.SCENARIOS["secure"]
    )

    assert "autoInstall: false" in config
    assert "autoUpdate: false" in config
    assert "requireSignature: true" in config


def test_insecure_docker_command_omits_hardening_flags() -> None:
    command = runtime_security_regression.build_docker_command(
        runtime_security_regression.SCENARIOS["insecure"],
        image="alpine:3.19",
        container_name="clawdbot-production",
    )

    assert "--read-only" not in command
    assert "--cap-drop" not in command
    assert "--pids-limit" not in command
    assert "--security-opt" not in command
    assert command[-2:] == ["sleep", "600"]


def test_secure_docker_command_includes_hardening_flags() -> None:
    command = runtime_security_regression.build_docker_command(
        runtime_security_regression.SCENARIOS["secure"],
        image="alpine:3.19",
        container_name="clawdbot-production",
    )

    assert "--read-only" in command
    assert ["--cap-drop", "ALL"] == command[command.index("--cap-drop") : command.index("--cap-drop") + 2]
    assert "--pids-limit" in command
    assert "--security-opt" in command
    assert "100" in command


def test_verify_output_reports_missing_markers() -> None:
    errors = runtime_security_regression.verify_output(
        runtime_security_regression.SCENARIOS["secure"],
        output="partial output only",
        exit_code=2,
    )

    assert any("Expected exit code 0" in error for error in errors)
    assert any("Missing expected marker" in error for error in errors)


def test_write_fixture_home_seeds_expected_files(tmp_path: Path) -> None:
    runtime_security_regression.write_fixture_home(
        tmp_path,
        runtime_security_regression.SCENARIOS["secure"],
    )

    gateway = tmp_path / ".openclaw" / "config" / "gateway.yml"
    skills = tmp_path / ".openclaw" / "config" / "skills.yml"
    shield = tmp_path / ".openclaw" / "config" / "shield" / "config.yml"
    telemetry = tmp_path / ".openclaw" / "config" / "telemetry" / "config.yml"

    assert gateway.exists()
    assert skills.exists()
    assert shield.exists()
    assert telemetry.exists()
    assert "127.0.0.1" in gateway.read_text(encoding="utf-8")