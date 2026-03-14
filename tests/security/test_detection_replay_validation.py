#!/usr/bin/env python3
"""Unit tests for detection replay validation."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys


MODULE_PATH = Path(__file__).resolve().parents[2] / "scripts" / "verification" / "validate_detection_replay.py"
SPEC = importlib.util.spec_from_file_location("validate_detection_replay", MODULE_PATH)
validate_detection_replay = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = validate_detection_replay
SPEC.loader.exec_module(validate_detection_replay)


def test_sigma_replay_cases_pass_without_yara_requirement() -> None:
    cases_path = Path(__file__).resolve().parent / "fixtures" / "detection-replay" / "replay_cases.json"
    results = validate_detection_replay.run_validation(cases_path, skip_yara=True, require_yara=False)

    sigma_results = [result for result in results if result.kind == "sigma"]
    assert sigma_results
    assert all(result.passed for result in sigma_results)


def test_condition_parser_handles_parentheses_and_not() -> None:
    tokens = validate_detection_replay.tokenize_condition("(a or b) and c and not d")
    parser = validate_detection_replay.ConditionParser(tokens, {"a": False, "b": True, "c": True, "d": False})
    assert parser.parse() is True


def test_contains_all_selector_requires_every_fragment() -> None:
    selector = {
        "CommandLine|contains|all": [
            "docker run",
            "--cap-drop ALL"
        ]
    }
    assert validate_detection_replay.selector_matches(
        {"CommandLine": "docker run --cap-drop ALL clawdbot"},
        selector,
    ) is True
    assert validate_detection_replay.selector_matches(
        {"CommandLine": "docker run clawdbot"},
        selector,
    ) is False