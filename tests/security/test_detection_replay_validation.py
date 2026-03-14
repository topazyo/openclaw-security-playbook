#!/usr/bin/env python3
"""Unit tests for detection replay validation."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys

import pytest


MODULE_PATH = Path(__file__).resolve().parents[2] / "scripts" / "verification" / "validate_detection_replay.py"
SPEC = importlib.util.spec_from_file_location("validate_detection_replay", MODULE_PATH)
assert SPEC is not None
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


def test_archive_results_writes_summary_file(tmp_path: Path) -> None:
    cases_path = Path(__file__).resolve().parent / "fixtures" / "detection-replay" / "replay_cases.json"
    results = validate_detection_replay.run_validation(cases_path, skip_yara=True, require_yara=False)

    validate_detection_replay.archive_results(
        tmp_path,
        cases_path,
        skip_yara=True,
        require_yara=False,
        yara_command=None,
        results=results,
    )

    summary_path = tmp_path / "summary.json"
    assert summary_path.exists()
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    assert summary["skip_yara"] is True
    assert summary["require_yara"] is False
    assert summary["results"]


def test_normalize_text_handles_case_whitespace_encoding_and_null_bytes() -> None:
    normalized = validate_detection_replay.normalize_text(
        "SYSTEM%20%20Instructions\x00\nFOR%20AI%20ASSISTANT"
    )

    assert normalized == "system instructions for ai assistant"


def test_validate_sigma_detection_rejects_regex_modifiers() -> None:
    with pytest.raises(ValueError):
        validate_detection_replay.validate_sigma_detection(
            {
                "CommandLine|contains|regex": "openclaw",
                "condition": "selection"
            }
        )


def test_yara_rules_avoid_high_risk_regex_patterns() -> None:
    yara_path = Path(__file__).resolve().parents[2] / "detections" / "ioc" / "ioc-openclaw.yar"
    findings = validate_detection_replay.find_high_risk_yara_patterns(
        yara_path.read_text(encoding="utf-8")
    )

    assert findings == []