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


# --- C6-H-10: conflicting operator modifiers must raise, not silently pick one ---

@pytest.mark.parametrize(
    "expression",
    [
        "FieldName|contains|gte",
        "FieldName|gt|lt",
        "FieldName|endswith|contains",
        "FieldName|lte|gt",
        "FieldName|all|contains|gte",
    ],
)
def test_field_matches_rejects_conflicting_operator_modifiers(expression: str) -> None:
    with pytest.raises(ValueError, match="conflicting operator modifiers"):
        validate_detection_replay.field_matches({"FieldName": "anything"}, expression, "x")


def test_field_matches_rejects_conflicting_modifiers_when_field_missing() -> None:
    # FIX: C6-H-10 — guard against the early-return-hides-bad-rule case the reviewer flagged
    with pytest.raises(ValueError, match="conflicting operator modifiers"):
        validate_detection_replay.field_matches({}, "FieldName|contains|gte", "x")


@pytest.mark.parametrize(
    "expression,event_value,expected,want",
    [
        ("FieldName|contains", "openclaw runtime", "claw", True),
        ("FieldName|all|contains", "docker run --cap-drop ALL", ["docker", "ALL"], True),
        ("FieldName|gte", 42, 10, True),
        ("FieldName|all|gte", 42, [10, 20, 30], True),
        ("FieldName|all|gte", 15, [10, 20, 30], False),
        ("FieldName|endswith", "value.exe", ".exe", True),
    ],
)
def test_field_matches_accepts_single_operator_with_or_without_all(
    expression: str, event_value: object, expected: object, want: bool
) -> None:
    assert validate_detection_replay.field_matches({"FieldName": event_value}, expression, expected) is want


def test_evaluate_sigma_case_surfaces_conflict_as_failed_replayresult(tmp_path: Path) -> None:
    rule_path = tmp_path / "rule.yml"
    rule_path.write_text(
        "title: bad-rule\n"
        "detection:\n"
        "  selection:\n"
        "    FieldName|contains|gte: 1\n"
        "  condition: selection\n",
        encoding="utf-8",
    )
    fixture_path = tmp_path / "fixture.json"
    fixture_path.write_text(json.dumps({"FieldName": "anything"}), encoding="utf-8")
    case = {
        "name": "conflict-case",
        "rule": str(rule_path),
        "fixture": str(fixture_path),
        "should_match": True,
    }
    result = validate_detection_replay.evaluate_sigma_case(case)
    assert result.passed is False
    assert "invalid-rule" in result.details
    assert "conflicting operator modifiers" in result.details


# --- C6-H-10: malformed Sigma rules must surface as failed cases, not crash ---

@pytest.mark.parametrize(
    "rule_yaml,why",
    [
        # missing detection block
        ("title: no-detection\n", "missing-detection"),
        # missing condition inside detection
        (
            "title: no-condition\n"
            "detection:\n"
            "  selection:\n"
            "    FieldName: x\n",
            "missing-condition",
        ),
        # non-dict detection (list)
        (
            "title: list-detection\n"
            "detection:\n"
            "  - selection\n"
            "  - condition\n",
            "non-dict-detection",
        ),
        # non-dict detection (string)
        (
            "title: string-detection\n"
            "detection: just-a-string\n",
            "string-detection",
        ),
    ],
)
def test_evaluate_sigma_case_surfaces_malformed_rule_as_failed_replayresult(
    tmp_path: Path, rule_yaml: str, why: str
) -> None:
    rule_path = tmp_path / f"{why}.yml"
    rule_path.write_text(rule_yaml, encoding="utf-8")
    fixture_path = tmp_path / "fixture.json"
    fixture_path.write_text(json.dumps({"FieldName": "anything"}), encoding="utf-8")
    case = {
        "name": why,
        "rule": str(rule_path),
        "fixture": str(fixture_path),
        "should_match": True,
    }
    result = validate_detection_replay.evaluate_sigma_case(case)
    assert result.passed is False
    assert "invalid-rule" in result.details


# --- C6-H-10: per-modifier numeric coverage that C5-H-05 omitted ---

@pytest.mark.parametrize(
    "operator,event_value,expected,want",
    [
        # gte: matching
        ("gte", 10, 10, True),
        ("gte", 11, 10, True),
        # gte: non-matching
        ("gte", 9, 10, False),
        # lte: matching / non-matching
        ("lte", 10, 10, True),
        ("lte", 9, 10, True),
        ("lte", 11, 10, False),
        # gt: matching / non-matching
        ("gt", 11, 10, True),
        ("gt", 10, 10, False),
        # lt: matching / non-matching
        ("lt", 9, 10, True),
        ("lt", 10, 10, False),
    ],
)
def test_numeric_operators_match_and_nonmatch(
    operator: str, event_value: float, expected: float, want: bool
) -> None:
    expression = f"FieldName|{operator}"
    assert validate_detection_replay.field_matches(
        {"FieldName": event_value}, expression, expected
    ) is want


@pytest.mark.parametrize(
    "operator,event_value,expected,want",
    [
        # gte: coerces numeric string, matches when >=
        ("gte", "10", 10, True),
        ("gte", "9", 10, False),
        # lte: coerces numeric string, matches when <=
        ("lte", "10", 10, True),
        ("lte", "11", 10, False),
        # gt: coerces numeric string, matches when >
        ("gt", "11", 10, True),
        ("gt", "10", 10, False),
        # lt: coerces numeric string, matches when <
        ("lt", "9", 10, True),
        ("lt", "10", 10, False),
    ],
)
def test_numeric_string_event_values_are_coerced(
    operator: str, event_value: str, expected: float, want: bool
) -> None:
    # Existing code uses float(actual) which coerces numeric strings — assert that behavior.
    expression = f"FieldName|{operator}"
    assert validate_detection_replay.field_matches(
        {"FieldName": event_value}, expression, expected
    ) is want


@pytest.mark.parametrize("operator", ["gte", "lte", "gt", "lt"])
def test_non_numeric_event_values_return_false_without_crash(operator: str) -> None:
    expression = f"FieldName|{operator}"
    # Per C5-H-05 code path: float("abc") raises ValueError -> caught -> returns False
    assert validate_detection_replay.field_matches(
        {"FieldName": "abc"}, expression, 10
    ) is False


def test_field_all_gte_with_list_requires_all_values_satisfied() -> None:
    expression = "FieldName|all|gte"
    # actual=100 must be >= every expected; 100 >= 10, 50, 99 -> True
    assert validate_detection_replay.field_matches(
        {"FieldName": 100}, expression, [10, 50, 99]
    ) is True
    # actual=50 fails for expected=99 -> False
    assert validate_detection_replay.field_matches(
        {"FieldName": 50}, expression, [10, 50, 99]
    ) is False