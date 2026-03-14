#!/usr/bin/env python3
"""Validate replay fixtures against OpenClaw Sigma and YARA detections."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CASES_PATH = REPO_ROOT / "tests" / "security" / "fixtures" / "detection-replay" / "replay_cases.json"


@dataclass
class ReplayResult:
    name: str
    kind: str
    passed: bool
    details: str


def load_cases(cases_path: Path) -> list[dict[str, Any]]:
    with open(cases_path, encoding="utf-8") as handle:
        cases = json.load(handle)
    if not isinstance(cases, list):
        raise ValueError("Replay case file must contain a JSON list")
    return cases


def parse_field_expression(expression: str) -> tuple[str, list[str]]:
    parts = expression.split("|")
    return parts[0], parts[1:]


def field_matches(event: dict[str, Any], expression: str, expected: Any) -> bool:
    field_name, modifiers = parse_field_expression(expression)
    actual = event.get(field_name)
    if actual is None:
        return False

    require_all = "all" in modifiers
    operation = "equals"
    for modifier in modifiers:
        if modifier in {"contains", "endswith"}:
            operation = modifier

    expected_values = expected if isinstance(expected, list) else [expected]

    if operation == "equals":
        return any(actual == value for value in expected_values)

    actual_text = str(actual)
    if operation == "contains":
        if require_all:
            return all(str(value) in actual_text for value in expected_values)
        return any(str(value) in actual_text for value in expected_values)

    if operation == "endswith":
        if require_all:
            return all(actual_text.endswith(str(value)) for value in expected_values)
        return any(actual_text.endswith(str(value)) for value in expected_values)

    raise ValueError(f"Unsupported Sigma field modifier chain: {expression}")


def selector_matches(event: dict[str, Any], selector: dict[str, Any]) -> bool:
    return all(field_matches(event, expression, expected) for expression, expected in selector.items())


def tokenize_condition(condition: str) -> list[str]:
    tokens: list[str] = []
    current = []
    for char in condition:
        if char.isspace():
            if current:
                tokens.append("".join(current))
                current = []
            continue
        if char in "()":
            if current:
                tokens.append("".join(current))
                current = []
            tokens.append(char)
            continue
        current.append(char)
    if current:
        tokens.append("".join(current))
    return tokens


class ConditionParser:
    def __init__(self, tokens: list[str], values: dict[str, bool]) -> None:
        self.tokens = tokens
        self.values = values
        self.index = 0

    def parse(self) -> bool:
        result = self.parse_or()
        if self.index != len(self.tokens):
            raise ValueError(f"Unexpected trailing tokens in condition: {self.tokens[self.index:]}")
        return result

    def parse_or(self) -> bool:
        result = self.parse_and()
        while self._peek() == "or":
            self.index += 1
            right = self.parse_and()
            result = result or right
        return result

    def parse_and(self) -> bool:
        result = self.parse_not()
        while self._peek() == "and":
            self.index += 1
            right = self.parse_not()
            result = result and right
        return result

    def parse_not(self) -> bool:
        if self._peek() == "not":
            self.index += 1
            return not self.parse_not()
        return self.parse_primary()

    def parse_primary(self) -> bool:
        token = self._peek()
        if token is None:
            raise ValueError("Unexpected end of condition")
        if token == "(":
            self.index += 1
            result = self.parse_or()
            if self._peek() != ")":
                raise ValueError("Missing closing parenthesis in condition")
            self.index += 1
            return result

        self.index += 1
        if token not in self.values:
            raise ValueError(f"Unknown selector in Sigma condition: {token}")
        return self.values[token]

    def _peek(self) -> str | None:
        if self.index >= len(self.tokens):
            return None
        return self.tokens[self.index]


def evaluate_sigma_case(case: dict[str, Any]) -> ReplayResult:
    rule_path = REPO_ROOT / case["rule"]
    fixture_path = REPO_ROOT / case["fixture"]

    with open(rule_path, encoding="utf-8") as handle:
        rule = yaml.safe_load(handle)
    with open(fixture_path, encoding="utf-8") as handle:
        event = json.load(handle)

    detection = rule["detection"]
    selector_results = {
        name: selector_matches(event, selector)
        for name, selector in detection.items()
        if name != "condition"
    }
    parser = ConditionParser(tokenize_condition(detection["condition"]), selector_results)
    matched = parser.parse()
    expected = bool(case["should_match"])
    details = f"matched={matched} expected={expected} selectors={selector_results}"
    return ReplayResult(case["name"], "sigma", matched == expected, details)


def resolve_yara_command() -> str | None:
    for candidate in ("yara", "yara64", "yara.exe"):
        path = shutil.which(candidate)
        if path:
            return path
    return None


def evaluate_yara_case(case: dict[str, Any], yara_command: str | None, require_yara: bool) -> ReplayResult:
    if not yara_command:
        if require_yara:
            return ReplayResult(case["name"], "yara", False, "yara command not available")
        return ReplayResult(case["name"], "yara", True, "skipped: yara command not available")

    rule_path = REPO_ROOT / case["rule"]
    fixture_path = REPO_ROOT / case["fixture"]
    result = subprocess.run(
        [yara_command, str(rule_path), str(fixture_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode not in {0, 1}:
        return ReplayResult(case["name"], "yara", False, result.stderr.strip() or result.stdout.strip())

    matched_rules = {
        line.split()[0]
        for line in result.stdout.splitlines()
        if line.strip()
    }
    expected_rules = set(case.get("expected_rules", []))
    unexpected_rules = set(case.get("unexpected_rules", []))

    passed = expected_rules.issubset(matched_rules) and matched_rules.isdisjoint(unexpected_rules)
    details = f"matched_rules={sorted(matched_rules)} expected_rules={sorted(expected_rules)} unexpected_rules={sorted(unexpected_rules)}"
    return ReplayResult(case["name"], "yara", passed, details)


def run_validation(cases_path: Path, *, skip_yara: bool, require_yara: bool) -> list[ReplayResult]:
    cases = load_cases(cases_path)
    yara_command = None if skip_yara else resolve_yara_command()
    results: list[ReplayResult] = []
    for case in cases:
        kind = case["kind"]
        if kind == "sigma":
            results.append(evaluate_sigma_case(case))
        elif kind == "yara":
            results.append(evaluate_yara_case(case, yara_command, require_yara))
        else:
            raise ValueError(f"Unsupported replay case kind: {kind}")
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate detection replay fixtures")
    parser.add_argument("--cases", default=str(DEFAULT_CASES_PATH), help="Replay case definition JSON file")
    parser.add_argument("--skip-yara", action="store_true", help="Skip YARA replay cases")
    parser.add_argument("--require-yara", action="store_true", help="Fail if YARA is unavailable")
    args = parser.parse_args(argv)

    results = run_validation(Path(args.cases), skip_yara=args.skip_yara, require_yara=args.require_yara)
    failures = [result for result in results if not result.passed]

    for result in results:
        status = "PASS" if result.passed else "FAIL"
        print(f"[{status}] {result.kind} {result.name}: {result.details}")

    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())