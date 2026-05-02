#!/usr/bin/env python3
"""Validate replay fixtures against OpenClaw Sigma and YARA detections."""

import argparse
import json
import re
import shutil
import subprocess  # nosec B404
import unicodedata
import urllib.parse
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import yaml


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CASES_PATH = REPO_ROOT / "tests" / "security" / "fixtures" / "detection-replay" / "replay_cases.json"
SIGMA_REGEX_MODIFIERS = {"re", "regex", "match"}
GROUP_OPEN_TOKEN = "("  # nosec B105
HIGH_RISK_YARA_PATTERNS = (
    re.compile(r"\(\.\*\)\+"),
    re.compile(r"\(\.\+\)\+"),
    re.compile(r"\(\.\*\)\*"),
    re.compile(r"\(\.\+\)\*"),
)


@dataclass
class ReplayResult:
    name: str
    kind: str
    passed: bool
    details: str


def load_cases(cases_path: Path) -> list[dict[str, Any]]:
    with open(cases_path, encoding="utf-8") as handle:
        raw_cases: Any = json.load(handle)
    if not isinstance(raw_cases, list):
        raise ValueError("Replay case file must contain a JSON list")
    raw_case_list = cast(list[Any], raw_cases)
    cases: list[dict[str, Any]] = []
    for case in raw_case_list:
        if not isinstance(case, dict):
            raise ValueError("Each replay case must be a JSON object")
        cases.append(cast(dict[str, Any], case))
    return cases


def parse_field_expression(expression: str) -> tuple[str, list[str]]:
    parts = expression.split("|")
    return parts[0], parts[1:]


def normalize_text(value: str) -> str:
    normalized = value
    for _ in range(3):
        decoded = urllib.parse.unquote(normalized)
        if decoded == normalized:
            break
        normalized = decoded
    normalized = normalized.replace("\x00", "")
    normalized = unicodedata.normalize("NFC", normalized)
    normalized = re.sub(r"\s+", " ", normalized).strip()
    return normalized.casefold()


def validate_sigma_detection(detection: dict[str, Any]) -> None:
    for expression in detection:
        if expression == "condition":
            continue
        _, modifiers = parse_field_expression(expression)
        unsupported = sorted(SIGMA_REGEX_MODIFIERS.intersection(modifiers))
        if unsupported:
            raise ValueError(
                f"Regex-style Sigma modifiers are not allowed in replay validation: {expression} ({', '.join(unsupported)})"
            )


def find_high_risk_yara_patterns(rule_text: str) -> list[str]:
    matches: list[str] = []
    for pattern in HIGH_RISK_YARA_PATTERNS:
        for match in pattern.finditer(rule_text):
            matches.append(match.group(0))
    return matches


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

    expected_values: list[Any] = cast(list[Any], expected) if isinstance(expected, list) else [expected]

    if operation == "equals":
        if isinstance(actual, str) or any(isinstance(value, str) for value in expected_values):
            actual_normalized = normalize_text(str(actual))
            return any(actual_normalized == normalize_text(str(value)) for value in expected_values)
        return any(actual == value for value in expected_values)

    actual_text = normalize_text(str(actual))
    if operation == "contains":
        if require_all:
            return all(normalize_text(str(value)) in actual_text for value in expected_values)
        return any(normalize_text(str(value)) in actual_text for value in expected_values)

    if operation == "endswith":
        if require_all:
            return all(actual_text.endswith(normalize_text(str(value))) for value in expected_values)
        return any(actual_text.endswith(normalize_text(str(value))) for value in expected_values)

    raise ValueError(f"Unsupported Sigma field modifier chain: {expression}")


def selector_matches(event: dict[str, Any], selector: dict[str, Any]) -> bool:
    return all(field_matches(event, expression, expected) for expression, expected in selector.items())


def tokenize_condition(condition: str) -> list[str]:
    tokens: list[str] = []
    current: list[str] = []
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
        if token == GROUP_OPEN_TOKEN:  # nosec B105
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
    validate_sigma_detection(detection)
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
            return ReplayResult(case["name"], "yara", False, "yara command not available")  # FIX: C5-M-01
        # FIX: C5-M-01 — returning passed=True here was a false-pass: YARA rules were never evaluated.
        # A skipped-but-unchecked YARA case is not a pass; it is a coverage gap that must surface as
        # a non-pass so callers cannot treat the run as a clean full-coverage result.
        return ReplayResult(case["name"], "yara", False, "coverage-incomplete: yara command not available (use --skip-yara to opt out explicitly or --require-yara to hard-fail)")  # FIX: C5-M-01

    rule_path = REPO_ROOT / case["rule"]
    fixture_path = REPO_ROOT / case["fixture"]
    result = subprocess.run(  # nosec B603
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
    yara_command = None if skip_yara else resolve_yara_command()  # FIX: C5-M-01
    results: list[ReplayResult] = []
    yara_cases_present = False  # FIX: C5-M-01
    for case in cases:
        kind = case["kind"]
        if kind == "sigma":
            results.append(evaluate_sigma_case(case))
        elif kind == "yara":
            yara_cases_present = True  # FIX: C5-M-01
            results.append(evaluate_yara_case(case, yara_command, require_yara))
        else:
            raise ValueError(f"Unsupported replay case kind: {kind}")
    # FIX: C5-M-01 — when YARA cases exist but YARA is not available and not explicitly skipped,
    # append a top-level coverage-incomplete sentinel so callers see a definitive non-pass state
    # even if the case list happens to be empty or the caller does not inspect per-case results.
    if yara_cases_present and not skip_yara and not yara_command:  # FIX: C5-M-01
        results.append(ReplayResult(  # FIX: C5-M-01
            "_yara_coverage",  # FIX: C5-M-01
            "yara",  # FIX: C5-M-01
            False,  # FIX: C5-M-01
            "coverage-incomplete: one or more YARA cases were not executed because yara is unavailable",  # FIX: C5-M-01
        ))  # FIX: C5-M-01
    return results


def archive_results(
    archive_root: Path,
    cases_path: Path,
    *,
    skip_yara: bool,
    require_yara: bool,
    yara_command: str | None,
    results: list[ReplayResult],
) -> None:
    archive_root.mkdir(parents=True, exist_ok=True)
    summary: dict[str, Any] = {
        "created_at": datetime.now(UTC).isoformat(),
        "cases_path": str(cases_path),
        "skip_yara": skip_yara,
        "require_yara": require_yara,
        "yara_command": yara_command,
        "results": [
            {
                "name": result.name,
                "kind": result.kind,
                "passed": result.passed,
                "details": result.details,
            }
            for result in results
        ],
    }
    (archive_root / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate detection replay fixtures")
    parser.add_argument("--cases", default=str(DEFAULT_CASES_PATH), help="Replay case definition JSON file")
    parser.add_argument("--skip-yara", action="store_true", help="Skip YARA replay cases")
    parser.add_argument("--require-yara", action="store_true", help="Fail if YARA is unavailable")
    parser.add_argument("--archive-root", help="Directory where replay evidence should be written")
    args = parser.parse_args(argv)

    cases_path = Path(args.cases)
    yara_command = None if args.skip_yara else resolve_yara_command()
    results = run_validation(cases_path, skip_yara=args.skip_yara, require_yara=args.require_yara)
    failures = [result for result in results if not result.passed]  # FIX: C5-M-01
    # FIX: C5-M-01 — a coverage-incomplete result (passed=False, name="_yara_coverage") is now
    # included in failures when YARA is unavailable without --skip-yara, so the exit code is 2
    # (distinct from a test-assertion failure at exit 1) and downstream automation cannot
    # misread the run as a clean full-coverage pass.
    coverage_incomplete = any(  # FIX: C5-M-01
        result.name == "_yara_coverage" and not result.passed  # FIX: C5-M-01
        for result in results  # FIX: C5-M-01
    )  # FIX: C5-M-01

    if args.archive_root:
        archive_results(
            Path(args.archive_root).resolve(),
            cases_path,
            skip_yara=args.skip_yara,
            require_yara=args.require_yara,
            yara_command=yara_command,
            results=results,
        )

    for result in results:
        status = "PASS" if result.passed else "FAIL"
        print(f"[{status}] {result.kind} {result.name}: {result.details}")

    if coverage_incomplete:  # FIX: C5-M-01
        print("[COVERAGE-INCOMPLETE] YARA cases were not executed; pass --skip-yara to opt out or --require-yara to hard-fail")  # FIX: C5-M-01
        return 2  # FIX: C5-M-01 — exit 2 = coverage incomplete (not a test failure, not a clean pass)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())