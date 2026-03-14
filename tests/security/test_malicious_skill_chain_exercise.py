#!/usr/bin/env python3
"""Tests for the Cycle 4 malicious skill chain exercise."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys


MODULE_PATH = Path(__file__).resolve().parents[2] / "scripts" / "verification" / "exercise_malicious_skill_chain.py"
SPEC = importlib.util.spec_from_file_location("exercise_malicious_skill_chain", MODULE_PATH)
assert SPEC is not None
exercise_malicious_skill_chain = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = exercise_malicious_skill_chain
SPEC.loader.exec_module(exercise_malicious_skill_chain)


def test_exercise_attack_chain_writes_correlated_artifacts(tmp_path: Path) -> None:
    manifest = exercise_malicious_skill_chain.exercise_attack_chain(tmp_path, "INC-TEST-C4D-001")

    assert manifest["incident_id"] == "INC-TEST-C4D-001"
    assert manifest["chain_intact"] is True

    detection_summary = json.loads((tmp_path / "detection" / "detection-summary.json").read_text(encoding="utf-8"))
    assert all(result["passed"] for result in detection_summary["results"])

    report_text = (tmp_path / "reporting" / "incident-report.md").read_text(encoding="utf-8")
    assert "INC-TEST-C4D-001" in report_text
    assert "detection/detection-summary.json" in report_text

    timeline_text = (tmp_path / "forensics" / "timeline.tsv").read_text(encoding="utf-8")
    assert "shell_exec" in timeline_text
    assert "file_read" in timeline_text