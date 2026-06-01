#!/usr/bin/env python3
"""Adversarial tests for the forensic hash-chain verifier (finding C6-RT-01).

These prove WRITER-COMPATIBILITY, not self-consistency: the intact fixture is built
with the canonical writer ``exercise_malicious_skill_chain.apply_hash_chain`` (the sole
producer of ``chain_hash``/``prev_hash`` in the repo), and the verifier must accept it
while rejecting any event whose *content* was tampered — including the genesis event —
and failing closed on unverifiable events. Before C6-RT-01 the verifier only compared
the stored ``prev_hash`` pointer, so content edits that preserved the pointer passed.
"""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]


def _load(module_path: Path, module_name: str):
    # Load a source file as a throwaway module WITHOUT leaving it in the global module
    # cache. The entry is registered only for the duration of exec_module (so a module that
    # imports itself by name still resolves) under a name namespaced to THIS test module,
    # then removed in finally. Registering under the source file's canonical name instead
    # would (a) leak module state — globals, monkeypatches — across tests and (b) collide
    # with other tests that load the same file under that name (e.g.
    # test_malicious_skill_chain_exercise also registers "exercise_malicious_skill_chain").
    qualified_name = f"{__name__}.{module_name}"
    spec = importlib.util.spec_from_file_location(qualified_name, module_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[qualified_name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(qualified_name, None)
    return module


# The canonical writer (apply_hash_chain / build_incident_events) and the verifier under test.
exercise = _load(
    REPO_ROOT / "scripts" / "verification" / "exercise_malicious_skill_chain.py",
    "exercise_malicious_skill_chain",
)
verifier = _load(
    REPO_ROOT / "scripts" / "forensics" / "verify_hash_chain.py",
    "verify_hash_chain_under_test",
)


def _build_chain() -> list[dict[str, Any]]:
    """A realistic, correctly hash-chained incident produced by the canonical writer."""
    return exercise.build_incident_events("INC-TEST-C6RT01")


def _write_jsonl(tmp_path: Path, events: list[dict[str, Any]]) -> str:
    # Mirror exercise_malicious_skill_chain's telemetry writer: one json.dumps line per event.
    path = tmp_path / "telemetry.jsonl"
    path.write_text("".join(json.dumps(event) + "\n" for event in events), encoding="utf-8")
    return str(path)


def _rehash(event: dict[str, Any]) -> str:
    """Recompute an event's chain_hash the way the canonical writer does."""
    body = {k: v for k, v in event.items() if k != "chain_hash"}
    return hashlib.sha256(json.dumps(body, sort_keys=True).encode("utf-8")).hexdigest()


def test_accepts_intact_chain_from_canonical_writer(tmp_path: Path) -> None:
    # WRITER-COMPATIBILITY: a chain straight from apply_hash_chain must verify intact.
    events = _build_chain()
    assert verifier.verify_hash_chain(_write_jsonl(tmp_path, events)) is True


def test_rejects_non_genesis_content_tamper_with_intact_pointers(tmp_path: Path) -> None:
    # The exact gap C6-RT-01 closes: edit a non-genesis event's body but leave its stored
    # prev_hash AND chain_hash untouched. Pointer linkage is still intact, so the old
    # verifier passed this; the content recomputation must now reject it.
    events = copy.deepcopy(_build_chain())
    events[2]["tool_args"] = {"path": "/home/clawdbot/.ssh/id_rsa"}  # tampered content
    report_path = str(tmp_path / "report.json")
    assert verifier.verify_hash_chain(_write_jsonl(tmp_path, events), report_path) is False

    report = json.loads(Path(report_path).read_text(encoding="utf-8"))
    assert report["chain_intact"] is False
    reasons = {(b["position"], b["reason"]) for b in report["breaks"]}
    assert (2, "content_hash_mismatch") in reasons


def test_rejects_genesis_content_tamper(tmp_path: Path) -> None:
    # No genesis exemption: event 0's content is hash-verified too.
    events = copy.deepcopy(_build_chain())
    events[0]["skill_name"] = "@totally/benign-skill"  # tampered genesis content, hash untouched
    report_path = str(tmp_path / "report.json")
    assert verifier.verify_hash_chain(_write_jsonl(tmp_path, events), report_path) is False

    report = json.loads(Path(report_path).read_text(encoding="utf-8"))
    assert any(b["position"] == 0 and b["reason"] == "content_hash_mismatch" for b in report["breaks"])


def test_fails_closed_on_missing_chain_hash(tmp_path: Path) -> None:
    # An event without a recomputable chain_hash is unverifiable -> must NOT pass by default.
    events = copy.deepcopy(_build_chain())
    del events[1]["chain_hash"]
    report_path = str(tmp_path / "report.json")
    assert verifier.verify_hash_chain(_write_jsonl(tmp_path, events), report_path) is False

    report = json.loads(Path(report_path).read_text(encoding="utf-8"))
    assert any(b["position"] == 1 and b["reason"] == "missing_or_invalid_chain_hash" for b in report["breaks"])


def test_rejects_prev_hash_link_tamper_even_when_content_hash_valid(tmp_path: Path) -> None:
    # Linkage is still enforced after the content-hash addition: rewrite a non-genesis event's
    # prev_hash to a bogus value and RE-HASH it so its own content check passes — the broken
    # link to the prior event must still be detected.
    events = copy.deepcopy(_build_chain())
    events[3]["prev_hash"] = "0" * 64
    events[3]["chain_hash"] = _rehash(events[3])  # content now self-consistent, but link is wrong
    report_path = str(tmp_path / "report.json")
    assert verifier.verify_hash_chain(_write_jsonl(tmp_path, events), report_path) is False

    report = json.loads(Path(report_path).read_text(encoding="utf-8"))
    assert any(b["position"] == 3 and b["reason"] == "prev_hash_link_mismatch" for b in report["breaks"])


def test_rejects_genesis_prev_hash_not_null(tmp_path: Path) -> None:
    # The genesis event must declare prev_hash=null; a re-hashed event 0 with a non-null
    # prev_hash is self-consistent on content but violates the genesis convention.
    events = copy.deepcopy(_build_chain())
    events[0]["prev_hash"] = "f" * 64
    events[0]["chain_hash"] = _rehash(events[0])
    report_path = str(tmp_path / "report.json")
    assert verifier.verify_hash_chain(_write_jsonl(tmp_path, events), report_path) is False

    report = json.loads(Path(report_path).read_text(encoding="utf-8"))
    assert any(b["position"] == 0 and b["reason"] == "genesis_prev_hash_not_null" for b in report["breaks"])
