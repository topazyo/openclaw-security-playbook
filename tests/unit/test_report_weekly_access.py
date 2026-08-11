"""C6-RT-20: the weekly report must not discard the access-review signal.

Covers ``clawdbot.report_weekly`` (backend) and the ``openclaw-cli scan access``
counts table.  The pre-existing ``test_report_weekly_cli.py`` mocks the backend
away entirely, so backend-level assertions live here instead.

Every case below is robust against BOTH access artifacts:
  * post-#136 artifacts carrying ``summary.incomplete_data_count`` plus
    ``incomplete_data`` marker dicts inside the findings categories, and
  * pre-#136 artifacts with neither key (must behave exactly as before).
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from clawdbot.report_weekly import (  # FIX: C6-RT-20
    _access_incomplete_checks,
    _overall_status,
    _render_pdf,
    generate_weekly_report,
)
import clawdbot.report_weekly as report_weekly_mod  # FIX: C6-RT-20

# ---------------------------------------------------------------------------
# Load the CLI module directly (same idiom as test_report_weekly_cli.py)
# ---------------------------------------------------------------------------
_CLI_PATH = Path(__file__).resolve().parents[2] / "tools" / "openclaw-cli.py"
_spec = importlib.util.spec_from_file_location("openclaw_cli_access_counts_tests", _CLI_PATH)
assert _spec is not None and _spec.loader is not None
_cli_mod = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = _cli_mod
_spec.loader.exec_module(_cli_mod)
cli = _cli_mod.cli


# ---------------------------------------------------------------------------
# Fixtures / builders
# ---------------------------------------------------------------------------

_CREEP_MARKER = {
    "status": "incomplete_data",
    "check": "production_access_in_non_prod_role",
    "missing_fields": ["Systems"],
    "issue": (
        "production-access privilege-creep check could not run: "
        "'Systems' field unavailable from this data source"
    ),
}

_APPROVER_MARKER = {
    "status": "incomplete_data",
    "check": "orphaned_approver",
    "missing_fields": ["GrantedBy"],
    "issue": "orphaned-approver check could not run: 'GrantedBy' field unavailable",
}


def _access(*, inactive=0, creep=0, orphaned=0, incomplete=None, compliance=None, markers=False):
    """Build an access-review payload.  ``incomplete=None`` omits the key entirely."""
    summary = {
        "total_users": 3,
        "inactive_count": inactive,
        "privilege_creep_count": creep,
        "orphaned_approver_count": orphaned,
    }
    if incomplete is not None:
        summary["incomplete_data_count"] = incomplete
    payload: dict = {
        "summary": summary,
        "inactive_users": [],
        "privilege_creep": [],
        "orphaned_approvers": [],
    }
    if markers:
        payload["privilege_creep"].append(dict(_CREEP_MARKER))
        payload["orphaned_approvers"].append(dict(_APPROVER_MARKER))
    if compliance is not None:
        payload["compliance"] = compliance
    return payload


_PASS_COMPLIANCE = {"soc2_cc6_1": "pass", "iso27001_a9_2_5": "pass"}
_INCOMPLETE_COMPLIANCE = {"soc2_cc6_1": "pass", "iso27001_a9_2_5": "incomplete"}


# ---------------------------------------------------------------------------
# _overall_status
# ---------------------------------------------------------------------------

class TestOverallStatusAccessIncompleteness:
    """An access review that could not complete every check is not HEALTHY."""

    def test_incomplete_data_count_is_not_healthy(self):
        access = _access(incomplete=2, compliance=_INCOMPLETE_COMPLIANCE)
        status = _overall_status({}, {}, None, access)
        assert status != "healthy"
        assert status == "warning"

    def test_incomplete_count_alone_warns_with_passing_compliance(self):
        access = _access(incomplete=2, compliance=_PASS_COMPLIANCE)
        assert _overall_status({}, {}, None, access) == "warning"

    def test_incomplete_compliance_control_alone_warns(self):
        # incomplete_data_count is 0 but ISO 27001 A.9.2.5 could not be attested.
        access = _access(incomplete=0, compliance=_INCOMPLETE_COMPLIANCE)
        assert _overall_status({}, {}, None, access) == "warning"

    def test_not_collapsed_into_unknown(self):
        # "unknown" is reserved for a report that could not be assembled at all.
        access = _access(incomplete=2, compliance=_INCOMPLETE_COMPLIANCE)
        assert _overall_status({}, {}, None, access) != "unknown"

    def test_unknown_still_wins_for_unassembled_report(self):
        access = _access(incomplete=2, compliance=_INCOMPLETE_COMPLIANCE)
        assert _overall_status({"error": "boom"}, {}, None, access) == "unknown"


class TestOverallStatusRegressionGuards:
    """Pre-existing behaviour must be untouched."""

    def test_all_clean_is_healthy(self):
        access = _access(incomplete=0, compliance=_PASS_COMPLIANCE)
        assert _overall_status({}, {}, None, access) == "healthy"

    def test_real_findings_still_warn_when_complete(self):
        access = _access(inactive=1, incomplete=0, compliance=_PASS_COMPLIANCE)
        assert _overall_status({}, {}, None, access) == "warning"

    def test_privilege_creep_still_warns(self):
        access = _access(creep=1, incomplete=0)
        assert _overall_status({}, {}, None, access) == "warning"

    def test_pre_136_artifact_without_incomplete_key_is_healthy(self):
        access = _access()  # no incomplete_data_count key at all
        assert "incomplete_data_count" not in access["summary"]
        assert _overall_status({}, {}, None, access) == "healthy"

    def test_pre_136_artifact_with_findings_still_warns(self):
        access = _access(inactive=1)
        assert _overall_status({}, {}, None, access) == "warning"

    def test_no_access_section_is_healthy(self):
        assert _overall_status({}, {}, None, None) == "healthy"

    def test_critical_escalation_unchanged(self):
        compliance = {"soc2": {"compliance_percentage": 80.0}}
        access = _access(incomplete=5, compliance=_INCOMPLETE_COMPLIANCE)
        assert _overall_status(compliance, {}, None, access) == "critical"

    def test_critical_cve_still_beats_access_warning(self):
        vuln = {"summary": {"critical": 1, "high": 0}}
        access = _access(incomplete=5)
        assert _overall_status({}, {}, vuln, access) == "critical"


# ---------------------------------------------------------------------------
# _access_incomplete_checks
# ---------------------------------------------------------------------------

class TestAccessIncompleteChecks:

    def test_markers_are_named(self):
        details = _access_incomplete_checks(_access(incomplete=2, markers=True))
        joined = " | ".join(details)
        assert "production_access_in_non_prod_role" in joined
        assert "Systems" in joined
        assert "orphaned_approver" in joined
        assert "GrantedBy" in joined

    def test_real_findings_are_not_treated_as_markers(self):
        access = _access(inactive=1)
        access["inactive_users"].append({"user": "alice", "last_login": "2025-01-01"})
        assert _access_incomplete_checks(access) == []

    def test_pre_136_artifact_yields_no_detail(self):
        assert _access_incomplete_checks(_access()) == []

    def test_nested_findings_layout_supported(self):
        access = {"summary": {"incomplete_data_count": 1},
                  "findings": {"privilege_creep": [dict(_CREEP_MARKER)]}}
        details = _access_incomplete_checks(access)
        assert len(details) == 1
        assert "production_access_in_non_prod_role" in details[0]

    def test_none_and_garbage_do_not_raise(self):
        assert _access_incomplete_checks(None) == []
        assert _access_incomplete_checks({"privilege_creep": "not-a-list"}) == []
        assert _access_incomplete_checks({"privilege_creep": ["not-a-dict"]}) == []


# ---------------------------------------------------------------------------
# generate_weekly_report
# ---------------------------------------------------------------------------

def _healthy_compliance():
    return {"soc2": {"compliance_percentage": 99.0}, "iso27001": {"compliance_percentage": 99.0}}


def _healthy_certs():
    return {"total": 2, "expiring_soon": 0, "certificates": []}


def _run_report(tmp_path, access_payload, **kwargs):
    access_file = tmp_path / "access.json"
    access_file.write_text(json.dumps(access_payload), encoding="utf-8")
    with (
        patch.object(report_weekly_mod, "_gather_compliance", return_value=_healthy_compliance()),
        patch.object(report_weekly_mod, "_gather_certificates", return_value=_healthy_certs()),
    ):
        return generate_weekly_report(
            start_date="2026-03-14",
            end_date="2026-03-21",
            access_scan_path=str(access_file),
            **kwargs,
        )


class TestGenerateWeeklyReportSurfacesIncompleteness:

    def test_warnings_name_the_specific_unrun_check(self, tmp_path):
        report = _run_report(
            tmp_path, _access(incomplete=2, compliance=_INCOMPLETE_COMPLIANCE, markers=True)
        )
        joined = " | ".join(report["warnings"])
        assert "production_access_in_non_prod_role" in joined
        assert "Systems" in joined
        assert "orphaned_approver" in joined

    def test_status_is_warning_not_healthy(self, tmp_path):
        report = _run_report(
            tmp_path, _access(incomplete=2, compliance=_INCOMPLETE_COMPLIANCE, markers=True)
        )
        assert report["overall_status"] == "warning"

    def test_incomplete_compliance_control_named_in_warnings(self, tmp_path):
        report = _run_report(tmp_path, _access(incomplete=0, compliance=_INCOMPLETE_COMPLIANCE))
        joined = " | ".join(report["warnings"])
        assert "iso27001_a9_2_5" in joined

    def test_count_only_artifact_falls_back_to_count_message(self, tmp_path):
        # Counts say incomplete but no marker detail is present.
        report = _run_report(tmp_path, _access(incomplete=3, compliance=_PASS_COMPLIANCE))
        joined = " | ".join(report["warnings"])
        assert "access review incomplete" in joined
        assert "3" in joined
        assert report["overall_status"] == "warning"

    def test_clean_review_adds_no_access_warning(self, tmp_path):
        report = _run_report(tmp_path, _access(incomplete=0, compliance=_PASS_COMPLIANCE))
        assert [w for w in report["warnings"] if "access review incomplete" in w] == []
        assert report["overall_status"] == "healthy"

    def test_pre_136_artifact_adds_no_access_warning(self, tmp_path):
        report = _run_report(tmp_path, _access())
        assert [w for w in report["warnings"] if "access review incomplete" in w] == []
        assert report["overall_status"] == "healthy"

    def test_unloadable_access_file_still_warns_as_before(self, tmp_path):
        bad = tmp_path / "bad.json"
        bad.write_text("{not json", encoding="utf-8")
        with (
            patch.object(report_weekly_mod, "_gather_compliance", return_value=_healthy_compliance()),
            patch.object(report_weekly_mod, "_gather_certificates", return_value=_healthy_certs()),
        ):
            report = generate_weekly_report(
                start_date="2026-03-14", end_date="2026-03-21", access_scan_path=str(bad)
            )
        assert any("access review could not be loaded" in w for w in report["warnings"])


class TestGenerateWeeklyReportAgainstRealProducerLayout:  # FIX: C6-RT-20
    """End-to-end against the EXACT dict `run_access_review` writes to disk.

    The other tests in this file build the finding categories at the top level.
    The real producer (src/clawdbot/scan_access.py) nests them under a
    ``"findings"`` mapping alongside ``summary`` and ``compliance``.  A consumer
    fix that only ever sees the flat shape in its tests would pass here and still
    discard the signal on a real artifact -- which is the very failure class
    C6-RT-20 exists to close.  These cases pin the nested layout.
    """

    @staticmethod
    def _producer_payload():  # FIX: C6-RT-20
        # Mirrors run_access_review()'s result dict for provider="azure-ad".
        return {  # FIX: C6-RT-20
            "command": "scan access",  # FIX: C6-RT-20
            "generated_at": "2026-03-21T00:00:00+00:00",  # FIX: C6-RT-20
            "input_source": "azure-ad",  # FIX: C6-RT-20
            "days_threshold": 90,  # FIX: C6-RT-20
            "findings": {  # FIX: C6-RT-20
                "inactive_users": [],  # FIX: C6-RT-20
                "privilege_creep": [dict(_CREEP_MARKER)],  # FIX: C6-RT-20
                "orphaned_approvers": [dict(_APPROVER_MARKER)],  # FIX: C6-RT-20
            },  # FIX: C6-RT-20
            "summary": {  # FIX: C6-RT-20
                "total_users": 3,  # FIX: C6-RT-20
                "inactive_count": 0,  # FIX: C6-RT-20
                "privilege_creep_count": 0,  # FIX: C6-RT-20
                "orphaned_approver_count": 0,  # FIX: C6-RT-20
                "incomplete_data_count": 2,  # FIX: C6-RT-20
            },  # FIX: C6-RT-20
            "compliance": dict(_INCOMPLETE_COMPLIANCE),  # FIX: C6-RT-20
        }  # FIX: C6-RT-20

    def test_nested_producer_payload_is_not_healthy(self, tmp_path):  # FIX: C6-RT-20
        report = _run_report(tmp_path, self._producer_payload())  # FIX: C6-RT-20
        assert report["overall_status"] == "warning"  # FIX: C6-RT-20

    def test_nested_producer_payload_names_the_unrun_checks(self, tmp_path):  # FIX: C6-RT-20
        report = _run_report(tmp_path, self._producer_payload())  # FIX: C6-RT-20
        joined = " | ".join(report["warnings"])  # FIX: C6-RT-20
        # The specific check names must survive the nesting, not a generic string.
        assert "production_access_in_non_prod_role" in joined  # FIX: C6-RT-20
        assert "Systems" in joined  # FIX: C6-RT-20
        assert "orphaned_approver" in joined  # FIX: C6-RT-20
        assert "GrantedBy" in joined  # FIX: C6-RT-20
        # And the count-only fallback must NOT fire when real detail exists.
        assert "carries no per-check detail" not in joined  # FIX: C6-RT-20

    def test_nested_clean_producer_payload_stays_healthy(self, tmp_path):  # FIX: C6-RT-20
        payload = self._producer_payload()  # FIX: C6-RT-20
        payload["findings"]["privilege_creep"] = []  # FIX: C6-RT-20
        payload["findings"]["orphaned_approvers"] = []  # FIX: C6-RT-20
        payload["summary"]["incomplete_data_count"] = 0  # FIX: C6-RT-20
        payload["compliance"] = dict(_PASS_COMPLIANCE)  # FIX: C6-RT-20
        payload["input_source"] = "csv"  # FIX: C6-RT-20
        report = _run_report(tmp_path, payload)  # FIX: C6-RT-20
        assert report["overall_status"] == "healthy"  # FIX: C6-RT-20
        assert [w for w in report["warnings"] if "access review incomplete" in w] == []  # FIX: C6-RT-20


# ---------------------------------------------------------------------------
# PDF rendering
# ---------------------------------------------------------------------------

def _install_fake_reportlab(monkeypatch, captured: list[str]):
    """Install a minimal in-memory reportlab so _render_pdf runs without the dep.

    reportlab is not a test dependency of this repo, so the real-PDF tests below
    are importorskip-guarded.  This stub exercises the same code path and lets us
    assert on the exact text the access section emits.
    """
    import types

    rl = types.ModuleType("reportlab")
    lib = types.ModuleType("reportlab.lib")
    pagesizes = types.ModuleType("reportlab.lib.pagesizes")
    pagesizes.letter = (612.0, 792.0)
    styles_mod = types.ModuleType("reportlab.lib.styles")
    styles_mod.getSampleStyleSheet = lambda: {
        "Title": "Title", "Normal": "Normal", "Heading2": "Heading2",
    }
    platypus = types.ModuleType("reportlab.platypus")

    class _Paragraph:
        def __init__(self, text, style=None):
            self.text = text

    class _Spacer:
        def __init__(self, *args):
            pass

    class _SimpleDocTemplate:
        def __init__(self, path, **kwargs):
            self.path = path

        def build(self, story):
            captured.extend(getattr(item, "text", "") for item in story)
            Path(self.path).write_bytes(b"%PDF-1.4 stub")

    platypus.Paragraph = _Paragraph
    platypus.Spacer = _Spacer
    platypus.SimpleDocTemplate = _SimpleDocTemplate

    for name, module in (
        ("reportlab", rl),
        ("reportlab.lib", lib),
        ("reportlab.lib.pagesizes", pagesizes),
        ("reportlab.lib.styles", styles_mod),
        ("reportlab.platypus", platypus),
    ):
        monkeypatch.setitem(sys.modules, name, module)


class TestRenderPdfAccessSectionText:
    """Assert on the rendered text via a stubbed reportlab."""

    def test_access_section_shows_four_counts_and_named_checks(self, tmp_path, monkeypatch):
        report = _run_report(
            tmp_path, _access(inactive=1, incomplete=2,
                              compliance=_INCOMPLETE_COMPLIANCE, markers=True)
        )
        captured: list[str] = []
        _install_fake_reportlab(monkeypatch, captured)
        assert _render_pdf(report, str(tmp_path / "r.pdf")) is not None
        text = "\n".join(captured)
        assert "Access Review" in text
        assert "Inactive: 1" in text
        assert "Privilege creep: 0" in text
        assert "Orphaned approvers: 0" in text
        assert "Checks that could not run: 2" in text
        assert "production_access_in_non_prod_role" in text
        assert "iso27001_a9_2_5" in text

    def test_pre_136_artifact_renders_zero_incomplete(self, tmp_path, monkeypatch):
        report = _run_report(tmp_path, _access())
        captured: list[str] = []
        _install_fake_reportlab(monkeypatch, captured)
        assert _render_pdf(report, str(tmp_path / "r.pdf")) is not None
        text = "\n".join(captured)
        assert "Access Review" in text
        assert "Checks that could not run: 0" in text

    def test_no_access_section_when_absent(self, tmp_path, monkeypatch):
        captured: list[str] = []
        _install_fake_reportlab(monkeypatch, captured)
        report = {
            "period": {"start": "2026-03-14", "end": "2026-03-21"},
            "generated_at": "2026-03-21T00:00:00+00:00",
            "overall_status": "healthy",
            "sections": {
                "compliance_status": {},
                "certificate_status": {"total": 0, "expiring_soon": 0},
                "vulnerability_summary": None,
                "access_review_status": None,
            },
            "missing_evidence": [],
            "warnings": [],
        }
        assert _render_pdf(report, str(tmp_path / "r.pdf")) is not None
        assert "Access Review" not in "\n".join(captured)


class TestRenderPdfAccessSection:

    def test_pdf_includes_access_section(self, tmp_path):
        pytest.importorskip("reportlab")
        report = _run_report(
            tmp_path, _access(incomplete=2, compliance=_INCOMPLETE_COMPLIANCE, markers=True)
        )
        pdf_path = tmp_path / "report.pdf"
        written = _render_pdf(report, str(pdf_path))
        assert written is not None
        assert Path(written).exists()
        assert Path(written).stat().st_size > 0

    def test_pdf_renders_without_access_section(self, tmp_path):
        pytest.importorskip("reportlab")
        pdf_path = tmp_path / "no-access.pdf"
        report = {
            "period": {"start": "2026-03-14", "end": "2026-03-21"},
            "generated_at": "2026-03-21T00:00:00+00:00",
            "overall_status": "healthy",
            "sections": {
                "compliance_status": {},
                "certificate_status": {"total": 0, "expiring_soon": 0},
                "vulnerability_summary": None,
                "access_review_status": None,
            },
            "missing_evidence": [],
            "warnings": [],
        }
        assert _render_pdf(report, str(pdf_path)) is not None


# ---------------------------------------------------------------------------
# CLI access counts table
# ---------------------------------------------------------------------------

def _cli_access_result(summary_extra: dict):
    summary = {
        "total_users": 3,
        "inactive_count": 0,
        "privilege_creep_count": 0,
        "orphaned_approver_count": 0,
    }
    summary.update(summary_extra)
    return {
        "summary": summary,
        "input_source": "access-export.csv",
        "compliance": _INCOMPLETE_COMPLIANCE,
    }


class TestScanAccessCountsTable:

    def _invoke(self, monkeypatch, result):
        mod = SimpleNamespace(run_access_review=lambda **kw: result)
        monkeypatch.setattr(_cli_mod, "_load_clawdbot_module", lambda _n: mod)
        runner = CliRunner()
        return runner.invoke(cli, ["scan", "access", "--input-csv", "access-export.csv"])

    def test_incomplete_count_is_printed(self, monkeypatch):
        out = self._invoke(monkeypatch, _cli_access_result({"incomplete_data_count": 2}))
        assert out.exit_code == 0, out.output
        assert "Incomplete checks" in out.output

    def test_incomplete_row_hidden_when_zero(self, monkeypatch):
        out = self._invoke(monkeypatch, _cli_access_result({"incomplete_data_count": 0}))
        assert out.exit_code == 0, out.output
        assert "Incomplete checks" not in out.output

    def test_pre_136_payload_does_not_keyerror(self, monkeypatch):
        out = self._invoke(monkeypatch, _cli_access_result({}))
        assert out.exit_code == 0, out.output
        assert "Incomplete checks" not in out.output
