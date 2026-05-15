"""ISO 27001 compliance reporter tests — C6-H-05.

Covers:
  T1 — reporter exits 0 with corpus smaller than SoA; correct counts/status
  T2 — compliance_percentage_basis field present with value 'loaded_corpus'
  T3 — stderr WARNING emitted when corpus < SoA
  T4 — no WARNING emitted when corpus == SoA (COMPLETE_MAPPING)
  T5 — SoA internal inconsistency raises ValueError
  T6 — applicable_controls == 0 still raises ValueError (D4 preservation)
  T7 — SOC2 and GDPR report shapes unchanged (regression guard)
  T8 — coverage_summary invariants (parametrized, Architect Revision 1)

All tests use pytest.  No new dependencies required.
"""
# FIX: C6-H-05
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any
from unittest.mock import patch, mock_open, MagicMock

import pytest

# ---------------------------------------------------------------------------
# Load the reporter module from its file path (not an installed package)
# ---------------------------------------------------------------------------
_REPO_ROOT = Path(__file__).resolve().parents[2]
_REPORTER_PATH = _REPO_ROOT / "tools" / "compliance-reporter.py"

_spec = importlib.util.spec_from_file_location("compliance_reporter_c6h05", _REPORTER_PATH)
assert _spec is not None and _spec.loader is not None
_mod = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = _mod
_spec.loader.exec_module(_mod)

ComplianceReporter = _mod.ComplianceReporter  # FIX: C6-H-05


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------

def _make_statement(
    total: int = 93,
    implemented: int = 45,
    planned: int = 25,
    not_applicable: int = 23,
) -> dict[str, Any]:  # FIX: C6-H-05
    """Return a minimal statement_of_applicability dict."""  # FIX: C6-H-05
    return {
        "total_controls": total,
        "implemented": implemented,
        "planned": planned,
        "not_applicable": not_applicable,
        "justification_required": True,
    }  # FIX: C6-H-05


def _make_corpus_controls(
    n_implemented: int,
    n_pending: int = 0,
    group: str = "organizational_controls",
) -> list[dict[str, Any]]:  # FIX: C6-H-05
    """Return a minimal list of corpus control records."""  # FIX: C6-H-05
    controls: list[dict[str, Any]] = []  # FIX: C6-H-05
    for i in range(n_implemented):  # FIX: C6-H-05
        controls.append({"group": group, "control_id": f"A.impl.{i}", "status": "implemented"})  # FIX: C6-H-05
    for j in range(n_pending):  # FIX: C6-H-05
        controls.append({"group": group, "control_id": f"A.pend.{j}", "status": "pending"})  # FIX: C6-H-05
    return controls  # FIX: C6-H-05


# ---------------------------------------------------------------------------
# T1 — reporter exits 0 with corpus smaller than SoA; correct counts/status
# ---------------------------------------------------------------------------

class TestT1ReporterExitsZeroWithSmallerCorpus:  # FIX: C6-H-05
    """T1: ISO27001 report generates when corpus < SoA applicable controls."""  # FIX: C6-H-05

    def test_iso27001_report_generates_with_corpus_smaller_than_soa(self):  # FIX: C6-H-05
        """Reporter produces a valid report against the real corpus (19 controls, SoA 70 applicable).

        The old code raised ValueError due to count mismatch (SoA says 45+25=70,
        corpus has 19).  Post-fix: report exits 0 with corpus-derived counts.
        """  # FIX: C6-H-05
        reporter = ComplianceReporter()  # FIX: C6-H-05
        report = reporter.generate_report("ISO27001")  # FIX: C6-H-05

        assert report.get("implemented_count") == 19, (  # FIX: C6-H-05
            f"implemented_count must be 19 (corpus-derived); got {report.get('implemented_count')}"  # FIX: C6-H-05
        )  # FIX: C6-H-05
        assert report.get("pending_count") == 0, (  # FIX: C6-H-05
            f"pending_count must be 0; got {report.get('pending_count')}"  # FIX: C6-H-05
        )  # FIX: C6-H-05
        assert report.get("compliance_percentage") == 100.0, (  # FIX: C6-H-05
            f"compliance_percentage must be 100.0; got {report.get('compliance_percentage')}"  # FIX: C6-H-05
        )  # FIX: C6-H-05
        cs = report.get("coverage_summary", {})  # FIX: C6-H-05
        assert cs.get("gap_status") == "INCOMPLETE_MAPPING", (  # FIX: C6-H-05
            f"gap_status must be INCOMPLETE_MAPPING; got {cs.get('gap_status')}"  # FIX: C6-H-05
        )  # FIX: C6-H-05
        assert cs.get("unmapped_applicable_controls") == 51, (  # FIX: C6-H-05
            f"unmapped_applicable_controls must be 51; got {cs.get('unmapped_applicable_controls')}"  # FIX: C6-H-05
        )  # FIX: C6-H-05


# ---------------------------------------------------------------------------
# T2 — compliance_percentage_basis field present with value 'loaded_corpus'
# ---------------------------------------------------------------------------

class TestT2CompliancePercentageBasisField:  # FIX: C6-H-05
    """T2: compliance_percentage_basis is present and set to 'loaded_corpus'."""  # FIX: C6-H-05

    def test_iso27001_compliance_percentage_basis_field_present(self):  # FIX: C6-H-05
        """Output JSON contains key compliance_percentage_basis == 'loaded_corpus'.

        This field is the load-bearing semantic-break signal.  Its absence would
        allow a future consumer to silently misinterpret the denominator.
        """  # FIX: C6-H-05
        reporter = ComplianceReporter()  # FIX: C6-H-05
        report = reporter.generate_report("ISO27001")  # FIX: C6-H-05

        assert "compliance_percentage_basis" in report, (  # FIX: C6-H-05
            "compliance_percentage_basis key must be present in the ISO27001 report"  # FIX: C6-H-05
        )  # FIX: C6-H-05
        assert report["compliance_percentage_basis"] == "loaded_corpus", (  # FIX: C6-H-05
            f"compliance_percentage_basis must be 'loaded_corpus'; got {report['compliance_percentage_basis']!r}"  # FIX: C6-H-05
        )  # FIX: C6-H-05


# ---------------------------------------------------------------------------
# T3 — stderr WARNING emitted when corpus < SoA
# ---------------------------------------------------------------------------

class TestT3StderrWarningEmittedOnGap:  # FIX: C6-H-05
    """T3: A WARNING line is written to stderr when mapped controls < SoA applicable."""  # FIX: C6-H-05

    def test_iso27001_stderr_warning_emitted_on_gap(self, capsys):  # FIX: C6-H-05
        """capsys.readouterr().err must contain the WARNING line with correct counts."""  # FIX: C6-H-05
        reporter = ComplianceReporter()  # FIX: C6-H-05
        reporter.generate_report("ISO27001")  # FIX: C6-H-05

        captured = capsys.readouterr()  # FIX: C6-H-05
        assert "WARNING: ISO27001 compliance_mapping coverage gap:" in captured.err, (  # FIX: C6-H-05
            f"WARNING prefix must appear on stderr; got: {captured.err!r}"  # FIX: C6-H-05
        )  # FIX: C6-H-05
        assert "mapped=19" in captured.err, (  # FIX: C6-H-05
            f"stderr WARNING must include mapped=19; got: {captured.err!r}"  # FIX: C6-H-05
        )  # FIX: C6-H-05
        assert "soa_applicable=70" in captured.err, (  # FIX: C6-H-05
            f"stderr WARNING must include soa_applicable=70; got: {captured.err!r}"  # FIX: C6-H-05
        )  # FIX: C6-H-05
        assert "gap=51" in captured.err, (  # FIX: C6-H-05
            f"stderr WARNING must include gap=51; got: {captured.err!r}"  # FIX: C6-H-05
        )  # FIX: C6-H-05
        assert "basis=loaded_corpus" in captured.err, (  # FIX: C6-H-05
            f"stderr WARNING must include basis=loaded_corpus; got: {captured.err!r}"  # FIX: C6-H-05
        )  # FIX: C6-H-05


# ---------------------------------------------------------------------------
# T4 — no WARNING emitted when corpus == SoA (COMPLETE_MAPPING)
# ---------------------------------------------------------------------------

class TestT4StderrSilentOnCompleteMapping:  # FIX: C6-H-05
    """T4: No WARNING on stderr when corpus fully covers SoA applicable controls."""  # FIX: C6-H-05

    def test_iso27001_stderr_silent_on_complete_mapping(self, capsys):  # FIX: C6-H-05
        """With a fabricated full corpus (70 controls, SoA applicable=70), no WARNING emitted."""  # FIX: C6-H-05
        # Build a synthetic statement with applicable = 70 (45+25)
        soa_statement = _make_statement(total=93, implemented=45, planned=25, not_applicable=23)  # FIX: C6-H-05
        # Build corpus with exactly 70 implemented controls  # FIX: C6-H-05
        full_corpus = _make_corpus_controls(n_implemented=70)  # FIX: C6-H-05

        coverage = ComplianceReporter._build_iso27001_coverage_summary(full_corpus, soa_statement)  # FIX: C6-H-05
        ComplianceReporter._emit_iso27001_coverage_warning(coverage)  # FIX: C6-H-05

        captured = capsys.readouterr()  # FIX: C6-H-05
        assert "WARNING" not in captured.err, (  # FIX: C6-H-05
            f"No WARNING must be emitted when corpus == soa_applicable; stderr: {captured.err!r}"  # FIX: C6-H-05
        )  # FIX: C6-H-05
        assert coverage["gap_status"] == "COMPLETE_MAPPING", (  # FIX: C6-H-05
            f"gap_status must be COMPLETE_MAPPING; got {coverage['gap_status']!r}"  # FIX: C6-H-05
        )  # FIX: C6-H-05


# ---------------------------------------------------------------------------
# T5 — SoA internal inconsistency raises ValueError
# ---------------------------------------------------------------------------

class TestT5SoaInternalInconsistencyRaises:  # FIX: C6-H-05
    """T5: _validate_soa_internal_consistency raises when fields don't sum to total_controls."""  # FIX: C6-H-05

    def test_iso27001_soa_internal_inconsistency_raises(self):  # FIX: C6-H-05
        """Patched SoA with total=93, impl=45, planned=25, not_applicable=10 (sum=80) -> ValueError.

        This is the exact prior failure mode: a worker set not_applicable to a
        value that made the sum diverge from total_controls=93.
        """  # FIX: C6-H-05
        bad_statement = _make_statement(total=93, implemented=45, planned=25, not_applicable=10)  # FIX: C6-H-05

        with pytest.raises(ValueError) as exc_info:  # FIX: C6-H-05
            ComplianceReporter._validate_soa_internal_consistency(bad_statement)  # FIX: C6-H-05

        msg = str(exc_info.value)  # FIX: C6-H-05
        assert "total_controls(93)" in msg, (  # FIX: C6-H-05
            f"Error message must name total_controls(93); got: {msg!r}"  # FIX: C6-H-05
        )  # FIX: C6-H-05
        assert "80" in msg, (  # FIX: C6-H-05
            f"Error message must include the actual sum 80; got: {msg!r}"  # FIX: C6-H-05
        )  # FIX: C6-H-05


# ---------------------------------------------------------------------------
# T6 — applicable_controls == 0 still raises ValueError (D4 preservation)
# ---------------------------------------------------------------------------

class TestT6ApplicableZeroStillErrors:  # FIX: C6-H-05
    """T6: D4 guard — _calculate_statement_summary raises when applicable <= 0."""  # FIX: C6-H-05

    def test_iso27001_applicable_zero_still_errors(self):  # FIX: C6-H-05
        """SoA with implemented=0, planned=0 -> ValueError('has no applicable controls').

        Verifies that the D4 guard (line 68-69 in original) is preserved by the fix.
        Without this guard, division by zero would occur at percentage calculation.
        """  # FIX: C6-H-05
        zero_statement = _make_statement(total=23, implemented=0, planned=0, not_applicable=23)  # FIX: C6-H-05
        # First validate consistency (0+0+23=23 == total=23 — consistent)  # FIX: C6-H-05
        ComplianceReporter._validate_soa_internal_consistency(zero_statement)  # FIX: C6-H-05

        with pytest.raises(ValueError, match="has no applicable controls"):  # FIX: C6-H-05
            ComplianceReporter._calculate_statement_summary(zero_statement)  # FIX: C6-H-05


# ---------------------------------------------------------------------------
# T7 — SOC2 and GDPR report shapes unchanged (regression guard)
# ---------------------------------------------------------------------------

@pytest.mark.integration  # FIX: C6-H-05
class TestT7Soc2GdprUnchanged:  # FIX: C6-H-05
    """T7: SOC2 and GDPR report shapes are unaffected by the ISO27001 fix."""  # FIX: C6-H-05

    def test_soc2_and_gdpr_reports_unchanged_by_iso_fix(self):  # FIX: C6-H-05
        """SOC2 returns implemented_count=17, compliance_percentage=100.0, no coverage_summary.
        GDPR returns compliance_percentage present, no coverage_summary.

        Regression guard: ensures _generate_iso27001_report changes did not
        accidentally modify the SOC2 or GDPR code paths.
        """  # FIX: C6-H-05
        reporter = ComplianceReporter()  # FIX: C6-H-05

        soc2 = reporter.generate_report("SOC2")  # FIX: C6-H-05
        assert soc2["implemented_count"] == 17, (  # FIX: C6-H-05
            f"SOC2 implemented_count must remain 17; got {soc2['implemented_count']}"  # FIX: C6-H-05
        )  # FIX: C6-H-05
        assert soc2["compliance_percentage"] == 100.0, (  # FIX: C6-H-05
            f"SOC2 compliance_percentage must remain 100.0; got {soc2['compliance_percentage']}"  # FIX: C6-H-05
        )  # FIX: C6-H-05
        assert "coverage_summary" not in soc2, (  # FIX: C6-H-05
            "SOC2 report must NOT contain coverage_summary (ISO-only field)"  # FIX: C6-H-05
        )  # FIX: C6-H-05

        gdpr = reporter.generate_report("GDPR")  # FIX: C6-H-05
        assert "compliance_percentage" in gdpr, (  # FIX: C6-H-05
            "GDPR report must still contain compliance_percentage"  # FIX: C6-H-05
        )  # FIX: C6-H-05
        assert "coverage_summary" not in gdpr, (  # FIX: C6-H-05
            "GDPR report must NOT contain coverage_summary (ISO-only field)"  # FIX: C6-H-05
        )  # FIX: C6-H-05


# ---------------------------------------------------------------------------
# T8 — coverage_summary invariants (Architect Revision 1, parametrized)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "n_mapped, soa_impl, soa_planned, soa_na, expected_gap_status",
    [
        # Incomplete: 19 mapped, 70 applicable (45+25)
        (19, 45, 25, 23, "INCOMPLETE_MAPPING"),
        # Complete: 70 mapped, 70 applicable (45+25)
        (70, 45, 25, 23, "COMPLETE_MAPPING"),
        # Over-mapping: 80 mapped > 70 applicable
        (80, 45, 25, 23, "OVER_MAPPING"),
    ],
    ids=["incomplete", "complete", "over-mapped"],
)  # FIX: C6-H-05
class TestT8CoverageSummaryInvariants:  # FIX: C6-H-05
    """T8 (Architect Revision 1): coverage_summary field invariants across parametrized cases."""  # FIX: C6-H-05

    def test_coverage_summary_invariants(
        self,
        n_mapped: int,
        soa_impl: int,
        soa_planned: int,
        soa_na: int,
        expected_gap_status: str,
    ):  # FIX: C6-H-05
        """Assert coverage_summary arithmetic invariants hold for every parametrized case.

        Invariants verified:
          1. mapped_controls + unmapped_applicable_controls == soa_applicable_controls
          2. corpus_to_soa_coverage_percentage == round(mapped / soa_applicable * 100, 2)
             (within float tolerance via pytest.approx)
          3. gap_status enum value is correct for each scenario
        """  # FIX: C6-H-05
        statement = _make_statement(  # FIX: C6-H-05
            total=soa_impl + soa_planned + soa_na,  # FIX: C6-H-05
            implemented=soa_impl,  # FIX: C6-H-05
            planned=soa_planned,  # FIX: C6-H-05
            not_applicable=soa_na,  # FIX: C6-H-05
        )  # FIX: C6-H-05
        corpus = _make_corpus_controls(n_implemented=n_mapped)  # FIX: C6-H-05

        coverage = ComplianceReporter._build_iso27001_coverage_summary(corpus, statement)  # FIX: C6-H-05

        soa_applicable = soa_impl + soa_planned  # FIX: C6-H-05

        # Invariant 1: mapped + unmapped == soa_applicable  # FIX: C6-H-05
        assert (  # FIX: C6-H-05
            coverage["mapped_controls"] + coverage["unmapped_applicable_controls"]  # FIX: C6-H-05
            == coverage["soa_applicable_controls"]  # FIX: C6-H-05
        ), (  # FIX: C6-H-05
            f"mapped({coverage['mapped_controls']}) + unmapped({coverage['unmapped_applicable_controls']}) "  # FIX: C6-H-05
            f"must equal soa_applicable({coverage['soa_applicable_controls']})"  # FIX: C6-H-05
        )  # FIX: C6-H-05

        # Invariant 2: corpus_to_soa_coverage_percentage formula  # FIX: C6-H-05
        expected_pct = round(n_mapped / soa_applicable * 100, 2)  # FIX: C6-H-05
        assert coverage["corpus_to_soa_coverage_percentage"] == pytest.approx(expected_pct, abs=0.01), (  # FIX: C6-H-05
            f"corpus_to_soa_coverage_percentage must be {expected_pct}; "  # FIX: C6-H-05
            f"got {coverage['corpus_to_soa_coverage_percentage']}"  # FIX: C6-H-05
        )  # FIX: C6-H-05

        # Invariant 3: gap_status enum  # FIX: C6-H-05
        assert coverage["gap_status"] == expected_gap_status, (  # FIX: C6-H-05
            f"gap_status must be {expected_gap_status!r}; got {coverage['gap_status']!r}"  # FIX: C6-H-05
        )  # FIX: C6-H-05
