"""Weekly security report backend for openclaw-cli report weekly.

Aggregates repo-backed evidence into one canonical JSON report:

  Always included (repo-local tools):
    - Compliance status (SOC2, ISO27001, GDPR) via tools/compliance-reporter.py
    - Certificate expiry status via tools/certificate-manager.py

  Optionally embedded (pass the JSON output paths from prior CLI runs):
    - Vulnerability scan results  (--vulnerability-scan)
    - Access review results       (--access-scan)

Output
------
Primary: canonical JSON report (--output).
Optional: PDF rendered from the same JSON payload (--pdf), requires reportlab.
"""

import importlib.util
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
TOOLS_DIR = REPO_ROOT / "tools"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _load_tool(filename: str, module_name: str) -> Any | None:
    """Load a tool module from tools/ by filename.  Returns None on failure."""
    module_path = (TOOLS_DIR / filename).resolve()
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
        return module
    except Exception:
        return None


def _gather_compliance() -> dict[str, Any]:
    reporter = _load_tool("compliance-reporter.py", "compliance_reporter")
    if reporter is None:
        return {"error": "compliance-reporter.py could not be loaded"}
    results: dict[str, Any] = {}
    for fw in ("SOC2", "ISO27001", "GDPR"):
        try:
            results[fw.lower()] = reporter.generate_report(framework=fw)
        except Exception as exc:
            results[fw.lower()] = {"error": str(exc)}
    return results


def _gather_certificates() -> dict[str, Any]:
    cert_mgr = _load_tool("certificate-manager.py", "certificate_manager")
    if cert_mgr is None:
        return {"error": "certificate-manager.py could not be loaded"}
    try:
        certs = cert_mgr.list_certificates()
        expiring_soon = [c for c in certs if c.get("needs_renewal")]
        return {
            "total": len(certs),
            "expiring_soon": len(expiring_soon),
            "certificates": certs,
        }
    except Exception as exc:
        return {"error": str(exc)}


def _load_optional_json(path: str | None, label: str) -> dict[str, Any] | None:
    """Load a JSON file from a prior scan run.  Returns None if path is None."""
    if path is None:
        return None
    p = Path(path).expanduser().resolve()
    if not p.exists():
        return {"error": f"{label} file not found at: {path}"}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        return {"error": f"could not load {label}: {exc}"}


#: Findings categories emitted by ``scan access`` that may carry
#: ``incomplete_data`` markers interleaved with real findings.
_ACCESS_FINDING_CATEGORIES = (  # FIX: C6-RT-20
    "inactive_users",  # FIX: C6-RT-20
    "privilege_creep",  # FIX: C6-RT-20
    "orphaned_approvers",  # FIX: C6-RT-20
)  # FIX: C6-RT-20


def _access_incomplete_checks(access: dict[str, Any] | None) -> list[str]:  # FIX: C6-RT-20
    """Return one human-readable line per access check that COULD NOT RUN.

    The ``scan access`` producer interleaves ``incomplete_data`` marker dicts of
    the shape::

        {"status": "incomplete_data",
         "check": "production_access_in_non_prod_role",
         "missing_fields": ["Systems"],
         "issue": "... could not run: 'Systems' field unavailable ..."}

    with real findings inside each category list.  Real findings never carry a
    ``status`` key, so markers are detected with
    ``f.get("status") == "incomplete_data"``.

    Returns an empty list for an artifact produced before the marker schema
    existed (no markers, no ``incomplete_data_count``); the caller falls back to
    a count-based message in that case.  Never raises on a missing key.
    """
    if not isinstance(access, dict):  # FIX: C6-RT-20
        return []  # FIX: C6-RT-20

    # Markers may live at the top level or nested under a "findings" mapping;
    # accept either layout so the consumer is not coupled to one nesting.
    containers: list[dict[str, Any]] = [access]  # FIX: C6-RT-20
    nested = access.get("findings")  # FIX: C6-RT-20
    if isinstance(nested, dict):  # FIX: C6-RT-20
        containers.append(nested)  # FIX: C6-RT-20

    details: list[str] = []  # FIX: C6-RT-20
    seen: set[tuple[str, tuple[str, ...]]] = set()  # FIX: C6-RT-20
    for container in containers:  # FIX: C6-RT-20
        for category in _ACCESS_FINDING_CATEGORIES:  # FIX: C6-RT-20
            entries = container.get(category)  # FIX: C6-RT-20
            if not isinstance(entries, list):  # FIX: C6-RT-20
                continue  # FIX: C6-RT-20
            for entry in entries:  # FIX: C6-RT-20
                if not isinstance(entry, dict):  # FIX: C6-RT-20
                    continue  # FIX: C6-RT-20
                if entry.get("status") != "incomplete_data":  # FIX: C6-RT-20
                    continue  # FIX: C6-RT-20
                check = str(entry.get("check") or category)  # FIX: C6-RT-20
                raw_fields = entry.get("missing_fields") or []  # FIX: C6-RT-20
                if isinstance(raw_fields, str):  # FIX: C6-RT-20
                    raw_fields = [raw_fields]  # FIX: C6-RT-20
                fields = tuple(str(f) for f in raw_fields)  # FIX: C6-RT-20
                key = (check, fields)  # FIX: C6-RT-20
                if key in seen:  # FIX: C6-RT-20
                    continue  # FIX: C6-RT-20
                seen.add(key)  # FIX: C6-RT-20
                if len(fields) == 1:  # FIX: C6-RT-20
                    reason = f"missing field: {fields[0]}"  # FIX: C6-RT-20
                elif fields:  # FIX: C6-RT-20
                    reason = f"missing fields: {', '.join(fields)}"  # FIX: C6-RT-20
                else:  # FIX: C6-RT-20
                    reason = "missing field not reported by the data source"  # FIX: C6-RT-20
                details.append(  # FIX: C6-RT-20
                    f"access review incomplete: check '{check}' "  # FIX: C6-RT-20
                    f"could not run ({reason})"  # FIX: C6-RT-20
                )  # FIX: C6-RT-20
    return details  # FIX: C6-RT-20


def _access_incomplete_controls(access: dict[str, Any] | None) -> list[str]:  # FIX: C6-RT-20
    """Return the access compliance control keys whose status is ``incomplete``."""
    if not isinstance(access, dict):  # FIX: C6-RT-20
        return []  # FIX: C6-RT-20
    comp = access.get("compliance")  # FIX: C6-RT-20
    if not isinstance(comp, dict):  # FIX: C6-RT-20
        return []  # FIX: C6-RT-20
    return [str(k) for k, v in comp.items() if v == "incomplete"]  # FIX: C6-RT-20


def _overall_status(
    compliance: dict[str, Any],
    certificates: dict[str, Any],
    vuln: dict[str, Any] | None,
    access: dict[str, Any] | None,
) -> str:
    """Collapse every embedded section into one overall status string.

    Access-review incompleteness maps to ``"warning"``, not ``"unknown"``
    (FIX: C6-RT-20).  ``"unknown"`` is already reserved in this function for
    "the report itself could not be assembled" - the
    ``if "error" in compliance or "error" in certificates`` branch below.  An
    access review that RAN but could not complete every check is a materially
    different state, and it must not be collapsed into the same bucket as a
    failed report load.  ``"warning"`` is the correct severity and is additive
    to the existing access branch, which previously looked only at
    ``inactive_count`` / ``privilege_creep_count`` and therefore reported
    ``healthy`` for a review in which checks silently could not run.
    """
    if "error" in compliance or "error" in certificates:
        return "unknown"
    # Critical: any compliance framework below 95 % or critical CVEs
    for fw_data in compliance.values():
        if isinstance(fw_data, dict) and fw_data.get("compliance_percentage", 100) < 95:
            return "critical"
    if vuln and vuln.get("summary", {}).get("critical", 0) > 0:
        return "critical"
    # Warning: certificates expiring, high CVEs, or access findings
    if certificates.get("expiring_soon", 0) > 0:
        return "warning"
    if vuln and vuln.get("summary", {}).get("high", 0) > 0:
        return "warning"
    if access:
        s = access.get("summary", {})
        if s.get("inactive_count", 0) > 0 or s.get("privilege_creep_count", 0) > 0:
            return "warning"
        # A review that ran but could not complete every check is NOT healthy.
        # `.get(..., 0)` keeps a pre-marker-schema artifact behaving as before.
        if s.get("incomplete_data_count", 0) > 0:  # FIX: C6-RT-20
            return "warning"  # FIX: C6-RT-20
        if _access_incomplete_controls(access):  # FIX: C6-RT-20
            return "warning"  # FIX: C6-RT-20
    return "healthy"


# ---------------------------------------------------------------------------
# Optional PDF rendering
# ---------------------------------------------------------------------------

def _render_pdf(report: dict[str, Any], output_path: str) -> str | None:
    """Render the canonical JSON report to PDF.

    Returns the path written, or ``None`` when reportlab is not installed.
    """
    try:
        from reportlab.lib.pagesizes import letter             # type: ignore[import-untyped]
        from reportlab.lib.styles import getSampleStyleSheet   # type: ignore[import-untyped]
        from reportlab.platypus import (                       # type: ignore[import-untyped]
            Paragraph, SimpleDocTemplate, Spacer,
        )
    except ImportError:
        return None

    out = Path(output_path).expanduser().resolve()
    out.parent.mkdir(parents=True, exist_ok=True)

    doc = SimpleDocTemplate(str(out), pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    period = report.get("period", {})
    story.append(Paragraph("OpenClaw Weekly Security Report", styles["Title"]))
    story.append(Spacer(1, 12))
    story.append(Paragraph(
        f"Period: {period.get('start', '?')} to {period.get('end', '?')}",
        styles["Normal"],
    ))
    story.append(Paragraph(
        f"Generated: {report.get('generated_at', '?')}",
        styles["Normal"],
    ))
    story.append(Paragraph(
        f"Overall Status: {report.get('overall_status', '?').upper()}",
        styles["Heading2"],
    ))
    story.append(Spacer(1, 8))

    # Compliance section
    story.append(Paragraph("Compliance Summary", styles["Heading2"]))
    comp = report.get("sections", {}).get("compliance_status", {})
    for fw, data in comp.items():
        if isinstance(data, dict) and "compliance_percentage" in data:
            pct = data["compliance_percentage"]
            story.append(Paragraph(f"{fw.upper()}: {pct:.1f}%", styles["Normal"]))
    story.append(Spacer(1, 8))

    # Certificates
    story.append(Paragraph("Certificate Status", styles["Heading2"]))
    certs = report.get("sections", {}).get("certificate_status", {})
    if "error" not in certs:
        story.append(Paragraph(
            f"Total: {certs.get('total', 0)}  Expiring soon: {certs.get('expiring_soon', 0)}",
            styles["Normal"],
        ))
    story.append(Spacer(1, 8))

    # Vulnerability section
    vuln = report.get("sections", {}).get("vulnerability_summary")
    if vuln and "summary" in vuln:
        s = vuln["summary"]
        story.append(Paragraph("Vulnerability Summary", styles["Heading2"]))
        story.append(Paragraph(
            f"Critical: {s.get('critical', 0)}  High: {s.get('high', 0)}"
            f"  Total: {s.get('total', 0)}",
            styles["Normal"],
        ))
        story.append(Spacer(1, 8))

    # Access review section  # FIX: C6-RT-20
    access = report.get("sections", {}).get("access_review_status")  # FIX: C6-RT-20
    if isinstance(access, dict) and "error" not in access:  # FIX: C6-RT-20
        a_summary = access.get("summary", {})  # FIX: C6-RT-20
        if not isinstance(a_summary, dict):  # FIX: C6-RT-20
            a_summary = {}  # FIX: C6-RT-20
        story.append(Paragraph("Access Review", styles["Heading2"]))  # FIX: C6-RT-20
        story.append(Paragraph(  # FIX: C6-RT-20
            f"Inactive: {a_summary.get('inactive_count', 0)}"  # FIX: C6-RT-20
            f"  Privilege creep: {a_summary.get('privilege_creep_count', 0)}"  # FIX: C6-RT-20
            f"  Orphaned approvers: {a_summary.get('orphaned_approver_count', 0)}"  # FIX: C6-RT-20
            f"  Checks that could not run: {a_summary.get('incomplete_data_count', 0)}",  # FIX: C6-RT-20
            styles["Normal"],  # FIX: C6-RT-20
        ))  # FIX: C6-RT-20
        for detail in _access_incomplete_checks(access):  # FIX: C6-RT-20
            story.append(Paragraph(f"\u2022 {detail}", styles["Normal"]))  # FIX: C6-RT-20
        for control in _access_incomplete_controls(access):  # FIX: C6-RT-20
            story.append(Paragraph(  # FIX: C6-RT-20
                f"\u2022 control {control} is INCOMPLETE - not attested",  # FIX: C6-RT-20
                styles["Normal"],  # FIX: C6-RT-20
            ))  # FIX: C6-RT-20
        story.append(Spacer(1, 8))  # FIX: C6-RT-20

    # Missing evidence
    missing = report.get("missing_evidence", [])
    if missing:
        story.append(Paragraph("Missing Evidence", styles["Heading2"]))
        for item in missing:
            story.append(Paragraph(f"\u2022 {item}", styles["Normal"]))

    # Warnings
    for w in report.get("warnings", []):
        story.append(Paragraph(f"\u26a0 {w}", styles["Normal"]))

    doc.build(story)
    return str(out)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_weekly_report(
    start_date: str,
    end_date: str,
    output_path: str | None = None,
    pdf_path: str | None = None,
    vulnerability_scan_path: str | None = None,
    access_scan_path: str | None = None,
) -> dict[str, Any]:
    """Generate a weekly security report and return the canonical result dict.

    Args:
        start_date: ISO date (YYYY-MM-DD) for the period start.
        end_date: ISO date (YYYY-MM-DD) for the period end.
        output_path: write the canonical JSON result to this path.
        pdf_path: optionally render a PDF to this path (requires reportlab).
        vulnerability_scan_path: path to a ``scan vulnerability`` JSON output.
        access_scan_path: path to a ``scan access`` JSON output.
    """
    compliance = _gather_compliance()
    certs = _gather_certificates()
    vuln = _load_optional_json(vulnerability_scan_path, "vulnerability scan")
    access = _load_optional_json(access_scan_path, "access review")

    missing_evidence: list[str] = []
    warnings: list[str] = []

    if vuln is None:
        missing_evidence.append(
            "vulnerability_summary: run "
            "'openclaw-cli scan vulnerability --output vuln.json' "
            "and embed with --vulnerability-scan vuln.json"
        )
    elif "error" in vuln:
        warnings.append(f"vulnerability scan could not be loaded: {vuln['error']}")
        vuln = None

    if access is None:
        missing_evidence.append(
            "access_review_status: run "
            "'openclaw-cli scan access --output access.json' "
            "and embed with --access-scan access.json"
        )
    elif "error" in access:
        warnings.append(f"access review could not be loaded: {access['error']}")
        access = None
    else:  # FIX: C6-RT-20
        # An access review that RAN but could not complete every check must name
        # the specific checks it skipped -- a generic "incomplete" string is not
        # actionable for an auditor.  Marker detail is preferred; a pre-marker
        # artifact (no markers, counts only) falls back to a count-based line.
        incomplete_details = _access_incomplete_checks(access)  # FIX: C6-RT-20
        incomplete_controls = _access_incomplete_controls(access)  # FIX: C6-RT-20
        access_summary = access.get("summary", {})  # FIX: C6-RT-20
        if not isinstance(access_summary, dict):  # FIX: C6-RT-20
            access_summary = {}  # FIX: C6-RT-20
        incomplete_count = access_summary.get("incomplete_data_count", 0)  # FIX: C6-RT-20
        if incomplete_details:  # FIX: C6-RT-20
            warnings.extend(incomplete_details)  # FIX: C6-RT-20
        elif incomplete_count:  # FIX: C6-RT-20: guard on the count alone -- an
            # 'incomplete' compliance control with a zero count is reported by the
            # loop below, and folding it in here emitted "0 check(s) could not run",
            # a false statement in an audit-facing warning.
            warnings.append(  # FIX: C6-RT-20
                f"access review incomplete: {incomplete_count} check(s) could "  # FIX: C6-RT-20
                "not run; this artifact carries no per-check detail "  # FIX: C6-RT-20
                "(re-run 'openclaw-cli scan access' to name them)"  # FIX: C6-RT-20
            )  # FIX: C6-RT-20
        for control in incomplete_controls:  # FIX: C6-RT-20
            warnings.append(  # FIX: C6-RT-20
                f"access review incomplete: compliance control {control} is "  # FIX: C6-RT-20
                "'incomplete' - it is NOT attested by this report"  # FIX: C6-RT-20
            )  # FIX: C6-RT-20

    if "error" in compliance:
        warnings.append(f"compliance reporter error: {compliance['error']}")
    if "error" in certs:
        warnings.append(f"certificate manager error: {certs['error']}")

    status = _overall_status(compliance, certs, vuln, access)

    report: dict[str, Any] = {
        "command": "report weekly",
        "generated_at": datetime.now(UTC).isoformat(),
        "period": {"start": start_date, "end": end_date},
        "sections": {
            "compliance_status": compliance,
            "certificate_status": certs,
            "vulnerability_summary": vuln,
            "access_review_status": access,
        },
        "overall_status": status,
        "missing_evidence": missing_evidence,
        "warnings": warnings,
        "artifacts": {
            "json_report": None,
            "pdf_report": None,
        },
    }

    if output_path:
        out = Path(output_path).expanduser().resolve()
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, indent=2), encoding="utf-8")
        report["artifacts"]["json_report"] = str(out)

    if pdf_path:
        rendered = _render_pdf(report, pdf_path)
        if rendered:
            report["artifacts"]["pdf_report"] = rendered
        else:
            warnings.append(
                "PDF rendering skipped: reportlab is not installed. "
                "Install with: pip install reportlab"
            )
            report["warnings"] = warnings

    return report
