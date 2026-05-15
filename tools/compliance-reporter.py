#!/usr/bin/env python3
"""Compliance Reporter - Generates SOC 2/ISO 27001/GDPR audit reports.

Run from repo root:
    python tools/compliance-reporter.py --help
"""

import argparse
import json
import sys  # FIX: C6-H-05
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TypeAlias, cast  # FIX: C5-finding-4


REPO_ROOT = Path(__file__).resolve().parent.parent
ControlRecord: TypeAlias = dict[str, Any]  # FIX: C5-finding-4
ComplianceReport: TypeAlias = dict[str, Any]  # FIX: C5-finding-4


def _safe_repo_path(relative_path: str) -> Path:
    candidate = (REPO_ROOT / relative_path).resolve()
    if REPO_ROOT not in candidate.parents and candidate != REPO_ROOT:
        raise ValueError(f"Path traversal detected: {relative_path}")
    return candidate


def _validate_output_path(output_path: str) -> Path:
    path = Path(output_path).expanduser().resolve()
    blocked_roots = [Path("/etc"), Path("/usr"), Path("/bin"), Path("/sbin"), Path("/var")]
    blocked_roots.extend([
        Path("C:/Windows"),
        Path("C:/Program Files"),
        Path("C:/Program Files (x86)"),
    ])

    for blocked in blocked_roots:
        if blocked in path.parents or path == blocked:
            raise ValueError(f"Refusing to write to system path: {path}")

    config_root = (REPO_ROOT / "configs").resolve()
    if config_root in path.parents:
        raise ValueError(f"Refusing to overwrite configuration files: {path}")

    return path


class ComplianceReporter:
    """Generates compliance reports for audits."""

    @staticmethod
    def _calculate_summary(controls: list[ControlRecord]) -> tuple[int, int, float]:  # FIX: C5-finding-4
        if not controls:
            raise ValueError("Compliance mapping did not yield any controls")

        implemented = sum(1 for control in controls if control.get("status") == "implemented")
        pending = len(controls) - implemented
        percentage = round((implemented / len(controls)) * 100, 2)
        return implemented, pending, percentage

    @staticmethod
    def _calculate_statement_summary(statement: ControlRecord) -> tuple[int, int, float]:  # FIX: C5-finding-5
        implemented = statement.get("implemented")  # FIX: C5-finding-5
        pending = statement.get("planned")  # FIX: C5-finding-5
        if not isinstance(implemented, int) or not isinstance(pending, int) or isinstance(implemented, bool) or isinstance(pending, bool):  # FIX: C5-finding-5
            raise ValueError("ISO27001 statement_of_applicability requires integer implemented and planned counts")  # FIX: C5-finding-5

        applicable = implemented + pending  # FIX: C5-finding-5
        if applicable <= 0:  # FIX: C5-finding-5
            raise ValueError("ISO27001 statement_of_applicability has no applicable controls")  # FIX: C5-finding-5

        percentage = round((implemented / applicable) * 100, 2)  # FIX: C5-finding-5
        return implemented, pending, percentage  # FIX: C5-finding-5

    @staticmethod  # FIX: C6-H-05
    def _validate_soa_internal_consistency(statement: ControlRecord) -> None:  # FIX: C6-H-05
        """Assert that statement_of_applicability fields sum to total_controls.

        Catches the prior failure mode where a worker set implemented=19, planned=0,
        not_applicable=23 (sum=42) while total_controls remained 93 — an inconsistency
        that the old code silently accepted.  Raises ValueError with all four numbers
        so the offending field is immediately identifiable.
        """  # FIX: C6-H-05
        total = statement.get("total_controls")  # FIX: C6-H-05
        implemented = statement.get("implemented")  # FIX: C6-H-05
        planned = statement.get("planned")  # FIX: C6-H-05
        not_applicable = statement.get("not_applicable", 0)  # FIX: C6-H-05
        if not all(isinstance(v, int) and not isinstance(v, bool) for v in (total, implemented, planned, not_applicable)):  # FIX: C6-H-05
            return  # type checking handled by _calculate_statement_summary  # FIX: C6-H-05
        actual_sum = implemented + planned + not_applicable  # FIX: C6-H-05
        if actual_sum != total:  # FIX: C6-H-05
            raise ValueError(  # FIX: C6-H-05
                f"ISO27001 statement_of_applicability internal inconsistency: "  # FIX: C6-H-05
                f"implemented({implemented}) + planned({planned}) + not_applicable({not_applicable}) "  # FIX: C6-H-05
                f"= {actual_sum} must equal total_controls({total})"  # FIX: C6-H-05
            )  # FIX: C6-H-05

    @staticmethod  # FIX: C6-H-05
    def _build_iso27001_coverage_summary(  # FIX: C6-H-05
        corpus_controls: list[ControlRecord],  # FIX: C6-H-05
        statement: ControlRecord,  # FIX: C6-H-05
    ) -> dict[str, Any]:  # FIX: C6-H-05
        """Build a structured coverage_summary dict comparing corpus to the SoA.

        Compares the actually loaded corpus controls against the Statement of
        Applicability (SoA) to surface the mapping gap as a structured, queryable
        JSON object.  Does not modify the SoA.

        gap_status enum:
          INCOMPLETE_MAPPING  — mapped controls < soa_applicable_controls
          COMPLETE_MAPPING    — mapped controls == soa_applicable_controls
          OVER_MAPPING        — mapped controls > soa_applicable_controls
        """  # FIX: C6-H-05
        mapped = len(corpus_controls)  # FIX: C6-H-05
        soa_total = statement.get("total_controls", 0)  # FIX: C6-H-05
        soa_implemented = statement.get("implemented", 0)  # FIX: C6-H-05
        soa_planned = statement.get("planned", 0)  # FIX: C6-H-05
        soa_not_applicable = statement.get("not_applicable", 0)  # FIX: C6-H-05
        soa_applicable = soa_implemented + soa_planned  # FIX: C6-H-05

        unmapped = soa_applicable - mapped  # FIX: C6-H-05 (signed: negative means OVER_MAPPING)
        coverage_pct = round(mapped / soa_applicable * 100, 2) if soa_applicable > 0 else 0.0  # FIX: C6-H-05

        if mapped < soa_applicable:  # FIX: C6-H-05
            gap_status = "INCOMPLETE_MAPPING"  # FIX: C6-H-05
        elif mapped == soa_applicable:  # FIX: C6-H-05
            gap_status = "COMPLETE_MAPPING"  # FIX: C6-H-05
        else:  # FIX: C6-H-05
            gap_status = "OVER_MAPPING"  # FIX: C6-H-05

        # Theme breakdown: count controls per top-level group key  # FIX: C6-H-05
        theme_counts: dict[str, int] = {}  # FIX: C6-H-05
        for control in corpus_controls:  # FIX: C6-H-05
            group = control.get("group", "unknown")  # FIX: C6-H-05
            theme_counts[group] = theme_counts.get(group, 0) + 1  # FIX: C6-H-05

        return {  # FIX: C6-H-05
            "mapped_controls": mapped,  # FIX: C6-H-05
            "soa_total_controls": soa_total,  # FIX: C6-H-05
            "soa_applicable_controls": soa_applicable,  # FIX: C6-H-05
            "soa_implemented": soa_implemented,  # FIX: C6-H-05
            "soa_planned": soa_planned,  # FIX: C6-H-05
            "soa_not_applicable": soa_not_applicable,  # FIX: C6-H-05
            "unmapped_applicable_controls": unmapped,  # FIX: C6-H-05
            "corpus_to_soa_coverage_percentage": coverage_pct,  # FIX: C6-H-05
            "theme_breakdown": theme_counts,  # FIX: C6-H-05
            "gap_status": gap_status,  # FIX: C6-H-05
        }  # FIX: C6-H-05

    @staticmethod  # FIX: C6-H-05
    def _emit_iso27001_coverage_warning(coverage: dict[str, Any]) -> None:  # FIX: C6-H-05
        """Write a single-line WARNING to stderr when corpus mapping is incomplete.

        No-op when gap_status is COMPLETE_MAPPING (corpus fully covers SoA applicable
        controls).  The WARNING: prefix is picked up by CI log scanners and most
        Splunk parsers without configuration.

        Format (machine-parseable, one line, no newlines):
          WARNING: ISO27001 compliance_mapping coverage gap: mapped=<n> soa_applicable=<n> gap=<n> (coverage=<n.nn>%) basis=loaded_corpus
        """  # FIX: C6-H-05
        if coverage.get("gap_status") == "COMPLETE_MAPPING":  # FIX: C6-H-05
            return  # FIX: C6-H-05
        mapped = coverage["mapped_controls"]  # FIX: C6-H-05
        soa_applicable = coverage["soa_applicable_controls"]  # FIX: C6-H-05
        gap = soa_applicable - mapped  # FIX: C6-H-05
        pct = coverage["corpus_to_soa_coverage_percentage"]  # FIX: C6-H-05
        print(  # FIX: C6-H-05
            f"WARNING: ISO27001 compliance_mapping coverage gap: "  # FIX: C6-H-05
            f"mapped={mapped} soa_applicable={soa_applicable} gap={gap} "  # FIX: C6-H-05
            f"(coverage={pct}%) basis=loaded_corpus",  # FIX: C6-H-05
            file=sys.stderr,  # FIX: C6-H-05
        )  # FIX: C6-H-05

    @staticmethod
    def _normalize_control_list(mapping_name: str, controls: list[Any]) -> list[ControlRecord]:  # FIX: C5-finding-4
        normalized_controls: list[ControlRecord] = []  # FIX: C5-finding-4
        for index, control in enumerate(controls):  # FIX: C5-finding-4
            if not isinstance(control, dict):  # FIX: C5-finding-4
                raise ValueError(f"{mapping_name} controls[{index}] must be an object")  # FIX: C5-finding-4
            normalized_controls.append(cast(ControlRecord, control))  # FIX: C5-finding-4

        return normalized_controls  # FIX: C5-finding-4

    @staticmethod
    def _validate_explicit_status(mapping_name: str, controls: list[ControlRecord]) -> None:  # FIX: C5-finding-4
        if any("status" not in control for control in controls):  # FIX: C5-finding-4
            raise ValueError(  # FIX: C5-finding-4
                f"{mapping_name} mapping schema drift: expected explicit status for each control"  # FIX: C5-finding-4
            )  # FIX: C5-finding-4

    @staticmethod
    def _normalize_mapping_controls(mapping_name: str, mapping: dict[str, Any]) -> list[ControlRecord]:  # FIX: C5-finding-4
        controls: list[ControlRecord] = []  # FIX: C5-finding-4
        for control_id, details in mapping.items():
            if not isinstance(details, dict):
                continue

            typed_details = cast(ControlRecord, details)  # FIX: C5-finding-4
            control: ControlRecord = {"control_id": control_id, **typed_details}  # FIX: C5-finding-4
            controls.append(control)

        if not controls:
            raise ValueError(f"{mapping_name} mapping is empty or invalid")

        ComplianceReporter._validate_explicit_status(mapping_name, controls)  # FIX: C5-finding-4

        return controls

    @staticmethod
    def _normalize_nested_control_groups(mapping_name: str, groups: dict[str, Any]) -> list[ControlRecord]:  # FIX: C5-finding-4
        controls: list[ControlRecord] = []  # FIX: C5-finding-4
        for group_name, group_controls in groups.items():
            if not isinstance(group_controls, dict):
                continue

            typed_group_controls = cast(dict[str, Any], group_controls)  # FIX: C5-finding-4

            for control_id, details in typed_group_controls.items():  # FIX: C5-finding-4
                if not isinstance(details, dict):
                    continue

                typed_details = cast(ControlRecord, details)  # FIX: C5-finding-4
                control: ControlRecord = {  # FIX: C5-finding-4
                    "group": group_name,
                    "control_id": control_id,
                    **typed_details,
                }
                controls.append(control)

        if not controls:
            raise ValueError(f"{mapping_name} mapping is empty or invalid")

        ComplianceReporter._validate_explicit_status(mapping_name, controls)  # FIX: C5-finding-4

        return controls
    
    def generate_report(self, framework: str = "SOC2") -> ComplianceReport:  # FIX: C5-finding-4
        """Generate compliance report for specified framework."""
        if framework == "SOC2":
            return self._generate_soc2_report()
        elif framework == "ISO27001":
            return self._generate_iso27001_report()
        elif framework == "GDPR":
            return self._generate_gdpr_report()
        else:
            return {"error": f"Unknown framework: {framework}"}
    
    def _generate_soc2_report(self) -> ComplianceReport:  # FIX: C5-finding-4
        """Generate SOC 2 compliance report."""
        controls = self._load_soc2_controls()
        implemented, pending, percentage = self._calculate_summary(controls)
        
        return {
            "framework": "SOC 2 Type II",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "controls": controls,
            "implemented_count": implemented,
            "pending_count": pending,
            "compliance_percentage": percentage,
        }
    
    def _generate_iso27001_report(self) -> ComplianceReport:  # FIX: C5-finding-4, C6-H-05
        """Generate ISO 27001 compliance report.

        compliance_percentage and implemented_count/pending_count are derived from
        the loaded corpus (basis=loaded_corpus), not from the Statement of
        Applicability (SoA).  The SoA is preserved verbatim under coverage_summary
        so the SoA-vs-corpus gap is visible to auditors in three channels:
          1. coverage_summary.gap_status (structured JSON)
          2. coverage_summary.unmapped_applicable_controls (integer gap)
          3. A WARNING line on stderr (see _emit_iso27001_coverage_warning)

        See ADR in .omc/plans/C6-H-05-compliance-reporter.md §8 for the decision
        rationale and the pre-mortem risk analysis (gate flip-flop scenario).
        """  # FIX: C6-H-05
        controls = self._load_iso27001_controls()  # FIX: C6-H-05
        implemented, pending, percentage = self._calculate_summary(controls)  # FIX: C6-H-05
        statement = self._load_iso27001_statement_raw()  # FIX: C6-H-05
        coverage = self._build_iso27001_coverage_summary(controls, statement)  # FIX: C6-H-05
        self._emit_iso27001_coverage_warning(coverage)  # FIX: C6-H-05

        return {  # FIX: C6-H-05
            "framework": "ISO 27001:2022",  # FIX: C6-H-05
            "generated_at": datetime.now(timezone.utc).isoformat(),  # FIX: C6-H-05
            "controls": controls,  # FIX: C6-H-05
            "implemented_count": implemented,  # FIX: C6-H-05
            "pending_count": pending,  # FIX: C6-H-05
            "compliance_percentage": percentage,  # FIX: C6-H-05
            "compliance_percentage_basis": "loaded_corpus",  # FIX: C6-H-05
            "coverage_summary": coverage,  # FIX: C6-H-05
        }  # FIX: C6-H-05

    def _generate_gdpr_report(self) -> ComplianceReport:  # FIX: C5-finding-4
        """Generate GDPR compliance report."""  # FIX: C5-finding-4
        controls = self._load_gdpr_controls()  # FIX: C5-finding-4
        implemented, pending, percentage = self._calculate_summary(controls)  # FIX: C5-finding-4

        return {  # FIX: C5-finding-4
            "framework": "GDPR",  # FIX: C5-finding-4
            "generated_at": datetime.now(timezone.utc).isoformat(),  # FIX: C5-finding-4
            "controls": controls,  # FIX: C5-finding-4
            "implemented_count": implemented,  # FIX: C5-finding-4
            "pending_count": pending,  # FIX: C5-finding-4
            "compliance_percentage": percentage,  # FIX: C5-finding-4
        }  # FIX: C5-finding-4
    
    def _load_soc2_controls(self) -> list[ControlRecord]:  # FIX: C5-finding-4
        """Load SOC 2 control status from configs."""
        controls_path = _safe_repo_path("configs/organization-policies/soc2-compliance-mapping.json")
        with open(controls_path, encoding="utf-8") as f:
            data = json.load(f)
        controls = data.get("controls")
        if isinstance(controls, list):
            typed_controls = cast(list[Any], controls)  # FIX: C5-finding-4
            return self._normalize_control_list("SOC2", typed_controls)  # FIX: C5-finding-4

        control_mappings = data.get("control_mappings")
        if isinstance(control_mappings, dict):
            typed_control_mappings = cast(dict[str, Any], control_mappings)  # FIX: C5-finding-4
            return self._normalize_mapping_controls("SOC2", typed_control_mappings)  # FIX: C5-finding-4

        raise ValueError("SOC2 controls format is invalid: expected controls list or control_mappings object")
    
    def _load_iso27001_controls(self) -> list[ControlRecord]:  # FIX: C5-finding-4
        """Load ISO 27001 control status."""
        controls_path = _safe_repo_path("configs/organization-policies/iso27001-compliance-mapping.json")
        with open(controls_path, encoding="utf-8") as f:
            data = json.load(f)
        controls = data.get("controls")
        if isinstance(controls, list):
            typed_controls = cast(list[Any], controls)  # FIX: C5-finding-4
            return self._normalize_control_list("ISO27001", typed_controls)  # FIX: C5-finding-4

        annex_a_controls = data.get("annex_a_controls")
        if isinstance(annex_a_controls, dict):
            typed_annex_a_controls = cast(dict[str, Any], annex_a_controls)  # FIX: C5-finding-4
            return self._normalize_nested_control_groups("ISO27001", typed_annex_a_controls)  # FIX: C5-finding-4

        raise ValueError("ISO27001 controls format is invalid: expected controls list or annex_a_controls object")

    def _load_iso27001_statement_raw(self) -> ControlRecord:  # FIX: C6-H-05
        """Load and validate the raw statement_of_applicability dict from the corpus.

        Runs _validate_soa_internal_consistency (D5) to catch prior failure mode
        where implemented+planned+not_applicable != total_controls.
        """  # FIX: C6-H-05
        controls_path = _safe_repo_path("configs/organization-policies/iso27001-compliance-mapping.json")  # FIX: C6-H-05
        with open(controls_path, encoding="utf-8") as f:  # FIX: C6-H-05
            data = json.load(f)  # FIX: C6-H-05

        statement = data.get("statement_of_applicability")  # FIX: C6-H-05
        if not isinstance(statement, dict):  # FIX: C6-H-05
            raise ValueError("ISO27001 report requires statement_of_applicability for truthful summary counts")  # FIX: C6-H-05

        typed_statement = cast(ControlRecord, statement)  # FIX: C6-H-05
        self._validate_soa_internal_consistency(typed_statement)  # FIX: C6-H-05
        return typed_statement  # FIX: C6-H-05

    def _load_iso27001_statement_summary(self) -> tuple[int, int, float]:  # FIX: C5-finding-5
        """Load ISO 27001 summary from the authoritative Statement of Applicability."""  # FIX: C5-finding-5
        typed_statement = self._load_iso27001_statement_raw()  # FIX: C6-H-05 (consistency check now in _load_iso27001_statement_raw)
        return self._calculate_statement_summary(typed_statement)  # FIX: C5-finding-5

    def _load_gdpr_controls(self) -> list[ControlRecord]:  # FIX: C5-finding-4
        """Load GDPR control status from existing organization policy mappings."""  # FIX: C5-finding-4
        policy_files = [  # FIX: C5-finding-4
            "configs/organization-policies/engineering-policy.json",  # FIX: C5-finding-4
            "configs/organization-policies/security-policy.json",  # FIX: C5-finding-4
        ]  # FIX: C5-finding-4
        controls_by_article: dict[str, ControlRecord] = {}  # FIX: C5-finding-4

        for relative_path in policy_files:  # FIX: C5-finding-4
            policy_path = _safe_repo_path(relative_path)  # FIX: C5-finding-4
            with open(policy_path, encoding="utf-8") as f:  # FIX: C5-finding-4
                data = json.load(f)  # FIX: C5-finding-4

            policy_id = data.get("policy_id", policy_path.stem)  # FIX: C5-finding-4
            policy_sections = data.get("policies", {})  # FIX: C5-finding-4
            if not isinstance(policy_sections, dict):  # FIX: C5-finding-4
                raise ValueError(f"GDPR policy source has invalid policies object: {relative_path}")  # FIX: C5-finding-4
            policy_sections = cast(dict[str, Any], policy_sections)  # FIX: C5-finding-4

            for section_name, details in policy_sections.items():  # FIX: C5-finding-4
                if not isinstance(details, dict):  # FIX: C5-finding-4
                    raise ValueError(f"GDPR policy section is invalid: {relative_path}:{section_name}")  # FIX: C5-finding-4
                details = cast(dict[str, Any], details)  # FIX: C5-finding-4

                compliance_mapping = details.get("compliance_mapping", {})  # FIX: C5-finding-4
                if not isinstance(compliance_mapping, dict):  # FIX: C5-finding-4
                    raise ValueError(f"GDPR compliance mapping is invalid: {relative_path}:{section_name}")  # FIX: C5-finding-4
                compliance_mapping = cast(dict[str, Any], compliance_mapping)  # FIX: C5-finding-4
                status = details.get("gdpr_status", "pending")  # FIX: C5-finding-4
                if not isinstance(status, str):  # FIX: C5-finding-4
                    raise ValueError(f"GDPR status must be a string: {relative_path}:{section_name}")  # FIX: C5-finding-4
                gdpr_articles = compliance_mapping.get("GDPR", [])  # FIX: C5-finding-4
                if not gdpr_articles:  # FIX: C5-finding-4
                    continue  # FIX: C5-finding-4
                if not isinstance(gdpr_articles, list):  # FIX: C5-finding-4
                    raise ValueError(f"GDPR compliance mapping must be a list: {relative_path}:{section_name}")  # FIX: C5-finding-4
                gdpr_articles = cast(list[Any], gdpr_articles)  # FIX: C5-finding-4

                for article in gdpr_articles:  # FIX: C5-finding-4
                    if not isinstance(article, str):  # FIX: C5-finding-4
                        raise ValueError(f"GDPR article identifier must be a string: {relative_path}:{section_name}")  # FIX: C5-finding-4
                    status = details.get("gdpr_status", "pending")  # FIX: C5-finding-4
                    if status not in {"implemented", "pending"}:  # FIX: C5-finding-4
                        raise ValueError(f"GDPR status must be implemented or pending: {relative_path}:{section_name}")  # FIX: C5-finding-4
                    evidence = details.get("controls", [])  # FIX: C5-finding-4
                    if not isinstance(evidence, list):  # FIX: C5-finding-4
                        raise ValueError(f"GDPR evidence controls must be a list: {relative_path}:{section_name}")  # FIX: C5-finding-4
                    evidence = cast(list[Any], evidence)  # FIX: C5-finding-4
                    source_section = f"{policy_id}:{section_name}"  # FIX: C5-finding-4
                    control = controls_by_article.setdefault(article, {  # FIX: C5-finding-4
                        "control_id": article,  # FIX: C5-finding-4
                        "policy_ids": [],  # FIX: C5-finding-4
                        "policy_sections": [],  # FIX: C5-finding-4
                        "control": article,  # FIX: C5-finding-4
                        "evidence": [],  # FIX: C5-finding-4
                        "status": "implemented",  # FIX: C5-finding-4
                        "status_reason": "Implemented only when every mapped policy section has explicit gdpr_status=implemented",  # FIX: C5-finding-4
                    })  # FIX: C5-finding-4
                    if policy_id not in control["policy_ids"]:  # FIX: C5-finding-4
                        control["policy_ids"].append(policy_id)  # FIX: C5-finding-4
                    if source_section not in control["policy_sections"]:  # FIX: C5-finding-4
                        control["policy_sections"].append(source_section)  # FIX: C5-finding-4
                    for evidence_item in evidence:  # FIX: C5-finding-4
                        if evidence_item not in control["evidence"]:  # FIX: C5-finding-4
                            control["evidence"].append(evidence_item)  # FIX: C5-finding-4
                    if status != "implemented":  # FIX: C5-finding-4
                        control["status"] = "pending"  # FIX: C5-finding-4

        controls = list(controls_by_article.values())  # FIX: C5-finding-4
        if not controls:  # FIX: C5-finding-4
            raise ValueError("GDPR controls format is invalid: expected GDPR compliance_mapping entries")  # FIX: C5-finding-4

        return controls  # FIX: C5-finding-4


def generate_report(framework: str = "SOC2") -> ComplianceReport:  # FIX: C5-finding-4
    """Module-level wrapper used by openclaw-cli."""
    return ComplianceReporter().generate_report(framework)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate OpenClaw compliance reports")
    parser.add_argument(
        "--framework",
        default="SOC2",
        choices=["SOC2", "ISO27001", "GDPR"],
        help="Compliance framework",
    )
    parser.add_argument("--output", help="Optional output path for JSON report")
    args = parser.parse_args()

    try:
        reporter = ComplianceReporter()
        report = reporter.generate_report(args.framework)

        if args.output:
            output_path = _validate_output_path(args.output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)
        else:
            print(json.dumps(report, indent=2))
    except (FileNotFoundError, json.JSONDecodeError, OSError, ValueError) as exc:
        print(json.dumps({"error": str(exc)}, indent=2))
        raise SystemExit(2)
