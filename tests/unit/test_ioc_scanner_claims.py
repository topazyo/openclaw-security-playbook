from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest


_IOC_PATH = Path(__file__).resolve().parents[2] / "scripts" / "incident-response" / "ioc-scanner.py"
_SPEC = importlib.util.spec_from_file_location("openclaw_ioc_scanner_claim_tests", _IOC_PATH)
assert _SPEC is not None and _SPEC.loader is not None
_IOC_MOD = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _IOC_MOD
_SPEC.loader.exec_module(_IOC_MOD)


def _request_failure(*_args, **_kwargs):
    raise _IOC_MOD.requests.exceptions.RequestException("upstream timeout")


def test___init___claim_initializes_scan_tracking(monkeypatch):
    monkeypatch.setattr(_IOC_MOD, "ABUSEIPDB_API_KEY", "unexpected-key")

    scanner = _IOC_MOD.IOCScanner()

    assert scanner.results["status"] == "success"
    assert scanner.results["scan_results"] == []
    assert scanner.results["iocs_found"] == []
    assert scanner.results["scan_timestamp"]


def test__record_scan_result_claim_tracks_error_over_prior_success():
    scanner = _IOC_MOD.IOCScanner()
    scanner._record_scan_result("ip", "203.0.113.10", {"status": "success", "is_malicious": False})
    scanner._record_scan_result("hash", "deadbeef", {"status": "error", "error": "upstream timeout"})

    assert scanner.results["status"] == "error"
    assert scanner.results["scan_results"][1]["target"] == "deadbeef"
    assert scanner.results["scan_results"][1]["status"] == "error"


def test_check_ip_reputation_claim_marks_request_failures_as_error(monkeypatch):
    monkeypatch.setattr(_IOC_MOD, "ABUSEIPDB_API_KEY", "test-token")
    monkeypatch.setattr(_IOC_MOD.requests, "get", _request_failure)

    scanner = _IOC_MOD.IOCScanner()
    result = scanner.check_ip_reputation("203.0.113.10")

    assert result["status"] == "error"
    assert scanner.results["status"] == "error"
    assert scanner.results["scan_results"][0]["target"] == "203.0.113.10"


def test_check_file_hash_claim_records_request_failures_as_error(monkeypatch):
    monkeypatch.setattr(_IOC_MOD, "VIRUSTOTAL_API_KEY", "test-token")
    monkeypatch.setattr(_IOC_MOD.requests, "get", _request_failure)

    scanner = _IOC_MOD.IOCScanner()
    result = scanner.check_file_hash("deadbeef")

    assert result["status"] == "error"
    assert scanner.results["status"] == "error"
    assert scanner.results["scan_results"][0]["scan_type"] == "hash"


def test_analyze_domain_claim_propagates_nested_reputation_failure(monkeypatch):
    monkeypatch.setattr(_IOC_MOD, "ABUSEIPDB_API_KEY", "test-token")
    monkeypatch.setattr(_IOC_MOD.socket, "gethostbyname", lambda _domain: "203.0.113.10")
    monkeypatch.setattr(_IOC_MOD.requests, "get", _request_failure)

    scanner = _IOC_MOD.IOCScanner()
    result = scanner.analyze_domain("example.com")

    assert result["status"] == "error"
    assert result["reputation_error"] == "upstream timeout"
    assert any(scan_result["status"] == "error" for scan_result in scanner.results["scan_results"])


def test_scan_file_claim_records_missing_file_errors(tmp_path):
    scanner = _IOC_MOD.IOCScanner()
    result = scanner.scan_file(tmp_path / "missing.bin")

    assert result["status"] == "error"
    assert scanner.results["status"] == "error"
    assert scanner.results["scan_results"][0]["target"].endswith("missing.bin")


def test_main_claim_returns_nonzero_on_failed_ioc_scan(tmp_path, monkeypatch):
    monkeypatch.setattr(_IOC_MOD, "ABUSEIPDB_API_KEY", "test-token")
    monkeypatch.setattr(_IOC_MOD.requests, "get", _request_failure)
    monkeypatch.setattr(
        _IOC_MOD.sys,
        "argv",
        [
            "ioc-scanner.py",
            "--ip",
            "203.0.113.10",
            "--output",
            str(tmp_path / "ioc-report.json"),
        ],
    )

    exit_code = _IOC_MOD.main()

    assert exit_code == 1