from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


_IOC_PATH = Path(__file__).resolve().parents[2] / "scripts" / "incident-response" / "ioc-scanner.py"
_SPEC = importlib.util.spec_from_file_location("openclaw_ioc_scanner_tests", _IOC_PATH)
assert _SPEC is not None and _SPEC.loader is not None
_IOC_MOD = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _IOC_MOD
_SPEC.loader.exec_module(_IOC_MOD)


def _request_failure(*_args, **_kwargs):
    raise _IOC_MOD.requests.exceptions.RequestException("upstream timeout")


def test_generate_report_marks_lookup_failures_as_error(tmp_path, monkeypatch):
    monkeypatch.setattr(_IOC_MOD, "ABUSEIPDB_API_KEY", "test-token")
    monkeypatch.setattr(_IOC_MOD.requests, "get", _request_failure)

    scanner = _IOC_MOD.IOCScanner()
    result = scanner.check_ip_reputation("203.0.113.10")
    report_path = tmp_path / "ioc-report.json"
    scanner.generate_report(str(report_path))

    report = json.loads(report_path.read_text(encoding="utf-8"))

    assert result["status"] == "error"
    assert report["status"] == "error"
    assert report["scan_results"][0]["status"] == "error"


def test_main_returns_nonzero_when_lookup_fails(tmp_path, monkeypatch):
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


def test_domain_analysis_propagates_nested_reputation_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(_IOC_MOD, "ABUSEIPDB_API_KEY", "test-token")
    monkeypatch.setattr(_IOC_MOD.socket, "gethostbyname", lambda _domain: "203.0.113.10")
    monkeypatch.setattr(_IOC_MOD.requests, "get", _request_failure)

    scanner = _IOC_MOD.IOCScanner()
    result = scanner.analyze_domain("example.com")
    report_path = tmp_path / "ioc-report.json"
    scanner.generate_report(str(report_path))

    report = json.loads(report_path.read_text(encoding="utf-8"))

    assert result["status"] == "error"
    assert report["status"] == "error"
    assert any(scan_result["status"] == "error" for scan_result in report["scan_results"])