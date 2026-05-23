"""Fixture-based tests for .claude/hooks/security_defaults_hook.sh TLS checks.

Covers C6-H-09: the TLS-version check used to false-positive on TLSv1.3 and
had no positive verification that TLSv1.3 is explicitly configured.
"""
# FIX: C6-H-09

from __future__ import annotations  # FIX: C6-H-09

import json  # FIX: C6-H-09
import shutil  # FIX: C6-H-09
import subprocess  # FIX: C6-H-09
from pathlib import Path  # FIX: C6-H-09

import pytest  # FIX: C6-H-09

_HOOK_PATH = (  # FIX: C6-H-09
    Path(__file__).resolve().parents[2] / ".claude" / "hooks" / "security_defaults_hook.sh"
)  # FIX: C6-H-09

_BASH = shutil.which("bash")  # FIX: C6-H-09
pytestmark = pytest.mark.skipif(  # FIX: C6-H-09
    not _BASH or not _HOOK_PATH.exists(),  # FIX: C6-H-09
    reason=f"bash unavailable on PATH or hook missing at {_HOOK_PATH}",  # FIX: C6-H-09
)  # FIX: C6-H-09


def _to_posix(path: Path) -> str:  # FIX: C6-H-09
    """Convert a Windows C:\\... path to /mnt/c/... for WSL bash."""  # FIX: C6-H-09
    s = str(path)  # FIX: C6-H-09
    s = s.replace(chr(92), "/")  # FIX: C6-H-09  (chr(92) == backslash)
    if len(s) >= 2 and s[1] == ":":  # FIX: C6-H-09
        drive = s[0].lower()  # FIX: C6-H-09
        return "/mnt/" + drive + s[2:]  # FIX: C6-H-09
    return s  # FIX: C6-H-09


def _run_hook(file_path: Path) -> tuple[int, str]:  # FIX: C6-H-09
    """Invoke the hook with a JSON payload on stdin; return (exit_code, combined_output)."""  # FIX: C6-H-09
    hook_posix = _to_posix(_HOOK_PATH)  # FIX: C6-H-09
    file_posix = _to_posix(file_path)  # FIX: C6-H-09
    payload = json.dumps({"tool_input": {"file_path": file_posix}})  # FIX: C6-H-09
    result = subprocess.run(  # FIX: C6-H-09
        ["bash", hook_posix],  # FIX: C6-H-09
        input=payload.encode('utf-8'),  # FIX: C6-H-09
        stdout=subprocess.PIPE,  # FIX: C6-H-09
        stderr=subprocess.PIPE,  # FIX: C6-H-09
        timeout=15,  # FIX: C6-H-09
    )
    combined = (  # FIX: C6-H-09
        (result.stdout or b'').decode('utf-8', errors='replace')  # FIX: C6-H-09
        + (result.stderr or b'').decode('utf-8', errors='replace')  # FIX: C6-H-09
    )
    return result.returncode, combined  # FIX: C6-H-09


@pytest.fixture()
def tls_nginx_conf(tmp_path: Path):  # FIX: C6-H-09
    """Factory: writes content into nginx.conf under tmp_path."""  # FIX: C6-H-09
    def _write(content: str) -> Path:  # FIX: C6-H-09
        f = tmp_path / "nginx.conf"  # FIX: C6-H-09
        f.write_text(content, encoding="utf-8")  # FIX: C6-H-09
        return f  # FIX: C6-H-09
    return _write  # FIX: C6-H-09


@pytest.fixture()
def tls_yml_conf(tmp_path: Path):  # FIX: C6-H-09
    """Factory: writes content into tls.yml under tmp_path."""  # FIX: C6-H-09
    def _write(content: str) -> Path:  # FIX: C6-H-09
        f = tmp_path / "tls.yml"  # FIX: C6-H-09
        f.write_text(content, encoding="utf-8")  # FIX: C6-H-09
        return f  # FIX: C6-H-09
    return _write  # FIX: C6-H-09


@pytest.fixture()
def compose_conf(tmp_path: Path):  # FIX: C6-H-09
    """Factory: writes content into docker-compose.yml under tmp_path."""  # FIX: C6-H-09
    def _write(content: str) -> Path:  # FIX: C6-H-09
        f = tmp_path / "docker-compose.yml"  # FIX: C6-H-09
        f.write_text(content, encoding="utf-8")  # FIX: C6-H-09
        return f  # FIX: C6-H-09
    return _write  # FIX: C6-H-09


class TestTLSNegativeRegex:  # FIX: C6-H-09
    """Negative regex: older TLS versions must trigger a violation; TLSv1.3 must not."""  # FIX: C6-H-09

    def test_tls13_only_passes(self, tls_nginx_conf) -> None:  # FIX: C6-H-09
        """ssl_protocols TLSv1.3; must NOT trigger any TLS violation (regression guard)."""  # FIX: C6-H-09
        path = tls_nginx_conf("ssl_protocols TLSv1.3;\n")  # FIX: C6-H-09
        rc, output = _run_hook(path)  # FIX: C6-H-09
        assert rc == 0, f"Expected PASS but got exit {rc}.\nOutput:\n{output}"  # FIX: C6-H-09
        assert "TLS" not in output or "intact" in output, (  # FIX: C6-H-09
            f"Unexpected TLS violation for hardened config.\nOutput:\n{output}"  # FIX: C6-H-09
        )

    def test_mixed_tls13_and_tls12_fails_with_older_version(  # FIX: C6-H-09
        self, tls_yml_conf
    ) -> None:  # FIX: C6-H-09
        """ssl_protocols TLSv1.3 TLSv1.2; must trigger older-version violation."""  # FIX: C6-H-09
        path = tls_yml_conf("ssl_protocols TLSv1.3 TLSv1.2;\n")  # FIX: C6-H-09
        rc, output = _run_hook(path)  # FIX: C6-H-09
        assert rc == 1, f"Expected FAIL but got exit {rc}.\nOutput:\n{output}"  # FIX: C6-H-09
        assert "older version" in output, (  # FIX: C6-H-09
            f"Expected older-version message.\nGot:\n{output}"  # FIX: C6-H-09
        )

    def test_tls1_bare_fails_with_older_version(self, tls_yml_conf) -> None:  # FIX: C6-H-09
        """ssl_protocols TLSv1; (bare TLSv1) must trigger older-version violation."""  # FIX: C6-H-09
        path = tls_yml_conf("ssl_protocols TLSv1;\n")  # FIX: C6-H-09
        rc, output = _run_hook(path)  # FIX: C6-H-09
        assert rc == 1, f"Expected FAIL but got exit {rc}.\nOutput:\n{output}"  # FIX: C6-H-09
        assert "older version" in output, (  # FIX: C6-H-09
            f"Expected older-version message.\nGot:\n{output}"  # FIX: C6-H-09
        )


class TestTLSPositiveVerification:  # FIX: C6-H-09
    """Positive verification: TLS keyword present but TLSv1.3 absent must trigger distinct violation."""  # FIX: C6-H-09

    def test_empty_ssl_protocols_fails_with_must_configure(  # FIX: C6-H-09
        self, tls_nginx_conf
    ) -> None:  # FIX: C6-H-09
        """ssl_protocols ; (empty) must trigger must-configure, not older-version."""  # FIX: C6-H-09
        path = tls_nginx_conf("ssl_protocols ;\n")  # FIX: C6-H-09
        rc, output = _run_hook(path)  # FIX: C6-H-09
        assert rc == 1, f"Expected FAIL but got exit {rc}.\nOutput:\n{output}"  # FIX: C6-H-09
        assert "must be explicitly configured" in output, (  # FIX: C6-H-09
            f"Expected must-configure message.\nGot:\n{output}"  # FIX: C6-H-09
        )
        assert "older version" not in output, (  # FIX: C6-H-09
            f"Expected no older-version message for empty ssl_protocols.\nGot:\n{output}"  # FIX: C6-H-09
        )

    def test_older_only_fails_with_both_violations(self, tls_yml_conf) -> None:  # FIX: C6-H-09
        """ssl_protocols TLSv1; triggers BOTH older-version AND must-configure violations."""  # FIX: C6-H-09
        path = tls_yml_conf("ssl_protocols TLSv1;\n")  # FIX: C6-H-09
        rc, output = _run_hook(path)  # FIX: C6-H-09
        assert rc == 1, f"Expected FAIL but got exit {rc}.\nOutput:\n{output}"  # FIX: C6-H-09
        assert "older version" in output, (  # FIX: C6-H-09
            f"Missing older-version message.\nGot:\n{output}"  # FIX: C6-H-09
        )
        assert "must be explicitly configured" in output, (  # FIX: C6-H-09
            f"Missing must-configure message.\nGot:\n{output}"  # FIX: C6-H-09
        )


class TestTLSNoTrigger:  # FIX: C6-H-09
    """Files that should not trigger the TLS check at all."""  # FIX: C6-H-09

    def test_comment_only_tls_notes_passes(self, compose_conf) -> None:  # FIX: C6-H-09
        """File with only # TLS notes passes: trigger pattern does NOT match TLS alone."""  # FIX: C6-H-09
        path = compose_conf("# TLS notes\nservices:\n  app:\n    image: myapp\n")  # FIX: C6-H-09
        rc, output = _run_hook(path)  # FIX: C6-H-09
        assert rc == 0, (  # FIX: C6-H-09
            f"Expected PASS for comment-only TLS file but got exit {rc}.\nOutput:\n{output}"  # FIX: C6-H-09
        )

    def test_no_tls_keywords_passes(self, tls_yml_conf) -> None:  # FIX: C6-H-09
        """File with no TLS keywords at all must pass without triggering TLS block."""  # FIX: C6-H-09
        path = tls_yml_conf("server:\n  listen: 80\n  host: 127.0.0.1\n")  # FIX: C6-H-09
        rc, output = _run_hook(path)  # FIX: C6-H-09
        assert rc == 0, (  # FIX: C6-H-09
            f"Expected PASS for file with no TLS keywords but got exit {rc}.\nOutput:\n{output}"  # FIX: C6-H-09
        )
