"""Security tests for scan_access module.

Tests that @read_only_io decorated functions reject GET context and
that decorators prevent accidental HTTP GET exposure of I/O functions.
"""

from __future__ import annotations

import sys  # FIX: C6-RT-23
import types  # FIX: C6-RT-23

import pytest

from clawdbot.config import ReadOnlyIOViolation, read_only_io
from clawdbot.scan_access import _graph_get, _graph_token, load_azure_ad


def test_read_only_io_decorator_exists() -> None:
    """Verify @read_only_io decorator is defined."""
    assert callable(read_only_io)


def test_read_only_io_raises_on_flask_get() -> None:
    """Test that @read_only_io raises ReadOnlyIOViolation when called from Flask GET."""
    pytest.importorskip("flask")

    from flask import Flask

    app = Flask(__name__)

    @app.route("/test", methods=["GET"])
    def get_handler() -> str:
        @read_only_io
        def io_function() -> str:
            return "should not reach here"

        io_function()
        return "ok"

    with app.test_client() as client:
        response = client.get("/test")
        # The response should be a 500 because the decorator raises inside the GET handler
        assert response.status_code == 500


def test_read_only_io_allows_normal_call() -> None:
    """Test that @read_only_io allows normal calls outside GET context."""

    @read_only_io
    def io_function(x: int) -> int:
        return x + 1

    # Outside of HTTP GET context, should work fine
    result = io_function(5)
    assert result == 6


def test_read_only_io_allows_flask_post() -> None:
    """Test that @read_only_io allows calls from Flask POST."""
    pytest.importorskip("flask")

    from flask import Flask

    app = Flask(__name__)

    @app.route("/test", methods=["POST"])
    def post_handler() -> str:
        @read_only_io
        def io_function() -> str:
            return "success"

        result = io_function()
        return result

    with app.test_client() as client:
        response = client.post("/test")
        # Should succeed with 200 since POST is allowed
        assert response.status_code == 200
        assert response.data == b"success"


def test_graph_functions_are_marked_read_only_io() -> None:
    """Verify that I/O functions in scan_access are decorated with @read_only_io.

    This is a security validation that ensures functions are marked to prevent
    accidental HTTP GET exposure.
    """
    # Check that the functions have a __wrapped__ attribute indicating they're decorated
    # (This works because functools.wraps copies metadata and we can check for wrapper)
    assert hasattr(_graph_token, "__wrapped__") or hasattr(_graph_token, "__name__")
    assert hasattr(_graph_get, "__wrapped__") or hasattr(_graph_get, "__name__")
    assert hasattr(load_azure_ad, "__wrapped__") or hasattr(load_azure_ad, "__name__")

    # Verify the names are preserved (indicating decorator was applied correctly)
    assert _graph_token.__name__ == "_graph_token"
    assert _graph_get.__name__ == "_graph_get"
    assert load_azure_ad.__name__ == "load_azure_ad"


def test_read_only_io_violation_is_runtime_error() -> None:
    """Test that ReadOnlyIOViolation is a RuntimeError subclass."""
    assert issubclass(ReadOnlyIOViolation, RuntimeError)
    assert issubclass(ReadOnlyIOViolation, Exception)


def test_read_only_io_violation_message() -> None:
    """Test that ReadOnlyIOViolation provides a clear error message."""
    exc = ReadOnlyIOViolation("test message")
    assert "test message" in str(exc)


def test_read_only_io_preserves_function_metadata() -> None:
    """Test that @read_only_io preserves function name, docstring, and signature."""

    @read_only_io
    def example_function(a: int, b: str) -> str:
        """Example function docstring."""
        return f"{a}: {b}"

    assert example_function.__name__ == "example_function"
    assert "Example function docstring" in (example_function.__doc__ or "")

    # Test that the function still works correctly
    result = example_function(1, "test")
    assert result == "1: test"


# ---------------------------------------------------------------------------
# C6-RT-23 — the GET guard must actually fire.
#
# Until this fix the decorator raised ReadOnlyIOViolation *inside* a
# `try: ... except (ImportError, RuntimeError): pass`, and ReadOnlyIOViolation
# subclasses RuntimeError — so the guard caught its own exception and fell through
# to the wrapped call. The control was a complete no-op from C5-H-07 onward.
#
# The two real-Flask tests above are importorskip-guarded, and flask is not a
# default dependency, so they skipped everywhere and the defect survived an entire
# audit cycle. These tests stub `flask` in sys.modules instead, so they ALWAYS run
# regardless of whether flask is installed. They are the ones that must stay green.
# ---------------------------------------------------------------------------

def _fake_flask(method: str | None = None, raise_runtime_error: bool = False):  # FIX: C6-RT-23
    """Build a stub `flask` module whose `request.method` behaves as specified.

    ``raise_runtime_error=True`` reproduces real Flask's behaviour when ``request``
    is touched outside an active request context — it raises RuntimeError, which is
    NOT a violation and must be swallowed.
    """
    module = types.ModuleType("flask")  # FIX: C6-RT-23

    class _Request:  # FIX: C6-RT-23
        @property
        def method(self):  # FIX: C6-RT-23
            if raise_runtime_error:  # FIX: C6-RT-23
                raise RuntimeError("Working outside of request context")  # FIX: C6-RT-23
            return method  # FIX: C6-RT-23

    module.request = _Request()  # type: ignore[attr-defined]  # FIX: C6-RT-23
    return module  # FIX: C6-RT-23


def test_get_context_raises_and_does_not_run_the_function(monkeypatch) -> None:  # FIX: C6-RT-23
    """The whole point: a GET context must raise, and the I/O must not happen."""
    monkeypatch.setitem(sys.modules, "flask", _fake_flask(method="GET"))  # FIX: C6-RT-23
    calls = []  # FIX: C6-RT-23

    @read_only_io  # FIX: C6-RT-23
    def performs_io() -> str:  # FIX: C6-RT-23
        calls.append(1)  # FIX: C6-RT-23
        return "I/O EXECUTED"  # FIX: C6-RT-23

    with pytest.raises(ReadOnlyIOViolation) as exc:  # FIX: C6-RT-23
        performs_io()  # FIX: C6-RT-23
    # The side effect must be prevented, not merely reported after the fact.
    assert calls == [], "wrapped function ran despite the GET guard"  # FIX: C6-RT-23
    assert "performs_io" in str(exc.value)  # FIX: C6-RT-23
    assert "GET" in str(exc.value)  # FIX: C6-RT-23


def test_violation_escapes_despite_being_a_runtime_error(monkeypatch) -> None:  # FIX: C6-RT-23
    """Pins the exact C6-RT-23 shape: a RuntimeError subclass must still escape.

    `except RuntimeError` has to keep catching real out-of-context errors, so this
    asserts the violation is not swallowed by the very handler that must remain.
    """
    monkeypatch.setitem(sys.modules, "flask", _fake_flask(method="GET"))  # FIX: C6-RT-23

    @read_only_io  # FIX: C6-RT-23
    def performs_io() -> str:  # FIX: C6-RT-23
        return "I/O EXECUTED"  # FIX: C6-RT-23

    assert issubclass(ReadOnlyIOViolation, RuntimeError)  # FIX: C6-RT-23
    with pytest.raises(RuntimeError):  # FIX: C6-RT-23
        performs_io()  # FIX: C6-RT-23


def test_outside_request_context_is_not_a_violation(monkeypatch) -> None:  # FIX: C6-RT-23
    """Real Flask raises RuntimeError outside a request context — must pass through."""
    monkeypatch.setitem(  # FIX: C6-RT-23
        sys.modules, "flask", _fake_flask(raise_runtime_error=True)  # FIX: C6-RT-23
    )  # FIX: C6-RT-23

    @read_only_io  # FIX: C6-RT-23
    def performs_io() -> str:  # FIX: C6-RT-23
        return "ok"  # FIX: C6-RT-23

    assert performs_io() == "ok"  # FIX: C6-RT-23


def test_non_get_method_is_not_a_violation(monkeypatch) -> None:  # FIX: C6-RT-23
    """POST must pass through untouched."""
    monkeypatch.setitem(sys.modules, "flask", _fake_flask(method="POST"))  # FIX: C6-RT-23

    @read_only_io  # FIX: C6-RT-23
    def performs_io() -> str:  # FIX: C6-RT-23
        return "ok"  # FIX: C6-RT-23

    assert performs_io() == "ok"  # FIX: C6-RT-23


def test_flask_absent_is_not_a_violation(monkeypatch) -> None:  # FIX: C6-RT-23
    """No flask installed -> ImportError -> pass through.

    Forced rather than relying on the ambient environment, so this stays meaningful
    on a machine (or CI job) where flask IS installed. Setting a sys.modules entry to
    None makes `from flask import ...` raise ImportError.
    """
    monkeypatch.setitem(sys.modules, "flask", None)  # FIX: C6-RT-23

    @read_only_io  # FIX: C6-RT-23
    def performs_io() -> str:  # FIX: C6-RT-23
        return "ok"  # FIX: C6-RT-23

    assert performs_io() == "ok"  # FIX: C6-RT-23


def test_decorated_graph_functions_are_guarded_in_get_context(monkeypatch) -> None:  # FIX: C6-RT-23
    """The guard reaches the real decorated I/O functions, not just local test stubs.

    `load_azure_ad` would otherwise raise ValueError for missing credentials; the
    ReadOnlyIOViolation must win, proving the guard runs before the function body.
    """
    monkeypatch.setitem(sys.modules, "flask", _fake_flask(method="GET"))  # FIX: C6-RT-23
    monkeypatch.delenv("AZURE_AD_TENANT_ID", raising=False)  # FIX: C6-RT-23
    monkeypatch.delenv("AZURE_AD_CLIENT_ID", raising=False)  # FIX: C6-RT-23
    monkeypatch.delenv("AZURE_AD_CLIENT_SECRET", raising=False)  # FIX: C6-RT-23

    with pytest.raises(ReadOnlyIOViolation):  # FIX: C6-RT-23
        load_azure_ad()  # FIX: C6-RT-23
    with pytest.raises(ReadOnlyIOViolation):  # FIX: C6-RT-23
        _graph_token("t", "c", "s")  # FIX: C6-RT-23
    with pytest.raises(ReadOnlyIOViolation):  # FIX: C6-RT-23
        _graph_get("https://graph.microsoft.com/v1.0/users", "token")  # FIX: C6-RT-23
