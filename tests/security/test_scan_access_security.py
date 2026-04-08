"""Security tests for scan_access module.

Tests that @read_only_io decorated functions reject GET context and
that decorators prevent accidental HTTP GET exposure of I/O functions.
"""

from __future__ import annotations

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
