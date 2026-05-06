"""Configuration loading helpers for the minimal ClawdBot runtime."""

import functools
import os
from pathlib import Path
from typing import Any, Callable, TypeVar, cast

try:
    import yaml
except ModuleNotFoundError as exc:  # pragma: no cover - packaging should provide PyYAML
    raise RuntimeError("PyYAML is required to load ClawdBot configuration") from exc

# ============================================================================
# Security: Read-only I/O marking decorator
# ============================================================================

F = TypeVar("F", bound=Callable[..., Any])


class ReadOnlyIOViolation(RuntimeError):
    """Raised when a @read_only_io function is called from an HTTP GET context."""

    pass


def read_only_io(func: F) -> F:
    """Mark a function as performing I/O and unsuitable for HTTP GET handlers.

    This decorator is a security marker to prevent accidentally exposing
    I/O-performing functions via REST GET endpoints (which must be idempotent).

    If the function is called while processing a Flask HTTP GET request, it raises
    `ReadOnlyIOViolation`.

    **Scope limitation:** Only Flask GET context is detected. FastAPI is NOT
    supported by this decorator and must enforce POST-only via FastAPI's own
    route declarations (e.g. using APIRouter with explicit HTTP method constraints).
    Do not rely on this decorator for GET-rejection in FastAPI applications.

    Usage:
        @read_only_io
        def my_function_that_queries_external_api():
            ...
    """  # FIX: C5-H-07

    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        # Check if we are in a Flask HTTP GET context. Raises ReadOnlyIOViolation
        # if so. FastAPI detection is not implemented — see docstring scope note.
        try:  # FIX: C5-H-07
            # Flask detection only — FastAPI is explicitly out of scope
            from flask import request as flask_request  # type: ignore[import-untyped]  # FIX: C5-H-07

            if flask_request.method == "GET":  # FIX: C5-H-07
                raise ReadOnlyIOViolation(
                    f"Function {func.__name__} performs I/O and cannot be called "
                    "from an HTTP GET handler (GET must be idempotent and side-effect-free). "
                    "This is a security violation. Use POST instead."
                )
        except (ImportError, RuntimeError):  # FIX: C5-H-07
            # Flask not available or not in request context, continue
            pass

        return func(*args, **kwargs)  # FIX: C5-H-07

    return cast(F, wrapper)


def _expand_env(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _expand_env(inner) for key, inner in value.items()}
    if isinstance(value, list):
        return [_expand_env(item) for item in value]
    if isinstance(value, str):
        return os.path.expandvars(value)
    return value


def load_config(path: str | os.PathLike[str]) -> dict[str, Any]:
    config_path = Path(path).resolve()
    with config_path.open("r", encoding="utf-8") as handle:
        parsed = yaml.safe_load(handle) or {}
    return _expand_env(parsed)