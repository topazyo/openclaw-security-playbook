"""Configuration loading helpers for the minimal ClawdBot runtime."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

try:
    import yaml
except ModuleNotFoundError as exc:  # pragma: no cover - packaging should provide PyYAML
    raise RuntimeError("PyYAML is required to load ClawdBot configuration") from exc


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