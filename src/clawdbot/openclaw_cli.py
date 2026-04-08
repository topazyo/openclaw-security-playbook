"""Console-script wrapper for the repo-local OpenClaw CLI.

This entrypoint supports editable installs and source checkouts by locating the
repository root and dispatching to ``tools/openclaw-cli.py``.
"""

import importlib.util
import sys
from pathlib import Path


def _find_repo_root() -> Path:
    current_path = Path(__file__).resolve()
    for parent in current_path.parents:
        if (parent / "tools" / "openclaw-cli.py").exists() and (parent / "README.md").exists():
            return parent

    raise RuntimeError(
        "openclaw-cli requires a source checkout or editable install because it "
        "dispatches to repo-local tooling under tools/ and scripts/."
    )


def _load_cli_module(repo_root: Path):
    cli_module_path = repo_root / "tools" / "openclaw-cli.py"
    repo_root_str = str(repo_root)
    if repo_root_str not in sys.path:
        sys.path.insert(0, repo_root_str)

    spec = importlib.util.spec_from_file_location("openclaw_cli_tool", cli_module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load OpenClaw CLI module from {cli_module_path}")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int | None:
    """Run the repo-local OpenClaw CLI through the packaged console entrypoint."""
    repo_root = _find_repo_root()
    cli_module = _load_cli_module(repo_root)
    return cli_module.cli()
