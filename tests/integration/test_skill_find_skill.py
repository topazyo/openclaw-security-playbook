"""C6-RT-06 regression tests — fail-closed `--find-skill` in skill_integrity_monitor.sh.

Claim: the skill-compromise playbook advertises
  `skill_integrity_monitor.sh --find-skill <skill> --output affected-agents.json`.
That command must be a real, accepted option, but since mapping a skill to the agents
that have it installed requires an EXTERNAL agent->skill inventory (not available to this
repo-local monitor), `find_skill` must FAIL CLOSED: return non-zero, write no output file,
and surface the documented contract — never fabricate an affected_agents list.

These drive the real bash `find_skill` function by sourcing the monitor script with its
`main` dispatch suppressed (BASH_SOURCE guard), inside an isolated sandbox. Mirrors the
bash-mount-path handling used by test_skill_restore_origin.py.
"""
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
_MONITOR_SCRIPT = _REPO_ROOT / "scripts" / "supply-chain" / "skill_integrity_monitor.sh"
_BASH_PATH = shutil.which("bash")


def _detect_bash_mount_root(bash_path: str | None) -> str:
    """WSL mounts C: at /mnt/c; Git Bash / MSYS / Cygwin mount it at /c."""
    if not bash_path:
        return "/mnt/"
    try:
        proc = subprocess.run(
            [bash_path, "--version"], capture_output=True, text=True, check=False, timeout=5
        )
    except (OSError, subprocess.SubprocessError):
        return "/mnt/"
    banner = (proc.stdout + proc.stderr).lower()
    if "cygwin" in banner or "msys" in banner or "mingw" in banner:
        return "/"
    return "/mnt/"


def _to_bash_path(path: Path, bash_path: str | None = None) -> str:
    """Convert an absolute path to the bash mount path for this flavor."""
    if sys.platform != "win32":
        return path.as_posix()
    drive_letter = path.drive.rstrip(":").lower()
    rest = path.as_posix()[len(path.drive):]
    return f"{_detect_bash_mount_root(bash_path)}{drive_letter}{rest}"


# Driver: source the monitor (main suppressed), isolate OPENCLAW_LOGS into the sandbox, then
# call find_skill directly and report RC, whether an output file was (wrongly) written, and the message.
_FIND_SKILL_DRIVER = r'''
SCRIPT="$1"; SB="$2"
export OPENCLAW_LOGS="$SB/logs"
mkdir -p "$SB/logs"
# shellcheck disable=SC1090
source "$SCRIPT"
set +e   # find_skill returns non-zero on the fail-closed path; capture $? rather than abort (errexit was set by the sourced script)
OUT="$SB/affected-agents.json"
find_skill "@attacker/credential-stealer" "$OUT" >"$SB/out.txt" 2>&1
echo "RC=$?"
[ -f "$OUT" ] && echo "OUTFILE=created" || echo "OUTFILE=absent"
echo "MSG<<"; cat "$SB/out.txt" 2>/dev/null; echo ">>MSG"
'''


def _run_find_skill(tmp_path: Path) -> str:
    assert _BASH_PATH, "bash is required for these tests"
    sandbox = tmp_path / "sb"
    sandbox.mkdir()
    out = subprocess.run(
        [
            _BASH_PATH, "-c", _FIND_SKILL_DRIVER, "driver",
            _to_bash_path(_MONITOR_SCRIPT, _BASH_PATH),
            _to_bash_path(sandbox, _BASH_PATH),
        ],
        capture_output=True, text=True, check=False, timeout=60,
    )
    return out.stdout + out.stderr


pytestmark = pytest.mark.skipif(_BASH_PATH is None, reason="bash not available")


def test_find_skill_fails_closed_and_writes_nothing(tmp_path):
    """find_skill must refuse to fabricate affected agents: non-zero, no output file, documented contract."""
    out = _run_find_skill(tmp_path)
    assert "RC=1" in out, out                 # fail closed (non-zero)
    assert "OUTFILE=absent" in out, out        # no fabricated affected-agents.json written
    low = out.lower()
    assert "not wired" in low, out             # documented contract surfaced
    assert "refusing to fabricate" in low, out


def test_help_lists_find_skill(tmp_path):
    """--find-skill is a documented option (and --help is handled before initialize)."""
    assert _BASH_PATH, "bash is required for these tests"
    proc = subprocess.run(
        [_BASH_PATH, _to_bash_path(_MONITOR_SCRIPT, _BASH_PATH), "--help"],
        capture_output=True, text=True, check=False, timeout=30,
    )
    combined = proc.stdout + proc.stderr
    assert proc.returncode == 0, combined
    assert "--find-skill" in combined, combined
