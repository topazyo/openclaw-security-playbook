"""C6-M-17 regression tests — restore_skill origin-ledger hardening.

Claim (issue #123):
  restore_skill must restore a quarantined skill to the location captured at
  quarantine time, recorded SEPARATELY from the (tamperable) QUARANTINE_INFO.txt.
  A rewritten QUARANTINE_INFO.txt must NOT be able to redirect the restore, an
  untracked quarantine must fail closed unless ALLOW_UNTRACKED_RESTORE=1, and a
  symlink swapped into the target's parent between quarantine and restore must
  be rejected.

These drive the real bash functions (quarantine_skill / restore_skill) by sourcing
scripts/supply-chain/skill_integrity_monitor.sh with its `main` dispatch suppressed,
inside an isolated sandbox (QUARANTINE_DIR / QUARANTINE_ORIGINS_DIR / OPENCLAW_LOGS
overridden). Mirrors the bash-mount-path handling used by test_cycle5_claim_regressions.
"""
import os
import shutil
import subprocess
import sys
import tempfile
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


def _can_make_resolvable_symlink() -> bool:
    """True iff this platform can create a symlink that realpath resolves
    (Windows/MSYS without Developer Mode cannot — the symlink case is skipped there)."""
    try:
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "target"
            link = Path(d) / "link"
            target.mkdir()
            os.symlink(target, link)
            return Path(os.path.realpath(link)) == target.resolve()
    except (OSError, NotImplementedError):
        return False


_CAN_SYMLINK = _can_make_resolvable_symlink()

# Bash driver: sources the monitor script (main suppressed), isolates the quarantine
# + origin-ledger dirs into the sandbox, then runs one named scenario and prints
# RC= plus scenario markers and the audit log.
_DRIVER = r'''
SCRIPT="$1"; SB="$2"; SCEN="$3"
export OPENCLAW_LOGS="$SB/logs"
mkdir -p "$SB/logs" "$SB/q" "$SB/origins" "$SB/skills"
# Sourcing defines the functions without running main (BASH_SOURCE guard in the script),
# so no sed-based suppression is needed.
# shellcheck disable=SC1090
source "$SCRIPT"
## FIX: C6-RT-11: pin "driver failed to source the script" (restore_skill undefined) as a loud,
## attributable error instead of a downstream "restore_skill: command not found" — distinguishes
## that failure mode from path-mangling. Runs before `set +e`; the `||` keeps errexit from aborting.
declare -f restore_skill >/dev/null 2>&1 || { echo "DRIVER_ERROR: restore_skill undefined after sourcing $SCRIPT (scenario=$SCEN)" >&2; exit 4; }  ## FIX: C6-RT-11
# errexit OFF: restore_skill returns non-zero on every rejection path and we capture $?
# (with -e on, `restore_skill ...; echo "RC=$?"` would abort before the echo). nounset and
# pipefail stay ON so unset-var bugs and pipe failures in the driver surface attributably.
set +e
QUARANTINE_DIR="$SB/q"
QUARANTINE_ORIGINS_DIR="$SB/origins"
# Fail loudly (and attributably) if no quarantine id matches, rather than silently using "".
_grep_qid() {
    local id
    id=$(ls -1 "$SB/q" | grep -F "$1" | head -n1)
    [ -n "$id" ] || { echo "DRIVER_ERROR: no quarantine id matching '$1' (scenario=$SCEN)" >&2; exit 3; }
    printf '%s\n' "$id"
}

case "$SCEN" in
  tracked)
    mkdir -p "$SB/skills/sk one"; echo d > "$SB/skills/sk one/f"
    quarantine_skill "$SB/skills/sk one" t >/dev/null 2>&1
    qid=$(_grep_qid "sk one")
    restore_skill "$qid" >/dev/null 2>&1; echo "RC=$?"
    [ -f "$SB/skills/sk one/f" ] && echo "RESTORED=yes" || echo "RESTORED=no" ;;
  tamper)
    mkdir -p "$SB/skills/tsk"; echo d > "$SB/skills/tsk/f"
    quarantine_skill "$SB/skills/tsk" t >/dev/null 2>&1
    qid=$(_grep_qid "tsk")
    printf 'Original Path: %s\n' "$SB/evil" > "$SB/q/$qid/QUARANTINE_INFO.txt"
    restore_skill "$qid" >/dev/null 2>&1; echo "RC=$?"
    [ -e "$SB/evil" ] && echo "EVIL=created" || echo "EVIL=absent"
    [ -d "$SB/q/$qid" ] && echo "QDIR=intact" || echo "QDIR=gone" ;;
  untracked)
    mkdir -p "$SB/skills/usk"; echo d > "$SB/skills/usk/f"
    quarantine_skill "$SB/skills/usk" t >/dev/null 2>&1
    qid=$(_grep_qid "usk"); rm -f "$SB/origins/$qid"
    restore_skill "$qid" >/dev/null 2>&1; echo "RC=$?" ;;
  untracked_flag)
    mkdir -p "$SB/skills/ufsk"; echo d > "$SB/skills/ufsk/f"
    quarantine_skill "$SB/skills/ufsk" t >/dev/null 2>&1
    qid=$(_grep_qid "ufsk"); rm -f "$SB/origins/$qid"
    ALLOW_UNTRACKED_RESTORE=1 restore_skill "$qid" >/dev/null 2>&1; echo "RC=$?"
    [ -f "$SB/skills/ufsk/f" ] && echo "RESTORED=yes" || echo "RESTORED=no" ;;
  symlink)
    mkdir -p "$SB/skills/realdir/ssk"; echo d > "$SB/skills/realdir/ssk/f"
    quarantine_skill "$SB/skills/realdir/ssk" t >/dev/null 2>&1
    qid=$(_grep_qid "ssk")
    rm -rf "$SB/skills/realdir"; mkdir -p "$SB/evil2"; ln -s "$SB/evil2" "$SB/skills/realdir"
    restore_skill "$qid" >/dev/null 2>&1; echo "RC=$?"
    [ -e "$SB/evil2/ssk" ] && echo "EVIL=landed" || echo "EVIL=clean" ;;
  invalid_id)
    restore_skill "../../escape" >/dev/null 2>&1; echo "RC_slash=$?"
    restore_skill ".." >/dev/null 2>&1; echo "RC_dotdot=$?" ;;
  empty_record)
    mkdir -p "$SB/skills/esk"; echo d > "$SB/skills/esk/f"
    quarantine_skill "$SB/skills/esk" t >/dev/null 2>&1
    qid=$(_grep_qid "esk"); : > "$SB/origins/$qid"   # truncate the ledger to empty
    restore_skill "$qid" >/dev/null 2>&1; echo "RC=$?" ;;
  parent_missing)
    mkdir -p "$SB/skills/realp/psk"; echo d > "$SB/skills/realp/psk/f"
    quarantine_skill "$SB/skills/realp/psk" t >/dev/null 2>&1
    qid=$(_grep_qid "psk"); rm -rf "$SB/skills/realp"   # remove the recorded target's parent
    restore_skill "$qid" >/dev/null 2>&1; echo "RC=$?" ;;
esac
echo "AUDIT<<"; cat "$SB/logs/skill_audit.log" 2>/dev/null; echo ">>AUDIT"
'''


def _run(scenario: str, tmp_path: Path) -> str:
    assert _BASH_PATH, "bash is required for these tests"
    sandbox = tmp_path / "sb"
    sandbox.mkdir()
    out = subprocess.run(
        [
            _BASH_PATH, "-c", _DRIVER, "driver",
            _to_bash_path(_MONITOR_SCRIPT, _BASH_PATH),
            _to_bash_path(sandbox, _BASH_PATH),
            scenario,
        ],
        capture_output=True, text=True, check=False, timeout=60,
    )
    return out.stdout + out.stderr


pytestmark = pytest.mark.skipif(_BASH_PATH is None, reason="bash not available")


def test_tracked_roundtrip_with_spaces_restores_to_origin(tmp_path):
    """Happy path (incl. spaces / M-06 invariant): a tracked quarantine restores."""
    out = _run("tracked", tmp_path)
    assert "RC=0" in out, out
    assert "RESTORED=yes" in out, out


def test_tampered_quarantine_info_is_rejected(tmp_path):
    """A rewritten Original Path that disagrees with the recorded origin -> reject, no mv."""
    out = _run("tamper", tmp_path)
    assert "RC=1" in out, out
    assert "EVIL=absent" in out, out          # mv did not follow the tampered path
    assert "QDIR=intact" in out, out          # quarantine not consumed
    assert "reason=tamper" in out, out


def test_untracked_quarantine_fails_closed_by_default(tmp_path):
    """No origin record -> refuse by default."""
    out = _run("untracked", tmp_path)
    assert "RC=1" in out, out
    assert "reason=untracked" in out, out


def test_untracked_with_optout_flag_restores(tmp_path):
    """ALLOW_UNTRACKED_RESTORE=1 falls back to QUARANTINE_INFO + shape checks."""
    out = _run("untracked_flag", tmp_path)
    assert "RC=0" in out, out
    assert "RESTORED=yes" in out, out


@pytest.mark.skipif(not _CAN_SYMLINK, reason="platform cannot create resolvable symlinks")
def test_symlink_swapped_parent_is_rejected(tmp_path):
    """A symlink swapped into the target's parent after quarantine -> reject, nothing escapes."""
    out = _run("symlink", tmp_path)
    assert "RC=1" in out, out
    assert "EVIL=clean" in out, out
    assert "reason=parent_symlink" in out, out


def test_path_traversal_quarantine_id_is_rejected(tmp_path):
    """A --restore id containing '/' or '..' is rejected before any path is built or rm-ed."""
    out = _run("invalid_id", tmp_path)
    assert "RC_slash=1" in out, out
    assert "RC_dotdot=1" in out, out
    assert "reason=invalid_id" in out, out


def test_empty_origin_record_is_rejected(tmp_path):
    """A present-but-empty origin ledger -> reject (cannot trust an empty authoritative path)."""
    out = _run("empty_record", tmp_path)
    assert "RC=1" in out, out
    assert "reason=empty_origin_record" in out, out


def test_missing_target_parent_is_rejected(tmp_path):
    """Recorded target's parent removed before restore -> reject (no mv into a vanished tree)."""
    out = _run("parent_missing", tmp_path)
    assert "RC=1" in out, out
    assert "reason=parent_missing" in out, out
