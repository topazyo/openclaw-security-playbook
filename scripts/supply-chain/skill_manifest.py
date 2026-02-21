#!/usr/bin/env python3
"""
Skill Integrity Manifest Generation and Validation

================================================================================
IMPORTANT: This script focuses on SUPPLY CHAIN SECURITY
================================================================================

This script handles Layer 5 (Supply Chain Integrity) of the defense-in-depth
model. For other security layers, consider these community tools:

RUNTIME SECURITY (Layer 4):
• openclaw-shield: https://github.com/knostic/openclaw-shield
  5-layer runtime security enforcement including tool blocking and PII redaction

BEHAVIORAL MONITORING (Layer 6):
• openclaw-telemetry: https://github.com/knostic/openclaw-telemetry
  Enterprise-grade logging with SIEM integration and tamper-proof audit trails

SHADOW AI DISCOVERY (Layer 7):
• openclaw-detect: https://github.com/knostic/openclaw-detect
  MDM-deployable scripts for discovering unauthorized AI agent installations

USE THIS SCRIPT FOR:
✓ Generating cryptographic manifests of installed skills
✓ Daily integrity checking to detect skill tampering
✓ Scanning for dangerous code patterns (eval, exec, innerHTML)
✓ Supply chain security and skill version tracking

INTEGRATION WITH COMMUNITY TOOLS:
This script complements openclaw-shield (which blocks dangerous tools at
runtime) by detecting when skills themselves are modified or compromised.

See: docs/guides/05-supply-chain-security.md
See: docs/guides/07-community-tools-integration.md

================================================================================
"""

import argparse
import hashlib
import json
import os
import re
import sys
import unicodedata
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

try:
    import fcntl
except ModuleNotFoundError:
    fcntl = None

try:
    import msvcrt
except ModuleNotFoundError:
    msvcrt = None


class SkillManifest:
    """
    Generate and validate cryptographic manifests for AI agent skills.

    Detects:
    - Skill file modifications (SHA256 hash comparison)
    - Dangerous code patterns (eval, exec, innerHTML)
    - New skill installations
    - Skill deletions
    """

    DANGEROUS_PATTERNS = [
        {
            "pattern": r"\beval\s*\(",
            "severity": "CRITICAL",
            "description": "Dynamic code execution via eval()"
        },
        {
            "pattern": r"\bexec\s*\(",
            "severity": "CRITICAL",
            "description": "Command execution via exec()"
        },
        {
            "pattern": r"\bFunction\s*\(",
            "severity": "HIGH",
            "description": "Dynamic function creation"
        },
        {
            "pattern": r"\bimport\s*\(",
            "severity": "HIGH",
            "description": "Dynamic module import execution"
        },
        {
            "pattern": r"\bReflect\s*\.\s*(apply|construct)\s*\(",
            "severity": "HIGH",
            "description": "Indirect reflective code invocation"
        },
        {
            "pattern": r"\b(globalThis|window|self)\s*\[",
            "severity": "HIGH",
            "description": "Indirect global-object invocation"
        },
        {
            "pattern": r"\.innerHTML\s*=",
            "severity": "HIGH",
            "description": "XSS risk via innerHTML"
        },
        {
            "pattern": r"child_process\.exec",
            "severity": "CRITICAL",
            "description": "Node.js command execution"
        },
        {
            "pattern": r"os\.system",
            "severity": "CRITICAL",
            "description": "Python command execution"
        },
        {
            "pattern": r"subprocess\.(call|run|Popen)",
            "severity": "CRITICAL",
            "description": "Python subprocess execution"
        },
        {
            "pattern": r"fetch\([^)]*api.*key",
            "severity": "HIGH",
            "description": "Potential credential exfiltration"
        },
    ]

    def __init__(self, skills_dir: Path):
        """Initialize manifest generator for skills directory."""
        self.skills_dir = Path(skills_dir).expanduser()

        if not self.skills_dir.exists():
            raise ValueError(f"Skills directory not found: {self.skills_dir}")

    def generate_manifest(self) -> Dict[str, Any]:
        """
        Generate cryptographic manifest of all skills.

        Returns:
            Dict containing skill hashes, metadata, and security warnings
        """
        manifest = {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "skills_directory": str(self.skills_dir),
            "skills": {},
            "security_warnings": []
        }

        # Find all skill files
        skill_files = list(self.skills_dir.rglob("*.md")) + \
                     list(self.skills_dir.rglob("*.js")) + \
                     list(self.skills_dir.rglob("*.py"))

        for skill_file in skill_files:
            relative_path = skill_file.relative_to(self.skills_dir)

            # Generate SHA256 hash
            sha256_hash = self._hash_file(skill_file)

            # Extract metadata
            metadata = self._extract_metadata(skill_file)

            # Scan for dangerous patterns
            warnings = self._scan_dangerous_patterns(skill_file)

            manifest["skills"][str(relative_path)] = {
                "sha256": sha256_hash,
                "size_bytes": skill_file.stat().st_size,
                "modified_at": datetime.fromtimestamp(
                    skill_file.stat().st_mtime
                ).isoformat(),
                "metadata": metadata,
                "warnings": warnings
            }

            # Add to global warnings
            if warnings:
                manifest["security_warnings"].extend([
                    {
                        "skill": str(relative_path),
                        **warning
                    }
                    for warning in warnings
                ])

        return manifest

    def compare_manifests(self, baseline_path: Path, current_manifest: Dict[str, Any]) -> Dict[str, Any]:
        """
        Compare current manifest against baseline to detect changes.

        Args:
            baseline_path: Path to baseline manifest JSON
            current_manifest: Current manifest dict

        Returns:
            Dict containing detected changes
        """
        with open(baseline_path, 'r') as f:
            baseline = json.load(f)

        changes = {
            "baseline_date": baseline.get("generated_at"),
            "current_date": current_manifest.get("generated_at"),
            "added_skills": [],
            "removed_skills": [],
            "modified_skills": [],
            "new_warnings": []
        }

        baseline_skills = set(baseline.get("skills", {}).keys())
        current_skills = set(current_manifest.get("skills", {}).keys())

        # Detect added skills
        changes["added_skills"] = list(current_skills - baseline_skills)

        # Detect removed skills
        changes["removed_skills"] = list(baseline_skills - current_skills)

        # Detect modified skills
        for skill_path in baseline_skills & current_skills:
            baseline_hash = baseline["skills"][skill_path]["sha256"]
            current_hash = current_manifest["skills"][skill_path]["sha256"]

            if baseline_hash != current_hash:
                changes["modified_skills"].append({
                    "skill": skill_path,
                    "baseline_hash": baseline_hash,
                    "current_hash": current_hash,
                    "baseline_size": baseline["skills"][skill_path]["size_bytes"],
                    "current_size": current_manifest["skills"][skill_path]["size_bytes"]
                })

        # Detect new warnings
        baseline_warned = {w["skill"] for w in baseline.get("security_warnings", [])}
        current_warned = {w["skill"] for w in current_manifest.get("security_warnings", [])}

        new_warned = current_warned - baseline_warned
        if new_warned:
            changes["new_warnings"] = [
                w for w in current_manifest["security_warnings"]
                if w["skill"] in new_warned
            ]

        return changes

    def _hash_file(self, file_path: Path) -> str:
        """Calculate SHA256 hash of file contents."""
        sha256 = hashlib.sha256()

        with open(file_path, 'rb') as f:
            try:
                if fcntl is not None:
                    fcntl.flock(f.fileno(), fcntl.LOCK_SH)
                elif msvcrt is not None:
                    size = max(1, os.path.getsize(file_path))
                    msvcrt.locking(f.fileno(), msvcrt.LK_RLCK, size)
            except OSError:
                pass

            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)

            try:
                if fcntl is not None:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
                elif msvcrt is not None:
                    size = max(1, os.path.getsize(file_path))
                    msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, size)
            except OSError:
                pass

        return sha256.hexdigest()

    def _extract_metadata(self, file_path: Path) -> Dict[str, Any]:
        """Extract metadata from skill file."""
        metadata = {
            "name": file_path.stem,
            "extension": file_path.suffix
        }

        # Try to extract additional metadata from file content
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read(1024)  # First 1KB

                # Look for common metadata patterns
                version_match = re.search(r"version[:\s]+([\d\.]+)", content, re.IGNORECASE)
                if version_match:
                    metadata["version"] = version_match.group(1)

                author_match = re.search(r"author[:\s]+([^\n]+)", content, re.IGNORECASE)
                if author_match:
                    metadata["author"] = author_match.group(1).strip()

        except (UnicodeDecodeError, IOError):
            pass

        return metadata

    def _scan_dangerous_patterns(self, file_path: Path) -> List[Dict[str, Any]]:
        """Scan file for dangerous code patterns."""
        warnings = []

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = unicodedata.normalize("NFKC", f.read())

                for pattern_def in self.DANGEROUS_PATTERNS:
                    try:
                        matches = re.finditer(pattern_def["pattern"], content, re.IGNORECASE)
                    except re.error:
                        continue

                    for match in matches:
                        # Find line number
                        line_num = content[:match.start()].count('\n') + 1

                        warnings.append({
                            "severity": pattern_def["severity"],
                            "description": pattern_def["description"],
                            "line": line_num,
                            "matched_text": match.group(0)[:50]  # First 50 chars
                        })

        except (UnicodeDecodeError, IOError):
            pass

        return warnings


def main():
    parser = argparse.ArgumentParser(
        description="Generate and validate skill integrity manifests",
        epilog="""
Examples:
  # Generate baseline manifest
  %(prog)s --skills-dir ~/.openclaw/skills --output manifest_baseline.json

  # Compare against baseline
  %(prog)s --skills-dir ~/.openclaw/skills --compare manifest_baseline.json --output manifest_today.json

  # Daily monitoring (for cron jobs)
  %(prog)s --skills-dir ~/.openclaw/skills --compare manifest_baseline.json --alert-on-changes

For runtime security enforcement, see:
- openclaw-shield: https://github.com/knostic/openclaw-shield
- docs/guides/07-community-tools-integration.md
        """
    )

    parser.add_argument(
        "--skills-dir",
        type=Path,
        default=Path("~/.openclaw/skills"),
        help="Path to skills directory (default: ~/.openclaw/skills)"
    )

    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Output path for manifest JSON file"
    )

    parser.add_argument(
        "--compare",
        type=Path,
        help="Compare against baseline manifest and show changes"
    )

    parser.add_argument(
        "--alert-on-changes",
        action="store_true",
        help="Exit with status 1 if changes detected (for monitoring)"
    )

    args = parser.parse_args()

    try:
        # Generate current manifest
        generator = SkillManifest(args.skills_dir)
        current_manifest = generator.generate_manifest()

        # Save manifest
        with open(args.output, 'w') as f:
            json.dump(current_manifest, f, indent=2)

        print(f"✓ Manifest generated: {args.output}")
        print(f"  Skills found: {len(current_manifest['skills'])}")
        print(f"  Security warnings: {len(current_manifest['security_warnings'])}")

        # Display warnings
        if current_manifest["security_warnings"]:
            print("\n⚠ SECURITY WARNINGS:")
            for warning in current_manifest["security_warnings"]:
                print(f"  [{warning['severity']}] {warning['skill']}")
                print(f"    Line {warning['line']}: {warning['description']}")

        # Compare with baseline if requested
        if args.compare:
            changes = generator.compare_manifests(args.compare, current_manifest)

            has_changes = (
                changes["added_skills"] or
                changes["removed_skills"] or
                changes["modified_skills"] or
                changes["new_warnings"]
            )

            if has_changes:
                print("\n⚠ CHANGES DETECTED:")

                if changes["added_skills"]:
                    print(f"\n  Added skills ({len(changes['added_skills'])}):")
                    for skill in changes["added_skills"]:
                        print(f"    + {skill}")

                if changes["removed_skills"]:
                    print(f"\n  Removed skills ({len(changes['removed_skills'])}):")
                    for skill in changes["removed_skills"]:
                        print(f"    - {skill}")

                if changes["modified_skills"]:
                    print(f"\n  Modified skills ({len(changes['modified_skills'])}):")
                    for mod in changes["modified_skills"]:
                        print(f"    ✎ {mod['skill']}")
                        print(f"      Hash: {mod['baseline_hash'][:16]}... → {mod['current_hash'][:16]}...")

                if changes["new_warnings"]:
                    print(f"\n  New security warnings ({len(changes['new_warnings'])}):")
                    for warning in changes["new_warnings"]:
                        print(f"    ⚠ {warning['skill']}: {warning['description']}")

                if args.alert_on_changes:
                    sys.exit(1)
            else:
                print("\n✓ No changes detected")

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
