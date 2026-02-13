#!/usr/bin/env python3
"""
Custom Behavioral Anomaly Detection for OpenClaw Deployments

================================================================================
PRODUCTION ALTERNATIVE: openclaw-telemetry (Recommended)
================================================================================

For production deployments, consider using openclaw-telemetry instead:
https://github.com/knostic/openclaw-telemetry

openclaw-telemetry provides:
• Native OpenClaw plugin integration (zero configuration)
• Tamper-proof hash chains for audit log integrity
• SIEM forwarding via CEF/syslog (Splunk, ELK, QRadar)
• Automatic sensitive data redaction
• Enterprise-grade logging with log rotation
• Real-time alerting integration
• Community support and regular updates

USE THIS SCRIPT WHEN:
✓ You need custom detection logic beyond standard patterns
✓ You have organization-specific behavioral requirements
✓ You need to extend openclaw-telemetry with specialized detection
✓ You are learning behavioral analysis implementation

INTEGRATION APPROACH:
For best results, use openclaw-telemetry for comprehensive logging and
use this script to read from openclaw-telemetry's structured output:

    # Read from openclaw-telemetry JSONL output
    telemetry_path = "~/.openclaw/logs/telemetry.jsonl"
    detect_custom_anomalies(telemetry_path)

See: docs/guides/07-community-tools-integration.md#openclaw-telemetry

================================================================================
"""

import argparse
import datetime
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import List, Dict, Any, Optional


class AnomalyDetector:
    """
    Custom anomaly detection for AI agent behavioral analysis.

    Focuses on organization-specific patterns not covered by
    standard telemetry tools.
    """

    def __init__(self, work_hours: tuple = (9, 18), 
                 allowed_recipients: List[str] = None):
        """
        Initialize anomaly detector with organization-specific settings.

        Args:
            work_hours: Tuple of (start_hour, end_hour) for normal operation
            allowed_recipients: List of approved email domains
        """
        self.work_hours = work_hours
        self.allowed_recipients = allowed_recipients or ["company.com"]

        # Detection thresholds (customize for your environment)
        self.thresholds = {
            "burst_window_seconds": 60,
            "burst_max_tools": 10,
            "file_read_size_mb_threshold": 100,
            "suspicious_tool_sequence_length": 3
        }

        # Track state for sequence detection
        self.tool_sequence_buffer = []

    def detect_anomalies(self, log_entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Analyze log entries and return detected anomalies.

        Args:
            log_entries: List of log entry dicts from openclaw-telemetry or custom logs

        Returns:
            List of anomaly dicts with severity, reason, and recommendations
        """
        anomalies = []

        for entry in log_entries:
            # Off-hours execution
            anomalies.extend(self._check_off_hours(entry))

            # Suspicious tool sequences
            anomalies.extend(self._check_suspicious_sequences(entry))

            # Unusual recipients
            anomalies.extend(self._check_recipients(entry))

            # Large file operations
            anomalies.extend(self._check_file_operations(entry))

        # Burst activity detection (requires multiple entries)
        anomalies.extend(self._check_burst_activity(log_entries))

        return anomalies

    def _check_off_hours(self, entry: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect tool execution outside normal working hours."""
        anomalies = []

        try:
            timestamp = datetime.datetime.fromisoformat(entry.get("timestamp", ""))
            tool = entry.get("tool_name", "")

            # High-risk tools executed off-hours
            if tool in ["exec", "shell", "python_repl", "file_write"]:
                hour = timestamp.hour

                if hour < self.work_hours[0] or hour > self.work_hours[1]:
                    anomalies.append({
                        "severity": "HIGH",
                        "category": "temporal_anomaly",
                        "tool": tool,
                        "timestamp": timestamp.isoformat(),
                        "reason": f"{tool} executed at {timestamp.strftime('%H:%M')} (outside working hours {self.work_hours[0]}-{self.work_hours[1]})",
                        "recommendation": "Investigate immediately. Verify user was active at this time.",
                        "event_id": entry.get("event_id")
                    })

        except (ValueError, KeyError) as e:
            # Log parsing error, skip entry
            pass

        return anomalies

    def _check_suspicious_sequences(self, entry: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect suspicious tool execution sequences indicating exfiltration."""
        anomalies = []

        tool = entry.get("tool_name")
        self.tool_sequence_buffer.append(tool)

        # Keep only recent tools
        if len(self.tool_sequence_buffer) > self.thresholds["suspicious_tool_sequence_length"]:
            self.tool_sequence_buffer.pop(0)

        # Known exfiltration patterns
        exfiltration_patterns = [
            ["file_read", "base64_encode", "http_post"],
            ["file_read", "email_send"],
            ["exec", "curl", "http_post"],
            ["file_read", "browser_action"],
        ]

        for pattern in exfiltration_patterns:
            if all(tool in self.tool_sequence_buffer for tool in pattern):
                anomalies.append({
                    "severity": "CRITICAL",
                    "category": "exfiltration_pattern",
                    "sequence": self.tool_sequence_buffer.copy(),
                    "pattern_matched": pattern,
                    "reason": f"Detected credential exfiltration pattern: {' → '.join(pattern)}",
                    "recommendation": "ISOLATE AGENT IMMEDIATELY. Rotate all credentials. Investigate session logs.",
                    "event_id": entry.get("event_id")
                })

                # Clear buffer after detection
                self.tool_sequence_buffer = []

        return anomalies

    def _check_recipients(self, entry: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect messages sent to external/unauthorized recipients."""
        anomalies = []

        tool = entry.get("tool_name")
        if tool in ["email_send", "slack_send", "discord_send"]:
            recipients = entry.get("arguments", {}).get("recipients", [])

            if isinstance(recipients, str):
                recipients = [recipients]

            for recipient in recipients:
                # Check if recipient domain is in allowed list
                domain = recipient.split("@")[-1] if "@" in recipient else ""

                if not any(allowed in domain for allowed in self.allowed_recipients):
                    anomalies.append({
                        "severity": "HIGH",
                        "category": "unauthorized_recipient",
                        "tool": tool,
                        "recipient": recipient,
                        "reason": f"Message sent to external recipient: {recipient}",
                        "recommendation": "Verify this is legitimate business communication. Check message content.",
                        "event_id": entry.get("event_id")
                    })

        return anomalies

    def _check_file_operations(self, entry: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect large file reads that may indicate credential harvesting."""
        anomalies = []

        tool = entry.get("tool_name")
        if tool == "file_read":
            # Check file size
            size_bytes = entry.get("result", {}).get("size_bytes", 0)
            size_mb = size_bytes / (1024 * 1024)

            if size_mb > self.thresholds["file_read_size_mb_threshold"]:
                anomalies.append({
                    "severity": "MEDIUM",
                    "category": "large_file_operation",
                    "tool": tool,
                    "size_mb": round(size_mb, 2),
                    "path": entry.get("arguments", {}).get("path"),
                    "reason": f"Large file read detected: {size_mb:.2f} MB",
                    "recommendation": "Verify file is legitimate work artifact, not credential store.",
                    "event_id": entry.get("event_id")
                })

            # Check for sensitive paths
            path = entry.get("arguments", {}).get("path", "")
            sensitive_patterns = [
                r"\.ssh",
                r"\.aws",
                r"\.config.*credential",
                r"\.moltbot",
                r"\.clawdbot",
                r"\.openclaw",
            ]

            for pattern in sensitive_patterns:
                if re.search(pattern, path, re.IGNORECASE):
                    anomalies.append({
                        "severity": "CRITICAL",
                        "category": "sensitive_path_access",
                        "tool": tool,
                        "path": path,
                        "reason": f"Access to sensitive path: {path}",
                        "recommendation": "IMMEDIATE INVESTIGATION REQUIRED. Potential credential exfiltration.",
                        "event_id": entry.get("event_id")
                    })

        return anomalies

    def _check_burst_activity(self, log_entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect burst activity indicating automated exploitation."""
        anomalies = []

        # Group entries by time windows
        window_seconds = self.thresholds["burst_window_seconds"]
        time_windows = defaultdict(list)

        for entry in log_entries:
            try:
                timestamp = datetime.datetime.fromisoformat(entry.get("timestamp", ""))
                window_key = int(timestamp.timestamp() / window_seconds)
                time_windows[window_key].append(entry)
            except (ValueError, KeyError):
                continue

        # Check each window for excessive activity
        for window_key, entries in time_windows.items():
            tool_count = len(entries)

            if tool_count > self.thresholds["burst_max_tools"]:
                window_start = datetime.datetime.fromtimestamp(window_key * window_seconds)

                anomalies.append({
                    "severity": "HIGH",
                    "category": "burst_activity",
                    "tool_count": tool_count,
                    "window_seconds": window_seconds,
                    "window_start": window_start.isoformat(),
                    "tools": [e.get("tool_name") for e in entries],
                    "reason": f"Burst activity detected: {tool_count} tool calls in {window_seconds} seconds",
                    "recommendation": "Potential automated exploitation or prompt injection. Review session context.",
                    "event_ids": [e.get("event_id") for e in entries]
                })

        return anomalies


def load_log_entries(log_path: Path) -> List[Dict[str, Any]]:
    """
    Load log entries from JSONL file.

    Compatible with:
    - openclaw-telemetry output format
    - Custom log formats with timestamp, tool_name, arguments fields
    """
    entries = []

    try:
        with open(log_path, 'r') as f:
            for line in f:
                try:
                    entry = json.loads(line.strip())
                    entries.append(entry)
                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        print(f"Error: Log file not found: {log_path}", file=sys.stderr)
        sys.exit(1)

    return entries


def main():
    parser = argparse.ArgumentParser(
        description="Custom behavioral anomaly detection for AI agents",
        epilog="""
Examples:
  # Analyze openclaw-telemetry logs
  %(prog)s --logfile ~/.openclaw/logs/telemetry.jsonl

  # Continuous monitoring mode
  %(prog)s --logfile ~/.openclaw/logs/telemetry.jsonl --follow

  # Custom work hours and recipients
  %(prog)s --logfile logs/telemetry.jsonl --work-hours 8 17 --allowed-recipients company.com partner.com

For production deployments, consider openclaw-telemetry:
https://github.com/knostic/openclaw-telemetry
        """
    )

    parser.add_argument(
        "--logfile",
        type=Path,
        required=True,
        help="Path to JSONL log file (openclaw-telemetry or custom format)"
    )

    parser.add_argument(
        "--follow",
        action="store_true",
        help="Continuous monitoring mode (tail -f behavior)"
    )

    parser.add_argument(
        "--work-hours",
        type=int,
        nargs=2,
        default=[9, 18],
        metavar=("START", "END"),
        help="Normal working hours (default: 9 18)"
    )

    parser.add_argument(
        "--allowed-recipients",
        nargs="+",
        default=["company.com"],
        help="Allowed email recipient domains (default: company.com)"
    )

    parser.add_argument(
        "--output-json",
        action="store_true",
        help="Output anomalies as JSON (for integration with other tools)"
    )

    args = parser.parse_args()

    # Initialize detector
    detector = AnomalyDetector(
        work_hours=tuple(args.work_hours),
        allowed_recipients=args.allowed_recipients
    )

    # Load and analyze logs
    log_entries = load_log_entries(args.logfile)
    anomalies = detector.detect_anomalies(log_entries)

    # Output results
    if args.output_json:
        print(json.dumps(anomalies, indent=2))
    else:
        if not anomalies:
            print("✓ No anomalies detected")
        else:
            print(f"⚠ {len(anomalies)} anomalies detected:\n")

            for i, anomaly in enumerate(anomalies, 1):
                print(f"[{i}] {anomaly['severity']} - {anomaly['category']}")
                print(f"    Reason: {anomaly['reason']}")
                print(f"    Recommendation: {anomaly['recommendation']}")
                print()

    # Exit with status code indicating anomalies found
    sys.exit(1 if anomalies else 0)


if __name__ == "__main__":
    main()
