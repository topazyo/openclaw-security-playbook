#!/usr/bin/env python3
"""Incident Simulator - Simulates security incidents for testing playbooks.

Run from repo root:
    python tools/incident-simulator.py --help
"""

import argparse
import json
import uuid
from datetime import datetime


class IncidentSimulator:
    """Simulates security incidents for testing."""
    
    def create_incident(self, incident_type, severity="P1"):
        """Create simulated security incident."""
        incident_id = f"INC-{datetime.now().strftime('%Y-%m-%d')}-{uuid.uuid4().hex[:6]}"
        
        scenarios = {
            "credential-theft": {
                "type": "Credential Exfiltration",
                "affected_resources": ["i-0abc123", "rds-prod-db"],
                "description": "Simulated credential exfiltration via backup file",
            },
            "mcp-compromise": {
                "type": "MCP Server Compromise",
                "affected_resources": ["mcp-01.openclaw.ai"],
                "description": "Simulated MCP server exploitation",
            },
            "dos-attack": {
                "type": "Denial of Service",
                "affected_resources": ["api-gateway"],
                "description": "Simulated resource exhaustion attack",
            },
        }
        
        scenario = scenarios.get(incident_type, scenarios["credential-theft"])
        
        return {
            "incident_id": incident_id,
            "type": scenario["type"],
            "severity": severity,
            "affected_resources": scenario["affected_resources"],
            "description": scenario["description"],
            "detected_at": datetime.utcnow().isoformat(),
            "status": "active",
        }


def create_incident(incident_type, severity="P1"):
    """Module-level wrapper used by openclaw-cli."""
    return IncidentSimulator().create_incident(incident_type, severity)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simulate OpenClaw security incidents")
    parser.add_argument(
        "--type",
        dest="incident_type",
        default="credential-theft",
        choices=["credential-theft", "mcp-compromise", "dos-attack"],
        help="Incident scenario type",
    )
    parser.add_argument(
        "--severity",
        default="P1",
        choices=["P0", "P1", "P2", "P3"],
        help="Incident severity",
    )
    args = parser.parse_args()

    simulator = IncidentSimulator()
    print(json.dumps(simulator.create_incident(args.incident_type, args.severity), indent=2))
