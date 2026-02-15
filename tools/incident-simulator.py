#!/usr/bin/env python3
"""Incident Simulator - Simulates security incidents for testing playbooks"""

import uuid
from datetime import datetime


class IncidentSimulator:
    """Simulates security incidents for testing."""
    
    def create_incident(self, incident_type, severity="P1"):
        """Create simulated security incident."""
        incident_id = f"INC-{datetime.now().strftime('%Y-%m-%d')}-{uuid.uuid4().hex[:6]}"
        
        scenarios = {
            "credential-theft": {
                "type": "Credential Theft",
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


if __name__ == "__main__":
    simulator = IncidentSimulator()
    print(simulator.create_incident("credential-theft", "P0"))
