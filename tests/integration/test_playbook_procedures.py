#!/usr/bin/env python3
"""
Integration Tests for Incident Response Playbook Procedures

Tests execution of IRP-001 from examples/incident-response/IRP-001-security-incident-response.md

Test Coverage:
  - Detection phase (forensics, IOC scanning)
  - Containment phase (isolation, notifications)
  - Eradication phase (timeline, impact analysis)
  - Recovery phase (service restoration)
  - PIR phase (weekly reporting)

Compliance:
  - SOC 2 CC7.3: Incident response
  - ISO 27001 A.16.1.5: Response procedures

Usage:
  pytest tests/integration/test_playbook_procedures.py -v
"""

import pytest
from unittest.mock import Mock, patch, call
from datetime import datetime
import json


@pytest.fixture
def incident_simulator():
    """Simulate security incident."""
    return {
        "incident_id": "INC-2024-001",
        "severity": "P0",
        "type": "Credential Theft",
        "affected_resources": ["i-0abc123", "rds-prod-db"],
        "detected_at": datetime.utcnow().isoformat(),
    }


class TestDetectionPhase:
    """Test incident detection procedures."""
    
    @patch("subprocess.run")
    def test_forensics_collector_execution(self, mock_subprocess, incident_simulator):
        """Test forensics-collector.py gathers evidence."""
        from scripts.incident_response import forensics_collector
        
        mock_subprocess.return_value.returncode = 0
        
        # Run forensics collection
        evidence = forensics_collector.collect(
            incident_id=incident_simulator["incident_id"],
            resources=incident_simulator["affected_resources"],
        )
        
        assert "memory_dumps" in evidence
        assert "disk_snapshots" in evidence
        assert "network_logs" in evidence
    
    @patch("requests.get")
    def test_ioc_scanner_threat_intel(self, mock_get, incident_simulator):
        """Test IOC scanner queries threat intelligence."""
        from scripts.discovery import ioc_scanner
        
        mock_get.return_value.json.return_value = {
            "indicators": [
                {"type": "ip", "value": "198.51.100.1", "threat_level": "high"}
            ]
        }
        
        iocs = ioc_scanner.scan(
            resources=incident_simulator["affected_resources"]
        )
        
        assert len(iocs) > 0
        assert iocs[0]["threat_level"] == "high"


class TestContainmentPhase:
    """Test incident containment procedures."""
    
    @patch("boto3.client")
    def test_auto_containment_isolates_ec2(self, mock_boto, incident_simulator):
        """Test auto-containment.py isolates compromised EC2."""
        from scripts.incident_response import auto_containment
        
        mock_ec2 = Mock()
        mock_boto.return_value = mock_ec2
        
        # Run containment
        auto_containment.isolate_ec2(
            instance_id="i-0abc123",
            incident_id=incident_simulator["incident_id"],
        )
        
        # Verify security group modification
        mock_ec2.modify_instance_attribute.assert_called()
    
    @patch("requests.post")
    def test_notification_manager_sends_pagerduty(self, mock_post, incident_simulator):
        """Test notification-manager.py sends PagerDuty alert."""
        from scripts.incident_response import notification_manager
        
        mock_post.return_value.status_code = 202
        
        # Send notification
        result = notification_manager.send_pagerduty(
            incident=incident_simulator,
            severity="critical",
        )
        
        assert result["status"] == "success"
        mock_post.assert_called()


class TestEradicationPhase:
    """Test threat eradication procedures."""
    
    @patch("subprocess.run")
    def test_timeline_generator_creates_html(self, mock_subprocess, incident_simulator):
        """Test timeline-generator.py creates incident timeline."""
        from scripts.incident_response import timeline_generator
        
        events = [
            {"timestamp": "2024-01-15T10:00:00Z", "event": "Initial detection"},
            {"timestamp": "2024-01-15T10:05:00Z", "event": "Containment initiated"},
        ]
        
        html_path = timeline_generator.generate(
            incident_id=incident_simulator["incident_id"],
            events=events,
        )
        
        assert html_path.endswith(".html")
        assert "INC-2024-001" in html_path
    
    @patch("requests.get")
    def test_impact_analyzer_calculates_blast_radius(self, mock_get, incident_simulator):
        """Test impact-analyzer.py calculates affected resources."""
        from scripts.incident_response import impact_analyzer
        
        mock_get.return_value.json.return_value = {
            "affected_services": ["api-gateway", "user-service"],
            "affected_users": 1500,
            "data_exposure": "HIGH",
        }
        
        impact = impact_analyzer.analyze(
            incident_id=incident_simulator["incident_id"],
            initial_resources=incident_simulator["affected_resources"],
        )
        
        assert impact["affected_users"] == 1500
        assert impact["data_exposure"] == "HIGH"


class TestRecoveryPhase:
    """Test service recovery procedures."""
    
    @patch("subprocess.run")
    def test_service_restoration(self, mock_subprocess, incident_simulator):
        """Test services are restored after eradication."""
        from scripts.incident_response import recovery
        
        mock_subprocess.return_value.returncode = 0
        
        # Restore services
        result = recovery.restore_services(
            incident_id=incident_simulator["incident_id"],
            services=["api-gateway", "user-service"],
        )
        
        assert result["status"] == "restored"
        assert all(s["health"] == "healthy" for s in result["services"])
    
    @patch("requests.get")
    def test_health_checks_pass(self, mock_get, incident_simulator):
        """Test health checks pass after recovery."""
        from scripts.monitoring import health_check
        
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {"status": "healthy"}
        
        health = health_check.check_all_services()
        
        assert all(s["status"] == "healthy" for s in health)


class TestPIRPhase:
    """Test post-incident review."""
    
    @patch("subprocess.run")
    def test_weekly_report_includes_incident(self, mock_subprocess, incident_simulator):
        """Test generate-weekly-report.py includes incident metrics."""
        from scripts.reporting import generate_weekly_report
        
        report = generate_weekly_report.generate(
            start_date="2024-01-15",
            end_date="2024-01-22",
        )
        
        assert "incidents" in report
        assert any(
            inc["incident_id"] == incident_simulator["incident_id"]
            for inc in report["incidents"]
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
