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

import importlib.util  # FIX: C5-finding-3
import sys

import pytest
from unittest.mock import Mock, MagicMock, patch, call
from datetime import datetime, timezone
import json
from pathlib import Path  # FIX: C5-finding-3
from types import ModuleType, SimpleNamespace  # FIX: C5-finding-3


AUTO_CONTAINMENT_PATH = Path(__file__).resolve().parents[2] / "scripts" / "incident-response" / "auto-containment.py"  # FIX: C5-finding-3
FORENSICS_COLLECTOR_PATH = Path(__file__).resolve().parents[2] / "scripts" / "incident-response" / "forensics-collector.py"  # FIX: C5-finding-3
IOC_SCANNER_PATH = Path(__file__).resolve().parents[2] / "scripts" / "incident-response" / "ioc-scanner.py"  # FIX: C5-finding-3
BACKUP_VERIFICATION_PATH = Path(__file__).resolve().parents[2] / "examples" / "security-controls" / "backup-verification.py"  # FIX: C5-finding-3
REPORT_WEEKLY_PATH = Path(__file__).resolve().parents[2] / "src" / "clawdbot" / "report_weekly.py"  # FIX: C5-finding-3
NOTIFICATION_MANAGER_PATH = Path(__file__).resolve().parents[2] / "scripts" / "incident-response" / "notification-manager.py"  # FIX: C5-finding-3
TIMELINE_GENERATOR_PATH = Path(__file__).resolve().parents[2] / "scripts" / "incident-response" / "timeline-generator.py"  # FIX: C5-finding-3
IMPACT_ANALYZER_PATH = Path(__file__).resolve().parents[2] / "scripts" / "incident-response" / "impact-analyzer.py"  # FIX: C5-finding-3


def _load_auto_containment_module(tmp_path):  # FIX: C5-finding-3
    log_dir = tmp_path / "containment"  # FIX: C5-finding-3
    fake_ec2 = MagicMock()  # FIX: C5-finding-3
    fake_iam = MagicMock()  # FIX: C5-finding-3
    fake_route53resolver = MagicMock()  # FIX: C5-finding-3
    fake_network = MagicMock()  # FIX: C5-finding-3
    fake_container = MagicMock()  # FIX: C5-finding-3
    fake_container.attrs = {"NetworkSettings": {"Networks": {"openclaw-network": {}, "bridge": {}}}}  # FIX: C5-finding-3
    fake_docker_client = MagicMock()  # FIX: C5-finding-3
    fake_docker_client.containers.get.return_value = fake_container  # FIX: C5-finding-3
    fake_docker_client.networks.get.return_value = fake_network  # FIX: C5-finding-3
    fake_boto3 = SimpleNamespace()  # FIX: C5-finding-3
    fake_boto3.client = MagicMock(  # FIX: C5-finding-3
        side_effect=lambda service_name, region_name=None: {  # FIX: C5-finding-3
            "ec2": fake_ec2,  # FIX: C5-finding-3
            "iam": fake_iam,  # FIX: C5-finding-3
            "route53resolver": fake_route53resolver,  # FIX: C5-finding-3
        }[service_name]  # FIX: C5-finding-3
    )  # FIX: C5-finding-3
    fake_docker = SimpleNamespace(  # FIX: C5-finding-3
        from_env=MagicMock(return_value=fake_docker_client),  # FIX: C5-finding-3
        errors=SimpleNamespace(DockerException=RuntimeError),  # FIX: C5-finding-3
    )  # FIX: C5-finding-3
    spec = importlib.util.spec_from_file_location("auto_containment_issue_4_tests", AUTO_CONTAINMENT_PATH)  # FIX: C5-finding-3
    assert spec is not None and spec.loader is not None  # FIX: C5-finding-3
    module = importlib.util.module_from_spec(spec)  # FIX: C5-finding-3
    with patch.dict(sys.modules, {"boto3": fake_boto3, "docker": fake_docker}):  # FIX: C5-finding-3
        sys.modules[spec.name] = module  # FIX: C5-finding-3
        spec.loader.exec_module(module)  # FIX: C5-finding-3
    module.CONTAINMENT_LOG_DIR = log_dir  # FIX: C5-finding-3
    return module, log_dir, fake_ec2, fake_route53resolver, fake_docker_client, fake_network, fake_container  # FIX: C5-finding-3


def _run_auto_containment(module, args):  # FIX: C5-finding-3
    with patch.object(sys, "argv", ["auto-containment.py", *args]):  # FIX: C5-finding-3
        return module.main()  # FIX: C5-finding-3


def _read_single_report(log_dir):  # FIX: C5-finding-3
    report_files = sorted(log_dir.glob("*-report.json"))  # FIX: C5-finding-3
    assert len(report_files) == 1  # FIX: C5-finding-3
    return json.loads(report_files[0].read_text(encoding="utf-8"))  # FIX: C5-finding-3


def _load_forensics_collector_module(module_name):  # FIX: C5-finding-3
    fake_psutil = ModuleType("psutil")  # FIX: C5-finding-3
    fake_psutil.Error = RuntimeError  # FIX: C5-finding-3
    fake_psutil.NoSuchProcess = RuntimeError  # FIX: C5-finding-3
    fake_psutil.AccessDenied = RuntimeError  # FIX: C5-finding-3
    fake_psutil.disk_partitions = Mock()  # FIX: C5-finding-3
    fake_psutil.disk_usage = Mock()  # FIX: C5-finding-3
    fake_psutil.process_iter = Mock()  # FIX: C5-finding-3
    fake_psutil.net_connections = Mock()  # FIX: C5-finding-3
    fake_cryptography = ModuleType("cryptography")  # FIX: C5-finding-3
    fake_hazmat = ModuleType("cryptography.hazmat")  # FIX: C5-finding-3
    fake_primitives = ModuleType("cryptography.hazmat.primitives")  # FIX: C5-finding-3
    fake_primitives.hashes = ModuleType("hashes")  # FIX: C5-finding-3
    fake_primitives.serialization = ModuleType("serialization")  # FIX: C5-finding-3
    fake_asymmetric = ModuleType("cryptography.hazmat.primitives.asymmetric")  # FIX: C5-finding-3
    fake_asymmetric.rsa = ModuleType("rsa")  # FIX: C5-finding-3
    fake_asymmetric.padding = ModuleType("padding")  # FIX: C5-finding-3
    spec = importlib.util.spec_from_file_location(module_name, FORENSICS_COLLECTOR_PATH)  # FIX: C5-finding-3
    assert spec is not None and spec.loader is not None  # FIX: C5-finding-3
    module = importlib.util.module_from_spec(spec)  # FIX: C5-finding-3
    with patch.dict(sys.modules, {  # FIX: C5-finding-3
        "psutil": fake_psutil,  # FIX: C5-finding-3
        "cryptography": fake_cryptography,  # FIX: C5-finding-3
        "cryptography.hazmat": fake_hazmat,  # FIX: C5-finding-3
        "cryptography.hazmat.primitives": fake_primitives,  # FIX: C5-finding-3
        "cryptography.hazmat.primitives.asymmetric": fake_asymmetric,  # FIX: C5-finding-3
    }):  # FIX: C5-finding-3
        sys.modules[spec.name] = module  # FIX: C5-finding-3
        spec.loader.exec_module(module)  # FIX: C5-finding-3
    return module  # FIX: C5-finding-3


def _load_ioc_scanner_module(module_name):  # FIX: C5-finding-3
    fake_requests = ModuleType("requests")  # FIX: C5-finding-3
    fake_requests.get = Mock()  # FIX: C5-finding-3
    fake_requests.exceptions = SimpleNamespace(RequestException=Exception)  # FIX: C5-finding-3
    spec = importlib.util.spec_from_file_location(module_name, IOC_SCANNER_PATH)  # FIX: C5-finding-3
    assert spec is not None and spec.loader is not None  # FIX: C5-finding-3
    module = importlib.util.module_from_spec(spec)  # FIX: C5-finding-3
    with patch.dict(sys.modules, {"requests": fake_requests}):  # FIX: C5-finding-3
        sys.modules[spec.name] = module  # FIX: C5-finding-3
        spec.loader.exec_module(module)  # FIX: C5-finding-3
    return module, fake_requests  # FIX: C5-finding-3


def _load_backup_verification_module(module_name):  # FIX: C5-finding-3
    spec = importlib.util.spec_from_file_location(module_name, BACKUP_VERIFICATION_PATH)  # FIX: C5-finding-3
    assert spec is not None and spec.loader is not None  # FIX: C5-finding-3
    module = importlib.util.module_from_spec(spec)  # FIX: C5-finding-3
    sys.modules[spec.name] = module  # FIX: C5-finding-3
    spec.loader.exec_module(module)  # FIX: C5-finding-3
    return module  # FIX: C5-finding-3


def _load_report_weekly_module(module_name):  # FIX: C5-finding-3
    spec = importlib.util.spec_from_file_location(module_name, REPORT_WEEKLY_PATH)  # FIX: C5-finding-3
    assert spec is not None and spec.loader is not None  # FIX: C5-finding-3
    module = importlib.util.module_from_spec(spec)  # FIX: C5-finding-3
    sys.modules[spec.name] = module  # FIX: C5-finding-3
    spec.loader.exec_module(module)  # FIX: C5-finding-3
    return module  # FIX: C5-finding-3


def _load_notification_manager_module(module_name):  # FIX: C5-finding-3
    spec = importlib.util.spec_from_file_location(module_name, NOTIFICATION_MANAGER_PATH)  # FIX: C5-finding-3
    assert spec is not None and spec.loader is not None  # FIX: C5-finding-3
    module = importlib.util.module_from_spec(spec)  # FIX: C5-finding-3
    sys.modules[spec.name] = module  # FIX: C5-finding-3
    spec.loader.exec_module(module)  # FIX: C5-finding-3
    return module  # FIX: C5-finding-3


def _load_timeline_generator_module(module_name):  # FIX: C5-finding-3
    fake_es_client = MagicMock()  # FIX: C5-finding-3
    fake_logs_client = MagicMock()  # FIX: C5-finding-3
    fake_cloudtrail_client = MagicMock()  # FIX: C5-finding-3
    fake_elasticsearch = ModuleType("elasticsearch")  # FIX: C5-finding-3
    fake_elasticsearch.Elasticsearch = MagicMock(return_value=fake_es_client)  # FIX: C5-finding-3
    fake_boto3 = ModuleType("boto3")  # FIX: C5-finding-3
    fake_boto3.client = MagicMock(side_effect=lambda service_name, region_name=None: {"logs": fake_logs_client, "cloudtrail": fake_cloudtrail_client}[service_name])  # FIX: C5-finding-3
    fake_pandas = ModuleType("pandas")  # FIX: C5-finding-3
    fake_pandas.DataFrame = MagicMock()  # FIX: C5-finding-3
    spec = importlib.util.spec_from_file_location(module_name, TIMELINE_GENERATOR_PATH)  # FIX: C5-finding-3
    assert spec is not None and spec.loader is not None  # FIX: C5-finding-3
    module = importlib.util.module_from_spec(spec)  # FIX: C5-finding-3
    with patch.dict(sys.modules, {"elasticsearch": fake_elasticsearch, "boto3": fake_boto3, "pandas": fake_pandas}):  # FIX: C5-finding-3
        sys.modules[spec.name] = module  # FIX: C5-finding-3
        spec.loader.exec_module(module)  # FIX: C5-finding-3
    return module, fake_es_client, fake_logs_client, fake_cloudtrail_client  # FIX: C5-finding-3


def _load_impact_analyzer_module(module_name):  # FIX: C5-finding-3
    fake_ec2 = MagicMock()  # FIX: C5-finding-3
    fake_iam = MagicMock()  # FIX: C5-finding-3
    fake_graph = MagicMock()  # FIX: C5-finding-3
    fake_boto3 = ModuleType("boto3")  # FIX: C5-finding-3
    fake_boto3.client = MagicMock(side_effect=lambda service_name, region_name=None: {"ec2": fake_ec2, "iam": fake_iam}[service_name])  # FIX: C5-finding-3
    fake_networkx = ModuleType("networkx")  # FIX: C5-finding-3
    fake_networkx.DiGraph = MagicMock(return_value=fake_graph)  # FIX: C5-finding-3
    spec = importlib.util.spec_from_file_location(module_name, IMPACT_ANALYZER_PATH)  # FIX: C5-finding-3
    assert spec is not None and spec.loader is not None  # FIX: C5-finding-3
    module = importlib.util.module_from_spec(spec)  # FIX: C5-finding-3
    with patch.dict(sys.modules, {"boto3": fake_boto3, "networkx": fake_networkx}):  # FIX: C5-finding-3
        sys.modules[spec.name] = module  # FIX: C5-finding-3
        spec.loader.exec_module(module)  # FIX: C5-finding-3
    return module, fake_ec2, fake_iam, fake_graph  # FIX: C5-finding-3


@pytest.fixture
def incident_simulator():
    """Simulate security incident."""
    return {
        "incident_id": "INC-2024-001",
        "severity": "P0",
        "type": "Credential Theft",
        "affected_resources": ["i-0abc123", "rds-prod-db"],
        "detected_at": datetime.now(timezone.utc).isoformat(),
    }


class TestDetectionPhase:
    """Test incident detection procedures."""

    def test_forensics_collector_execution(self, tmp_path, incident_simulator):  # FIX: C5-finding-3
        """Test forensics-collector.py gathers evidence through the real collection flow."""  # FIX: C5-finding-3
        module = _load_forensics_collector_module("forensics_collector_detection_issue_7_tests")  # FIX: C5-finding-3
        collector = module.ForensicsCollector(incident_simulator["incident_id"], "quick")  # FIX: C5-finding-3
        collector.evidence_dir = tmp_path / "forensics"  # FIX: C5-finding-3
        collector.evidence_dir.mkdir(parents=True, exist_ok=True)  # FIX: C5-finding-3
        source_logs_dir = tmp_path / "source-logs"  # FIX: C5-finding-3
        source_logs_dir.mkdir(parents=True, exist_ok=True)  # FIX: C5-finding-3
        (source_logs_dir / "agent.log").write_text("security event\n", encoding="utf-8")  # FIX: C5-finding-3

        fake_partition = SimpleNamespace(device="/dev/sda1", mountpoint="/", fstype="ext4", opts="rw")  # FIX: C5-finding-3
        fake_usage = SimpleNamespace(total=1000, used=400, free=600, percent=40.0)  # FIX: C5-finding-3
        fake_process_connection = SimpleNamespace(  # FIX: C5-finding-3
            family="AF_INET",  # FIX: C5-finding-3
            type="SOCK_STREAM",  # FIX: C5-finding-3
            laddr=SimpleNamespace(ip="127.0.0.1", port=8443),  # FIX: C5-finding-3
            raddr=SimpleNamespace(ip="198.51.100.10", port=443),  # FIX: C5-finding-3
            status="ESTABLISHED",  # FIX: C5-finding-3
        )  # FIX: C5-finding-3
        fake_network_connection = SimpleNamespace(  # FIX: C5-finding-3
            family="AF_INET",  # FIX: C5-finding-3
            type="SOCK_STREAM",  # FIX: C5-finding-3
            laddr=SimpleNamespace(ip="10.0.0.5", port=8080),  # FIX: C5-finding-3
            raddr=SimpleNamespace(ip="198.51.100.20", port=80),  # FIX: C5-finding-3
            status="ESTABLISHED",  # FIX: C5-finding-3
            pid=4242,  # FIX: C5-finding-3
        )  # FIX: C5-finding-3

        class FakeProcess:  # FIX: C5-finding-3
            info = {  # FIX: C5-finding-3
                "pid": 4242,  # FIX: C5-finding-3
                "name": "python",  # FIX: C5-finding-3
                "username": "tester",  # FIX: C5-finding-3
                "cmdline": ["python", "collector.py"],  # FIX: C5-finding-3
                "create_time": 1_700_000_000.0,  # FIX: C5-finding-3
            }  # FIX: C5-finding-3

            def connections(self):  # FIX: C5-finding-3
                return [fake_process_connection]  # FIX: C5-finding-3

        with patch.object(module.psutil, "disk_partitions", return_value=[fake_partition]), patch.object(module.psutil, "disk_usage", return_value=fake_usage), patch.object(module.psutil, "process_iter", return_value=[FakeProcess()]), patch.object(module.psutil, "net_connections", return_value=[fake_network_connection]), patch.object(module.shutil, "which", return_value=None), patch.object(module, "LOG_DIR", source_logs_dir):  # FIX: C5-finding-3
            assert collector.collect_all(include_memory=False, include_network=False) is True  # FIX: C5-finding-3

        manifest_path = collector.evidence_dir / "chain-of-custody.json"  # FIX: C5-finding-3
        assert manifest_path.exists()  # FIX: C5-finding-3
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))  # FIX: C5-finding-3
        evidence_names = {item["name"] for item in manifest["evidence_items"]}  # FIX: C5-finding-3
        assert {"disk_metadata", "process_list", "network_connections", "openclaw_log_agent.log"}.issubset(evidence_names)  # FIX: C5-finding-3

    def test_ioc_scanner_threat_intel(self, incident_simulator):  # FIX: C5-finding-3
        """Test IOC scanner queries threat intelligence through the real AbuseIPDB path."""  # FIX: C5-finding-3
        module, fake_requests = _load_ioc_scanner_module("ioc_scanner_detection_issue_7_tests")  # FIX: C5-finding-3
        module.ABUSEIPDB_API_KEY = "abuseipdb-test-key"  # FIX: C5-finding-3
        fake_response = Mock()  # FIX: C5-finding-3
        fake_response.raise_for_status.return_value = None  # FIX: C5-finding-3
        fake_response.json.return_value = {  # FIX: C5-finding-3
            "data": {  # FIX: C5-finding-3
                "abuseConfidenceScore": 75,  # FIX: C5-finding-3
                "totalReports": 4,  # FIX: C5-finding-3
                "countryCode": "US",  # FIX: C5-finding-3
                "isp": "ExampleISP",  # FIX: C5-finding-3
                "lastReportedAt": "2026-04-25T00:00:00Z",  # FIX: C5-finding-3
            }  # FIX: C5-finding-3
        }  # FIX: C5-finding-3
        fake_requests.get.return_value = fake_response  # FIX: C5-finding-3
        scanner = module.IOCScanner()  # FIX: C5-finding-3

        result = scanner.check_ip_reputation("198.51.100.1")  # FIX: C5-finding-3

        assert result["is_malicious"] is True  # FIX: C5-finding-3
        assert result["abuse_score"] == 75  # FIX: C5-finding-3
        assert scanner.results["threat_score"] == 75  # FIX: C5-finding-3
        assert scanner.results["iocs_found"][0]["value"] == "198.51.100.1"  # FIX: C5-finding-3
        fake_requests.get.assert_called_once()  # FIX: C5-finding-3


class TestContainmentPhase:
    """Test incident containment procedures."""

    def test_auto_containment_isolates_ec2(self, tmp_path, incident_simulator):  # FIX: C5-finding-3
        """Test auto-containment.py isolates compromised EC2."""  # FIX: C5-finding-3
        module, _log_dir, fake_ec2, _fake_route53resolver, _fake_docker_client, _fake_network, _fake_container = _load_auto_containment_module(tmp_path)  # FIX: C5-finding-3
        fake_ec2.describe_instances.return_value = {  # FIX: C5-finding-3
            "Reservations": [{  # FIX: C5-finding-3
                "Instances": [{  # FIX: C5-finding-3
                    "SecurityGroups": [{"GroupId": "sg-app-123"}],  # FIX: C5-finding-3
                    "SubnetId": "subnet-12345",  # FIX: C5-finding-3
                    "State": {"Name": "running"},  # FIX: C5-finding-3
                    "BlockDeviceMappings": [{"Ebs": {"VolumeId": "vol-12345"}}],  # FIX: C5-finding-3
                    "VpcId": "vpc-12345",  # FIX: C5-finding-3
                }]  # FIX: C5-finding-3
            }]  # FIX: C5-finding-3
        }  # FIX: C5-finding-3
        fake_ec2.create_snapshot.return_value = {"SnapshotId": "snap-12345"}  # FIX: C5-finding-3
        fake_ec2.create_security_group.return_value = {"GroupId": "sg-quarantine-12345"}  # FIX: C5-finding-3
        manager = module.ContainmentManager(incident_simulator["incident_id"])  # FIX: C5-finding-3
        assert manager.isolate_ec2_instance("i-0abc123") is True  # FIX: C5-finding-3
        fake_ec2.create_snapshot.assert_called_once_with(  # FIX: C5-finding-3
            VolumeId="vol-12345",  # FIX: C5-finding-3
            Description=f"Forensic snapshot for incident {incident_simulator['incident_id']}",  # FIX: C5-finding-3
        )  # FIX: C5-finding-3
        fake_ec2.modify_instance_attribute.assert_called_once_with(  # FIX: C5-finding-3
            InstanceId="i-0abc123",  # FIX: C5-finding-3
            Groups=["sg-quarantine-12345"],  # FIX: C5-finding-3
        )  # FIX: C5-finding-3
        assert manager.actions_taken[0]["action"] == "isolate_ec2"  # FIX: C5-finding-3
        assert manager.actions_taken[0]["status"] == "success"  # FIX: C5-finding-3


class TestAutoContainmentCliParity:
    """Test the documented auto-containment CLI actions."""

    def test_auto_containment_help_lists_all_documented_actions(self, tmp_path, capsys):  # FIX: C5-finding-3
        module, _log_dir, *_mocks = _load_auto_containment_module(tmp_path)  # FIX: C5-finding-3
        with patch.object(sys, "argv", ["auto-containment.py", "--help"]):  # FIX: C5-finding-3
            with pytest.raises(SystemExit) as exc_info:  # FIX: C5-finding-3
                module.main()  # FIX: C5-finding-3
        assert exc_info.value.code == 0  # FIX: C5-finding-3
        help_output = capsys.readouterr().out  # FIX: C5-finding-3
        assert "isolate-ec2" in help_output  # FIX: C5-finding-3
        assert "revoke-credentials" in help_output  # FIX: C5-finding-3
        assert "isolate-docker" in help_output  # FIX: C5-finding-3
        assert "block_ip" in help_output  # FIX: C5-finding-3
        assert "block_domain" in help_output  # FIX: C5-finding-3
        assert "isolate_container" in help_output  # FIX: C5-finding-3
        assert "update_rate_limits" in help_output  # FIX: C5-finding-3

    @pytest.mark.parametrize(  # FIX: C5-finding-3
        ("args", "expected_action", "expected_target", "expected_reason", "expected_mode"),  # FIX: C5-finding-3
        [  # FIX: C5-finding-3
            (  # FIX: C5-finding-3
                ["--action", "block_ip", "--ip-address", "198.51.100.42", "--duration", "7d", "--reason", "Credential exfiltration attempt - IRP-001"],  # FIX: C5-finding-3
                "block_ip",  # FIX: C5-finding-3
                "198.51.100.42",  # FIX: C5-finding-3
                "Credential exfiltration attempt - IRP-001",  # FIX: C5-finding-3
                None,  # FIX: C5-finding-3
            ),  # FIX: C5-finding-3
            (  # FIX: C5-finding-3
                ["--action", "block_domain", "--domain", "attacker.com", "--duration", "permanent", "--reason", "Data exfiltration destination - IRP-004"],  # FIX: C5-finding-3
                "block_domain",  # FIX: C5-finding-3
                "attacker.com",  # FIX: C5-finding-3
                "Data exfiltration destination - IRP-004",  # FIX: C5-finding-3
                None,  # FIX: C5-finding-3
            ),  # FIX: C5-finding-3
            (  # FIX: C5-finding-3
                ["--action", "isolate_container", "--container-id", "agent-prod-42", "--reason", "Potential compromise - IRP-001"],  # FIX: C5-finding-3
                "isolate_container",  # FIX: C5-finding-3
                "agent-prod-42",  # FIX: C5-finding-3
                "Potential compromise - IRP-001",  # FIX: C5-finding-3
                None,  # FIX: C5-finding-3
            ),  # FIX: C5-finding-3
            (  # FIX: C5-finding-3
                ["--action", "update_rate_limits", "--mode", "aggressive", "--limits", '{"per_ip_per_minute": 10, "per_user_per_minute": 20, "global_per_second": 500}'],  # FIX: C5-finding-3
                "update_rate_limits",  # FIX: C5-finding-3
                "aggressive",  # FIX: C5-finding-3
                None,  # FIX: C5-finding-3
                "aggressive",  # FIX: C5-finding-3
            ),  # FIX: C5-finding-3
        ],  # FIX: C5-finding-3
        ids=["block_ip", "block_domain", "isolate_container", "update_rate_limits"],  # FIX: C5-finding-3
    )  # FIX: C5-finding-3
    def test_auto_containment_accepts_documented_playbook_commands(  # FIX: C5-finding-3
        self, tmp_path, args, expected_action, expected_target, expected_reason, expected_mode  # FIX: C5-finding-3
    ):  # FIX: C5-finding-3
        module, log_dir, _fake_ec2, _fake_route53resolver, fake_docker_client, fake_network, fake_container = _load_auto_containment_module(tmp_path)  # FIX: C5-finding-3
        assert _run_auto_containment(module, args) == 0  # FIX: C5-finding-3
        report = _read_single_report(log_dir)  # FIX: C5-finding-3
        assert report["actions_taken"][0]["action"] == expected_action  # FIX: C5-finding-3
        assert report["actions_taken"][0]["target"] == expected_target  # FIX: C5-finding-3
        if expected_reason is not None:  # FIX: C5-finding-3
            assert report["actions_taken"][0]["details"]["reason"] == expected_reason  # FIX: C5-finding-3
        if expected_mode is not None:  # FIX: C5-finding-3
            assert report["actions_taken"][0]["details"]["mode"] == expected_mode  # FIX: C5-finding-3
            assert report["actions_taken"][0]["details"]["limits"]["global_per_second"] == 500  # FIX: C5-finding-3
        if expected_action == "isolate_container":  # FIX: C5-finding-3
            fake_docker_client.containers.get.assert_called_once_with("agent-prod-42")  # FIX: C5-finding-3
            fake_network.disconnect.assert_called()  # FIX: C5-finding-3
            fake_container.update.assert_called_once()  # FIX: C5-finding-3


class TestForensicsCollectorRuntimeParity:
    """Regression tests for forensics collector runtime behavior."""

    def test_collect_process_list_avoids_unsupported_connections_attr(self, tmp_path):  # FIX: C5-finding-3
        module = _load_forensics_collector_module("forensics_collector_issue_4_tests")  # FIX: C5-finding-3
        collector = module.ForensicsCollector("IRP-004-20260214", "quick")  # FIX: C5-finding-3
        collector.evidence_dir = tmp_path / "forensics"  # FIX: C5-finding-3
        collector.evidence_dir.mkdir(parents=True, exist_ok=True)  # FIX: C5-finding-3
        collector.manifest["evidence_items"] = []  # FIX: C5-finding-3

        fake_connection = SimpleNamespace(  # FIX: C5-finding-3
            family="AF_INET",  # FIX: C5-finding-3
            type="SOCK_STREAM",  # FIX: C5-finding-3
            laddr=SimpleNamespace(ip="127.0.0.1", port=8443),  # FIX: C5-finding-3
            raddr=SimpleNamespace(ip="198.51.100.10", port=443),  # FIX: C5-finding-3
            status="ESTABLISHED",  # FIX: C5-finding-3
        )  # FIX: C5-finding-3

        class FakeProcess:  # FIX: C5-finding-3
            info = {  # FIX: C5-finding-3
                "pid": 1234,  # FIX: C5-finding-3
                "name": "python",  # FIX: C5-finding-3
                "username": "tester",  # FIX: C5-finding-3
                "cmdline": ["python", "collector.py"],  # FIX: C5-finding-3
                "create_time": 1_700_000_000.0,  # FIX: C5-finding-3
            }  # FIX: C5-finding-3

            def connections(self):  # FIX: C5-finding-3
                return [fake_connection]  # FIX: C5-finding-3

        def fake_process_iter(attrs):  # FIX: C5-finding-3
            assert "connections" not in attrs  # FIX: C5-finding-3
            return [FakeProcess()]  # FIX: C5-finding-3

        with patch.object(module.psutil, "process_iter", side_effect=fake_process_iter):  # FIX: C5-finding-3
            assert collector.collect_process_list() is True  # FIX: C5-finding-3

        processes_file = collector.evidence_dir / "processes.json"  # FIX: C5-finding-3
        assert processes_file.exists()  # FIX: C5-finding-3
        processes = json.loads(processes_file.read_text(encoding="utf-8"))  # FIX: C5-finding-3
        assert processes[0]["connections_detail"][0]["raddr"] == "198.51.100.10:443"  # FIX: C5-finding-3
    
    def test_notification_manager_sends_pagerduty(self, incident_simulator):  # FIX: C5-finding-3
        """Test notification-manager.py sends PagerDuty alert."""  # FIX: C5-finding-3
        module = _load_notification_manager_module("notification_manager_issue_7_tests")  # FIX: C5-finding-3
        module.PAGERDUTY_API_KEY = "pagerduty-token"  # FIX: C5-finding-3
        module.PAGERDUTY_SERVICE_ID = "service-12345"  # FIX: C5-finding-3
        manager = module.NotificationManager(incident_simulator["incident_id"], "critical")  # FIX: C5-finding-3
        fake_response = Mock()  # FIX: C5-finding-3
        fake_response.raise_for_status.return_value = None  # FIX: C5-finding-3
        fake_response.json.return_value = {"incident": {"id": "PD-12345"}}  # FIX: C5-finding-3

        with patch.object(module.requests, "post", return_value=fake_response) as mock_post:  # FIX: C5-finding-3
            assert manager.create_pagerduty_incident(  # FIX: C5-finding-3
                title=f"Security Incident: {incident_simulator['incident_id']}",  # FIX: C5-finding-3
                description="Containment required immediately",  # FIX: C5-finding-3
            ) is True  # FIX: C5-finding-3

        assert mock_post.call_args is not None  # FIX: C5-finding-3
        assert mock_post.call_args.args[0] == "https://api.pagerduty.com/incidents"  # FIX: C5-finding-3
        assert mock_post.call_args.kwargs["headers"]["Authorization"] == "Token token=pagerduty-token"  # FIX: C5-finding-3
        assert mock_post.call_args.kwargs["json"]["incident"]["service"]["id"] == "service-12345"  # FIX: C5-finding-3
        assert mock_post.call_args.kwargs["json"]["incident"]["urgency"] == "high"  # FIX: C5-finding-3
        assert manager.notifications_sent[-1] == {"channel": "pagerduty", "status": "success", "id": "PD-12345"}  # FIX: C5-finding-3


class TestEradicationPhase:
    """Test threat eradication procedures."""

    def test_timeline_generator_creates_html(self, tmp_path, incident_simulator):  # FIX: C5-finding-3
        """Test timeline-generator.py creates incident timeline."""  # FIX: C5-finding-3
        module, _fake_es_client, _fake_logs_client, _fake_cloudtrail_client = _load_timeline_generator_module("timeline_generator_issue_7_tests")  # FIX: C5-finding-3
        generator = module.TimelineGenerator(incident_simulator["incident_id"], lookback_hours=24)  # FIX: C5-finding-3
        generator.events = [  # FIX: C5-finding-3
            {  # FIX: C5-finding-3
                "timestamp": "2024-01-15T10:00:00Z",  # FIX: C5-finding-3
                "event_type": "AUTHENTICATION_FAILURE",  # FIX: C5-finding-3
                "severity": "HIGH",  # FIX: C5-finding-3
                "user": "attacker@example.com",  # FIX: C5-finding-3
                "source_ip": "198.51.100.23",  # FIX: C5-finding-3
                "message": "Initial detection",  # FIX: C5-finding-3
            },  # FIX: C5-finding-3
            {  # FIX: C5-finding-3
                "timestamp": "2024-01-15T10:05:00Z",  # FIX: C5-finding-3
                "event_type": "CONTAINMENT_INITIATED",  # FIX: C5-finding-3
                "severity": "MEDIUM",  # FIX: C5-finding-3
                "user": "secops@example.com",  # FIX: C5-finding-3
                "source_ip": "127.0.0.1",  # FIX: C5-finding-3
                "message": "Containment initiated",  # FIX: C5-finding-3
            },  # FIX: C5-finding-3
        ]  # FIX: C5-finding-3
        output_path = tmp_path / "html" / f"{incident_simulator['incident_id']}.html"  # FIX: C5-finding-3
        generator.generate_html(output_path)  # FIX: C5-finding-3
        assert output_path.exists()  # FIX: C5-finding-3
        html_output = output_path.read_text(encoding="utf-8")  # FIX: C5-finding-3
        assert incident_simulator["incident_id"] in html_output  # FIX: C5-finding-3
        assert "AUTHENTICATION_FAILURE" in html_output  # FIX: C5-finding-3
        assert "Initial detection" in html_output  # FIX: C5-finding-3

    def test_timeline_generator_returns_false_when_no_events_found(self, tmp_path, incident_simulator):  # FIX: C5-finding-3
        """Test timeline-generator.py reports failure when no events are available."""  # FIX: C5-finding-3
        module, fake_es_client, _fake_logs_client, fake_cloudtrail_client = _load_timeline_generator_module("timeline_generator_no_events_issue_7_tests")  # FIX: C5-finding-3
        fake_es_client.search.return_value = {"hits": {"hits": []}}  # FIX: C5-finding-3
        fake_cloudtrail_client.lookup_events.return_value = {"Events": []}  # FIX: C5-finding-3
        generator = module.TimelineGenerator(incident_simulator["incident_id"], lookback_hours=24)  # FIX: C5-finding-3
        output_path = tmp_path / "empty" / f"{incident_simulator['incident_id']}.html"  # FIX: C5-finding-3
        assert generator.generate(output_path, output_format="html") is False  # FIX: C5-finding-3
        assert not output_path.exists()  # FIX: C5-finding-3
    
    def test_impact_analyzer_calculates_blast_radius(self, incident_simulator):  # FIX: C5-finding-3
        """Test impact-analyzer.py calculates affected resources."""  # FIX: C5-finding-3
        module, fake_ec2, _fake_iam, fake_graph = _load_impact_analyzer_module("impact_analyzer_issue_7_tests")  # FIX: C5-finding-3
        fake_ec2.describe_instances.return_value = {  # FIX: C5-finding-3
            "Reservations": [{  # FIX: C5-finding-3
                "Instances": [{  # FIX: C5-finding-3
                    "VpcId": "vpc-12345",  # FIX: C5-finding-3
                    "SecurityGroups": [{"GroupId": "sg-app-123"}, {"GroupId": "sg-db-456"}],  # FIX: C5-finding-3
                    "IamInstanceProfile": {"Arn": "arn:aws:iam::123456789012:instance-profile/app-role"},  # FIX: C5-finding-3
                }]  # FIX: C5-finding-3
            }]  # FIX: C5-finding-3
        }  # FIX: C5-finding-3
        analyzer = module.ImpactAnalyzer(incident_simulator["incident_id"])  # FIX: C5-finding-3
        assert analyzer.analyze_ec2_blast_radius("i-0abc123") is True  # FIX: C5-finding-3
        fake_ec2.describe_instances.assert_called_once_with(InstanceIds=["i-0abc123"])  # FIX: C5-finding-3
        fake_graph.add_node.assert_any_call("i-0abc123", type="ec2", vpc="vpc-12345")  # FIX: C5-finding-3
        fake_graph.add_edge.assert_any_call("i-0abc123", "sg-app-123")  # FIX: C5-finding-3
        fake_graph.add_edge.assert_any_call("i-0abc123", "sg-db-456")  # FIX: C5-finding-3
        fake_graph.add_edge.assert_any_call("i-0abc123", "app-role")  # FIX: C5-finding-3
        assert analyzer.impact_report["blast_radius"]["ec2_instances"] == 1  # FIX: C5-finding-3
        assert analyzer.impact_report["blast_radius"]["total_resources"] == 4  # FIX: C5-finding-3

    def test_impact_analyzer_returns_false_on_malformed_instance_data(self, incident_simulator):  # FIX: C5-finding-3
        """Test impact-analyzer.py reports failure when EC2 metadata is incomplete."""  # FIX: C5-finding-3
        module, fake_ec2, _fake_iam, _fake_graph = _load_impact_analyzer_module("impact_analyzer_malformed_issue_7_tests")  # FIX: C5-finding-3
        fake_ec2.describe_instances.return_value = {"Reservations": [{"Instances": [{"SecurityGroups": [{"GroupId": "sg-app-123"}]}]}]}  # FIX: C5-finding-3
        analyzer = module.ImpactAnalyzer(incident_simulator["incident_id"])  # FIX: C5-finding-3
        assert analyzer.analyze_ec2_blast_radius("i-0abc123") is False  # FIX: C5-finding-3
        assert analyzer.affected_resources == set()  # FIX: C5-finding-3
        assert analyzer.impact_report["blast_radius"] == {}  # FIX: C5-finding-3

    def test_impact_analyzer_tracks_multiple_ec2_instances(self, incident_simulator):  # FIX: C5-finding-3
        """Test impact-analyzer.py counts all analyzed EC2 instances."""  # FIX: C5-finding-3
        module, fake_ec2, _fake_iam, _fake_graph = _load_impact_analyzer_module("impact_analyzer_multiple_issue_7_tests")  # FIX: C5-finding-3
        fake_ec2.describe_instances.side_effect = [  # FIX: C5-finding-3
            {"Reservations": [{"Instances": [{"VpcId": "vpc-1", "SecurityGroups": [{"GroupId": "sg-1"}]}]}]},  # FIX: C5-finding-3
            {"Reservations": [{"Instances": [{"VpcId": "vpc-2", "SecurityGroups": [{"GroupId": "sg-2"}]}]}]},  # FIX: C5-finding-3
        ]  # FIX: C5-finding-3
        analyzer = module.ImpactAnalyzer(incident_simulator["incident_id"])  # FIX: C5-finding-3
        assert analyzer.analyze_ec2_blast_radius("i-1") is True  # FIX: C5-finding-3
        assert analyzer.analyze_ec2_blast_radius("i-2") is True  # FIX: C5-finding-3
        assert analyzer.impact_report["blast_radius"]["ec2_instances"] == 2  # FIX: C5-finding-3
        assert analyzer.impact_report["blast_radius"]["total_resources"] == 4  # FIX: C5-finding-3

    def test_impact_analyzer_does_not_count_failed_analysis_in_later_success(self, incident_simulator):  # FIX: C5-finding-3
        """Test impact-analyzer.py does not retain failed EC2 analyses in later counts."""  # FIX: C5-finding-3
        module, fake_ec2, _fake_iam, _fake_graph = _load_impact_analyzer_module("impact_analyzer_poison_issue_7_tests")  # FIX: C5-finding-3
        fake_ec2.describe_instances.side_effect = [  # FIX: C5-finding-3
            {"Reservations": [{"Instances": [{"VpcId": "vpc-1", "SecurityGroups": [{"GroupId": "sg-1"}], "IamInstanceProfile": {}}]}]},  # FIX: C5-finding-3
            {"Reservations": [{"Instances": [{"VpcId": "vpc-2", "SecurityGroups": [{"GroupId": "sg-2"}]}]}]},  # FIX: C5-finding-3
        ]  # FIX: C5-finding-3
        analyzer = module.ImpactAnalyzer(incident_simulator["incident_id"])  # FIX: C5-finding-3
        assert analyzer.analyze_ec2_blast_radius("i-bad") is False  # FIX: C5-finding-3
        assert analyzer.analyze_ec2_blast_radius("i-good") is True  # FIX: C5-finding-3
        assert analyzer.analyzed_ec2_instances == {"i-good"}  # FIX: C5-finding-3
        assert analyzer.impact_report["blast_radius"]["ec2_instances"] == 1  # FIX: C5-finding-3
        assert analyzer.impact_report["blast_radius"]["total_resources"] == 2  # FIX: C5-finding-3

    def test_impact_analyzer_trailing_slash_arn_does_not_pollute_graph(self, incident_simulator):  # FIX: C5-finding-3
        """Test that an IamInstanceProfile ARN ending with '/' does not add an empty-string node."""  # FIX: C5-finding-3
        module, fake_ec2, _fake_iam, fake_graph = _load_impact_analyzer_module("impact_analyzer_trailing_slash_7_tests")  # FIX: C5-finding-3
        fake_ec2.describe_instances.return_value = {  # FIX: C5-finding-3
            "Reservations": [{"Instances": [{  # FIX: C5-finding-3
                "VpcId": "vpc-1",  # FIX: C5-finding-3
                "SecurityGroups": [{"GroupId": "sg-1"}],  # FIX: C5-finding-3
                "IamInstanceProfile": {"Arn": "arn:aws:iam::123456789012:instance-profile/"},  # FIX: C5-finding-3
            }]}]  # FIX: C5-finding-3
        }  # FIX: C5-finding-3
        analyzer = module.ImpactAnalyzer(incident_simulator["incident_id"])  # FIX: C5-finding-3
        result = analyzer.analyze_ec2_blast_radius("i-trailing")  # FIX: C5-finding-3
        assert result is True  # FIX: C5-finding-3
        graph_nodes = list(analyzer.graph.nodes)  # FIX: C5-finding-3
        assert "" not in graph_nodes, "empty-string IAM role node must not be added for trailing-slash ARN"  # FIX: C5-finding-3
        assert "" not in analyzer.affected_resources  # FIX: C5-finding-3


class TestRecoveryPhase:
    """Test service recovery procedures."""

    def test_service_restoration(self, tmp_path):  # FIX: C5-finding-3
        """Test the real disaster recovery flow restores a backup and returns recovery metrics."""  # FIX: C5-finding-3
        module = _load_backup_verification_module("backup_verification_recovery_issue_7_tests")  # FIX: C5-finding-3
        backup_path = tmp_path / "openclaw-backup.sql.gz"  # FIX: C5-finding-3
        backup_path.write_bytes(b"compressed-backup")  # FIX: C5-finding-3
        manager = module.DisasterRecoveryManager(module.BackupStrategy())  # FIX: C5-finding-3

        with patch.object(module.BackupVerifier, "verify_backup_integrity", return_value=(True, [])), patch.object(module.BackupVerifier, "_verify_database_records", return_value={"users": 10, "sessions": 5}), patch.object(module.DisasterRecoveryManager, "_run_smoke_tests", return_value=None), patch.object(module.subprocess, "run", return_value=SimpleNamespace(returncode=0)) as mock_run:  # FIX: C5-finding-3
            metrics = manager.execute_recovery(str(backup_path), "postgresql://restore-target")  # FIX: C5-finding-3

        assert metrics.meets_rto is True  # FIX: C5-finding-3
        assert metrics.meets_rpo is True  # FIX: C5-finding-3
        assert metrics.actual_recovery_time is not None  # FIX: C5-finding-3
        assert mock_run.call_count == 2  # FIX: C5-finding-3
        assert mock_run.call_args_list[0].args[0][:2] == ["gunzip", "-c"]  # FIX: C5-finding-3
        assert mock_run.call_args_list[1].args[0][:2] == ["psql", "postgresql://restore-target"]  # FIX: C5-finding-3

    def test_health_checks_pass(self):  # FIX: C5-finding-3
        """Test the real recovery smoke tests pass when the restored database looks healthy."""  # FIX: C5-finding-3
        module = _load_backup_verification_module("backup_verification_smoke_issue_7_tests")  # FIX: C5-finding-3
        manager = module.DisasterRecoveryManager(module.BackupStrategy())  # FIX: C5-finding-3
        fake_cursor = MagicMock()  # FIX: C5-finding-3
        fake_cursor.fetchone.side_effect = [(2,), (10,)]  # FIX: C5-finding-3
        fake_conn = MagicMock()  # FIX: C5-finding-3
        fake_conn.cursor.return_value = fake_cursor  # FIX: C5-finding-3
        fake_psycopg2 = ModuleType("psycopg2")  # FIX: C5-finding-3
        fake_psycopg2.connect = Mock(return_value=fake_conn)  # FIX: C5-finding-3
        fake_psycopg2.Error = Exception  # FIX: C5-finding-3

        with patch.dict(sys.modules, {"psycopg2": fake_psycopg2}):  # FIX: C5-finding-3
            manager._run_smoke_tests("postgresql://restore-target")  # FIX: C5-finding-3

        assert fake_cursor.execute.call_count == 2  # FIX: C5-finding-3
        fake_cursor.close.assert_called_once()  # FIX: C5-finding-3
        fake_conn.close.assert_called_once()  # FIX: C5-finding-3


class TestPIRPhase:
    """Test post-incident review."""

    def test_weekly_report_generates_canonical_report(self, tmp_path):  # FIX: C5-finding-3
        """Test the real weekly report backend writes the canonical weekly review schema."""  # FIX: C5-finding-3
        module = _load_report_weekly_module("report_weekly_issue_7_tests")  # FIX: C5-finding-3
        output_path = tmp_path / "weekly-report.json"  # FIX: C5-finding-3

        with patch.object(module, "_gather_compliance", return_value={"soc2": {"compliance_percentage": 98.5}, "iso27001": {"compliance_percentage": 97.0}, "gdpr": {"compliance_percentage": 99.0}}), patch.object(module, "_gather_certificates", return_value={"total": 2, "expiring_soon": 0, "certificates": []}):  # FIX: C5-finding-3
            report = module.generate_weekly_report(  # FIX: C5-finding-3
                start_date="2026-04-18",  # FIX: C5-finding-3
                end_date="2026-04-25",  # FIX: C5-finding-3
                output_path=str(output_path),  # FIX: C5-finding-3
            )  # FIX: C5-finding-3

        assert report["command"] == "report weekly"  # FIX: C5-finding-3
        assert report["period"] == {"start": "2026-04-18", "end": "2026-04-25"}  # FIX: C5-finding-3
        assert report["overall_status"] == "healthy"  # FIX: C5-finding-3
        assert output_path.exists()  # FIX: C5-finding-3


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
