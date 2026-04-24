#!/usr/bin/env python3

import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest


AUTO_CONTAINMENT_PATH = Path(__file__).resolve().parents[2] / "scripts" / "incident-response" / "auto-containment.py"
FORENSICS_COLLECTOR_PATH = Path(__file__).resolve().parents[2] / "scripts" / "incident-response" / "forensics-collector.py"


def _load_module_from_path(module_path: Path, module_name: str, patched_modules=None):
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    if patched_modules is None:
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        return module
    with patch.dict(sys.modules, patched_modules):
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
    return module


def _load_auto_containment_context(tmp_path, module_name: str):
    fake_ec2 = MagicMock()
    fake_iam = MagicMock()
    fake_route53resolver = MagicMock()
    fake_network = MagicMock()
    fake_container = MagicMock()
    fake_container.attrs = {
        "NetworkSettings": {
            "Networks": {"openclaw-network": {}, "bridge": {}}
        }
    }
    fake_docker_client = MagicMock()
    fake_docker_client.containers.get.return_value = fake_container
    fake_docker_client.networks.get.return_value = fake_network

    fake_ec2.describe_network_acls.return_value = {
        "NetworkAcls": [{"NetworkAclId": "acl-default"}]
    }
    fake_ec2.describe_instances.return_value = {
        "Reservations": [{
            "Instances": [{
                "SecurityGroups": [{"GroupId": "sg-app"}],
                "SubnetId": "subnet-123",
                "State": {"Name": "running"},
                "BlockDeviceMappings": [{"Ebs": {"VolumeId": "vol-123"}}],
                "VpcId": "vpc-123",
            }]
        }]
    }
    fake_ec2.create_snapshot.return_value = {"SnapshotId": "snap-123"}
    fake_iam.list_access_keys.return_value = {
        "AccessKeyMetadata": [
            {"AccessKeyId": "AKIAFIRST"},
            {"AccessKeyId": "AKIASECOND"},
        ]
    }
    fake_route53resolver.list_firewall_domain_lists.return_value = {
        "FirewallDomainLists": [
            {"Name": "openclaw-auto-containment", "Id": "fdl-default"}
        ]
    }
    fake_route53resolver.create_firewall_domain_list.return_value = {
        "FirewallDomainList": {"Id": "fdl-created"}
    }

    fake_boto3 = SimpleNamespace()
    fake_boto3.client = MagicMock(
        side_effect=lambda service_name, region_name=None: {
            "ec2": fake_ec2,
            "iam": fake_iam,
            "route53resolver": fake_route53resolver,
        }[service_name]
    )
    fake_docker = SimpleNamespace(
        from_env=MagicMock(return_value=fake_docker_client),
        errors=SimpleNamespace(DockerException=RuntimeError),
    )

    module = _load_module_from_path(
        AUTO_CONTAINMENT_PATH,
        module_name,
        {"boto3": fake_boto3, "docker": fake_docker},
    )
    module.CONTAINMENT_LOG_DIR = tmp_path / module_name
    module.CONTAINMENT_LOG_DIR.mkdir(parents=True, exist_ok=True)
    module.BLOCK_NETWORK_ACL_ID = None
    module.DNS_FIREWALL_DOMAIN_LIST_ID = None
    module.RATE_LIMIT_CONFIG_PATH = None
    module.QUARANTINE_SG_ID = "sg-quarantine"

    return SimpleNamespace(
        module=module,
        log_dir=module.CONTAINMENT_LOG_DIR,
        fake_ec2=fake_ec2,
        fake_iam=fake_iam,
        fake_route53resolver=fake_route53resolver,
        fake_docker_client=fake_docker_client,
        fake_network=fake_network,
        fake_container=fake_container,
    )


def _load_forensics_collector_module(module_name: str):
    return _load_module_from_path(FORENSICS_COLLECTOR_PATH, module_name)


def _read_single_report(log_dir: Path):
    report_files = sorted(log_dir.glob("*-report.json"))
    assert len(report_files) == 1
    return json.loads(report_files[0].read_text(encoding="utf-8"))


def test___init___claim_initializes_optional_clients_without_sdk_crash(tmp_path):
    ctx = _load_auto_containment_context(tmp_path, "auto_containment_claim_init")
    ctx.module.boto3 = None
    ctx.module.docker = None
    ctx.module.CONTAINMENT_LOG_DIR = tmp_path / "containment-init"

    manager = ctx.module.ContainmentManager("INC-INIT")

    assert manager.ec2 is None
    assert manager.iam is None
    assert manager.route53resolver is None
    assert manager.docker_client is None
    assert ctx.module.CONTAINMENT_LOG_DIR.exists()


def test__resolve_network_acl_id_claim_resolves_ip_blocking_acl(tmp_path):
    ctx = _load_auto_containment_context(tmp_path, "auto_containment_claim_resolve_acl")
    manager = ctx.module.ContainmentManager("INC-ACL")

    ctx.fake_ec2.describe_network_acls.return_value = {
        "NetworkAcls": [{"NetworkAclId": "acl-emergency"}]
    }
    assert manager._resolve_network_acl_id() == "acl-emergency"

    ctx.fake_ec2.describe_network_acls.return_value = {"NetworkAcls": ["malformed-entry"]}
    assert manager._resolve_network_acl_id() == "acl-auto-containment-inc-acl"


def test__resolve_firewall_domain_list_id_claim_resolves_domain_blocklist(tmp_path):
    ctx = _load_auto_containment_context(tmp_path, "auto_containment_claim_resolve_domain_list")
    manager = ctx.module.ContainmentManager("INC-DOMAIN")

    ctx.fake_route53resolver.list_firewall_domain_lists.return_value = {
        "FirewallDomainLists": [{"Name": "openclaw-auto-containment", "Id": "fdl-existing"}]
    }
    assert manager._resolve_firewall_domain_list_id() == "fdl-existing"

    ctx.fake_route53resolver.list_firewall_domain_lists.return_value = {
        "FirewallDomainLists": [{"Name": "other-list", "Id": "fdl-other"}]
    }
    ctx.fake_route53resolver.create_firewall_domain_list.return_value = {"unexpected": "shape"}
    assert manager._resolve_firewall_domain_list_id() == "fdl-auto-containment-inc-domain"
    ctx.fake_route53resolver.create_firewall_domain_list.assert_called_once()


def test_block_ip_address_claim_blocks_attack_ip(tmp_path):
    ctx = _load_auto_containment_context(tmp_path, "auto_containment_claim_block_ip")
    manager = ctx.module.ContainmentManager("INC-IP")

    assert manager.block_ip_address(
        "198.51.100.42",
        duration="7d",
        reason="Credential exfiltration attempt",
    ) is True
    assert ctx.fake_ec2.create_network_acl_entry.call_count == 2
    ingress_call, egress_call = ctx.fake_ec2.create_network_acl_entry.call_args_list
    assert ingress_call.kwargs["CidrBlock"] == "198.51.100.42/32"
    assert ingress_call.kwargs["Egress"] is False
    assert egress_call.kwargs["Egress"] is True
    assert manager.rollback_commands[0]["action"] == "delete_network_acl_entry"

    previous_call_count = ctx.fake_ec2.create_network_acl_entry.call_count
    assert manager.block_ip_address("198.51.100.999", reason="Malformed IP") is False
    assert ctx.fake_ec2.create_network_acl_entry.call_count == previous_call_count
    assert manager.actions_taken[-1]["status"] == "failed"


def test_block_domain_name_claim_blocks_attack_domain(tmp_path):
    ctx = _load_auto_containment_context(tmp_path, "auto_containment_claim_block_domain")
    manager = ctx.module.ContainmentManager("INC-DNS")

    assert manager.block_domain_name(
        " Attacker.COM ",
        duration="permanent",
        reason="Data exfiltration destination",
    ) is True
    ctx.fake_route53resolver.update_firewall_domains.assert_called_once_with(
        FirewallDomainListId="fdl-default",
        Operation="ADD",
        Domains=["attacker.com"],
    )
    assert manager.rollback_commands[-1]["domain"] == "attacker.com"

    assert manager.block_domain_name("   ", reason="Blank domain") is False
    assert manager.actions_taken[-1]["status"] == "failed"


def test_isolate_container_claim_isolates_documented_container(tmp_path):
    ctx = _load_auto_containment_context(tmp_path, "auto_containment_claim_isolate_container")
    manager = ctx.module.ContainmentManager("INC-CONTAINER")

    assert manager.isolate_container("agent-prod-42", reason="Potential compromise") is True
    ctx.fake_docker_client.containers.get.assert_called_once_with("agent-prod-42")
    assert ctx.fake_network.disconnect.call_count == 2
    assert len(manager.rollback_commands) == 2
    labels = ctx.fake_container.update.call_args.kwargs["labels"]
    assert labels["quarantine"] == "INC-CONTAINER"
    assert labels["containment_reason"] == "Potential compromise"

    no_docker_manager = ctx.module.ContainmentManager("INC-NODOCKER")
    no_docker_manager.docker_client = None
    assert no_docker_manager.isolate_container("agent-prod-42", reason="Missing Docker") is False


def test_update_rate_limits_claim_writes_emergency_override_profile(tmp_path):
    ctx = _load_auto_containment_context(tmp_path, "auto_containment_claim_rate_limits")
    ctx.module.boto3 = None
    ctx.module.docker = None
    rate_limit_path = tmp_path / "rate-limits" / "override.json"
    ctx.module.RATE_LIMIT_CONFIG_PATH = str(rate_limit_path)
    manager = ctx.module.ContainmentManager("INC-RATE")

    limits = {
        "per_ip_per_minute": 10,
        "per_user_per_minute": 20,
        "global_per_second": 500,
    }
    assert manager.update_rate_limits("aggressive", limits, reason="DoS containment") is True
    payload = json.loads(rate_limit_path.read_text(encoding="utf-8"))
    assert payload["mode"] == "aggressive"
    assert payload["limits"]["global_per_second"] == 500

    assert manager.update_rate_limits("aggressive", {"bad": {1, 2}}, reason="Malformed limits") is False
    assert manager.actions_taken[-1]["status"] == "failed"


def test_isolate_ec2_instance_claim_isolates_instance_when_requested(tmp_path):
    ctx = _load_auto_containment_context(tmp_path, "auto_containment_claim_isolate_ec2")
    manager = ctx.module.ContainmentManager("INC-EC2")

    assert manager.isolate_ec2_instance("i-1234567890abcdef0") is True
    ctx.fake_ec2.create_snapshot.assert_called_once_with(
        VolumeId="vol-123",
        Description="Forensic snapshot for incident INC-EC2",
    )
    ctx.fake_ec2.modify_instance_attribute.assert_called_once_with(
        InstanceId="i-1234567890abcdef0",
        Groups=["sg-quarantine"],
    )
    assert any(
        command["action"] == "restore_security_groups"
        for command in manager.rollback_commands
    )

    no_ec2_manager = ctx.module.ContainmentManager("INC-NOEC2")
    no_ec2_manager.ec2 = None
    assert no_ec2_manager.isolate_ec2_instance("i-1234567890abcdef0") is False


def test_revoke_iam_credentials_claim_revokes_user_access_keys(tmp_path):
    ctx = _load_auto_containment_context(tmp_path, "auto_containment_claim_revoke_iam")
    manager = ctx.module.ContainmentManager("INC-IAM")

    assert manager.revoke_iam_credentials("alice") is True
    assert ctx.fake_iam.update_access_key.call_count == 2
    ctx.fake_iam.put_user_policy.assert_called_once()
    assert [command["action"] for command in manager.rollback_commands] == [
        "reactivate_access_key",
        "reactivate_access_key",
    ]

    no_iam_manager = ctx.module.ContainmentManager("INC-NOIAM")
    no_iam_manager.iam = None
    assert no_iam_manager.revoke_iam_credentials("alice") is False


def test_main_claim_dispatches_requested_containment_action(tmp_path):
    ctx = _load_auto_containment_context(tmp_path, "auto_containment_claim_main")
    ctx.module.boto3 = None
    ctx.module.docker = None
    ctx.module.RATE_LIMIT_CONFIG_PATH = str(tmp_path / "main-rate-limits.json")
    ctx.module.CONTAINMENT_LOG_DIR = tmp_path / "containment-main"
    ctx.module.CONTAINMENT_LOG_DIR.mkdir(parents=True, exist_ok=True)

    with patch.object(
        sys,
        "argv",
        [
            "auto-containment.py",
            "--incident",
            "INC-MAIN",
            "--action",
            "update_rate_limits",
            "--mode",
            "aggressive",
            "--limits",
            '{"global_per_second": 500}',
        ],
    ):
        assert ctx.module.main() == 0

    report = _read_single_report(ctx.module.CONTAINMENT_LOG_DIR)
    assert report["actions_taken"][0]["action"] == "update_rate_limits"
    assert report["actions_taken"][0]["details"]["limits"]["global_per_second"] == 500

    with patch.object(
        sys,
        "argv",
        [
            "auto-containment.py",
            "--action",
            "update_rate_limits",
            "--mode",
            "aggressive",
            "--limits",
            "not-json",
        ],
    ):
        with pytest.raises(SystemExit) as exc_info:
            ctx.module.main()
    assert exc_info.value.code == 2


def test_collect_process_list_claim_collects_running_process_details(tmp_path):
    module = _load_forensics_collector_module("forensics_collector_claim_process_list")
    collector = module.ForensicsCollector("IRP-CLAIM-001", "quick")
    collector.evidence_dir = tmp_path / "forensics"
    collector.evidence_dir.mkdir(parents=True, exist_ok=True)
    collector.manifest["evidence_items"] = []

    fake_connection = SimpleNamespace(
        family="AF_INET",
        type="SOCK_STREAM",
        laddr=SimpleNamespace(ip="127.0.0.1", port=8443),
        raddr=SimpleNamespace(ip="198.51.100.10", port=443),
        status="ESTABLISHED",
    )

    class GoodProcess:
        info = {
            "pid": 1234,
            "name": "python",
            "username": "tester",
            "cmdline": ["python", "collector.py"],
            "create_time": 1_700_000_000.0,
        }

        def net_connections(self):
            return [fake_connection]

    class GuardedProcess:
        info = {
            "pid": 9999,
            "name": "systemd",
            "username": "SYSTEM",
            "cmdline": ["systemd"],
            "create_time": 1_700_000_100.0,
        }

        def net_connections(self):
            raise OSError("access denied")

    def fake_process_iter(attrs):
        assert "connections" not in attrs
        return [GoodProcess(), GuardedProcess()]

    with patch.object(module.psutil, "process_iter", side_effect=fake_process_iter):
        assert collector.collect_process_list() is True

    processes_file = collector.evidence_dir / "processes.json"
    processes = json.loads(processes_file.read_text(encoding="utf-8"))
    assert processes[0]["connections_detail"][0]["raddr"] == "198.51.100.10:443"
    assert processes[1]["connections_detail"] == []