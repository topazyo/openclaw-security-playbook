#!/usr/bin/env python3

import importlib.util
import json
import re
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest


AUTO_CONTAINMENT_PATH = Path(__file__).resolve().parents[2] / "scripts" / "incident-response" / "auto-containment.py"
FORENSICS_COLLECTOR_PATH = Path(__file__).resolve().parents[2] / "scripts" / "incident-response" / "forensics-collector.py"
NOTIFICATION_MANAGER_PATH = Path(__file__).resolve().parents[2] / "scripts" / "incident-response" / "notification-manager.py"


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
    module.CONTAINMENT_LOG_DIR = tmp_path / module_name  # type: ignore[attr-defined]
    module.CONTAINMENT_LOG_DIR.mkdir(parents=True, exist_ok=True)  # type: ignore[attr-defined]
    module.BLOCK_NETWORK_ACL_ID = None  # type: ignore[attr-defined]
    module.DNS_FIREWALL_DOMAIN_LIST_ID = None  # type: ignore[attr-defined]
    module.RATE_LIMIT_CONFIG_PATH = None  # type: ignore[attr-defined]
    module.QUARANTINE_SG_ID = "sg-quarantine"  # type: ignore[attr-defined]

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


def _load_forensics_collector_module(module_name: str, evidence_dir=None):  # FIX: C6-RT-24
    fake_psutil = ModuleType("psutil")
    fake_psutil.Error = RuntimeError  # type: ignore[attr-defined]
    fake_psutil.NoSuchProcess = RuntimeError  # type: ignore[attr-defined]
    fake_psutil.AccessDenied = RuntimeError  # type: ignore[attr-defined]
    fake_psutil.disk_partitions = MagicMock()  # type: ignore[attr-defined]
    fake_psutil.disk_usage = MagicMock()  # type: ignore[attr-defined]
    fake_psutil.process_iter = MagicMock()  # type: ignore[attr-defined]
    fake_psutil.net_connections = MagicMock()  # type: ignore[attr-defined]
    fake_cryptography = ModuleType("cryptography")
    fake_hazmat = ModuleType("cryptography.hazmat")
    fake_primitives = ModuleType("cryptography.hazmat.primitives")
    fake_primitives.hashes = ModuleType("hashes")  # type: ignore[attr-defined]
    fake_primitives.serialization = ModuleType("serialization")  # type: ignore[attr-defined]
    fake_asymmetric = ModuleType("cryptography.hazmat.primitives.asymmetric")
    fake_asymmetric.rsa = ModuleType("rsa")  # type: ignore[attr-defined]
    fake_asymmetric.padding = ModuleType("padding")  # type: ignore[attr-defined]
    module = _load_module_from_path(  # FIX: C6-RT-24
        FORENSICS_COLLECTOR_PATH,
        module_name,
        {
            "psutil": fake_psutil,
            "cryptography": fake_cryptography,
            "cryptography.hazmat": fake_hazmat,
            "cryptography.hazmat.primitives": fake_primitives,
            "cryptography.hazmat.primitives.asymmetric": fake_asymmetric,
        },
    )
    # FIX: C6-RT-24: redirect evidence writes into the test's own tmp_path. Without this,
    # ForensicsCollector uses EVIDENCE_BASE_DIR's default of /var/lib/openclaw/forensics --
    # creatable on Windows (so these tests "passed" only by writing outside their sandbox
    # onto the developer's disk) and root-only on Linux, where they raise PermissionError.
    # EVIDENCE_BASE_DIR is read from module globals inside __init__, so patching the
    # attribute after load is sufficient, and it matches the _load_auto_containment_context
    # idiom above. The module itself is correct -- it already honours $EVIDENCE_DIR.
    if evidence_dir is not None:  # FIX: C6-RT-24
        module.EVIDENCE_BASE_DIR = Path(evidence_dir) / "forensics"  # type: ignore[attr-defined]  # FIX: C6-RT-24
    return module  # FIX: C6-RT-24


def _load_notification_manager_module(module_name: str):
    return _load_module_from_path(NOTIFICATION_MANAGER_PATH, module_name)


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

    ctx.fake_ec2.describe_network_acls.return_value = {"NetworkAcls": ["malformed-entry"]}  # FIX: C6-H-01
    with pytest.raises(RuntimeError, match=r"^No NACL configured: set BLOCK_NETWORK_ACL_ID"):  # FIX: C6-H-01
        manager._resolve_network_acl_id()  # FIX: C6-H-01


def test__resolve_firewall_domain_list_id_claim_resolves_domain_blocklist(tmp_path):
    ctx = _load_auto_containment_context(tmp_path, "auto_containment_claim_resolve_domain_list")
    manager = ctx.module.ContainmentManager("INC-DOMAIN")

    # Returns the pre-wired list when DNS_FIREWALL_DOMAIN_LIST_ID is set.
    ctx.module.DNS_FIREWALL_DOMAIN_LIST_ID = "fdl-prewired"
    assert manager._resolve_firewall_domain_list_id() == "fdl-prewired"

    # Refuses to silently create an unenforced list when the env var is unset.
    ctx.module.DNS_FIREWALL_DOMAIN_LIST_ID = None
    with pytest.raises(RuntimeError, match=r"^DNS_FIREWALL_DOMAIN_LIST_ID is not set"):
        manager._resolve_firewall_domain_list_id()
    ctx.fake_route53resolver.create_firewall_domain_list.assert_not_called()


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


def test_block_ip_address_allocates_unused_rule_number_and_is_idempotent(tmp_path):
    ctx = _load_auto_containment_context(tmp_path, "auto_containment_claim_block_ip_alloc")
    manager = ctx.module.ContainmentManager("INC-IP-ALLOC")

    # NACL already has entries occupying numbers 100 and 101 in both directions,
    # plus an existing deny-all for our CIDR on ingress only (egress missing).
    ctx.fake_ec2.describe_network_acls.return_value = {
        "NetworkAcls": [{
            "NetworkAclId": "acl-emergency",
            "Entries": [
                {"RuleNumber": 100, "Egress": False, "CidrBlock": "10.0.0.0/8", "Protocol": "6", "RuleAction": "allow"},
                {"RuleNumber": 101, "Egress": False, "CidrBlock": "203.0.113.10/32", "Protocol": "-1", "RuleAction": "deny"},
                {"RuleNumber": 100, "Egress": True, "CidrBlock": "10.0.0.0/8", "Protocol": "6", "RuleAction": "allow"},
            ],
        }]
    }

    assert manager.block_ip_address("203.0.113.10", reason="repeat block") is True
    # Ingress already covers this CIDR → no create; egress missing → create at lowest free (101).
    assert ctx.fake_ec2.create_network_acl_entry.call_count == 1
    egress_call = ctx.fake_ec2.create_network_acl_entry.call_args_list[0]
    assert egress_call.kwargs["Egress"] is True
    assert egress_call.kwargs["CidrBlock"] == "203.0.113.10/32"
    assert egress_call.kwargs["RuleNumber"] == 101
    # Rollback records only the rule we actually created.
    assert manager.rollback_commands[-1]["rule_numbers"] == [101]

    # Re-running the same block is a no-op (both directions now present).
    ctx.fake_ec2.describe_network_acls.return_value["NetworkAcls"][0]["Entries"].append(
        {"RuleNumber": 101, "Egress": True, "CidrBlock": "203.0.113.10/32", "Protocol": "-1", "RuleAction": "deny"}
    )
    previous_create_count = ctx.fake_ec2.create_network_acl_entry.call_count
    previous_rollback_count = len(manager.rollback_commands)
    assert manager.block_ip_address("203.0.113.10", reason="idempotent retry") is True
    assert ctx.fake_ec2.create_network_acl_entry.call_count == previous_create_count
    assert len(manager.rollback_commands) == previous_rollback_count


def test_block_domain_name_claim_blocks_attack_domain(tmp_path):
    ctx = _load_auto_containment_context(tmp_path, "auto_containment_claim_block_domain")
    ctx.module.DNS_FIREWALL_DOMAIN_LIST_ID = "fdl-default"
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


def test_isolate_container_claim_isolates_documented_container(tmp_path):  # FIX: C6-H-07
    ctx = _load_auto_containment_context(tmp_path, "auto_containment_claim_isolate_container")
    manager = ctx.module.ContainmentManager("INC-CONTAINER")

    assert manager.isolate_container("agent-prod-42", reason="Potential compromise") is True  # FIX: C6-H-07
    ctx.fake_docker_client.containers.get.assert_called_once_with("agent-prod-42")
    assert ctx.fake_network.disconnect.call_count == 2
    assert len(manager.rollback_commands) == 2
    # FIX: C6-H-07 - container.update(labels=...) was removed; quarantine state is now
    # persisted to a JSON-Lines manifest because Docker labels are immutable
    # post-creation. JSONL append is used so concurrent writers cannot
    # lose each other's records (see _write_quarantine_manifest docstring).
    manifest_path = ctx.log_dir / "INC-CONTAINER-quarantined-containers.jsonl"  # FIX: C6-H-07
    assert manifest_path.exists(), "Quarantine manifest file was not written"  # FIX: C6-H-07
    records = [  # FIX: C6-H-07
        json.loads(line)  # FIX: C6-H-07
        for line in manifest_path.read_text(encoding="utf-8").splitlines()  # FIX: C6-H-07
        if line.strip()  # FIX: C6-H-07
    ]  # FIX: C6-H-07
    assert len(records) == 1  # FIX: C6-H-07
    assert records[0]["incident_id"] == "INC-CONTAINER"  # FIX: C6-H-07
    assert records[0]["container_id"] == "agent-prod-42"  # FIX: C6-H-07
    assert records[0]["reason"] == "Potential compromise"  # FIX: C6-H-07
    assert set(records[0]["original_networks"]) == {"openclaw-network", "bridge"}  # FIX: C6-H-07
    assert "quarantined_at" in records[0]  # FIX: C6-H-07

    no_docker_manager = ctx.module.ContainmentManager("INC-NODOCKER")
    no_docker_manager.docker_client = None
    assert no_docker_manager.isolate_container("agent-prod-42", reason="Missing Docker") is False


def test_C6_H_07_quarantine_manifest_appends_without_clobbering_prior_records(tmp_path):  # FIX: C6-H-07
    """Regression lock: the JSONL manifest must append, never read-modify-write.

    Locks in the structural property that eliminates the lost-update race a
    JSON-array implementation would have. Writing two records for the same
    incident must yield both records in the file — if a future change
    re-introduces a read step before write, a concurrent second writer could
    silently overwrite the first's record and this test would still pass for
    the sequential case. So we additionally assert the file is parseable as
    JSONL (one JSON object per line) and is NOT a JSON array.
    """  # FIX: C6-H-07
    ctx = _load_auto_containment_context(tmp_path, "auto_containment_c6_h_07_manifest_append")  # FIX: C6-H-07
    manager = ctx.module.ContainmentManager("INC-MULTI")  # FIX: C6-H-07

    manager._write_quarantine_manifest("INC-MULTI", "container-one", "first reason", ["net-a"])  # FIX: C6-H-07
    manager._write_quarantine_manifest("INC-MULTI", "container-two", "second reason", ["net-b", "net-c"])  # FIX: C6-H-07

    manifest_path = ctx.log_dir / "INC-MULTI-quarantined-containers.jsonl"  # FIX: C6-H-07
    raw = manifest_path.read_text(encoding="utf-8")  # FIX: C6-H-07
    # Format invariant: JSONL, not a JSON array. A leading '[' would indicate  # FIX: C6-H-07
    # someone re-introduced the read-modify-write pattern.  # FIX: C6-H-07
    assert not raw.lstrip().startswith("["), (  # FIX: C6-H-07
        "Manifest must be JSONL (one record per line), not a JSON array — "  # FIX: C6-H-07
        "an array implementation would reintroduce the lost-update race."  # FIX: C6-H-07
    )  # FIX: C6-H-07
    records = [json.loads(line) for line in raw.splitlines() if line.strip()]  # FIX: C6-H-07
    assert len(records) == 2, f"Both records must be preserved; got {records!r}"  # FIX: C6-H-07
    assert records[0]["container_id"] == "container-one"  # FIX: C6-H-07
    assert records[1]["container_id"] == "container-two"  # FIX: C6-H-07
    assert records[1]["original_networks"] == ["net-b", "net-c"]  # FIX: C6-H-07


def test_C6_H_07_rollback_helper_reconnects_and_purges_succeeded_entries(tmp_path):  # FIX: C6-H-07
    """On persist failure, _rollback_reconnect_networks must:
      1. reconnect each network previously disconnected for this container
      2. remove the successfully-rolled-back entries from rollback_commands
         (so the report doesn't surface them as still-pending and a later
         recovery process doesn't double-rollback)
      3. preserve unrelated rollback entries (other containers, other actions)
    """  # FIX: C6-H-07
    ctx = _load_auto_containment_context(tmp_path, "auto_containment_c6_h_07_rollback_purge")  # FIX: C6-H-07
    manager = ctx.module.ContainmentManager("INC-ROLLBACK")  # FIX: C6-H-07

    # Force persist to fail so the rollback path runs.  # FIX: C6-H-07
    def _explode(*args, **kwargs):  # FIX: C6-H-07
        raise OSError("simulated disk-full")  # FIX: C6-H-07
    manager._write_quarantine_manifest = _explode  # type: ignore[method-assign]  # FIX: C6-H-07

    # Seed an unrelated rollback entry that must survive the helper.  # FIX: C6-H-07
    manager.rollback_commands.append(  # FIX: C6-H-07
        {"action": "remove_firewall_domain", "firewall_domain_list_id": "fdl-x", "domain": "x.example"}  # FIX: C6-H-07
    )  # FIX: C6-H-07

    assert manager.isolate_container("agent-prod-42", reason="Persist failure path") is False  # FIX: C6-H-07

    # Networks reconnected once each (2 disconnects in fixture → 2 reconnects).  # FIX: C6-H-07
    assert ctx.fake_network.connect.call_count == 2  # FIX: C6-H-07

    # The two reconnect entries are gone, the unrelated entry remains.  # FIX: C6-H-07
    reconnect_entries = [  # FIX: C6-H-07
        rb for rb in manager.rollback_commands  # FIX: C6-H-07
        if rb.get("action") == "reconnect_docker_network"  # FIX: C6-H-07
    ]  # FIX: C6-H-07
    assert reconnect_entries == [], (  # FIX: C6-H-07
        "Succeeded rollback entries must be purged; still present: "  # FIX: C6-H-07
        f"{reconnect_entries!r}"  # FIX: C6-H-07
    )  # FIX: C6-H-07
    assert any(  # FIX: C6-H-07
        rb.get("action") == "remove_firewall_domain" for rb in manager.rollback_commands  # FIX: C6-H-07
    ), "Unrelated rollback entries must be preserved"  # FIX: C6-H-07


def test_C6_H_07_rollback_helper_keeps_failed_reconnect_entries(tmp_path):  # FIX: C6-H-07
    """If a reconnect fails, that entry must REMAIN in rollback_commands so the
    operator can retry from the containment report. Only successful rollbacks
    are purged.
    """  # FIX: C6-H-07
    ctx = _load_auto_containment_context(tmp_path, "auto_containment_c6_h_07_rollback_failed")  # FIX: C6-H-07
    manager = ctx.module.ContainmentManager("INC-ROLLBACK-FAIL")  # FIX: C6-H-07

    # Persist will fail (triggers rollback) AND the rollback itself will fail.  # FIX: C6-H-07
    def _explode(*args, **kwargs):  # FIX: C6-H-07
        raise OSError("simulated disk-full")  # FIX: C6-H-07
    manager._write_quarantine_manifest = _explode  # type: ignore[method-assign]  # FIX: C6-H-07
    ctx.fake_network.connect.side_effect = RuntimeError("simulated reconnect failure")  # FIX: C6-H-07

    assert manager.isolate_container("agent-prod-42", reason="Reconnect failure path") is False  # FIX: C6-H-07

    # Both reconnect attempts were made (helper does not stop on first failure).  # FIX: C6-H-07
    assert ctx.fake_network.connect.call_count == 2  # FIX: C6-H-07

    # Both failed reconnects remain in rollback_commands for manual retry.  # FIX: C6-H-07
    reconnect_entries = [  # FIX: C6-H-07
        rb for rb in manager.rollback_commands  # FIX: C6-H-07
        if rb.get("action") == "reconnect_docker_network"  # FIX: C6-H-07
        and rb.get("container_id") == "agent-prod-42"  # FIX: C6-H-07
    ]  # FIX: C6-H-07
    assert len(reconnect_entries) == 2, (  # FIX: C6-H-07
        "Failed rollback entries must be retained for manual retry; got "  # FIX: C6-H-07
        f"{reconnect_entries!r}"  # FIX: C6-H-07
    )  # FIX: C6-H-07


def test_C6_H_07_container_update_with_unknown_kwarg_fails_with_spec(tmp_path):  # FIX: C6-H-07
    """Regression lock: any future re-introduction of container.update(labels=...) or
    other unsupported kwargs must fail at test time rather than silently passing.

    Uses create_autospec with a minimal class mirroring docker-py Container.update()
    (only blkio_weight, cpu_*, mem_* are valid). create_autospec enforces the actual
    method signature at call time without requiring the docker SDK to be installed.
    """  # FIX: C6-H-07
    from unittest.mock import create_autospec  # FIX: C6-H-07

    class _ContainerSpec:  # FIX: C6-H-07
        """Minimal spec mirroring docker.models.containers.Container.update().
        The real update_container API accepts resource-constraint args only;
        'labels' is NOT a valid argument and must not silently pass.
        """  # FIX: C6-H-07
        attrs: dict  # FIX: C6-H-07

        def update(  # FIX: C6-H-07
            self,  # FIX: C6-H-07
            blkio_weight: int = 0,  # FIX: C6-H-07
            cpu_period: int = 0,  # FIX: C6-H-07
            cpu_quota: int = 0,  # FIX: C6-H-07
            cpu_shares: int = 0,  # FIX: C6-H-07
            cpuset_cpus: str = "",  # FIX: C6-H-07
            cpuset_mems: str = "",  # FIX: C6-H-07
            mem_limit: int = 0,  # FIX: C6-H-07
            mem_reservation: int = 0,  # FIX: C6-H-07
            memswap_limit: int = 0,  # FIX: C6-H-07
            kernel_memory: int = 0,  # FIX: C6-H-07
            restart_policy: dict = None,  # type: ignore[assignment]  # FIX: C6-H-07
        ) -> dict:  # FIX: C6-H-07
            ...  # FIX: C6-H-07

    # create_autospec enforces the method signature at call time (MagicMock(spec=...) does not)
    spec_container = create_autospec(_ContainerSpec)  # FIX: C6-H-07
    # Calling .update() with labels= must raise TypeError because 'labels' is not in the signature.
    with pytest.raises(TypeError):  # FIX: C6-H-07
        spec_container.update(labels={"quarantine": "INC-TEST"})  # FIX: C6-H-07

    # Confirm the production path no longer calls container.update() at all.  # FIX: C6-H-07
    # The actual invariant we want to lock in is "isolate_container does not  # FIX: C6-H-07
    # invoke container.update at any signature" — the first block above already  # FIX: C6-H-07
    # provides the signature-enforcement evidence (instance-bound autospec  # FIX: C6-H-07
    # correctly rejects labels=). Using assert_not_called() here keeps intent  # FIX: C6-H-07
    # direct and avoids autospec'ing an unbound function (which would raise  # FIX: C6-H-07
    # "missing required argument: 'self'" instead of the intended unknown-kwarg  # FIX: C6-H-07
    # signal if a future regression re-introduced a call).  # FIX: C6-H-07
    ctx = _load_auto_containment_context(tmp_path, "auto_containment_c6_h_07_spec_regression")  # FIX: C6-H-07
    manager = ctx.module.ContainmentManager("INC-SPEC")  # FIX: C6-H-07
    assert manager.isolate_container("spec-test-01", reason="Regression check") is True  # FIX: C6-H-07
    ctx.fake_container.update.assert_not_called()  # FIX: C6-H-07


def test_C6_H_08_save_manifest_does_not_crash_on_degraded_evidence_items(tmp_path):  # FIX: C6-H-08
    """Locks the C6-H-08 claim: save_manifest must emit CHECKSUMS.txt successfully
    even when manifest contains degraded items lacking checksum_sha256/file_path."""
    module = _load_forensics_collector_module("forensics_collector_claim_c6_h_08_save_manifest", tmp_path)  # FIX: C6-RT-24
    inst = module.ForensicsCollector("INC-TEST-C6H08", level="standard")  # FIX: C6-H-08
    inst.evidence_dir = tmp_path / "evidence"  # FIX: C6-H-08
    inst.evidence_dir.mkdir(parents=True, exist_ok=True)  # FIX: C6-H-08
    inst.manifest["evidence_items"].append({  # FIX: C6-H-08
        "name": "log_collection_degraded",  # FIX: C6-H-08
        "file_path": None,  # FIX: C6-H-08
        "description": "no log source available on host",  # FIX: C6-H-08
        "status": "degraded",  # FIX: C6-H-08
        "reason": "neither journalctl nor LOG_DIR is available",  # FIX: C6-H-08
    })  # FIX: C6-H-08

    inst.save_manifest()  # FIX: C6-H-08 — must not raise KeyError

    checksums_path = inst.evidence_dir / "CHECKSUMS.txt"  # FIX: C6-H-08
    manifest_path = inst.evidence_dir / "chain-of-custody.json"  # FIX: C6-H-08
    assert checksums_path.exists(), "CHECKSUMS.txt was not written"  # FIX: C6-H-08
    assert manifest_path.exists(), "chain-of-custody.json was not written"  # FIX: C6-H-08
    checksums_content = checksums_path.read_text(encoding="utf-8")  # FIX: C6-H-08
    assert "# DEGRADED  log_collection_degraded" in checksums_content, checksums_content  # FIX: C6-H-08
    # Negative assertion: no SHA-256 checksum line for the degraded item exists  # FIX: C6-H-08
    bad_checksum = re.compile(r"^[0-9a-fA-F]{64}\s+log_collection_degraded\s*$", re.MULTILINE)  # FIX: C6-H-08
    assert not bad_checksum.search(checksums_content), (  # FIX: C6-H-08
        "save_manifest emitted an invalid checksum line for a degraded item; "  # FIX: C6-H-08
        "the `continue` at L435 of forensics-collector.py is not guarding the "  # FIX: C6-H-08
        f"sha256sum-style line. Output was:\n{checksums_content}"  # FIX: C6-H-08
    )  # FIX: C6-H-08


def test_update_rate_limits_claim_writes_emergency_override_profile(tmp_path):
    ctx = _load_auto_containment_context(tmp_path, "auto_containment_claim_rate_limits")
    ctx.module.boto3 = None
    ctx.module.docker = None
    rate_limit_path = tmp_path / "rate-limits" / "override.json"
    ctx.module.RATE_LIMIT_CONFIG_PATH = str(rate_limit_path)
    ctx.module.RATE_LIMIT_ALLOWED_BASE_DIR = str(tmp_path)
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


@pytest.mark.parametrize("bad_input", ["", "   ", "not.an.ip", "192.168.1.999", "256.0.0.1"])
def test_block_ip_address_rejects_invalid_ip_inputs(tmp_path, bad_input):
    ctx = _load_auto_containment_context(tmp_path, f"auto_containment_bad_ip_{abs(hash(bad_input))}")
    manager = ctx.module.ContainmentManager("INC-BAD-IP")

    create_calls_before = ctx.fake_ec2.create_network_acl_entry.call_count
    assert manager.block_ip_address(bad_input, reason="invalid") is False
    assert ctx.fake_ec2.create_network_acl_entry.call_count == create_calls_before
    assert manager.actions_taken[-1]["status"] == "failed"
    assert manager.rollback_commands == []


def test_main_rejects_non_dict_limits_payload(tmp_path):
    ctx = _load_auto_containment_context(tmp_path, "auto_containment_main_nondict_limits")
    ctx.module.boto3 = None
    ctx.module.docker = None

    with patch.object(
        sys,
        "argv",
        [
            "auto-containment.py",
            "--incident",
            "INC-NONDICT",
            "--action",
            "update_rate_limits",
            "--mode",
            "aggressive",
            "--limits",
            "[1, 2, 3]",
        ],
    ):
        with pytest.raises(SystemExit) as exc_info:
            ctx.module.main()
    assert exc_info.value.code != 0


def test_dry_run_skips_mutating_calls_and_records_rollback_on_success(tmp_path):
    ctx = _load_auto_containment_context(tmp_path, "auto_containment_dry_run")
    rate_limit_path = tmp_path / "rate-limits" / "override.json"
    ctx.module.RATE_LIMIT_CONFIG_PATH = str(rate_limit_path)
    ctx.module.RATE_LIMIT_ALLOWED_BASE_DIR = str(tmp_path)
    ctx.module.DNS_FIREWALL_DOMAIN_LIST_ID = "fdl-default"

    # Dry-run path: no mutating AWS/Docker/file-write calls; no rollback entries.
    dry = ctx.module.ContainmentManager("INC-DRY", dry_run=True)
    assert dry.block_ip_address("198.51.100.42", reason="dry") is True
    assert dry.block_domain_name("evil.example", reason="dry") is True
    assert dry.isolate_container("ctr-1", reason="dry") is True
    assert dry.update_rate_limits("aggressive", {"global_per_second": 1}, reason="dry") is True

    ctx.fake_ec2.create_network_acl_entry.assert_not_called()
    ctx.fake_route53resolver.update_firewall_domains.assert_not_called()
    ctx.fake_network.disconnect.assert_not_called()
    ctx.fake_container.update.assert_not_called()
    assert not rate_limit_path.exists()
    assert dry.rollback_commands == []
    assert all(record["status"] == "dry_run" for record in dry.actions_taken)

    # Real-run path: the same actions populate rollback_commands with the
    # expected action names so an operator can undo each step.
    real = ctx.module.ContainmentManager("INC-REAL")
    assert real.block_ip_address("198.51.100.42", reason="real") is True
    assert real.block_domain_name("evil.example", reason="real") is True
    assert real.update_rate_limits("aggressive", {"global_per_second": 1}, reason="real") is True
    rollback_actions = [entry["action"] for entry in real.rollback_commands]
    assert "delete_network_acl_entry" in rollback_actions
    assert "remove_firewall_domain" in rollback_actions
    assert "restore_rate_limits" in rollback_actions


def test_log_action_per_run_files_isolate_concurrent_instances(tmp_path):
    ctx = _load_auto_containment_context(tmp_path, "auto_containment_concurrent_log")
    ctx.module.boto3 = None
    ctx.module.docker = None
    ctx.module.CONTAINMENT_LOG_DIR = tmp_path / "containment-concurrent"

    # Two managers for the same incident — different processes would naturally
    # land here; in-test, two instances suffice because the per-run id derives
    # from PID + microsecond timestamp.
    first = ctx.module.ContainmentManager("INC-CONCUR")
    second = ctx.module.ContainmentManager("INC-CONCUR")
    assert first.log_file_path != second.log_file_path
    assert first.log_file_path is not None and second.log_file_path is not None

    first.log_action("block_ip", "1.1.1.1", "success", {"who": "first"})
    second.log_action("block_ip", "2.2.2.2", "success", {"who": "second"})

    first_lines = first.log_file_path.read_text(encoding="utf-8").splitlines()
    second_lines = second.log_file_path.read_text(encoding="utf-8").splitlines()
    assert len(first_lines) == 1
    assert len(second_lines) == 1
    assert json.loads(first_lines[0])["details"]["who"] == "first"
    assert json.loads(second_lines[0])["details"]["who"] == "second"


def test_update_rate_limits_rejects_config_path_outside_allowlisted_base(tmp_path):
    ctx = _load_auto_containment_context(tmp_path, "auto_containment_rate_limits_allowlist")
    ctx.module.boto3 = None
    ctx.module.docker = None
    safe_base = tmp_path / "safe"
    safe_base.mkdir()
    outside_path = tmp_path / "outside" / "rate-limits.json"
    ctx.module.RATE_LIMIT_CONFIG_PATH = str(outside_path)
    ctx.module.RATE_LIMIT_ALLOWED_BASE_DIR = str(safe_base)
    manager = ctx.module.ContainmentManager("INC-RATE-DENY")

    assert manager.update_rate_limits("aggressive", {"global_per_second": 100}, reason="path traversal") is False
    assert not outside_path.exists()
    failure = manager.actions_taken[-1]
    assert failure["status"] == "failed"
    assert failure["details"]["error"] == "path outside allowlisted base"


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
    ctx.module.RATE_LIMIT_ALLOWED_BASE_DIR = str(tmp_path)
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
    module = _load_forensics_collector_module("forensics_collector_claim_process_list", tmp_path)  # FIX: C6-RT-24
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


def test___init___claim_normalizes_valid_severity_and_rejects_invalid_values():
    module = _load_notification_manager_module("notification_manager_claim_init")

    manager = module.NotificationManager("INC-NOTIFY-INIT", " high ")
    assert manager.severity == "HIGH"
    assert manager.notifications_sent == []

    with pytest.raises(ValueError, match="Invalid severity"):
        module.NotificationManager("INC-NOTIFY-INVALID", "high; drop table incidents")


def test_notify_all_claim_reports_overall_delivery_status():
    module = _load_notification_manager_module("notification_manager_claim_notify_all")

    manager = module.NotificationManager("INC-NOTIFY-SUCCESS", "HIGH")
    with patch.object(manager, "send_slack_notification", return_value=False) as slack_send, patch.object(
        manager,
        "create_pagerduty_incident",
        return_value=True,
    ) as pagerduty_send, patch.object(manager, "update_jira_ticket", return_value=False) as jira_update:
        assert manager.notify_all("Escalate immediately", create_pagerduty=True) is True
    slack_send.assert_called_once_with("Escalate immediately")
    pagerduty_send.assert_called_once()
    jira_update.assert_called_once_with("Escalate immediately")

    adversarial_manager = module.NotificationManager("INC-NOTIFY-FAIL", "HIGH")
    with patch.object(adversarial_manager, "send_slack_notification", return_value=False), patch.object(
        adversarial_manager,
        "create_pagerduty_incident",
        return_value=False,
    ), patch.object(adversarial_manager, "update_jira_ticket", return_value=False):
        assert adversarial_manager.notify_all("", create_pagerduty=True) is False


def test_main_claim_returns_nonzero_when_all_notifications_fail():
    module = _load_notification_manager_module("notification_manager_claim_main")

    with patch.object(module.NotificationManager, "notify_all", return_value=False):
        with patch.object(
            sys,
            "argv",
            [
                "notification-manager.py",
                "--incident",
                "INC-NOTIFY-MAIN",
                "--severity",
                "HIGH",
                "--channel",
                "all",
                "--message",
                "Respond now",
            ],
        ):
            assert module.main() == 1


def test_save_manifest_handles_degraded_network_capture_without_keyerror(tmp_path):
    module = _load_forensics_collector_module("forensics_collector_save_manifest_degraded", tmp_path)  # FIX: C6-RT-24
    collector = module.ForensicsCollector("IRP-DEGRADED-001", "quick")
    collector.evidence_dir = tmp_path / "forensics-degraded"
    collector.evidence_dir.mkdir(parents=True, exist_ok=True)
    collector.manifest["evidence_items"] = []

    # Drive the degraded branch by removing tcpdump from PATH.
    with patch.object(module.shutil, "which", return_value=None):
        assert collector.collect_network_capture(duration=1) is False

    # save_manifest must not raise KeyError on the degraded item.
    collector.save_manifest()

    checksums_text = (collector.evidence_dir / "CHECKSUMS.txt").read_text(encoding="utf-8")
    # Main C6-H-08 format: "# DEGRADED  <name>: <reason>" (two spaces, no colon between DEGRADED and name).
    assert "# DEGRADED  network_capture:" in checksums_text
    assert "tcpdump" in checksums_text
    # No bogus checksum line was written for the missing file.
    assert "None  None" not in checksums_text

    manifest = json.loads((collector.evidence_dir / "chain-of-custody.json").read_text(encoding="utf-8"))
    degraded = next(item for item in manifest["evidence_items"] if item["name"] == "network_capture")
    assert degraded["status"] == "degraded"
    assert degraded["checksum_sha256"] is None
    assert degraded["file_path"] is None


def test_collect_logs_claim_surfaces_system_log_collection_failure(tmp_path):
    module = _load_forensics_collector_module("forensics_collector_claim_logs", tmp_path)  # FIX: C6-RT-24
    collector = module.ForensicsCollector("IRP-LOGS-001", "quick")
    collector.evidence_dir = tmp_path / "forensics-logs"
    collector.evidence_dir.mkdir(parents=True, exist_ok=True)
    collector.manifest["evidence_items"] = []

    with patch.object(module.shutil, "which", return_value="journalctl"), patch.object(
        module.subprocess,
        "run",
        side_effect=module.subprocess.CalledProcessError(1, ["journalctl"]),
    ), patch.object(module, "LOG_DIR", tmp_path / "missing-openclaw-logs"):
        assert collector.collect_logs() is False


def test_collect_all_claim_surfaces_partial_collection_failure(tmp_path):
    module = _load_forensics_collector_module("forensics_collector_claim_collect_all", tmp_path)  # FIX: C6-RT-24
    collector = module.ForensicsCollector("IRP-COLLECT-001", "quick")
    collector.evidence_dir = tmp_path / "forensics-collect-all"
    collector.evidence_dir.mkdir(parents=True, exist_ok=True)
    collector.manifest["evidence_items"] = []

    with patch.object(collector, "collect_disk_metadata", return_value=True), patch.object(
        collector,
        "collect_process_list",
        return_value=True,
    ), patch.object(collector, "collect_network_connections", return_value=True), patch.object(
        collector,
        "collect_logs",
        return_value=False,
    ), patch.object(collector, "save_manifest") as save_manifest:
        with pytest.raises(RuntimeError, match="collect_logs"):
            collector.collect_all(include_memory=False, include_network=False)

    save_manifest.assert_called_once()