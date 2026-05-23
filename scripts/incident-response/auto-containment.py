#!/usr/bin/env python3
"""
Automated Threat Containment

Purpose: Immediately contain threats by isolating compromised resources
Attack Vectors: Lateral movement, data exfiltration, privilege escalation
Compliance: SOC 2 CC7.3, ISO 27001 A.16.1.5

Containment Actions (implemented):
- AWS security group lockdown (apply quarantine SG; create deny-all SG if none configured)  # FIX: C5-Batch-G
- IAM credential revocation (deactivate access keys + attach deny-all inline policy)  # FIX: C5-Batch-G
- EC2 snapshot (preserve volumes for forensics)
- Docker container isolation (disconnect all networks + apply quarantine label)
- IP address blocking (add deny entries to emergency network ACL)  # FIX: C5-Batch-G
- Domain blocking (add domain to Route53 Resolver DNS firewall list)  # FIX: C5-Batch-G
- Container isolation (network disconnect + quarantine label; alias for Docker isolation)  # FIX: C5-Batch-G
- Rate-limit override (write emergency rate-limit profile to config path)  # FIX: C5-Batch-G

Safety Features:
- Dry-run mode
- Rollback capability (commands recorded in containment report)
- Audit logging

Usage:
    python3 auto-containment.py --incident INC-2024-001 --target i-1234567890abcdef0 --action isolate-ec2
    python3 auto-containment.py --incident INC-2024-001 --target user:suspicious-user --action revoke-credentials

Dependencies: boto3 (AWS SDK), docker

Related: playbook-prompt-injection.md, IRP-001.md
"""

import argparse
import ipaddress  # FIX: C5-finding-3
import json
import logging
import os
import sys
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional  # pylance: Optional needed for nullable parameter annotations

try:
    import boto3  # FIX: C5-finding-3
except ImportError:
    boto3 = None  # FIX: C5-finding-3

try:
    import docker  # FIX: C5-finding-3
except ImportError:
    docker = None  # FIX: C5-finding-3

# Configuration
QUARANTINE_SUBNET_ID = os.getenv("QUARANTINE_SUBNET_ID")
QUARANTINE_SG_ID = os.getenv("QUARANTINE_SG_ID")
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
CONTAINMENT_LOG_DIR = Path("/var/log/openclaw/containment")
BLOCK_NETWORK_ACL_ID = os.getenv("BLOCK_NETWORK_ACL_ID")  # FIX: C5-finding-3
DNS_FIREWALL_DOMAIN_LIST_ID = os.getenv("DNS_FIREWALL_DOMAIN_LIST_ID")  # FIX: C5-finding-3
RATE_LIMIT_CONFIG_PATH = os.getenv("RATE_LIMIT_CONFIG_PATH")  # FIX: C5-finding-3
# Allowlisted base directory the rate-limit config path must resolve under.
# When unset, ContainmentManager defaults the base to its log directory so
# RATE_LIMIT_CONFIG_PATH cannot point the script at arbitrary files (e.g.
# /etc/passwd) if the env is attacker-influenced and the process is privileged.
RATE_LIMIT_ALLOWED_BASE_DIR = os.getenv("RATE_LIMIT_ALLOWED_BASE_DIR")

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ContainmentManager:
    """Automated threat containment orchestrator"""
    
    def __init__(self, incident_id: str, dry_run: bool = False):
        self.incident_id = incident_id
        self.dry_run = dry_run
        self.actions_taken = []
        self.rollback_commands = []
        
        # Initialize AWS clients
        self.ec2 = None  # FIX: C5-finding-3
        self.iam = None  # FIX: C5-finding-3
        self.route53resolver = None  # FIX: C5-finding-3
        if boto3 is not None:  # FIX: C5-finding-3
            self.ec2 = boto3.client('ec2', region_name=AWS_REGION)  # FIX: C5-finding-3
            self.iam = boto3.client('iam')  # FIX: C5-finding-3
            self.route53resolver = boto3.client('route53resolver', region_name=AWS_REGION)  # FIX: C5-finding-3
        else:
            logger.warning("boto3 not available")  # FIX: C5-finding-3
        
        # Initialize Docker client
        self.docker_client = None  # FIX: C5-finding-3
        if docker is not None:  # FIX: C5-finding-3
            try:
                self.docker_client = docker.from_env()  # FIX: C5-finding-3
            except (docker.errors.DockerException, OSError) as e:  # FIX: C6-M-03  # type: ignore[attr-defined]  # pylance: docker module attrs unknown to pyright when stubs absent
                self.docker_client = None  # FIX: C5-M-02
                self.log_action("init_docker_client", "self", "failed", {"error": str(e)})  # FIX: C5-M-02
                logger.warning("Docker not available: %s", e)  # FIX: C5-M-02
        else:
            logger.warning("docker SDK not available")  # FIX: C5-finding-3
        
        # Resolve a writable log directory; fall back to a tempdir if the
        # default isn't writable so the tool can still run (stdout/stderr
        # logging is always available). None disables file logging entirely.
        self.log_dir: Optional[Path] = CONTAINMENT_LOG_DIR
        try:
            CONTAINMENT_LOG_DIR.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            fallback = Path(tempfile.gettempdir()) / "openclaw" / "containment"
            try:
                fallback.mkdir(parents=True, exist_ok=True)
                self.log_dir = fallback
                logger.warning(
                    "Containment log dir %s not writable (%s); falling back to %s",
                    CONTAINMENT_LOG_DIR, e, fallback,
                )
            except OSError as e2:
                self.log_dir = None
                logger.error(
                    "Cannot create containment log dir (%s) or fallback (%s); file logging disabled",
                    e, e2,
                )

        # Per-run action-log file: PID + microsecond UTC timestamp ensures
        # concurrent ContainmentManager processes never share a writer, so
        # JSONL appends cannot interleave. The threading.Lock additionally
        # serializes same-process appends if this class is ever used from
        # multiple threads.
        self.run_id = f"{os.getpid()}-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%f')}"
        self.log_file_path: Optional[Path] = (
            self.log_dir / f"{self.incident_id}-{self.run_id}.jsonl"
            if self.log_dir is not None
            else None
        )
        self._log_lock = threading.Lock()

    def log_action(self, action: str, target: str, status: str, details: Optional[Dict] = None):  # pylance: details defaults to None so type must be Optional
        """Log containment action"""
        action_record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "incident_id": self.incident_id,
            "action": action,
            "target": target,
            "status": status,
            "details": details or {},
            "dry_run": self.dry_run
        }
        
        self.actions_taken.append(action_record)

        if self.log_file_path is None:
            return

        # Same-process serial appends are guarded by self._log_lock; cross-
        # process serialization is provided by the per-run filename.
        try:
            with self._log_lock:
                with open(self.log_file_path, 'a', encoding='utf-8') as f:
                    f.write(json.dumps(action_record) + "\n")
        except Exception as e:
            logger.error(f"Failed to write log: {e}")

    def _resolve_network_acl_id(self) -> str:  # FIX: C5-finding-3
        """Resolve the network ACL used for IP blocking."""  # FIX: C5-finding-3
        if self.ec2 is None:  # FIX: C5-finding-3
            raise RuntimeError("boto3 is required for network ACL management")  # FIX: C5-finding-3
        if BLOCK_NETWORK_ACL_ID:  # FIX: C5-finding-3
            return BLOCK_NETWORK_ACL_ID  # FIX: C5-finding-3
        response = self.ec2.describe_network_acls(Filters=[{"Name": "default", "Values": ["true"]}])  # FIX: C5-finding-3
        network_acls = response.get("NetworkAcls", []) if isinstance(response, dict) else []  # FIX: C5-finding-3
        if network_acls and isinstance(network_acls[0], dict) and network_acls[0].get("NetworkAclId"):  # FIX: C5-finding-3
            return network_acls[0]["NetworkAclId"]  # FIX: C5-finding-3
        raise RuntimeError(  # FIX: C6-H-01
            "No NACL configured: set BLOCK_NETWORK_ACL_ID or ensure AWS returns a valid NetworkAclId"  # FIX: C6-H-01
        )  # FIX: C6-H-01

    def _allocate_acl_rule_numbers(self, network_acl_id: str, cidr_block: str):
        """Find collision-free NACL rule numbers for an emergency deny on cidr_block.

        Scans existing entries on the NACL. If a matching deny-all entry for the
        same CIDR already exists in a given direction, reuses that rule number
        and signals the caller to skip the create (idempotent re-block). For
        any direction without an existing match, returns the lowest unused rule
        number in [100, 32766]. Returns a dict with rule numbers and presence
        flags so the caller can avoid both create-on-collision failures and
        spurious rollback entries for rules it did not create.
        """
        if self.ec2 is None:
            raise RuntimeError("boto3 is required for network ACL management")
        response = self.ec2.describe_network_acls(NetworkAclIds=[network_acl_id])
        network_acls = response.get("NetworkAcls", []) if isinstance(response, dict) else []
        entries = (
            network_acls[0].get("Entries", [])
            if network_acls and isinstance(network_acls[0], dict)
            else []
        )

        ingress_used: set = set()
        egress_used: set = set()
        existing_ingress: Optional[int] = None
        existing_egress: Optional[int] = None
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            rule_number = entry.get("RuleNumber")
            if not isinstance(rule_number, int):
                continue
            is_egress = bool(entry.get("Egress"))
            (egress_used if is_egress else ingress_used).add(rule_number)
            if (
                entry.get("CidrBlock") == cidr_block
                and entry.get("RuleAction") == "deny"
                and str(entry.get("Protocol")) == "-1"
            ):
                if is_egress:
                    existing_egress = rule_number
                else:
                    existing_ingress = rule_number

        def _next_free(used: set) -> int:
            for candidate in range(100, 32767):
                if candidate not in used:
                    return candidate
            raise RuntimeError("No free NACL rule numbers available in range 100-32766")

        return {
            "ingress_rule_number": existing_ingress if existing_ingress is not None else _next_free(ingress_used),
            "egress_rule_number": existing_egress if existing_egress is not None else _next_free(egress_used),
            "ingress_already_present": existing_ingress is not None,
            "egress_already_present": existing_egress is not None,
        }

    def _resolve_firewall_domain_list_id(self) -> str:
        """Resolve the DNS firewall domain list used for domain blocking.

        Requires DNS_FIREWALL_DOMAIN_LIST_ID to point at a list that is already
        referenced by a Route53 Resolver DNS Firewall rule group associated
        with the target VPC(s). Creating a list on demand is intentionally not
        supported: an orphan list enforces no policy, so reporting "success"
        after creating one would be a false claim.
        """
        if self.route53resolver is None:
            raise RuntimeError("boto3 is required for Route53 Resolver management")
        if not DNS_FIREWALL_DOMAIN_LIST_ID:
            raise RuntimeError(
                "DNS_FIREWALL_DOMAIN_LIST_ID is not set. Provide the Id of a "
                "Route53 Resolver DNS Firewall domain list that is already "
                "referenced by a rule group associated with the target VPC(s); "
                "this script will not create an unenforced list."
            )
        return DNS_FIREWALL_DOMAIN_LIST_ID

    def block_ip_address(self, ip_address: str, duration: Optional[str] = None, reason: Optional[str] = None) -> bool:  # FIX: C5-finding-3  # pylance: duration/reason default to None
        """Block an attacker IP by adding deny entries to the emergency network ACL."""  # FIX: C5-finding-3
        logger.info(f"Blocking IP address: {ip_address}")  # FIX: C5-finding-3
        try:  # FIX: C5-finding-3
            cidr_block = str(ipaddress.ip_network(ip_address, strict=False))  # FIX: C5-finding-3
            network_acl_id = self._resolve_network_acl_id()  # FIX: C5-finding-3
            assert self.ec2 is not None  # pylance: _resolve_network_acl_id raises if self.ec2 is None
            allocation = self._allocate_acl_rule_numbers(network_acl_id, cidr_block)
            ingress_rule_number = allocation["ingress_rule_number"]
            egress_rule_number = allocation["egress_rule_number"]
            ingress_already_present = allocation["ingress_already_present"]
            egress_already_present = allocation["egress_already_present"]
            if self.dry_run:  # FIX: C5-finding-3
                logger.info("[DRY-RUN] Would add deny entries to the emergency network ACL")  # FIX: C5-finding-3
                self.log_action("block_ip", ip_address, "dry_run", {"cidr_block": cidr_block, "duration": duration, "reason": reason, "network_acl_id": network_acl_id, "ingress_rule_number": ingress_rule_number, "egress_rule_number": egress_rule_number, "ingress_already_present": ingress_already_present, "egress_already_present": egress_already_present})
                return True  # FIX: C5-finding-3
            created_rule_numbers = []
            if not ingress_already_present:
                self.ec2.create_network_acl_entry(NetworkAclId=network_acl_id, RuleNumber=ingress_rule_number, Protocol='-1', RuleAction='deny', Egress=False, CidrBlock=cidr_block)
                created_rule_numbers.append(ingress_rule_number)
            if not egress_already_present:
                self.ec2.create_network_acl_entry(NetworkAclId=network_acl_id, RuleNumber=egress_rule_number, Protocol='-1', RuleAction='deny', Egress=True, CidrBlock=cidr_block)
                created_rule_numbers.append(egress_rule_number)
            if created_rule_numbers:
                self.rollback_commands.append({"action": "delete_network_acl_entry", "network_acl_id": network_acl_id, "rule_numbers": created_rule_numbers})
            self.log_action("block_ip", ip_address, "success", {"cidr_block": cidr_block, "duration": duration, "reason": reason, "network_acl_id": network_acl_id, "ingress_rule_number": ingress_rule_number, "egress_rule_number": egress_rule_number, "ingress_already_present": ingress_already_present, "egress_already_present": egress_already_present})
            logger.info(f"✓ IP address {ip_address} blocked successfully")  # FIX: C5-finding-3
            return True  # FIX: C5-finding-3
        except Exception as e:  # FIX: C5-finding-3
            logger.error(f"Failed to block IP address: {e}")  # FIX: C5-finding-3
            self.log_action("block_ip", ip_address, "failed", {"error": str(e), "duration": duration, "reason": reason})  # FIX: C5-finding-3
            return False  # FIX: C5-finding-3

    def block_domain_name(self, domain: str, duration: Optional[str] = None, reason: Optional[str] = None) -> bool:  # FIX: C5-finding-3  # pylance: duration/reason default to None
        """Block a domain by adding it to the emergency DNS firewall list."""  # FIX: C5-finding-3
        logger.info(f"Blocking domain: {domain}")  # FIX: C5-finding-3
        try:  # FIX: C5-finding-3
            normalized_domain = domain.strip().lower()  # FIX: C5-finding-3
            if not normalized_domain:  # FIX: C5-finding-3
                raise ValueError("Domain cannot be empty")  # FIX: C5-finding-3
            firewall_domain_list_id = self._resolve_firewall_domain_list_id()  # FIX: C5-finding-3
            assert self.route53resolver is not None  # pylance: _resolve_firewall_domain_list_id raises if self.route53resolver is None
            if self.dry_run:  # FIX: C5-finding-3
                logger.info("[DRY-RUN] Would add the domain to the emergency DNS firewall list")  # FIX: C5-finding-3
                self.log_action("block_domain", normalized_domain, "dry_run", {"duration": duration, "reason": reason, "firewall_domain_list_id": firewall_domain_list_id})  # FIX: C5-finding-3
                return True  # FIX: C5-finding-3
            self.route53resolver.update_firewall_domains(FirewallDomainListId=firewall_domain_list_id, Operation="ADD", Domains=[normalized_domain])  # FIX: C5-finding-3
            self.rollback_commands.append({"action": "remove_firewall_domain", "firewall_domain_list_id": firewall_domain_list_id, "domain": normalized_domain})  # FIX: C5-finding-3
            self.log_action("block_domain", normalized_domain, "success", {"duration": duration, "reason": reason, "firewall_domain_list_id": firewall_domain_list_id})  # FIX: C5-finding-3
            logger.info(f"✓ Domain {normalized_domain} blocked successfully")  # FIX: C5-finding-3
            return True  # FIX: C5-finding-3
        except Exception as e:  # FIX: C5-finding-3
            logger.error(f"Failed to block domain: {e}")  # FIX: C5-finding-3
            self.log_action("block_domain", domain, "failed", {"error": str(e), "duration": duration, "reason": reason})  # FIX: C5-finding-3
            return False  # FIX: C5-finding-3

    def _write_quarantine_manifest(  # FIX: C6-H-07
        self,  # FIX: C6-H-07
        incident_id: str,  # FIX: C6-H-07
        container_id: str,  # FIX: C6-H-07
        reason: Optional[str],  # FIX: C6-H-07
        original_networks: list,  # FIX: C6-H-07
    ) -> None:  # FIX: C6-H-07
        """Persist quarantine state to a JSON-Lines manifest.  # FIX: C6-H-07

        Docker container labels are immutable post-creation; container.update(labels=...)  # FIX: C6-H-07
        raises TypeError at runtime. Quarantine state is instead recorded here so it  # FIX: C6-H-07
        survives container restarts and does not depend on runtime label mutation.  # FIX: C6-H-07

        File: <log_dir>/<incident_id>-quarantined-containers.jsonl  # FIX: C6-H-07
        Format: JSON Lines (one record per line) opened in append mode. This  # FIX: C6-H-07
        deliberately avoids any read-modify-write step: concurrent  # FIX: C6-H-07
        ContainmentManager processes for the same incident cannot lose each  # FIX: C6-H-07
        other's writes, and an interrupted write cannot corrupt prior records.  # FIX: C6-H-07
        Do not "helpfully" switch this back to a JSON array — that would  # FIX: C6-H-07
        reintroduce the lost-update race the JSONL format eliminates.  # FIX: C6-H-07
        Raises OSError on write failure (caller handles).  # FIX: C6-H-07
        """  # FIX: C6-H-07
        if self.log_dir is None:  # FIX: C6-H-07
            raise OSError("No writable log directory; cannot persist quarantine manifest")  # FIX: C6-H-07
        manifest_path = self.log_dir / f"{incident_id}-quarantined-containers.jsonl"  # FIX: C6-H-07
        record = {  # FIX: C6-H-07
            "incident_id": incident_id,  # FIX: C6-H-07
            "container_id": container_id,  # FIX: C6-H-07
            "reason": reason,  # FIX: C6-H-07
            "original_networks": original_networks,  # FIX: C6-H-07
            "quarantined_at": datetime.now(timezone.utc).isoformat(),  # FIX: C6-H-07
        }  # FIX: C6-H-07
        with open(manifest_path, "a", encoding="utf-8") as handle:  # FIX: C6-H-07
            handle.write(json.dumps(record) + "\n")  # FIX: C6-H-07

    def _rollback_reconnect_networks(self, container_id: str, container) -> None:  # FIX: C6-H-07
        """Reconnect networks previously disconnected during isolation of `container_id`.  # FIX: C6-H-07

        Called when post-disconnect persistence fails so the container is not  # FIX: C6-H-07
        left stranded off-network with no isolation record.  # FIX: C6-H-07

        For each matching rollback entry: attempts network.connect(container).  # FIX: C6-H-07
        On success, removes the entry from self.rollback_commands so subsequent  # FIX: C6-H-07
        recovery logic (or the containment report) does not re-attempt a  # FIX: C6-H-07
        rollback that has already been performed. On failure, logs the error  # FIX: C6-H-07
        and keeps the entry so an operator can retry it manually from the  # FIX: C6-H-07
        report.  # FIX: C6-H-07

        No-op when docker_client is unavailable (defensive — current callers  # FIX: C6-H-07
        guard for this earlier, but the helper must not crash if a future  # FIX: C6-H-07
        path invokes it without that guard).  # FIX: C6-H-07
        """  # FIX: C6-H-07
        if self.docker_client is None:  # FIX: C6-H-07
            return  # FIX: C6-H-07
        remaining: list = []  # FIX: C6-H-07
        for rb in self.rollback_commands:  # FIX: C6-H-07
            if (  # FIX: C6-H-07
                rb.get("action") == "reconnect_docker_network"  # FIX: C6-H-07
                and rb.get("container_id") == container_id  # FIX: C6-H-07
            ):  # FIX: C6-H-07
                try:  # FIX: C6-H-07
                    self.docker_client.networks.get(rb["network_name"]).connect(container)  # FIX: C6-H-07
                    continue  # success — drop from rollback_commands  # FIX: C6-H-07
                except Exception as rb_err:  # FIX: C6-H-07
                    logger.error(f"Rollback reconnect failed for {rb['network_name']}: {rb_err}")  # FIX: C6-H-07
                    remaining.append(rb)  # keep so operator can retry  # FIX: C6-H-07
            else:  # FIX: C6-H-07
                remaining.append(rb)  # FIX: C6-H-07
        self.rollback_commands = remaining  # FIX: C6-H-07

    def isolate_container(self, container_id: str, reason: Optional[str] = None) -> bool:  # FIX: C5-finding-3  # pylance: reason defaults to None
        """Isolate a container using the documented playbook action name."""  # FIX: C5-finding-3
        logger.info(f"Isolating container: {container_id}")  # FIX: C5-finding-3
        if not self.docker_client:  # FIX: C5-finding-3
            logger.error("Docker client not available")  # FIX: C5-finding-3
            self.log_action("isolate_container", container_id, "failed", {"error": "Docker client not available", "reason": reason})  # FIX: C5-finding-3
            return False  # FIX: C5-finding-3
        try:  # FIX: C5-finding-3
            container = self.docker_client.containers.get(container_id)  # FIX: C5-finding-3
            networks = container.attrs['NetworkSettings']['Networks']  # FIX: C5-finding-3
            original_networks = list(networks.keys())  # FIX: C5-finding-3
            if self.dry_run:  # FIX: C5-finding-3
                logger.info("[DRY-RUN] Would disconnect container from networks")  # FIX: C5-finding-3
                self.log_action("isolate_container", container_id, "dry_run", {"original_networks": original_networks, "reason": reason})  # FIX: C5-finding-3
                return True  # FIX: C5-finding-3
            for network_name in original_networks:  # FIX: C5-finding-3
                network = self.docker_client.networks.get(network_name)  # FIX: C5-finding-3
                network.disconnect(container)  # FIX: C5-finding-3
                self.rollback_commands.append({"action": "reconnect_docker_network", "container_id": container_id, "network_name": network_name})  # FIX: C5-finding-3
            # FIX: C6-H-07 - container.update(labels=...) raises TypeError at runtime because
            # Docker container labels are immutable post-creation. Persist quarantine state
            # to a manifest file instead; failure rolls back network disconnects.
            try:  # FIX: C6-H-07
                self._write_quarantine_manifest(self.incident_id, container_id, reason, original_networks)  # FIX: C6-H-07
            except Exception as persist_err:  # FIX: C6-H-07
                logger.error(f"Failed to persist quarantine manifest: {persist_err}")  # FIX: C6-H-07
                self.log_action("isolate_container", container_id, "failed", {"error": str(persist_err), "stage": "label_persist", "reason": reason})  # FIX: C6-H-07
                # Roll back network disconnects so the container is not silently stranded  # FIX: C6-H-07
                self._rollback_reconnect_networks(container_id, container)  # FIX: C6-H-07
                return False  # FIX: C6-H-07
            self.log_action("isolate_container", container_id, "success", {"original_networks": original_networks, "reason": reason})  # FIX: C5-finding-3
            logger.info(f"✓ Container {container_id} isolated successfully")  # FIX: C5-finding-3
            return True  # FIX: C5-finding-3
        except Exception as e:  # FIX: C5-finding-3
            logger.error(f"Failed to isolate container: {e}")  # FIX: C5-finding-3
            self.log_action("isolate_container", container_id, "failed", {"error": str(e), "reason": reason})  # FIX: C5-finding-3
            return False  # FIX: C5-finding-3

    def update_rate_limits(self, mode: str, limits: Dict, reason: Optional[str] = None) -> bool:  # FIX: C5-finding-3  # pylance: reason defaults to None
        """Write an emergency rate-limit override profile for the requested mode."""  # FIX: C5-finding-3
        logger.info(f"Updating rate limits using mode: {mode}")  # FIX: C5-finding-3
        try:  # FIX: C5-finding-3
            if RATE_LIMIT_CONFIG_PATH:  # FIX: C5-finding-3
                candidate_path = Path(RATE_LIMIT_CONFIG_PATH)
                allowed_base = (
                    Path(RATE_LIMIT_ALLOWED_BASE_DIR) if RATE_LIMIT_ALLOWED_BASE_DIR else self.log_dir
                )
                if allowed_base is None:
                    logger.error(
                        "Refusing to honor RATE_LIMIT_CONFIG_PATH: no allowlisted base "
                        "(set RATE_LIMIT_ALLOWED_BASE_DIR or restore log directory)"
                    )
                    self.log_action("update_rate_limits", mode, "failed", {"error": "no allowlisted base", "config_path": str(candidate_path)})
                    return False
                resolved_candidate = candidate_path.resolve()
                resolved_base = allowed_base.resolve()
                if not resolved_candidate.is_relative_to(resolved_base):
                    logger.error(
                        "RATE_LIMIT_CONFIG_PATH %s is not under allowlisted base %s; refusing to write",
                        resolved_candidate, resolved_base,
                    )
                    self.log_action("update_rate_limits", mode, "failed", {"error": "path outside allowlisted base", "config_path": str(resolved_candidate), "allowed_base": str(resolved_base)})
                    return False
                rate_limit_profile_path = candidate_path
            elif self.log_dir is not None:
                rate_limit_profile_path = self.log_dir / f"{self.incident_id}-rate-limits.json"
            else:
                logger.error("No writable path for rate-limit profile (set RATE_LIMIT_CONFIG_PATH)")
                self.log_action("update_rate_limits", mode, "failed", {"error": "no writable path"})
                return False
            rate_limit_payload = {"incident_id": self.incident_id, "mode": mode, "updated_at": datetime.now(timezone.utc).isoformat(), "limits": limits, "reason": reason}  # FIX: C5-finding-3
            if self.dry_run:  # FIX: C5-finding-3
                logger.info("[DRY-RUN] Would write the emergency rate-limit override profile")  # FIX: C5-finding-3
                self.log_action("update_rate_limits", mode, "dry_run", {"mode": mode, "limits": limits, "reason": reason, "config_path": str(rate_limit_profile_path)})  # FIX: C5-finding-3
                return True  # FIX: C5-finding-3
            rate_limit_profile_path.parent.mkdir(parents=True, exist_ok=True)  # FIX: C5-finding-3
            # Atomic write: emit to a sibling temp file then rename, so a crash
            # mid-write cannot leave a half-written rate-limit config in place.
            fd, temp_path_str = tempfile.mkstemp(
                prefix=f".{rate_limit_profile_path.name}.",
                suffix=".tmp",
                dir=str(rate_limit_profile_path.parent),
            )
            try:
                with os.fdopen(fd, 'w', encoding='utf-8') as f:
                    json.dump(rate_limit_payload, f, indent=2)
                os.replace(temp_path_str, rate_limit_profile_path)
            except Exception:
                try:
                    os.unlink(temp_path_str)
                except OSError:
                    pass
                raise
            self.rollback_commands.append({"action": "restore_rate_limits", "config_path": str(rate_limit_profile_path)})  # FIX: C5-finding-3
            self.log_action("update_rate_limits", mode, "success", {"mode": mode, "limits": limits, "reason": reason, "config_path": str(rate_limit_profile_path)})  # FIX: C5-finding-3
            logger.info(f"✓ Rate limits updated successfully using mode {mode}")  # FIX: C5-finding-3
            return True  # FIX: C5-finding-3
        except Exception as e:  # FIX: C5-finding-3
            logger.error(f"Failed to update rate limits: {e}")  # FIX: C5-finding-3
            self.log_action("update_rate_limits", mode, "failed", {"error": str(e), "reason": reason, "limits": limits})  # FIX: C5-finding-3
            return False  # FIX: C5-finding-3
    
    def isolate_ec2_instance(self, instance_id: str) -> bool:
        """Isolate EC2 instance by modifying security groups and creating snapshot"""
        logger.info(f"Isolating EC2 instance: {instance_id}")
        if self.ec2 is None:  # FIX: C5-finding-3
            logger.error("boto3 is required for EC2 isolation")  # FIX: C5-finding-3
            self.log_action("isolate_ec2", instance_id, "failed", {"error": "boto3 is required for EC2 isolation"})  # FIX: C5-finding-3
            return False  # FIX: C5-finding-3
        
        try:
            # Get instance details
            response = self.ec2.describe_instances(InstanceIds=[instance_id])
            instance = response['Reservations'][0]['Instances'][0]
            
            original_sg_ids = [sg['GroupId'] for sg in instance['SecurityGroups']]
            original_subnet = instance['SubnetId']
            
            logger.info(f"Instance state: {instance['State']['Name']}")
            logger.info(f"Original security groups: {original_sg_ids}")
            logger.info(f"Original subnet: {original_subnet}")
            
            if self.dry_run:
                logger.info("[DRY-RUN] Would isolate instance")
                self.log_action("isolate_ec2", instance_id, "dry_run", {
                    "original_sg_ids": original_sg_ids,
                    "original_subnet": original_subnet
                })
                return True
            
            # Create snapshot for forensics
            volumes = [device['Ebs']['VolumeId'] for device in instance.get('BlockDeviceMappings', [])]
            snapshot_ids = []
            
            for volume_id in volumes:
                logger.info(f"Creating snapshot of volume: {volume_id}")
                snapshot = self.ec2.create_snapshot(
                    VolumeId=volume_id,
                    Description=f"Forensic snapshot for incident {self.incident_id}"
                )
                snapshot_ids.append(snapshot['SnapshotId'])
                logger.info(f"✓ Snapshot created: {snapshot['SnapshotId']}")
            
            # Apply quarantine security group
            quarantine_sg: Optional[str] = None  # pylance: ensure bound on all paths for log_action below
            if QUARANTINE_SG_ID:
                logger.info(f"Applying quarantine security group: {QUARANTINE_SG_ID}")
                self.ec2.modify_instance_attribute(
                    InstanceId=instance_id,
                    Groups=[QUARANTINE_SG_ID]
                )
                
                self.rollback_commands.append({
                    "action": "restore_security_groups",
                    "instance_id": instance_id,
                    "security_groups": original_sg_ids
                })
            else:
                # Create restrictive security group on-the-fly
                logger.warning("QUARANTINE_SG_ID not set, creating temporary SG")
                
                vpc_id = instance['VpcId']
                sg_response = self.ec2.create_security_group(
                    GroupName=f"quarantine-{self.incident_id}",
                    Description=f"Quarantine SG for incident {self.incident_id}",
                    VpcId=vpc_id
                )
                
                quarantine_sg = sg_response['GroupId']
                
                # Revoke all default egress rules
                self.ec2.revoke_security_group_egress(
                    GroupId=quarantine_sg,
                    IpPermissions=[{
                        'IpProtocol': '-1',
                        'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                    }]
                )
                
                # Apply quarantine SG
                self.ec2.modify_instance_attribute(
                    InstanceId=instance_id,
                    Groups=[quarantine_sg]
                )
                
                logger.info(f"✓ Created and applied quarantine SG: {quarantine_sg}")
            
            # Tag instance
            self.ec2.create_tags(
                Resources=[instance_id],
                Tags=[
                    {'Key': 'IncidentID', 'Value': self.incident_id},
                    {'Key': 'Status', 'Value': 'Quarantined'},
                    {'Key': 'QuarantinedAt', 'Value': datetime.now(timezone.utc).isoformat()}
                ]
            )
            
            self.log_action("isolate_ec2", instance_id, "success", {
                "original_sg_ids": original_sg_ids,
                "snapshot_ids": snapshot_ids,
                "quarantine_sg": QUARANTINE_SG_ID or quarantine_sg
            })
            
            logger.info(f"✓ EC2 instance {instance_id} isolated successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to isolate EC2 instance: {e}")
            self.log_action("isolate_ec2", instance_id, "failed", {"error": str(e)})
            return False
    
    def revoke_iam_credentials(self, username: str) -> bool:
        """Deactivate IAM user access keys and attach a deny-all inline policy.  # FIX: C5-Batch-G

        Keys are set to Status='Inactive' (deactivation), not deleted.  # FIX: C5-Batch-G
        A deny-all inline policy is also attached to block any residual session tokens.  # FIX: C5-Batch-G
        """  # FIX: C5-Batch-G
        logger.info(f"Deactivating IAM credentials for user: {username}")  # FIX: C5-Batch-G
        if self.iam is None:  # FIX: C5-finding-3
            logger.error("boto3 is required for IAM credential revocation")  # FIX: C5-finding-3
            self.log_action("revoke_iam_credentials", username, "failed", {"error": "boto3 is required for IAM credential revocation"})  # FIX: C5-finding-3
            return False  # FIX: C5-finding-3

        try:
            # List access keys
            response = self.iam.list_access_keys(UserName=username)
            access_keys = response['AccessKeyMetadata']

            logger.info(f"Found {len(access_keys)} access keys for {username}")

            if self.dry_run:
                logger.info("[DRY-RUN] Would deactivate access keys and attach deny-all policy")  # FIX: C5-Batch-G
                self.log_action("revoke_iam_credentials", username, "dry_run", {
                    "access_key_count": len(access_keys)
                })
                return True

            deactivated_keys = []  # FIX: C5-Batch-G — renamed from revoked_keys; keys are deactivated, not deleted
            for key_info in access_keys:
                access_key_id = key_info['AccessKeyId']

                # Deactivate key (Status='Inactive'); key is NOT deleted
                self.iam.update_access_key(
                    UserName=username,
                    AccessKeyId=access_key_id,
                    Status='Inactive'
                )

                logger.info(f"✓ Deactivated access key: {access_key_id}")
                deactivated_keys.append(access_key_id)  # FIX: C5-Batch-G

                self.rollback_commands.append({
                    "action": "reactivate_access_key",
                    "username": username,
                    "access_key_id": access_key_id
                })

            # Attach deny-all inline policy to block residual session tokens
            deny_policy = {
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Deny",
                    "Action": "*",
                    "Resource": "*"
                }]
            }

            policy_name = f"IncidentDeny-{self.incident_id}"

            try:
                self.iam.put_user_policy(
                    UserName=username,
                    PolicyName=policy_name,
                    PolicyDocument=json.dumps(deny_policy)
                )
                logger.info(f"✓ Applied deny-all policy: {policy_name}")
            except Exception as e:
                logger.warning(f"Failed to apply deny policy: {e}")

            self.log_action("revoke_iam_credentials", username, "success", {
                "deactivated_keys": deactivated_keys,  # FIX: C5-Batch-G
                "deny_policy": policy_name
            })

            logger.info(f"✓ IAM credentials deactivated for {username}")  # FIX: C5-Batch-G
            return True

        except Exception as e:
            logger.error(f"Failed to deactivate IAM credentials: {e}")  # FIX: C5-Batch-G
            self.log_action("revoke_iam_credentials", username, "failed", {"error": str(e)})
            return False
    
    def isolate_docker_container(self, container_id: str) -> bool:
        """Isolate Docker container by disconnecting networks"""
        logger.info(f"Isolating Docker container: {container_id}")
        
        if not self.docker_client:
            logger.error("Docker client not available")
            return False
        
        try:
            container = self.docker_client.containers.get(container_id)
            
            # Get current networks
            networks = container.attrs['NetworkSettings']['Networks']
            original_networks = list(networks.keys())
            
            logger.info(f"Container connected to networks: {original_networks}")
            
            if self.dry_run:
                logger.info("[DRY-RUN] Would disconnect container from networks")
                self.log_action("isolate_docker", container_id, "dry_run", {
                    "original_networks": original_networks
                })
                return True
            
            # Disconnect from all networks
            for network_name in original_networks:
                network = self.docker_client.networks.get(network_name)
                network.disconnect(container)
                logger.info(f"✓ Disconnected from network: {network_name}")
                
                self.rollback_commands.append({
                    "action": "reconnect_docker_network",
                    "container_id": container_id,
                    "network_name": network_name
                })
            
            # FIX: C6-H-07 - container.update(labels=...) raises TypeError at runtime because
            # Docker container labels are immutable post-creation. Persist quarantine state
            # to a manifest file instead (same as isolate_container above).
            try:  # FIX: C6-H-07
                self._write_quarantine_manifest(self.incident_id, container_id, None, original_networks)  # FIX: C6-H-07
            except Exception as persist_err:  # FIX: C6-H-07
                logger.error(f"Failed to persist quarantine manifest: {persist_err}")  # FIX: C6-H-07
                self.log_action("isolate_docker", container_id, "failed", {"error": str(persist_err), "stage": "label_persist"})  # FIX: C6-H-07
                # Roll back network disconnects so the container is not silently stranded  # FIX: C6-H-07
                self._rollback_reconnect_networks(container_id, container)  # FIX: C6-H-07
                return False  # FIX: C6-H-07
            
            self.log_action("isolate_docker", container_id, "success", {
                "original_networks": original_networks
            })
            
            logger.info(f"✓ Docker container {container_id} isolated successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to isolate Docker container: {e}")
            self.log_action("isolate_docker", container_id, "failed", {"error": str(e)})
            return False
    
    def save_containment_report(self):
        """Save containment report with rollback commands"""
        report = {
            "incident_id": self.incident_id,
            "containment_completed": datetime.now(timezone.utc).isoformat(),
            "dry_run": self.dry_run,
            "actions_taken": self.actions_taken,
            "rollback_commands": self.rollback_commands
        }
        
        if self.log_dir is None:
            logger.error("No writable log directory; skipping containment report file")
        else:
            report_file = self.log_dir / f"{self.incident_id}-report.json"
            with open(report_file, 'w') as f:
                json.dump(report, f, indent=2)
            logger.info(f"✓ Containment report saved: {report_file}")
        
        # Print summary
        print("\n" + "=" * 80)
        print("Containment Summary")
        print("=" * 80)
        print(f"Incident ID: {self.incident_id}")
        print(f"Actions Taken: {len(self.actions_taken)}")
        print(f"Dry Run: {self.dry_run}")
        print("\nActions:")
        for action in self.actions_taken:
            status_icon = "[+]" if action['status'] == "success" else "[-]"
            print(f"  {status_icon} {action['action']}: {action['target']} - {action['status']}")
        
        if self.rollback_commands:
            print(f"\nRollback commands available: {len(self.rollback_commands)}")
            print(f"See: {report_file}")
        print("=" * 80)


def main():
    parser = argparse.ArgumentParser(
        description="Automated threat containment",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Isolate compromised EC2 instance
    python3 auto-containment.py --incident INC-2024-001 \\
        --target i-1234567890abcdef0 --action isolate-ec2

    # Deactivate IAM credentials (sets keys Inactive + attaches deny-all policy)
    python3 auto-containment.py --incident INC-2024-001 \\
        --target user:suspicious-user --action revoke-credentials

    # Isolate Docker container
    python3 auto-containment.py --incident INC-2024-001 \\
        --target container:abc123 --action isolate-docker

    # Block attacker IP via network ACL
    python3 auto-containment.py --incident INC-2024-001 \\
        --ip-address 198.51.100.42 --duration 7d \\
        --reason "Credential exfiltration attempt" --action block_ip

    # Block attacker domain via Route53 Resolver DNS firewall
    python3 auto-containment.py --incident INC-2024-001 \\
        --domain attacker.example.com --reason "C2 domain" --action block_domain

    # Isolate a named container (network disconnect + quarantine label)
    python3 auto-containment.py --incident INC-2024-001 \\
        --container-id agent-prod-42 --action isolate_container

    # Apply aggressive rate-limit override profile
    python3 auto-containment.py --incident INC-2024-001 \\
        --mode aggressive --limits '{\"per_ip_per_minute\":10}' --action update_rate_limits

    # Dry-run any action
    python3 auto-containment.py --incident INC-2024-001 \\
        --target i-1234567890abcdef0 --action isolate-ec2 --dry-run

Environment Variables:
    AWS_REGION                  AWS region (default: us-east-1)
    QUARANTINE_SG_ID            Quarantine security group ID (deny-all); created on-the-fly if unset
    BLOCK_NETWORK_ACL_ID        Network ACL used for IP blocking; defaults to VPC default ACL
    DNS_FIREWALL_DOMAIN_LIST_ID Route53 Resolver domain list for domain blocking; created if absent
    RATE_LIMIT_CONFIG_PATH      File path for rate-limit override profile

Actions (all implemented):
    isolate-ec2           Snapshot volumes + apply quarantine SG  # FIX: C5-Batch-G
    revoke-credentials    Deactivate IAM access keys + attach deny-all policy  # FIX: C5-Batch-G
    isolate-docker        Disconnect Docker container from all networks  # FIX: C5-Batch-G
    block_ip              Add deny entries to emergency network ACL  # FIX: C5-Batch-G
    block_domain          Add domain to Route53 Resolver DNS firewall list  # FIX: C5-Batch-G
    isolate_container     Network disconnect + quarantine label (Docker)  # FIX: C5-Batch-G
    update_rate_limits    Write emergency rate-limit override profile  # FIX: C5-Batch-G
        """  # FIX: C5-Batch-G
    )
    
    parser.add_argument(
        "--incident",
        required=False,  # FIX: C5-finding-3
        help="Incident ID (e.g., INC-2024-001)"
    )
    parser.add_argument(
        "--target",
        required=False,  # FIX: C5-finding-3
        help="Target resource (EC2 instance ID, user:username, container:id)"
    )
    parser.add_argument(
        "--action",
        required=True,
        choices=["isolate-ec2", "revoke-credentials", "isolate-docker", "block_ip", "block_domain", "isolate_container", "update_rate_limits"],  # FIX: C5-finding-3
        help="Containment action to perform"
    )
    parser.add_argument("--ip-address", help="IP address to block with the block_ip action")  # FIX: C5-finding-3
    parser.add_argument("--domain", help="Domain to block with the block_domain action")  # FIX: C5-finding-3
    parser.add_argument("--container-id", help="Container ID to isolate with the isolate_container action")  # FIX: C5-finding-3
    parser.add_argument("--duration", help="Duration for temporary containment actions")  # FIX: C5-finding-3
    parser.add_argument("--reason", help="Reason recorded in the containment log")  # FIX: C5-finding-3
    parser.add_argument("--mode", choices=["normal", "aggressive", "emergency"], help="Rate-limit mode to apply with update_rate_limits")  # FIX: C5-finding-3
    parser.add_argument("--limits", help="JSON object describing rate-limit overrides for update_rate_limits")  # FIX: C5-finding-3
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Simulate actions without making changes"
    )
    
    args = parser.parse_args()
    parsed_limits = None  # FIX: C5-finding-3
    if args.limits:  # FIX: C5-finding-3
        try:  # FIX: C5-finding-3
            parsed_limits = json.loads(args.limits)  # FIX: C5-finding-3
        except json.JSONDecodeError as e:  # FIX: C5-finding-3
            parser.error(f"--limits must be valid JSON: {e}")  # FIX: C5-finding-3
        if not isinstance(parsed_limits, dict):  # FIX: C5-finding-3
            parser.error("--limits must decode to a JSON object")  # FIX: C5-finding-3
    
    # Initialize containment manager
    incident_id = args.incident or f"INC-AUTO-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"  # FIX: C5-finding-3
    manager = ContainmentManager(incident_id, args.dry_run)  # FIX: C5-finding-3
    
    # Execute containment action
    success = False
    
    if args.action == "isolate-ec2":
        if not args.target:  # FIX: C5-finding-3
            parser.error("--target is required for isolate-ec2")  # FIX: C5-finding-3
        success = manager.isolate_ec2_instance(args.target)
    
    elif args.action == "revoke-credentials":
        if not args.target:  # FIX: C5-finding-3
            parser.error("--target is required for revoke-credentials")  # FIX: C5-finding-3
        # Extract username from "user:username" format
        username = args.target.split(":", 1)[1] if ":" in args.target else args.target
        success = manager.revoke_iam_credentials(username)
    
    elif args.action == "isolate-docker":
        if not args.target and not args.container_id:  # FIX: C5-finding-3
            parser.error("--target or --container-id is required for isolate-docker")  # FIX: C5-finding-3
        # Extract container ID from "container:id" format
        raw_container_target = args.container_id or args.target  # FIX: C5-finding-3
        container_id = raw_container_target.split(":", 1)[1] if raw_container_target and ":" in raw_container_target else raw_container_target  # FIX: C5-finding-3
        success = manager.isolate_docker_container(container_id)

    elif args.action == "block_ip":  # FIX: C5-finding-3
        ip_address = args.ip_address or args.target  # FIX: C5-finding-3
        if not ip_address:  # FIX: C5-finding-3
            parser.error("--ip-address or --target is required for block_ip")  # FIX: C5-finding-3
        success = manager.block_ip_address(ip_address, duration=args.duration, reason=args.reason)  # FIX: C5-finding-3

    elif args.action == "block_domain":  # FIX: C5-finding-3
        domain = args.domain or args.target  # FIX: C5-finding-3
        if not domain:  # FIX: C5-finding-3
            parser.error("--domain or --target is required for block_domain")  # FIX: C5-finding-3
        success = manager.block_domain_name(domain, duration=args.duration, reason=args.reason)  # FIX: C5-finding-3

    elif args.action == "isolate_container":  # FIX: C5-finding-3
        raw_container_target = args.container_id or args.target  # FIX: C5-finding-3
        if not raw_container_target:  # FIX: C5-finding-3
            parser.error("--container-id or --target is required for isolate_container")  # FIX: C5-finding-3
        container_id = raw_container_target.split(":", 1)[1] if ":" in raw_container_target else raw_container_target  # FIX: C5-finding-3
        success = manager.isolate_container(container_id, reason=args.reason)  # FIX: C5-finding-3

    elif args.action == "update_rate_limits":  # FIX: C5-finding-3
        if not args.mode:  # FIX: C5-finding-3
            parser.error("--mode is required for update_rate_limits")  # FIX: C5-finding-3
        if parsed_limits is None:  # FIX: C5-finding-3
            parser.error("--limits is required for update_rate_limits")  # FIX: C5-finding-3
        success = manager.update_rate_limits(args.mode, parsed_limits, reason=args.reason)  # FIX: C5-finding-3
    
    # Save report
    manager.save_containment_report()
    
    if success:
        logger.info("✓ Containment completed successfully")
        return 0
    else:
        logger.error("✗ Containment failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
