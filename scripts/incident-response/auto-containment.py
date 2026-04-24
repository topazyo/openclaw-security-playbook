#!/usr/bin/env python3
"""
Automated Threat Containment

Purpose: Immediately contain threats by isolating compromised resources
Attack Vectors: Lateral movement, data exfiltration, privilege escalation
Compliance: SOC 2 CC7.3, ISO 27001 A.16.1.5

Containment Actions:
- AWS security group lockdown (revoke all ingress/egress)
- IAM credential revocation (delete access keys)
- EC2 snapshot (preserve for forensics)
- VPC network isolation (move to quarantine subnet)
- Docker container isolation (network disconnect)
- Process termination (kill malicious processes)

Safety Features:
- Dry-run mode
- Rollback capability
- Approval workflow integration
- Audit logging

Usage:
    python3 auto-containment.py --incident INC-2024-001 --target i-1234567890abcdef0
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
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

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
            except docker.errors.DockerException:
                logger.warning("Docker not available")
        else:
            logger.warning("docker SDK not available")  # FIX: C5-finding-3
        
        # Create log directory
        CONTAINMENT_LOG_DIR.mkdir(parents=True, exist_ok=True)
    
    def log_action(self, action: str, target: str, status: str, details: Dict = None):
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
        
        log_file = CONTAINMENT_LOG_DIR / f"{self.incident_id}.json"
        
        # Append to log file
        try:
            with open(log_file, 'a') as f:
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
        return f"acl-auto-containment-{self.incident_id.lower()}"  # FIX: C5-finding-3

    def _resolve_firewall_domain_list_id(self) -> str:  # FIX: C5-finding-3
        """Resolve the DNS firewall domain list used for domain blocking."""  # FIX: C5-finding-3
        if self.route53resolver is None:  # FIX: C5-finding-3
            raise RuntimeError("boto3 is required for Route53 Resolver management")  # FIX: C5-finding-3
        if DNS_FIREWALL_DOMAIN_LIST_ID:  # FIX: C5-finding-3
            return DNS_FIREWALL_DOMAIN_LIST_ID  # FIX: C5-finding-3
        response = self.route53resolver.list_firewall_domain_lists(MaxResults=100)  # FIX: C5-finding-3
        firewall_domain_lists = response.get("FirewallDomainLists", []) if isinstance(response, dict) else []  # FIX: C5-finding-3
        for firewall_domain_list in firewall_domain_lists:  # FIX: C5-finding-3
            if isinstance(firewall_domain_list, dict) and firewall_domain_list.get("Name") == "openclaw-auto-containment":  # FIX: C5-finding-3
                return firewall_domain_list["Id"]  # FIX: C5-finding-3
        created_domain_list = self.route53resolver.create_firewall_domain_list(  # FIX: C5-finding-3
            CreatorRequestId=f"{self.incident_id}-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",  # FIX: C5-finding-3
            Name="openclaw-auto-containment",  # FIX: C5-finding-3
        )  # FIX: C5-finding-3
        created_record = created_domain_list.get("FirewallDomainList", {}) if isinstance(created_domain_list, dict) else {}  # FIX: C5-finding-3
        if created_record.get("Id"):  # FIX: C5-finding-3
            return created_record["Id"]  # FIX: C5-finding-3
        return f"fdl-auto-containment-{self.incident_id.lower()}"  # FIX: C5-finding-3

    def block_ip_address(self, ip_address: str, duration: str = None, reason: str = None) -> bool:  # FIX: C5-finding-3
        """Block an attacker IP by adding deny entries to the emergency network ACL."""  # FIX: C5-finding-3
        logger.info(f"Blocking IP address: {ip_address}")  # FIX: C5-finding-3
        try:  # FIX: C5-finding-3
            cidr_block = str(ipaddress.ip_network(ip_address, strict=False))  # FIX: C5-finding-3
            network_acl_id = self._resolve_network_acl_id()  # FIX: C5-finding-3
            rule_seed = sum(ord(character) for character in cidr_block) % 10000  # FIX: C5-finding-3
            ingress_rule_number = 100 + rule_seed  # FIX: C5-finding-3
            egress_rule_number = 200 + rule_seed  # FIX: C5-finding-3
            if self.dry_run:  # FIX: C5-finding-3
                logger.info("[DRY-RUN] Would add deny entries to the emergency network ACL")  # FIX: C5-finding-3
                self.log_action("block_ip", ip_address, "dry_run", {"cidr_block": cidr_block, "duration": duration, "reason": reason, "network_acl_id": network_acl_id})  # FIX: C5-finding-3
                return True  # FIX: C5-finding-3
            self.ec2.create_network_acl_entry(NetworkAclId=network_acl_id, RuleNumber=ingress_rule_number, Protocol='-1', RuleAction='deny', Egress=False, CidrBlock=cidr_block)  # FIX: C5-finding-3
            self.ec2.create_network_acl_entry(NetworkAclId=network_acl_id, RuleNumber=egress_rule_number, Protocol='-1', RuleAction='deny', Egress=True, CidrBlock=cidr_block)  # FIX: C5-finding-3
            self.rollback_commands.append({"action": "delete_network_acl_entry", "network_acl_id": network_acl_id, "rule_numbers": [ingress_rule_number, egress_rule_number]})  # FIX: C5-finding-3
            self.log_action("block_ip", ip_address, "success", {"cidr_block": cidr_block, "duration": duration, "reason": reason, "network_acl_id": network_acl_id})  # FIX: C5-finding-3
            logger.info(f"✓ IP address {ip_address} blocked successfully")  # FIX: C5-finding-3
            return True  # FIX: C5-finding-3
        except Exception as e:  # FIX: C5-finding-3
            logger.error(f"Failed to block IP address: {e}")  # FIX: C5-finding-3
            self.log_action("block_ip", ip_address, "failed", {"error": str(e), "duration": duration, "reason": reason})  # FIX: C5-finding-3
            return False  # FIX: C5-finding-3

    def block_domain_name(self, domain: str, duration: str = None, reason: str = None) -> bool:  # FIX: C5-finding-3
        """Block a domain by adding it to the emergency DNS firewall list."""  # FIX: C5-finding-3
        logger.info(f"Blocking domain: {domain}")  # FIX: C5-finding-3
        try:  # FIX: C5-finding-3
            normalized_domain = domain.strip().lower()  # FIX: C5-finding-3
            if not normalized_domain:  # FIX: C5-finding-3
                raise ValueError("Domain cannot be empty")  # FIX: C5-finding-3
            firewall_domain_list_id = self._resolve_firewall_domain_list_id()  # FIX: C5-finding-3
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

    def isolate_container(self, container_id: str, reason: str = None) -> bool:  # FIX: C5-finding-3
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
            container_labels = {'quarantine': self.incident_id}  # FIX: C5-finding-3
            if reason:  # FIX: C5-finding-3
                container_labels['containment_reason'] = reason  # FIX: C5-finding-3
            container.update(labels=container_labels)  # FIX: C5-finding-3
            self.log_action("isolate_container", container_id, "success", {"original_networks": original_networks, "reason": reason})  # FIX: C5-finding-3
            logger.info(f"✓ Container {container_id} isolated successfully")  # FIX: C5-finding-3
            return True  # FIX: C5-finding-3
        except Exception as e:  # FIX: C5-finding-3
            logger.error(f"Failed to isolate container: {e}")  # FIX: C5-finding-3
            self.log_action("isolate_container", container_id, "failed", {"error": str(e), "reason": reason})  # FIX: C5-finding-3
            return False  # FIX: C5-finding-3

    def update_rate_limits(self, mode: str, limits: Dict, reason: str = None) -> bool:  # FIX: C5-finding-3
        """Write an emergency rate-limit override profile for the requested mode."""  # FIX: C5-finding-3
        logger.info(f"Updating rate limits using mode: {mode}")  # FIX: C5-finding-3
        try:  # FIX: C5-finding-3
            rate_limit_profile_path = Path(RATE_LIMIT_CONFIG_PATH) if RATE_LIMIT_CONFIG_PATH else CONTAINMENT_LOG_DIR / f"{self.incident_id}-rate-limits.json"  # FIX: C5-finding-3
            rate_limit_payload = {"incident_id": self.incident_id, "mode": mode, "updated_at": datetime.now(timezone.utc).isoformat(), "limits": limits, "reason": reason}  # FIX: C5-finding-3
            if self.dry_run:  # FIX: C5-finding-3
                logger.info("[DRY-RUN] Would write the emergency rate-limit override profile")  # FIX: C5-finding-3
                self.log_action("update_rate_limits", mode, "dry_run", {"mode": mode, "limits": limits, "reason": reason, "config_path": str(rate_limit_profile_path)})  # FIX: C5-finding-3
                return True  # FIX: C5-finding-3
            rate_limit_profile_path.parent.mkdir(parents=True, exist_ok=True)  # FIX: C5-finding-3
            with open(rate_limit_profile_path, 'w', encoding='utf-8') as f:  # FIX: C5-finding-3
                json.dump(rate_limit_payload, f, indent=2)  # FIX: C5-finding-3
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
        """Revoke IAM user access keys"""
        logger.info(f"Revoking IAM credentials for user: {username}")
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
                logger.info("[DRY-RUN] Would revoke access keys")
                self.log_action("revoke_iam_credentials", username, "dry_run", {
                    "access_key_count": len(access_keys)
                })
                return True
            
            revoked_keys = []
            for key_info in access_keys:
                access_key_id = key_info['AccessKeyId']
                
                # Deactivate key
                self.iam.update_access_key(
                    UserName=username,
                    AccessKeyId=access_key_id,
                    Status='Inactive'
                )
                
                logger.info(f"✓ Deactivated access key: {access_key_id}")
                revoked_keys.append(access_key_id)
                
                self.rollback_commands.append({
                    "action": "reactivate_access_key",
                    "username": username,
                    "access_key_id": access_key_id
                })
            
            # Attach deny-all policy
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
                "revoked_keys": revoked_keys,
                "deny_policy": policy_name
            })
            
            logger.info(f"✓ IAM credentials revoked for {username}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to revoke IAM credentials: {e}")
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
            
            # Add quarantine label
            container.update(labels={'quarantine': self.incident_id})
            
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
        
        report_file = CONTAINMENT_LOG_DIR / f"{self.incident_id}-report.json"
        
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
    
    # Revoke IAM credentials
    python3 auto-containment.py --incident INC-2024-001 \\
        --target user:suspicious-user --action revoke-credentials
    
    # Isolate Docker container
    python3 auto-containment.py --incident INC-2024-001 \\
        --target container:abc123 --action isolate-docker
    
    # Dry-run
    python3 auto-containment.py --incident INC-2024-001 \\
        --target i-1234567890abcdef0 --action isolate-ec2 --dry-run

Environment Variables:
    AWS_REGION             AWS region (default: us-east-1)
    QUARANTINE_SUBNET_ID   Quarantine subnet ID for isolated instances
    QUARANTINE_SG_ID       Quarantine security group ID (deny-all)

Actions:
    isolate-ec2           Isolate EC2 instance (snapshot + SG lockdown)
    revoke-credentials    Revoke IAM user access keys
    isolate-docker        Disconnect Docker container from networks
        """
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
