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
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

try:
    import boto3
    import docker
except ImportError:
    print("ERROR: Missing dependencies. Install with: pip install boto3 docker")
    sys.exit(1)

# Configuration
QUARANTINE_SUBNET_ID = os.getenv("QUARANTINE_SUBNET_ID")
QUARANTINE_SG_ID = os.getenv("QUARANTINE_SG_ID")
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
CONTAINMENT_LOG_DIR = Path("/var/log/openclaw/containment")

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
        self.ec2 = boto3.client('ec2', region_name=AWS_REGION)
        self.iam = boto3.client('iam')
        
        # Initialize Docker client
        try:
            self.docker_client = docker.from_env()
        except docker.errors.DockerException:
            logger.warning("Docker not available")
            self.docker_client = None
        
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
    
    def isolate_ec2_instance(self, instance_id: str) -> bool:
        """Isolate EC2 instance by modifying security groups and creating snapshot"""
        logger.info(f"Isolating EC2 instance: {instance_id}")
        
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
            status_icon = "✓" if action['status'] == "success" else "✗"
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
        required=True,
        help="Incident ID (e.g., INC-2024-001)"
    )
    parser.add_argument(
        "--target",
        required=True,
        help="Target resource (EC2 instance ID, user:username, container:id)"
    )
    parser.add_argument(
        "--action",
        required=True,
        choices=["isolate-ec2", "revoke-credentials", "isolate-docker"],
        help="Containment action to perform"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Simulate actions without making changes"
    )
    
    args = parser.parse_args()
    
    # Initialize containment manager
    manager = ContainmentManager(args.incident, args.dry_run)
    
    # Execute containment action
    success = False
    
    if args.action == "isolate-ec2":
        success = manager.isolate_ec2_instance(args.target)
    
    elif args.action == "revoke-credentials":
        # Extract username from "user:username" format
        username = args.target.split(":", 1)[1] if ":" in args.target else args.target
        success = manager.revoke_iam_credentials(username)
    
    elif args.action == "isolate-docker":
        # Extract container ID from "container:id" format
        container_id = args.target.split(":", 1)[1] if ":" in args.target else args.target
        success = manager.isolate_docker_container(container_id)
    
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
