#!/usr/bin/env python3
"""
Incident Impact Analyzer

Purpose: Calculate blast radius and business impact of security incidents
Attack Vectors: Scope creep, hidden compromises, lateral movement tracking
Compliance: SOC 2 CC7.3, ISO 27001 A.16.1.4, GDPR Article 33

Analysis:
- Resource dependency graph traversal
- Data classification impact assessment
- User/customer impact calculation
- Financial impact estimation
- GDPR breach notification requirements

Usage:
    python3 impact-analyzer.py --incident INC-2024-001 --resource i-1234567890abcdef0
    python3 impact-analyzer.py --incident INC-2024-001 --user compromised-user

Dependencies: boto3, networkx

Related: auto-containment.py, notification-manager.py
"""

import argparse
import json
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Dict, Set

try:
    import boto3
    import networkx as nx
except ImportError:
    print("ERROR: Missing dependencies. Install with: pip install boto3 networkx")
    sys.exit(1)

# Configuration
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
REVENUE_PER_USER_HOUR = float(os.getenv("REVENUE_PER_USER_HOUR", "5.0"))

# Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class ImpactAnalyzer:
    """Analyze incident blast radius"""
    
    def __init__(self, incident_id: str):
        self.incident_id = incident_id
        self.graph = nx.DiGraph()
        self.affected_resources = set()
        self.ec2 = boto3.client('ec2', region_name=AWS_REGION)
        self.iam = boto3.client('iam')
        
        self.impact_report = {
            "incident_id": incident_id,
            "analyzed_at": datetime.now(timezone.utc).isoformat(),
            "blast_radius": {}, "data_impact": {},
            "user_impact": {}, "financial_impact": {}
        }
    
    def analyze_ec2_blast_radius(self, instance_id: str):
        """Analyze EC2 instance dependencies"""
        logger.info(f"Analyzing EC2 blast radius: {instance_id}")
        
        try:
            response = self.ec2.describe_instances(InstanceIds=[instance_id])
            instance = response['Reservations'][0]['Instances'][0]
            
            # Add to graph
            self.graph.add_node(instance_id, type='ec2', vpc=instance['VpcId'])
            self.affected_resources.add(instance_id)
            
            # Security groups
            for sg in instance['SecurityGroups']:
                sg_id = sg['GroupId']
                self.graph.add_node(sg_id, type='security_group')
                self.graph.add_edge(instance_id, sg_id)
                self.affected_resources.add(sg_id)
            
            # IAM role
            if 'IamInstanceProfile' in instance:
                role_arn = instance['IamInstanceProfile']['Arn']
                role_name = role_arn.split('/')[-1]
                self.graph.add_node(role_name, type='iam_role')
                self.graph.add_edge(instance_id, role_name)
                self.affected_resources.add(role_name)
            
            self.impact_report['blast_radius']['total_resources'] = len(self.affected_resources)
            self.impact_report['blast_radius']['ec2_instances'] = 1
            
        except Exception as e:
            logger.error(f"Failed to analyze EC2: {e}")
    
    def estimate_financial_impact(self, downtime_hours: float = 4.0, affected_users: int = 100):
        """Estimate financial impact"""
        logger.info("Calculating financial impact...")
        
        # Revenue loss
        revenue_loss = affected_users * downtime_hours * REVENUE_PER_USER_HOUR
        
        # Response costs
        response_cost = downtime_hours * 500  # $500/hour IR cost
        
        # Compliance fines (estimated)
        compliance_risk = 50000 if self.impact_report['data_impact'].get('gdpr_breach') else 0
        
        total_impact = revenue_loss + response_cost + compliance_risk
        
        self.impact_report['financial_impact'] = {
            "revenue_loss_usd": round(revenue_loss, 2),
            "response_cost_usd": round(response_cost, 2),
            "compliance_risk_usd": compliance_risk,
            "total_estimated_impact_usd": round(total_impact, 2),
            "assumptions": {
                "downtime_hours": downtime_hours,
                "affected_users": affected_users,
                "revenue_per_user_hour": REVENUE_PER_USER_HOUR
            }
        }
        
        logger.info(f"Estimated financial impact: ${total_impact:,.2f}")
    
    def assess_data_classification_impact(self, data_types: list):
        """Assess impact based on data classification"""
        logger.info("Assessing data classification impact...")
        
        highest_severity = "LOW"
        gdpr_breach = False
        
        severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        
        for data_type in data_types:
            if data_type == "PII":
                highest_severity = "CRITICAL"
                gdpr_breach = True
            elif data_type == "Credentials":
                highest_severity = max(highest_severity, "CRITICAL", key=lambda x: severity_order.get(x, 0))
            elif data_type == "Financial":
                highest_severity = max(highest_severity, "HIGH", key=lambda x: severity_order.get(x, 0))
        
        self.impact_report['data_impact'] = {
            "affected_data_types": data_types,
            "highest_severity": highest_severity,
            "gdpr_breach": gdpr_breach,
            "notification_required": gdpr_breach,
            "notification_deadline_hours": 72 if gdpr_breach else None
        }
    
    def generate_report(self, output_path: str = None):
        """Generate impact analysis report"""
        logger.info("Generating impact report...")
        
        if output_path:
            with open(output_path, 'w') as f:
                json.dump(self.impact_report, f, indent=2)
            logger.info(f"✓ Report saved: {output_path}")
        
        # Print summary
        print("\n" + "=" * 80)
        print(f"Impact Analysis: {self.incident_id}")
        print("=" * 80)
        print(f"Affected Resources: {self.impact_report['blast_radius'].get('total_resources', 0)}")
        print(f"Data Impact Severity: {self.impact_report['data_impact'].get('highest_severity', 'N/A')}")
        print(f"GDPR Breach: {'YES' if self.impact_report['data_impact'].get('gdpr_breach') else 'NO'}")
        
        if 'financial_impact' in self.impact_report:
            print(f"\nFinancial Impact: ${self.impact_report['financial_impact']['total_estimated_impact_usd']:,.2f}")
        
        print("=" * 80)


def main():
    parser = argparse.ArgumentParser(description="Analyze incident impact")
    parser.add_argument("--incident", required=True, help="Incident ID")
    parser.add_argument("--resource", help="Affected resource ID (e.g., i-1234567890)")
    parser.add_argument("--data-types", help="Comma-separated data types (e.g., PII,Credentials)")
    parser.add_argument("--downtime", type=float, default=4.0, help="Estimated downtime (hours)")
    parser.add_argument("--users", type=int, default=100, help="Affected user count")
    parser.add_argument("--output", help="Output JSON file path")
    
    args = parser.parse_args()
    
    analyzer = ImpactAnalyzer(args.incident)
    
    if args.resource:
        if args.resource.startswith('i-'):
            analyzer.analyze_ec2_blast_radius(args.resource)
    
    if args.data_types:
        data_types = [t.strip() for t in args.data_types.split(',')]
        analyzer.assess_data_classification_impact(data_types)
    
    analyzer.estimate_financial_impact(args.downtime, args.users)
    analyzer.generate_report(args.output)
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
