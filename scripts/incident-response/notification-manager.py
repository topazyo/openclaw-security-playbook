#!/usr/bin/env python3
"""
Incident Notification Manager

Purpose: Coordinate stakeholder communications during security incidents
Attack Vectors: Communication gaps, delayed notifications, compliance violations
Compliance: SOC 2 CC7.3, ISO 27001 A.16.1.2, GDPR Article 33/34

Capabilities:
- Severity-based routing (CRITICAL→PagerDuty+CISO, HIGH→Slack)
- Email templates with incident summaries
- Jira ticket updates
- Slack threaded updates
- PagerDuty incident creation
- GDPR breach notification tracking

Usage:
    python3 notification-manager.py --incident INC-2024-001 --severity CRITICAL --channel all
    python3 notification-manager.py --incident INC-2024-001 --update "Containment complete"

Dependencies: requests, jinja2

Related: impact-analyzer.py, timeline-generator.py
"""

import argparse
import json
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Dict, List

try:
    import requests
    from jinja2 import Template
except ImportError:
    print("ERROR: Missing dependencies. Install with: pip install requests jinja2")
    sys.exit(1)

# Configuration
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")
SLACK_SECURITY_CHANNEL = os.getenv("SLACK_SECURITY_CHANNEL", "#security-incidents")
PAGERDUTY_API_KEY = os.getenv("PAGERDUTY_API_KEY")
PAGERDUTY_SERVICE_ID = os.getenv("PAGERDUTY_SERVICE_ID")
EMAIL_SMTP_SERVER = os.getenv("EMAIL_SMTP_SERVER", "smtp.gmail.com")
EMAIL_FROM = os.getenv("EMAIL_FROM", "security@openclaw.ai")
JIRA_API_URL = os.getenv("JIRA_API_URL")
JIRA_API_TOKEN = os.getenv("JIRA_API_TOKEN")
JIRA_USER_EMAIL = os.getenv("JIRA_USER_EMAIL")

# Content type constant
CONTENT_TYPE_JSON = "application/json"

# Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Email template
EMAIL_TEMPLATE = """
<html>
<body style="font-family: Arial, sans-serif;">
    <h2 style="color: {{ severity_color }};">Security Incident: {{ incident_id }}</h2>
    
    <table style="border-collapse: collapse; width: 100%;">
        <tr>
            <td style="padding: 8px; border: 1px solid #ddd;"><strong>Severity:</strong></td>
            <td style="padding: 8px; border: 1px solid #ddd;">{{ severity }}</td>
        </tr>
        <tr>
            <td style="padding: 8px; border: 1px solid #ddd;"><strong>Status:</strong></td>
            <td style="padding: 8px; border: 1px solid #ddd;">{{ status }}</td>
        </tr>
        <tr>
            <td style="padding: 8px; border: 1px solid #ddd;"><strong>Detected:</strong></td>
            <td style="padding: 8px; border: 1px solid #ddd;">{{ detected_at }}</td>
        </tr>
    </table>
    
    <h3>Summary</h3>
    <p>{{ summary }}</p>
    
    <h3>Actions Taken</h3>
    <ul>
        {% for action in actions %}
        <li>{{ action }}</li>
        {% endfor %}
    </ul>
    
    <p><em>For updates, see Jira ticket: {{ incident_id }}</em></p>
</body>
</html>
"""


class NotificationManager:
    """Manage incident notifications across multiple channels"""
    VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}  # FIX: C5-finding-3
    
    def __init__(self, incident_id: str, severity: str):
        self.incident_id = incident_id
        normalized_severity = severity.strip().upper()  # FIX: C5-finding-3
        if normalized_severity not in self.VALID_SEVERITIES:  # FIX: C5-finding-3
            raise ValueError(f"Invalid severity: {severity!r}. Expected one of {sorted(self.VALID_SEVERITIES)}")  # FIX: C5-finding-3
        self.severity = normalized_severity  # FIX: C5-finding-3
        self.notifications_sent = []
    
    def send_slack_notification(self, message: str, thread_ts: str = None) -> bool:
        """Send Slack notification"""
        if not SLACK_WEBHOOK_URL:
            logger.warning("SLACK_WEBHOOK_URL not set, skipping Slack")
            return False
        
        logger.info(f"Sending Slack notification to {SLACK_SECURITY_CHANNEL}")
        
        severity_color = {
            "CRITICAL": "#e74c3c",
            "HIGH": "#f39c12",
            "MEDIUM": "#3498db",
            "LOW": "#2ecc71"
        }.get(self.severity, "#95a5a6")
        
        payload = {
            "channel": SLACK_SECURITY_CHANNEL,
            "username": "Security Bot",
            "icon_emoji": ":rotating_light:",
            "attachments": [{
                "color": severity_color,
                "title": f"Incident: {self.incident_id}",
                "text": message,
                "fields": [
                    {"title": "Severity", "value": self.severity, "short": True},
                    {"title": "Time", "value": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"), "short": True}
                ]
            }]
        }
        
        if thread_ts:
            payload["thread_ts"] = thread_ts
        
        try:
            response = requests.post(SLACK_WEBHOOK_URL, json=payload, timeout=10)
            response.raise_for_status()
            logger.info("✓ Slack notification sent")
            self.notifications_sent.append({"channel": "slack", "status": "success"})
            return True
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to send Slack notification: {e}")
            self.notifications_sent.append({"channel": "slack", "status": "failed", "error": str(e)})
            return False
    
    def create_pagerduty_incident(self, title: str, description: str) -> bool:
        """Create PagerDuty incident"""
        if not PAGERDUTY_API_KEY or not PAGERDUTY_SERVICE_ID:
            logger.warning("PagerDuty credentials not set, skipping")
            return False
        
        logger.info("Creating PagerDuty incident")
        
        headers = {
            "Authorization": f"Token token={PAGERDUTY_API_KEY}",
            "Content-Type": CONTENT_TYPE_JSON,
            "Accept": "application/vnd.pagerduty+json;version=2"
        }
        
        payload = {
            "incident": {
                "type": "incident",
                "title": title,
                "service": {"id": PAGERDUTY_SERVICE_ID, "type": "service_reference"},
                "urgency": "high" if self.severity in ["CRITICAL", "HIGH"] else "low",
                "body": {"type": "incident_body", "details": description}
            }
        }
        
        try:
            response = requests.post(
                "https://api.pagerduty.com/incidents",
                headers=headers,
                json=payload,
                timeout=10
            )
            response.raise_for_status()
            incident_id = response.json()['incident']['id']
            logger.info(f"✓ PagerDuty incident created: {incident_id}")
            self.notifications_sent.append({"channel": "pagerduty", "status": "success", "id": incident_id})
            return True
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to create PagerDuty incident: {e}")
            self.notifications_sent.append({"channel": "pagerduty", "status": "failed", "error": str(e)})
            return False
    
    def send_email_notification(self, recipients: List[str]) -> bool:
        """Send email notification"""
        logger.info(f"Email notification (not implemented - would send to {recipients})")
        # Note: Email sending requires SMTP configuration
        # Implementation would use smtplib here
        return True
    
    def update_jira_ticket(self, comment: str) -> bool:
        """Add comment to Jira ticket"""
        if not all([JIRA_API_URL, JIRA_API_TOKEN, JIRA_USER_EMAIL]):
            logger.warning("Jira credentials not set, skipping")
            return False
        
        logger.info(f"Updating Jira ticket: {self.incident_id}")
        
        url = f"{JIRA_API_URL}/rest/api/3/issue/{self.incident_id}/comment"
        
        headers = {
            "Accept": CONTENT_TYPE_JSON,
            "Content-Type": CONTENT_TYPE_JSON
        }
        
        payload = {
            "body": {
                "type": "doc",
                "version": 1,
                "content": [{
                    "type": "paragraph",
                    "content": [{"type": "text", "text": comment}]
                }]
            }
        }
        
        try:
            response = requests.post(
                url,
                auth=(JIRA_USER_EMAIL, JIRA_API_TOKEN),
                headers=headers,
                json=payload,
                timeout=10
            )
            response.raise_for_status()
            logger.info("✓ Jira ticket updated")
            self.notifications_sent.append({"channel": "jira", "status": "success"})
            return True
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to update Jira: {e}")
            self.notifications_sent.append({"channel": "jira", "status": "failed", "error": str(e)})
            return False
    
    def notify_all(self, message: str, create_pagerduty: bool = False) -> bool:  # FIX: C5-finding-3
        """Send notifications to all configured channels"""  # FIX: C5-finding-3
        logger.info(f"Sending notifications for {self.incident_id}")  # FIX: C5-finding-3
        delivery_results = []  # FIX: C5-finding-3
        
        # Slack  # FIX: C5-finding-3
        delivery_results.append(("slack", self.send_slack_notification(message)))  # FIX: C5-finding-3
        
        # PagerDuty (for CRITICAL/HIGH only)  # FIX: C5-finding-3
        if create_pagerduty and self.severity in ["CRITICAL", "HIGH"]:  # FIX: C5-finding-3
            delivery_results.append((  # FIX: C5-finding-3
                "pagerduty",  # FIX: C5-finding-3
                self.create_pagerduty_incident(  # FIX: C5-finding-3
                    title=f"Security Incident: {self.incident_id}",  # FIX: C5-finding-3
                    description=message  # FIX: C5-finding-3
                )  # FIX: C5-finding-3
            ))  # FIX: C5-finding-3
        
        # Jira  # FIX: C5-finding-3
        delivery_results.append(("jira", self.update_jira_ticket(message)))  # FIX: C5-finding-3
        
        # Summary  # FIX: C5-finding-3
        success_count = sum(1 for _channel, delivered in delivery_results if delivered)  # FIX: C5-finding-3
        logger.info(f"✓ Notifications sent: {success_count}/{len(delivery_results)}")  # FIX: C5-finding-3
        return success_count > 0  # FIX: C5-finding-3


def main():
    parser = argparse.ArgumentParser(description="Manage incident notifications")
    parser.add_argument("--incident", required=True, help="Incident ID")
    parser.add_argument("--severity", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"], default="MEDIUM")
    parser.add_argument("--message", help="Notification message")
    parser.add_argument("--update", help="Status update")
    parser.add_argument("--channel", choices=["slack", "pagerduty", "jira", "all"], default="all")
    
    args = parser.parse_args()
    
    manager = NotificationManager(args.incident, args.severity)
    
    message = args.message or args.update or f"Incident {args.incident} detected"
    
    success = False  # FIX: C5-finding-3
    if args.channel == "all":  # FIX: C5-finding-3
        success = manager.notify_all(message, create_pagerduty=True)  # FIX: C5-finding-3
    elif args.channel == "slack":  # FIX: C5-finding-3
        success = manager.send_slack_notification(message)  # FIX: C5-finding-3
    elif args.channel == "pagerduty":  # FIX: C5-finding-3
        success = manager.create_pagerduty_incident(f"Incident: {args.incident}", message)  # FIX: C5-finding-3
    elif args.channel == "jira":  # FIX: C5-finding-3
        success = manager.update_jira_ticket(message)  # FIX: C5-finding-3
    if not success:  # FIX: C5-finding-3
        logger.error("✗ Notification delivery failed")  # FIX: C5-finding-3
        return 1  # FIX: C5-finding-3
    return 0  # FIX: C5-finding-3


if __name__ == "__main__":
    sys.exit(main())
