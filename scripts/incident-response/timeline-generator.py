#!/usr/bin/env python3
"""
Incident Timeline Generator

Purpose: Reconstruct detailed incident timelines from multiple data sources
Attack Vectors: Timeline gaps, correlation failures, incomplete attribution
Compliance: SOC 2 CC7.3, ISO 27001 A.16.1.7

Data Sources:
- Elasticsearch (openclaw-logs-*)
- AWS CloudWatch Logs
- Jira incident tickets
- CloudTrail events

Output Formats:
- Markdown timeline (human-readable)
- JSON (machine-readable)
- HTML interactive timeline (vis.js)
- CSV for spreadsheet analysis

Usage:
    python3 timeline-generator.py --incident INC-2024-001 --output timeline.md
    python3 timeline-generator.py --incident INC-2024-001 --format html --interactive

Dependencies: elasticsearch, boto3, pandas

Related: forensics-collector.py, impact-analyzer.py
"""

import argparse
import json
import logging
import os
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional

try:
    from elasticsearch import Elasticsearch
    import boto3
    import pandas as pd
except ImportError:
    print("ERROR: Missing dependencies. Install with: pip install elasticsearch boto3 pandas")
    sys.exit(1)

# Configuration
ES_URL = os.getenv("ELASTICSEARCH_URL", "http://localhost:9200")
ES_INDEX_PATTERN = "openclaw-logs-*"
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
JIRA_API_URL = os.getenv("JIRA_API_URL")
JIRA_API_TOKEN = os.getenv("JIRA_API_TOKEN")
JIRA_USER_EMAIL = os.getenv("JIRA_USER_EMAIL")

# Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# HTML template for interactive timeline
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Incident Timeline: {incident_id}</title>
    <script src="https://unpkg.com/vis-timeline@7.7.0/standalone/umd/vis-timeline-graph2d.min.js"></script>
    <link href="https://unpkg.com/vis-timeline@7.7.0/styles/vis-timeline-graph2d.min.css" rel="stylesheet" />
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #2c3e50; }}
        #timeline {{ height: 600px; border: 1px solid #ccc; }}
        .critical {{ background-color: #e74c3c !important; }}
        .high {{ background-color: #f39c12 !important; }}
        .medium {{ background-color: #3498db !important; }}
        .low {{ background-color: #2ecc71 !important; }}
    </style>
</head>
<body>
    <h1>Incident Timeline: {incident_id}</h1>
    <p><strong>Generated:</strong> {generated_date}</p>
    <p><strong>Total Events:</strong> {total_events}</p>
    <div id="timeline"></div>
    
    <script>
        var container = document.getElementById('timeline');
        var items = new vis.DataSet({items_json});
        
        var options = {{
            width: '100%',
            height: '600px',
            stack: true,
            showMajorLabels: true,
            showMinorLabels: true,
            zoomMin: 60000,  // 1 minute
            zoomMax: 31536000000  // 1 year
        }};
        
        var timeline = new vis.Timeline(container, items, options);
    </script>
</body>
</html>
"""


class TimelineGenerator:
    """Generate incident timelines from multiple sources"""
    
    def __init__(self, incident_id: str, lookback_hours: int = 24):
        self.incident_id = incident_id
        self.lookback_hours = lookback_hours
        self.start_time = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)
        self.events = []
        
        # Initialize clients
        self.es = Elasticsearch([ES_URL])
        self.cloudwatch = boto3.client('logs', region_name=AWS_REGION)
        self.cloudtrail = boto3.client('cloudtrail', region_name=AWS_REGION)
    
    def fetch_elasticsearch_events(self) -> List[Dict]:
        """Fetch events from Elasticsearch"""
        logger.info(f"Fetching events from Elasticsearch (last {self.lookback_hours}h)...")
        
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {"gte": self.start_time.isoformat()}}}
                    ],
                    "should": [
                        {"match": {"incident_id": self.incident_id}},
                        {"match": {"event_type": "SECURITY_ALERT"}},
                        {"match": {"event_type": "AUTHENTICATION_FAILURE"}},
                        {"match": {"event_type": "PRIVILEGE_ESCALATION"}}
                    ],
                    "minimum_should_match": 1
                }
            },
            "size": 10000,
            "sort": [{"@timestamp": "asc"}]
        }
        
        try:
            response = self.es.search(index=ES_INDEX_PATTERN, body=query)
            hits = response['hits']['hits']
            
            events = []
            for hit in hits:
                source = hit['_source']
                events.append({
                    'timestamp': source.get('@timestamp'),
                    'source': 'elasticsearch',
                    'event_type': source.get('event_type', 'UNKNOWN'),
                    'severity': source.get('severity', 'INFO'),
                    'user': source.get('user', {}).get('name', 'unknown'),
                    'source_ip': source.get('source', {}).get('ip', 'unknown'),
                    'message': source.get('message', ''),
                    'details': source
                })
            
            logger.info(f"Fetched {len(events)} events from Elasticsearch")
            return events
            
        except Exception as e:
            logger.error(f"Failed to fetch from Elasticsearch: {e}")
            return []
    
    def fetch_cloudtrail_events(self) -> List[Dict]:
        """Fetch events from AWS CloudTrail"""
        logger.info(f"Fetching events from CloudTrail (last {self.lookback_hours}h)...")
        
        try:
            response = self.cloudtrail.lookup_events(
                StartTime=self.start_time,
                MaxResults=1000
            )
            
            events = []
            for event in response.get('Events', []):
                event_data = json.loads(event.get('CloudTrailEvent', '{}'))
                
                events.append({
                    'timestamp': event['EventTime'].isoformat(),
                    'source': 'cloudtrail',
                    'event_type': event['EventName'],
                    'severity': 'INFO',
                    'user': event.get('Username', 'unknown'),
                    'source_ip': event_data.get('sourceIPAddress', 'unknown'),
                    'message': f"{event['EventName']} by {event.get('Username')}",
                    'details': event_data
                })
            
            logger.info(f"Fetched {len(events)} events from CloudTrail")
            return events
            
        except Exception as e:
            logger.error(f"Failed to fetch from CloudTrail: {e}")
            return []
    
    def correlate_events(self) -> List[Dict]:
        """Correlate events by user, IP, and time proximity"""
        logger.info("Correlating events...")
        
        # Sort by timestamp
        sorted_events = sorted(self.events, key=lambda x: x['timestamp'])
        
        # Group by user and IP
        user_groups = defaultdict(list)
        ip_groups = defaultdict(list)
        
        for event in sorted_events:
            user_groups[event['user']].append(event)
            ip_groups[event['source_ip']].append(event)
        
        # Add correlation metadata
        for event in sorted_events:
            event['correlation'] = {
                'user_event_count': len(user_groups[event['user']]),
                'ip_event_count': len(ip_groups[event['source_ip']]),
                'suspicious_user': len(user_groups[event['user']]) > 100,
                'suspicious_ip': len(ip_groups[event['source_ip']]) > 50
            }
        
        return sorted_events
    
    def generate_markdown(self, output_path: Path):
        """Generate Markdown timeline"""
        logger.info(f"Generating Markdown timeline: {output_path}")
        
        with open(output_path, 'w') as f:
            f.write(f"# Incident Timeline: {self.incident_id}\n\n")
            f.write(f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n")
            f.write(f"**Period:** Last {self.lookback_hours} hours\n\n")
            f.write(f"**Total Events:** {len(self.events)}\n\n")
            f.write("---\n\n")
            
            # Group by date
            events_by_date = defaultdict(list)
            for event in self.events:
                date = event['timestamp'][:10]
                events_by_date[date].append(event)
            
            # Write timeline
            for date in sorted(events_by_date.keys()):
                f.write(f"## {date}\n\n")
                
                for event in events_by_date[date]:
                    time = event['timestamp'][11:19]
                    severity_icon = {
                        'CRITICAL': '🔴',
                        'HIGH': '🟠',
                        'MEDIUM': '🟡',
                        'LOW': '🟢',
                        'INFO': 'ℹ️'
                    }.get(event['severity'], 'ℹ️')
                    
                    f.write(f"### {time} - {severity_icon} {event['event_type']}\n\n")
                    f.write(f"**Source:** {event['source']}\n\n")
                    f.write(f"**User:** {event['user']}  \n")
                    f.write(f"**IP:** {event['source_ip']}\n\n")
                    f.write(f"**Message:** {event['message']}\n\n")
                    
                    if event['correlation']['suspicious_user'] or event['correlation']['suspicious_ip']:
                        f.write("**⚠️ Suspicious Activity Detected**\n\n")
                    
                    f.write("---\n\n")
        
        logger.info(f"✓ Markdown timeline saved: {output_path}")
    
    def generate_json(self, output_path: Path):
        """Generate JSON timeline"""
        logger.info(f"Generating JSON timeline: {output_path}")
        
        timeline_data = {
            "incident_id": self.incident_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "lookback_hours": self.lookback_hours,
            "total_events": len(self.events),
            "events": self.events
        }
        
        with open(output_path, 'w') as f:
            json.dump(timeline_data, f, indent=2)
        
        logger.info(f"✓ JSON timeline saved: {output_path}")
    
    def generate_csv(self, output_path: Path):
        """Generate CSV timeline"""
        logger.info(f"Generating CSV timeline: {output_path}")
        
        # Flatten events for CSV
        flattened = []
        for event in self.events:
            flattened.append({
                'timestamp': event['timestamp'],
                'source': event['source'],
                'event_type': event['event_type'],
                'severity': event['severity'],
                'user': event['user'],
                'source_ip': event['source_ip'],
                'message': event['message'],
                'suspicious_user': event['correlation']['suspicious_user'],
                'suspicious_ip': event['correlation']['suspicious_ip']
            })
        
        df = pd.DataFrame(flattened)
        df.to_csv(output_path, index=False)
        
        logger.info(f"✓ CSV timeline saved: {output_path}")
    
    def generate_html(self, output_path: Path):
        """Generate interactive HTML timeline"""
        logger.info(f"Generating HTML timeline: {output_path}")
        
        # Prepare data for vis.js
        timeline_items = []
        for i, event in enumerate(self.events):
            severity_class = event['severity'].lower()
            
            timeline_items.append({
                'id': i,
                'content': f"{event['event_type']}<br/>{event['user']}@{event['source_ip']}",
                'start': event['timestamp'],
                'className': severity_class,
                'title': event['message']
            })
        
        # Render HTML        
        html_content = HTML_TEMPLATE.format(
            incident_id=self.incident_id,
            generated_date=datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'),
            total_events=len(self.events),
            items_json=json.dumps(timeline_items)
        )
        
        with open(output_path, 'w') as f:
            f.write(html_content)
        
        logger.info(f"✓ HTML timeline saved: {output_path}")
    
    def generate(self, output_path: Path, output_format: str = "markdown"):
        """Generate timeline in specified format"""
        logger.info(f"Generating timeline for incident: {self.incident_id}")
        
        # Fetch events from all sources
        self.events.extend(self.fetch_elasticsearch_events())
        self.events.extend(self.fetch_cloudtrail_events())
        
        if not self.events:
            logger.warning("No events found for timeline")
            return
        
        # Correlate events
        self.events = self.correlate_events()
        
        # Generate output
        if output_format == "markdown":
            self.generate_markdown(output_path)
        elif output_format == "json":
            self.generate_json(output_path)
        elif output_format == "csv":
            self.generate_csv(output_path)
        elif output_format == "html":
            self.generate_html(output_path)
        else:
            logger.error(f"Unsupported format: {output_format}")
            return
        
        logger.info(f"✓ Timeline generation complete ({len(self.events)} events)")


def main():
    parser = argparse.ArgumentParser(
        description="Generate incident timelines from multiple sources",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Generate Markdown timeline
    python3 timeline-generator.py --incident INC-2024-001 --output timeline.md
    
    # Generate interactive HTML timeline
    python3 timeline-generator.py --incident INC-2024-001 --format html --output timeline.html
    
    # Generate CSV for analysis
    python3 timeline-generator.py --incident INC-2024-001 --format csv --output timeline.csv
    
    # Last 48 hours
    python3 timeline-generator.py --incident INC-2024-001 --hours 48

Environment Variables:
    ELASTICSEARCH_URL    Elasticsearch endpoint
    AWS_REGION           AWS region for CloudTrail/CloudWatch
    JIRA_API_URL         Jira API endpoint (optional)
    JIRA_API_TOKEN       Jira API token (optional)

Output Formats:
    markdown   Human-readable timeline with markdown formatting
    json       Machine-readable JSON with full event details
    csv        CSV for spreadsheet analysis
    html       Interactive HTML timeline (vis.js)
        """
    )
    
    parser.add_argument(
        "--incident",
        required=True,
        help="Incident ID (e.g., INC-2024-001)"
    )
    parser.add_argument(
        "--output",
        required=True,
        type=Path,
        help="Output file path"
    )
    parser.add_argument(
        "--format",
        choices=["markdown", "json", "csv", "html"],
        default="markdown",
        help="Output format (default: markdown)"
    )
    parser.add_argument(
        "--hours",
        type=int,
        default=24,
        help="Lookback hours (default: 24)"
    )
    
    args = parser.parse_args()
    
    # Generate timeline
    generator = TimelineGenerator(args.incident, args.hours)
    generator.generate(args.output, args.format)
    
    logger.info("✓ Timeline generation completed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
