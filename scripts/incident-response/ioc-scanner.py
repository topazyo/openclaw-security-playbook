#!/usr/bin/env python3
"""
Indicator of Compromise (IOC) Scanner

Purpose: Scan for known IOCs (malicious IPs, file hashes, domains)
Attack Vectors: APT detection, malware identification, C2 communication
Compliance: SOC 2 CC7.2, ISO 27001 A.12.2.1

Capabilities:
- IP reputation checks (AbuseIPDB)
- File hash scanning (VirusTotal, SHA-256)
- Domain analysis (DNS resolution, suspicious TLD detection, IP reputation of resolved address)

NOT IMPLEMENTED (unsupported integrations — not wired):
- WHOIS lookup
- Certificate transparency checks
- YARA rule matching
- Threat intelligence feed integration

Usage:
    python3 ioc-scanner.py --ip 192.0.2.1
    python3 ioc-scanner.py --hash sha256:abc123...
    python3 ioc-scanner.py --domain malicious.example.com
    python3 ioc-scanner.py --file /path/to/suspicious_file

Dependencies: requests

Related: forensics-collector.py, auto-containment.py
"""  # FIX: C5-H-02

import argparse
import hashlib
import json
import logging
import os
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict

try:
    import requests
except ImportError:
    print("ERROR: Missing dependencies. Install with: pip install requests")
    sys.exit(1)

# API Configuration
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

# Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class IOCScanner:
    """Scan for indicators of compromise"""
    
    def __init__(self):
        self.results = {
            "scan_timestamp": datetime.now(timezone.utc).isoformat(),
            "iocs_found": [],
            "threat_score": 0,
            "scan_results": [],
            "status": "success",
        }

    def _record_scan_result(self, scan_type: str, target: str, result: Dict):
        normalized_result = {"scan_type": scan_type, "target": target, **result}
        status = normalized_result.get("status", "success")
        normalized_result["status"] = status
        self.results["scan_results"].append(normalized_result)
        if status == "error":
            self.results["status"] = "error"
        elif status == "skipped" and self.results["status"] != "error":
            self.results["status"] = "skipped"
    
    def check_ip_reputation(self, ip_address: str) -> Dict:
        """Check IP reputation using AbuseIPDB"""
        logger.info(f"Checking IP reputation: {ip_address}")
        
        if not ABUSEIPDB_API_KEY:
            logger.warning("ABUSEIPDB_API_KEY not set")
            result = {"status": "skipped", "reason": "API key not configured"}
            self._record_scan_result("ip", ip_address, result)
            return result
        
        headers = {
            "Key": ABUSEIPDB_API_KEY,
            "Accept": "application/json"
        }
        
        params = {
            "ipAddress": ip_address,
            "maxAgeInDays": 90
        }
        
        try:
            response = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers=headers,
                params=params,
                timeout=10
            )
            response.raise_for_status()
            
            data = response.json()['data']
            abuse_score = data['abuseConfidenceScore']
            is_malicious = abuse_score > 50
            
            result = {
                "ip": ip_address,
                "abuse_score": abuse_score,
                "is_malicious": is_malicious,
                "total_reports": data['totalReports'],
                "country": data.get('countryCode'),
                "isp": data.get('isp'),
                "last_reported": data.get('lastReportedAt')
            }
            
            if is_malicious:
                self.results["iocs_found"].append({
                    "type": "malicious_ip",
                    "value": ip_address,
                    "confidence": abuse_score,
                    "source": "AbuseIPDB"
                })
                self.results["threat_score"] += abuse_score
            
            logger.info(f"✓ IP reputation: {abuse_score}/100 (malicious: {is_malicious})")
            self._record_scan_result("ip", ip_address, result)
            return result
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to check IP reputation: {e}")
            result = {"status": "error", "error": str(e)}
            self._record_scan_result("ip", ip_address, result)
            return result
    
    def check_file_hash(self, file_hash: str) -> Dict:
        """Check file hash using VirusTotal"""
        logger.info(f"Checking file hash: {file_hash[:16]}...")
        
        if not VIRUSTOTAL_API_KEY:
            logger.warning("VIRUSTOTAL_API_KEY not set")
            result = {"status": "skipped", "reason": "API key not configured"}
            self._record_scan_result("hash", file_hash, result)
            return result
        
        headers = {
            "x-apikey": VIRUSTOTAL_API_KEY
        }
        
        try:
            response = requests.get(
                f"https://www.virustotal.com/api/v3/files/{file_hash}",
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 404:
                logger.info("Hash not found in VirusTotal (likely clean or unknown)")
                result = {"status": "not_found", "is_malicious": False}
                self._record_scan_result("hash", file_hash, result)
                return result
            
            response.raise_for_status()
            
            data = response.json()['data']['attributes']
            last_analysis = data.get('last_analysis_stats', {})
            
            malicious_count = last_analysis.get('malicious', 0)
            total_scans = sum(last_analysis.values())
            detection_rate = (malicious_count / total_scans * 100) if total_scans > 0 else 0
            
            is_malicious = malicious_count > 5  # Threshold: 5+ detections
            
            result = {
                "hash": file_hash,
                "is_malicious": is_malicious,
                "malicious_detections": malicious_count,
                "total_scans": total_scans,
                "detection_rate": round(detection_rate, 2),
                "file_type": data.get('type_description'),
                "file_names": data.get('names', [])
            }
            
            if is_malicious:
                self.results["iocs_found"].append({
                    "type": "malicious_file",
                    "value": file_hash,
                    "confidence": detection_rate,
                    "source": "VirusTotal"
                })
                self.results["threat_score"] += detection_rate
            
            logger.info(f"✓ File hash: {malicious_count}/{total_scans} detections (malicious: {is_malicious})")
            self._record_scan_result("hash", file_hash, result)
            return result
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to check file hash: {e}")
            result = {"status": "error", "error": str(e)}
            self._record_scan_result("hash", file_hash, result)
            return result
    
    def analyze_domain(self, domain: str) -> Dict:
        """Analyze domain for malicious indicators.

        Implemented checks: DNS resolution, IP reputation of resolved address,
        suspicious TLD detection.

        Unsupported checks (not wired — produce explicit 'unsupported' state):
        - WHOIS domain age lookup
        - Certificate transparency log search
        """  # FIX: C5-H-02
        logger.info(f"Analyzing domain: {domain}")

        result = {
            "domain": domain,
            "is_malicious": False,
            "indicators": [],
            "status": "success",
            "unsupported_checks": ["whois", "certificate_transparency"],  # FIX: C5-H-02
        }

        # DNS resolution
        try:
            ip_address = socket.gethostbyname(domain)
            result["resolved_ip"] = ip_address

            # Check resolved IP reputation
            ip_result = self.check_ip_reputation(ip_address)
            if ip_result.get("status") in {"error", "skipped"}:
                result["status"] = ip_result["status"]
                result["reputation_error"] = ip_result.get("error") or ip_result.get("reason")
            if ip_result.get("is_malicious"):
                result["is_malicious"] = True
                result["indicators"].append("Resolves to malicious IP")
        except socket.gaierror:
            result["status"] = "error"
            result["dns_status"] = "No DNS record found"
            result["indicators"].append("DNS lookup failed")

        # Check for suspicious TLDs
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz']
        if any(domain.endswith(tld) for tld in suspicious_tlds):
            result["indicators"].append("Suspicious TLD")

        # WHOIS and certificate transparency checks are NOT implemented.  # FIX: C5-H-02
        # They are listed in result["unsupported_checks"] above.          # FIX: C5-H-02

        if result["is_malicious"]:
            self.results["iocs_found"].append({
                "type": "malicious_domain",
                "value": domain,
                "indicators": result["indicators"],
                "source": "Domain Analysis"
            })
            self.results["threat_score"] += 30
        
        logger.info(f"✓ Domain analysis: malicious={result['is_malicious']}")
        self._record_scan_result("domain", domain, result)
        return result
    
    def scan_file(self, file_path: Path) -> Dict:
        """Scan file by calculating SHA-256 hash and checking it against VirusTotal.

        Unsupported checks (not wired — produce explicit 'unsupported' state):
        - YARA rule matching
        - Threat intelligence feed lookup
        """  # FIX: C5-H-02
        logger.info(f"Scanning file: {file_path}")
        
        if not file_path.exists():
            logger.error(f"File not found: {file_path}")
            result = {"status": "error", "error": "File not found"}
            self._record_scan_result("file", str(file_path), result)
            return result
        
        # Calculate SHA-256 hash
        sha256_hash = hashlib.sha256()
        
        try:
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b''):
                    sha256_hash.update(chunk)
            
            file_hash = sha256_hash.hexdigest()
            logger.info(f"File hash (SHA-256): {file_hash}")
            
            # Check hash against VirusTotal
            vt_result = self.check_file_hash(file_hash)
            
            return {
                "file_path": str(file_path),
                "sha256": file_hash,
                "size_bytes": file_path.stat().st_size,
                "virustotal_result": vt_result,
                "status": vt_result.get("status", "success") if isinstance(vt_result, dict) else "success",
                "unsupported_checks": ["yara", "threat_feeds"],  # FIX: C5-H-02
            }
            
        except Exception as e:
            logger.error(f"Failed to scan file: {e}")
            result = {"status": "error", "error": str(e)}
            self._record_scan_result("file", str(file_path), result)
            return result
    
    def generate_report(self, output_path: str = None):
        """Generate IOC scan report.

        The report preserves the scan's non-success status so callers can detect
        failures and unsupported integration states without reading individual
        scan_results entries.  Unsupported integrations are listed explicitly —
        they do not contribute to threat_score and are not presented as findings.
        """  # FIX: C5-H-02

        # Calculate overall threat level
        if self.results["threat_score"] > 200:
            threat_level = "CRITICAL"
        elif self.results["threat_score"] > 100:
            threat_level = "HIGH"
        elif self.results["threat_score"] > 50:
            threat_level = "MEDIUM"
        else:
            threat_level = "LOW"

        self.results["overall_threat_level"] = threat_level  # FIX: C5-H-02

        # Collect all unsupported checks declared across individual scan results.  # FIX: C5-H-02
        all_unsupported: list = []  # FIX: C5-H-02
        for scan_result in self.results.get("scan_results", []):  # FIX: C5-H-02
            all_unsupported.extend(scan_result.get("unsupported_checks", []))  # FIX: C5-H-02
        # De-duplicate while preserving declaration order.  # FIX: C5-H-02
        seen: set = set()  # FIX: C5-H-02
        deduplicated_unsupported: list = []  # FIX: C5-H-02
        for check in all_unsupported:  # FIX: C5-H-02
            if check not in seen:  # FIX: C5-H-02
                seen.add(check)  # FIX: C5-H-02
                deduplicated_unsupported.append(check)  # FIX: C5-H-02
        self.results["unsupported_checks"] = deduplicated_unsupported  # FIX: C5-H-02

        if output_path:
            with open(output_path, 'w') as f:
                json.dump(self.results, f, indent=2)
            logger.info(f"Report saved: {output_path}")

        # Print summary — machine-readable status on the first line after header.  # FIX: C5-H-02
        print("\n" + "=" * 80)
        print("IOC Scan Summary")
        print("=" * 80)
        print(f"Status: {self.results['status']}")  # FIX: C5-H-02
        print(f"Threat Level: {threat_level}")
        print(f"Threat Score: {self.results['threat_score']}")
        print(f"IOCs Found: {len(self.results['iocs_found'])}")
        if deduplicated_unsupported:  # FIX: C5-H-02
            print(f"Unsupported checks (not performed): {', '.join(deduplicated_unsupported)}")  # FIX: C5-H-02

        if self.results["iocs_found"]:
            print("\nDetected IOCs:")
            for ioc in self.results["iocs_found"]:
                print(f"  - {ioc['type']}: {ioc['value']} (confidence: {ioc.get('confidence', 'N/A')})")

        print("=" * 80)


def main():
    parser = argparse.ArgumentParser(
        description="Scan for indicators of compromise",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Check IP reputation
    python3 ioc-scanner.py --ip 192.0.2.1
    
    # Check file hash
    python3 ioc-scanner.py --hash sha256:abc123def456...
    
    # Scan file
    python3 ioc-scanner.py --file /tmp/suspicious_file
    
    # Analyze domain
    python3 ioc-scanner.py --domain malicious.example.com

Environment Variables:
    ABUSEIPDB_API_KEY     AbuseIPDB API key for IP reputation
    VIRUSTOTAL_API_KEY    VirusTotal API key for hash/file scanning
        """
    )
    
    parser.add_argument("--ip", help="IP address to check")
    parser.add_argument("--hash", help="File hash (SHA-256) to check")
    parser.add_argument("--file", type=Path, help="File to scan")
    parser.add_argument("--domain", help="Domain to analyze")
    parser.add_argument("--output", help="Output JSON report path")
    
    args = parser.parse_args()
    
    if not any([args.ip, args.hash, args.file, args.domain]):
        parser.error("At least one scan target required (--ip, --hash, --file, or --domain)")
    
    scanner = IOCScanner()
    
    if args.ip:
        scanner.check_ip_reputation(args.ip)
    
    if args.hash:
        # Strip 'sha256:' prefix if present
        file_hash = args.hash.replace('sha256:', '')
        scanner.check_file_hash(file_hash)
    
    if args.file:
        file_result = scanner.scan_file(args.file)
        if isinstance(file_result, dict) and file_result.get("status") != "error":
            scanner._record_scan_result("file", str(args.file), file_result)
    
    if args.domain:
        scanner.analyze_domain(args.domain)
    
    scanner.generate_report(args.output)
    
    return 1 if scanner.results.get("status") in {"error", "skipped"} else 0


if __name__ == "__main__":
    sys.exit(main())
