#!/usr/bin/env python3
"""Certificate Manager - Automates TLS certificate renewal via Let's Encrypt ACME.

Run from repo root:
    python tools/certificate-manager.py --help
"""

import subprocess
import argparse
import json
from datetime import datetime, timedelta
from pathlib import Path


class CertificateManager:
    """Manages TLS certificate lifecycle."""
    
    def __init__(self, config=None):
        self.config = config or self._default_config()
    
    def _default_config(self):
        """Default certificate manager configuration."""
        return {
            "acme_directory_url": "https://acme-v02.api.letsencrypt.org/directory",
            "email": "security-team@openclaw.ai",
            "domains": ["api.openclaw.ai", "mcp.openclaw.ai"],
            "renewal_days_before": 30,
        }
    
    def check_expiry(self, cert_path):
        """Check certificate expiration date."""
        result = subprocess.run(
            ["openssl", "x509", "-in", cert_path, "-noout", "-enddate"],
            capture_output=True,
            text=True,
        )
        
        # Parse: notAfter=Jan 15 10:00:00 2025 GMT
        expiry_str = result.stdout.split("=")[1].strip()
        expiry_date = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
        
        days_until_expiry = (expiry_date - datetime.utcnow()).days
        
        return {
            "cert_path": cert_path,
            "expiry_date": expiry_date.isoformat(),
            "days_until_expiry": days_until_expiry,
            "needs_renewal": days_until_expiry <= self.config["renewal_days_before"],
        }
    
    def renew_certificate(self, domain):
        """Renew certificate using certbot."""
        result = subprocess.run(
            ["certbot", "renew", "--domain", domain, "--non-interactive"],
            capture_output=True,
            text=True,
        )
        
        if result.returncode == 0:
            return {"status": "success", "domain": domain, "renewed_at": datetime.utcnow().isoformat()}
        else:
            return {"status": "failed", "domain": domain, "error": result.stderr}
    
    def list_certificates(self):
        """List all certificates."""
        cert_dir = Path("/etc/openclaw/tls")
        
        certs = []
        for cert_file in cert_dir.glob("*.crt"):
            expiry_info = self.check_expiry(str(cert_file))
            certs.append(expiry_info)
        
        return certs


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Manage OpenClaw TLS certificates")
    parser.add_argument(
        "--action",
        default="list",
        choices=["list", "expiry", "renew"],
        help="Certificate management action",
    )
    parser.add_argument("--cert-path", help="Certificate path for expiry checks")
    parser.add_argument("--domain", help="Domain for renewal")
    args = parser.parse_args()

    manager = CertificateManager()

    if args.action == "expiry":
        if not args.cert_path:
            print(json.dumps({"error": "--cert-path is required for action=expiry"}, indent=2))
        else:
            print(json.dumps(manager.check_expiry(args.cert_path), indent=2, default=str))
    elif args.action == "renew":
        if not args.domain:
            print(json.dumps({"error": "--domain is required for action=renew"}, indent=2))
        else:
            print(json.dumps(manager.renew_certificate(args.domain), indent=2))
    else:
        print(json.dumps(manager.list_certificates(), indent=2))
