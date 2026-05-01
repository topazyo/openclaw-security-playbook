#!/usr/bin/env python3
"""Certificate Manager - Automates TLS certificate renewal via Let's Encrypt ACME.

Run from repo root:
    python tools/certificate-manager.py --help
"""

import subprocess  # nosec B404
import argparse
import json
from datetime import datetime, timedelta, timezone
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
        def _unreadable(reason):  # FIX: C5-14
            return {  # FIX: C5-14
                "cert_path": cert_path,  # FIX: C5-14
                "expiry_date": None,  # FIX: C5-14
                "days_until_expiry": None,  # FIX: C5-14
                "needs_renewal": True,  # FIX: C5-14 — fail-safe: flag for review
                "status": "unreadable",  # FIX: C5-14
                "error": reason,  # FIX: C5-14
            }  # FIX: C5-14

        try:  # FIX: C5-14
            result = subprocess.run(  # nosec B603 B607
                ["openssl", "x509", "-in", cert_path, "-noout", "-enddate"],
                capture_output=True,
                text=True,
            )
        except OSError as exc:  # FIX: C5-14 — covers FileNotFoundError, PermissionError, and other OS failures
            return _unreadable(f"openssl could not be launched: {exc}")  # FIX: C5-14

        if result.returncode != 0:  # FIX: C5-14
            return _unreadable(f"openssl exited {result.returncode}: {result.stderr.strip()}")  # FIX: C5-14

        stdout = result.stdout.strip()  # FIX: C5-14
        if not stdout.startswith("notAfter="):  # FIX: C5-14
            return _unreadable(f"unexpected openssl output: {stdout!r}")  # FIX: C5-14

        # openssl -enddate always emits GMT; strip it before parsing to avoid
        # %Z producing a naive datetime in Python (CPython does not attach tzinfo for GMT).
        raw = stdout[len("notAfter="):].strip()  # FIX: C5-14
        if not raw.endswith(" GMT"):  # FIX: C5-14
            return _unreadable(f"unrecognised timezone in openssl output: {raw!r}")  # FIX: C5-14
        raw_no_tz = raw[: -len(" GMT")]  # FIX: C5-14

        try:  # FIX: C5-14
            expiry_date = datetime.strptime(raw_no_tz, "%b %d %H:%M:%S %Y").replace(  # FIX: C5-14
                tzinfo=timezone.utc  # FIX: C5-14 — attach UTC explicitly; aware-aware subtraction below
            )  # FIX: C5-14
        except ValueError as exc:  # FIX: C5-14
            return _unreadable(f"cannot parse expiry date {raw_no_tz!r}: {exc}")  # FIX: C5-14

        days_until_expiry = (expiry_date - datetime.now(timezone.utc)).days  # FIX: C5-14 — both aware

        needs_renewal = days_until_expiry <= self.config["renewal_days_before"]  # FIX: C5-14
        status = "expiring" if needs_renewal else "healthy"  # FIX: C5-14

        return {
            "cert_path": cert_path,
            "expiry_date": expiry_date.isoformat(),
            "days_until_expiry": days_until_expiry,
            "needs_renewal": needs_renewal,
            "status": status,  # FIX: C5-14
            "error": None,  # FIX: C5-14
        }
    
    def renew_certificate(self, domain):
        """Renew certificate using certbot."""
        result = subprocess.run(  # nosec B603 B607
            ["certbot", "renew", "--domain", domain, "--non-interactive"],
            capture_output=True,
            text=True,
        )
        
        if result.returncode == 0:
            return {"status": "success", "domain": domain, "renewed_at": datetime.now(timezone.utc).isoformat()}
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


def list_certificates():
    """Module-level wrapper used by openclaw-cli."""
    return CertificateManager().list_certificates()


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
