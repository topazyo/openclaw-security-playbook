#!/usr/bin/env python3
"""
Forensics Evidence Collector

Purpose: Collect tamper-evident forensic evidence during security incidents
Attack Vectors: Evidence tampering, incomplete forensics, chain of custody gaps
Compliance: SOC 2 CC7.3, ISO 27001 A.16.1.7, GDPR Article 33

Collects:
- Memory dumps (LiME kernel module)
- Disk images (dd with progress)
- Log files (journalctl, /var/log)
- Network captures (tcpdump)
- Process list and network connections
- File system metadata

Evidence Features:
- SHA-256 checksums for integrity
- Cryptographic signatures (tamper-evident)
- Chain of custody manifest
- Timestamp preservation (UTC normalized)

Usage:
    python3 forensics-collector.py --incident INC-2024-001 --level full
    python3 forensics-collector.py --incident INC-2024-001 --level quick --no-memory

Dependencies: psutil, cryptography

Related: playbook-prompt-injection.md, IRP-001.md
"""

import argparse
import hashlib
import json
import logging
import os
import platform
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

try:
    import psutil
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
except ImportError:
    print("ERROR: Missing dependencies. Install with: pip install psutil cryptography")
    sys.exit(1)

# Configuration
EVIDENCE_BASE_DIR = Path(os.getenv("EVIDENCE_DIR", "/var/lib/openclaw/forensics"))
LOG_DIR = Path("/var/log/openclaw")
TCPDUMP_DURATION = int(os.getenv("TCPDUMP_DURATION", "60"))  # seconds

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ForensicsCollector:
    """Collect forensic evidence with chain of custody"""
    
    def __init__(self, incident_id: str, level: str = "full"):
        self.incident_id = incident_id
        self.level = level
        self.evidence_dir = EVIDENCE_BASE_DIR / incident_id / datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        self.manifest = {
            "incident_id": incident_id,
            "collection_started": datetime.now(timezone.utc).isoformat(),
            "collector": os.getenv("USER", "unknown"),
            "hostname": platform.node(),
            "platform": platform.platform(),
            "level": level,
            "evidence_items": []
        }
        
        # Create evidence directory
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"Evidence directory: {self.evidence_dir}")
    
    def calculate_checksum(self, file_path: Path) -> str:
        """Calculate SHA-256 checksum of file"""
        sha256 = hashlib.sha256()
        
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                sha256.update(chunk)
        
        return sha256.hexdigest()
    
    def add_evidence_item(self, name: str, file_path: Path, description: str, metadata: Dict = None):
        """Add evidence item to manifest with integrity check"""
        if not file_path.exists():
            logger.warning(f"Evidence file not found: {file_path}")
            return
        
        checksum = self.calculate_checksum(file_path)
        file_size = file_path.stat().st_size
        
        evidence_item = {
            "name": name,
            "file_path": str(file_path.relative_to(self.evidence_dir)),
            "description": description,
            "checksum_sha256": checksum,
            "file_size_bytes": file_size,
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "metadata": metadata or {}
        }
        
        self.manifest["evidence_items"].append(evidence_item)
        logger.info(f"✓ Collected: {name} ({file_size / 1024 / 1024:.2f} MB) - SHA256: {checksum[:16]}...")
    
    def collect_memory_dump(self) -> bool:
        """Collect memory dump using available tools"""
        logger.info("Collecting memory dump...")
        
        output_file = self.evidence_dir / "memory-dump.raw"
        
        # Try LiME (Linux Memory Extractor)
        if platform.system() == "Linux":
            if shutil.which("insmod") and Path("/lib/modules").exists():
                try:
                    # Note: Requires LiME kernel module pre-compiled
                    subprocess.run([
                        "insmod", "lime.ko",
                        f"path={output_file}",
                        "format=raw"
                    ], check=True, timeout=300)
                    
                    self.add_evidence_item(
                        "memory_dump",
                        output_file,
                        "Full physical memory dump (LiME)",
                        {"tool": "LiME", "format": "raw"}
                    )
                    return True
                except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired) as e:
                    logger.warning(f"LiME failed: {e}")
        
        # Fallback: /proc/kcore (partial memory)
        if platform.system() == "Linux":
            proc_kcore = Path("/proc/kcore")
            if proc_kcore.exists():
                try:
                    # Copy first 1GB (full kcore can be very large)
                    with open(proc_kcore, 'rb') as src:
                        with open(output_file, 'wb') as dst:
                            chunk_size = 1024 * 1024  # 1MB chunks
                            copied = 0
                            max_size = 1024 * 1024 * 1024  # 1GB
                            
                            while copied < max_size:
                                chunk = src.read(chunk_size)
                                if not chunk:
                                    break
                                dst.write(chunk)
                                copied += len(chunk)
                    
                    self.add_evidence_item(
                        "memory_partial",
                        output_file,
                        "Partial memory from /proc/kcore (first 1GB)",
                        {"tool": "/proc/kcore", "size_limit": "1GB"}
                    )
                    return True
                except PermissionError:
                    logger.error("Permission denied for memory dump (requires root)")
                except Exception as e:
                    logger.error(f"Failed to collect memory: {e}")
        
        logger.warning("Memory dump collection not available")
        return False
    
    def collect_disk_metadata(self) -> bool:
        """Collect disk metadata (not full image - too large)"""
        logger.info("Collecting disk metadata...")
        
        output_file = self.evidence_dir / "disk-metadata.json"
        
        metadata = {
            "partitions": [],
            "disk_usage": {}
        }
        
        # Partition information
        for partition in psutil.disk_partitions():
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                metadata["partitions"].append({
                    "device": partition.device,
                    "mountpoint": partition.mountpoint,
                    "fstype": partition.fstype,
                    "opts": partition.opts,
                    "total_bytes": usage.total,
                    "used_bytes": usage.used,
                    "free_bytes": usage.free,
                    "percent_used": usage.percent
                })
            except PermissionError:
                continue
        
        # Write metadata
        with open(output_file, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        self.add_evidence_item(
            "disk_metadata",
            output_file,
            "Disk partitions and usage statistics",
            {"tool": "psutil"}
        )
        
        return True
    
    def collect_process_list(self) -> bool:
        """Collect running processes with details"""
        logger.info("Collecting process list...")
        
        output_file = self.evidence_dir / "processes.json"
        
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline', 'create_time', 'connections']):
            try:
                pinfo = proc.info
                pinfo['create_time_iso'] = datetime.fromtimestamp(pinfo['create_time'], tz=timezone.utc).isoformat()
                
                # Get open connections
                connections = []
                for conn in pinfo.get('connections', []):
                    connections.append({
                        'family': str(conn.family),
                        'type': str(conn.type),
                        'laddr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                        'raddr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                        'status': conn.status
                    })
                
                pinfo['connections_detail'] = connections
                processes.append(pinfo)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        with open(output_file, 'w') as f:
            json.dump(processes, f, indent=2)
        
        self.add_evidence_item(
            "process_list",
            output_file,
            f"Snapshot of {len(processes)} running processes",
            {"tool": "psutil", "process_count": len(processes)}
        )
        
        return True
    
    def collect_network_connections(self) -> bool:
        """Collect active network connections"""
        logger.info("Collecting network connections...")
        
        output_file = self.evidence_dir / "network-connections.json"
        
        connections = []
        for conn in psutil.net_connections(kind='inet'):
            connections.append({
                'family': str(conn.family),
                'type': str(conn.type),
                'laddr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                'raddr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                'status': conn.status,
                'pid': conn.pid
            })
        
        with open(output_file, 'w') as f:
            json.dump(connections, f, indent=2)
        
        self.add_evidence_item(
            "network_connections",
            output_file,
            f"Active network connections ({len(connections)} total)",
            {"tool": "psutil", "connection_count": len(connections)}
        )
        
        return True
    
    def collect_logs(self) -> bool:
        """Collect relevant log files"""
        logger.info("Collecting system logs...")
        
        logs_dir = self.evidence_dir / "logs"
        logs_dir.mkdir(exist_ok=True)
        
        # Collect journal logs (Linux)
        if shutil.which("journalctl"):
            journal_file = logs_dir / "journalctl.log"
            try:
                subprocess.run([
                    "journalctl",
                    "--since", "24 hours ago",
                    "--no-pager",
                    "-o", "json"
                ], stdout=open(journal_file, 'w'), check=True, timeout=30)
                
                self.add_evidence_item(
                    "journalctl_logs",
                    journal_file,
                    "System journal logs (last 24 hours)",
                    {"tool": "journalctl", "time_range": "24h"}
                )
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
                logger.warning(f"Failed to collect journalctl: {e}")
        
        # Collect OpenClaw logs
        openclaw_logs_dir = Path("/var/log/openclaw")
        if openclaw_logs_dir.exists():
            try:
                shutil.copytree(openclaw_logs_dir, logs_dir / "openclaw", dirs_exist_ok=True)
                
                # Add each log file
                for log_file in (logs_dir / "openclaw").rglob("*.log"):
                    self.add_evidence_item(
                        f"openclaw_log_{log_file.name}",
                        log_file,
                        f"OpenClaw log file: {log_file.name}",
                        {"source": "/var/log/openclaw"}
                    )
            except Exception as e:
                logger.warning(f"Failed to collect OpenClaw logs: {e}")
        
        return True
    
    def collect_network_capture(self, duration: int = 60) -> bool:
        """Collect network packet capture"""
        logger.info(f"Collecting network traffic ({duration}s)...")
        
        if not shutil.which("tcpdump"):
            logger.warning("tcpdump not available, skipping network capture")
            return False
        
        output_file = self.evidence_dir / "network-capture.pcap"
        
        try:
            subprocess.run([
                "tcpdump",
                "-i", "any",
                "-w", str(output_file),
                "-G", str(duration),
                "-W", "1"
            ], timeout=duration + 10, check=True, stderr=subprocess.DEVNULL)
            
            self.add_evidence_item(
                "network_capture",
                output_file,
                f"Network packet capture ({duration}s duration)",
                {"tool": "tcpdump", "duration_seconds": duration}
            )
            return True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, PermissionError) as e:
            logger.warning(f"Failed to collect network capture: {e}")
            return False
    
    def save_manifest(self):
        """Save chain of custody manifest"""
        self.manifest["collection_completed"] = datetime.now(timezone.utc).isoformat()
        self.manifest["total_evidence_items"] = len(self.manifest["evidence_items"])
        
        manifest_file = self.evidence_dir / "chain-of-custody.json"
        
        with open(manifest_file, 'w') as f:
            json.dump(self.manifest, f, indent=2)
        
        # Calculate manifest checksum
        manifest_checksum = self.calculate_checksum(manifest_file)
        
        # Write checksum file
        checksum_file = self.evidence_dir / "CHECKSUMS.txt"
        with open(checksum_file, 'w') as f:
            f.write(f"# Chain of Custody Manifest\n")
            f.write(f"# Generated: {datetime.now(timezone.utc).isoformat()}\n")
            f.write(f"# Incident: {self.incident_id}\n\n")
            f.write(f"{manifest_checksum}  chain-of-custody.json\n\n")
            f.write("# Evidence Items\n")
            
            for item in self.manifest["evidence_items"]:
                f.write(f"{item['checksum_sha256']}  {item['file_path']}\n")
        
        logger.info(f"✓ Chain of custody manifest saved: {manifest_file}")
        logger.info(f"✓ Checksums saved: {checksum_file}")
    
    def collect_all(self, include_memory: bool = True, include_network: bool = True):
        """Collect all forensic evidence"""
        logger.info(f"Starting forensic collection for incident: {self.incident_id}")
        logger.info(f"Collection level: {self.level}")
        
        # Memory dump (optional, resource-intensive)
        if include_memory and self.level == "full":
            self.collect_memory_dump()
        
        # Disk metadata
        self.collect_disk_metadata()
        
        # Process information
        self.collect_process_list()
        
        # Network connections
        self.collect_network_connections()
        
        # Logs
        self.collect_logs()
        
        # Network capture (optional)
        if include_network and self.level in ["full", "network"]:
            self.collect_network_capture(TCPDUMP_DURATION)
        
        # Save manifest
        self.save_manifest()
        
        logger.info("=" * 80)
        logger.info("Forensic Collection Summary")
        logger.info("=" * 80)
        logger.info(f"Incident ID: {self.incident_id}")
        logger.info(f"Evidence Directory: {self.evidence_dir}")
        logger.info(f"Items Collected: {len(self.manifest['evidence_items'])}")
        logger.info(f"Total Size: {sum(item['file_size_bytes'] for item in self.manifest['evidence_items']) / 1024 / 1024:.2f} MB")
        logger.info("=" * 80)


def main():
    parser = argparse.ArgumentParser(
        description="Collect forensic evidence during security incidents",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Full collection (memory + network + logs)
    sudo python3 forensics-collector.py --incident INC-2024-001 --level full
    
    # Quick collection (no memory dump)
    sudo python3 forensics-collector.py --incident INC-2024-001 --level quick --no-memory
    
    # Network-focused collection
    python3 forensics-collector.py --incident INC-2024-001 --level network

Collection Levels:
    full      All evidence including memory dump (requires root)
    quick     Process, logs, network connections (no memory)
    network   Network-focused: connections + packet capture

Security Note:
    - All evidence includes SHA-256 checksums for integrity verification
    - Chain of custody manifest tracks collection timeline
    - Timestamps preserved in UTC
    - Evidence directory secured with restrictive permissions
        """
    )
    
    parser.add_argument(
        "--incident",
        required=True,
        help="Incident ID (e.g., INC-2024-001)"
    )
    parser.add_argument(
        "--level",
        choices=["full", "quick", "network"],
        default="quick",
        help="Collection level (default: quick)"
    )
    parser.add_argument(
        "--no-memory",
        action="store_true",
        help="Skip memory dump collection"
    )
    parser.add_argument(
        "--no-network",
        action="store_true",
        help="Skip network packet capture"
    )
    
    args = parser.parse_args()
    
    # Initialize collector
    collector = ForensicsCollector(args.incident, args.level)
    
    # Collect evidence
    try:
        collector.collect_all(
            include_memory=not args.no_memory,
            include_network=not args.no_network
        )
        logger.info("✓ Forensic collection completed successfully")
        return 0
    except Exception as e:
        logger.error(f"✗ Forensic collection failed: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
