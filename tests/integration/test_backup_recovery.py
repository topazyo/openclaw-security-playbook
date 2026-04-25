#!/usr/bin/env python3
"""
Integration Tests for Backup and Recovery Procedures

Tests backup-verification.py and backup-restore.sh from examples/backups/

Test Coverage:
  - RTO verification (<4h restore time)
  - RPO verification (<15min data loss)
  - 3-2-1 backup strategy validation
  - Integrity checks (SHA-256)
  - Encryption at rest validation
  - Restore testing

Compliance:
  - SOC 2 CC9.1: Business continuity
  - ISO 27001 A.12.3.1: Information backup

Usage:
  pytest tests/integration/test_backup_recovery.py -v
"""

import importlib.util  # FIX: C5-finding-3
import sys  # FIX: C5-finding-3
from datetime import datetime, timezone  # FIX: C5-finding-3
from pathlib import Path  # FIX: C5-finding-3
from types import ModuleType  # FIX: C5-finding-3
from unittest.mock import MagicMock, Mock, patch  # FIX: C5-finding-3

import pytest  # FIX: C5-finding-3


BACKUP_VERIFICATION_PATH = Path(__file__).resolve().parents[2] / "examples" / "security-controls" / "backup-verification.py"  # FIX: C5-finding-3


def _load_backup_verification_module(module_name: str):  # FIX: C5-finding-3
    spec = importlib.util.spec_from_file_location(module_name, BACKUP_VERIFICATION_PATH)  # FIX: C5-finding-3
    assert spec is not None and spec.loader is not None  # FIX: C5-finding-3
    module = importlib.util.module_from_spec(spec)  # FIX: C5-finding-3
    sys.modules[spec.name] = module  # FIX: C5-finding-3
    spec.loader.exec_module(module)  # FIX: C5-finding-3
    return module  # FIX: C5-finding-3


def _fake_boto3_with_backup_pages(pages, snapshots=None):  # FIX: C5-finding-3
    fake_s3_client = MagicMock()  # FIX: C5-finding-3
    fake_paginator = MagicMock()  # FIX: C5-finding-3
    fake_paginator.paginate.return_value = pages  # FIX: C5-finding-3
    fake_s3_client.get_paginator.return_value = fake_paginator  # FIX: C5-finding-3
    fake_ec2_client = MagicMock()  # FIX: C5-finding-3
    fake_ec2_client.describe_snapshots.return_value = {"Snapshots": snapshots or []}  # FIX: C5-finding-3
    fake_boto3 = ModuleType("boto3")  # FIX: C5-finding-3
    fake_boto3.client = Mock(side_effect=lambda service_name, region_name=None: {"s3": fake_s3_client, "ec2": fake_ec2_client}[service_name])  # FIX: C5-finding-3
    return fake_boto3, fake_s3_client, fake_paginator, fake_ec2_client  # FIX: C5-finding-3


@pytest.fixture
def backup_config():
    """Backup configuration."""
    return {
        "rto_hours": 4,
        "rpo_minutes": 15,
        "backup_locations": ["local", "s3-us-east-1", "s3-glacier"],
        "encryption_enabled": True,
    }


class TestRTOVerification:
    """Test Recovery Time Objective."""

    def test_restore_completes_under_rto(self, tmp_path, backup_config):  # FIX: C5-finding-3
        """Test the real disaster recovery flow completes within the configured RTO."""  # FIX: C5-finding-3
        module = _load_backup_verification_module("backup_verification_rto_issue_7_tests")  # FIX: C5-finding-3
        backup_path = tmp_path / "openclaw-backup.sql.gz"  # FIX: C5-finding-3
        backup_path.write_bytes(b"compressed-backup")  # FIX: C5-finding-3
        manager = module.DisasterRecoveryManager(module.BackupStrategy())  # FIX: C5-finding-3
        start_time = datetime.now(timezone.utc)  # FIX: C5-finding-3

        with patch.object(module.BackupVerifier, "verify_backup_integrity", return_value=(True, [])), patch.object(module.BackupVerifier, "_verify_database_records", return_value={"users": 10}), patch.object(module.DisasterRecoveryManager, "_run_smoke_tests", return_value=None), patch.object(module.subprocess, "run", return_value=Mock(returncode=0)):  # FIX: C5-finding-3
            metrics = manager.execute_recovery(str(backup_path), "postgresql://restore-target")  # FIX: C5-finding-3

        duration = (datetime.now(timezone.utc) - start_time).total_seconds() / 3600  # FIX: C5-finding-3
        assert duration < backup_config["rto_hours"]  # FIX: C5-finding-3
        assert metrics.meets_rto is True  # FIX: C5-finding-3


class TestRPOVerification:
    """Test Recovery Point Objective."""

    def test_recovery_metrics_preserve_fifteen_minute_rpo(self, tmp_path, backup_config):  # FIX: C5-finding-3
        """Test the real recovery metrics preserve the documented 15-minute RPO."""  # FIX: C5-finding-3
        module = _load_backup_verification_module("backup_verification_rpo_issue_7_tests")  # FIX: C5-finding-3
        backup_path = tmp_path / "openclaw-backup.sql.gz"  # FIX: C5-finding-3
        backup_path.write_bytes(b"compressed-backup")  # FIX: C5-finding-3
        manager = module.DisasterRecoveryManager(module.BackupStrategy())  # FIX: C5-finding-3

        with patch.object(module.BackupVerifier, "verify_backup_integrity", return_value=(True, [])), patch.object(module.BackupVerifier, "_verify_database_records", return_value={"users": 10}), patch.object(module.DisasterRecoveryManager, "_run_smoke_tests", return_value=None), patch.object(module.subprocess, "run", return_value=Mock(returncode=0)):  # FIX: C5-finding-3
            metrics = manager.execute_recovery(str(backup_path), "postgresql://restore-target")  # FIX: C5-finding-3

        assert metrics.rpo_minutes == backup_config["rpo_minutes"]  # FIX: C5-finding-3
        assert metrics.actual_data_loss == 15.0  # FIX: C5-finding-3
        assert metrics.meets_rpo is True  # FIX: C5-finding-3


class Test321Strategy:
    """Test 3-2-1 backup strategy."""

    def test_does_not_match_hyphen_suffixed_backup_ids(self, backup_config):  # FIX: C5-finding-3
        """Test the real 3-2-1 compliance check does not treat hyphen-suffixed backup ids as matches."""  # FIX: C5-finding-3
        module = _load_backup_verification_module("backup_verification_321_substring_issue_7_tests")  # FIX: C5-finding-3
        strategy = module.BackupStrategy(backup_region=backup_config["backup_locations"][1].split("-")[-1])  # FIX: C5-finding-3
        strategy.account_id = "123456789012"  # FIX: C5-finding-3
        fake_boto3, _fake_s3_client, _fake_paginator, _fake_ec2_client = _fake_boto3_with_backup_pages(  # FIX: C5-finding-3
            [{"Contents": [{"Key": "database/2026/04/25/backup-2024-01-15-extra.sql.gz"}]}],  # FIX: C5-finding-3
            [{"Description": "backup-2024-01-15-extra hourly snapshot", "Tags": [{"Key": "BackupId", "Value": "backup-2024-01-15-extra"}]}],  # FIX: C5-finding-3
        )  # FIX: C5-finding-3

        with patch.dict(sys.modules, {"boto3": fake_boto3}):  # FIX: C5-finding-3
            compliance = strategy.verify_3_2_1_compliance("backup-2024-01-15")  # FIX: C5-finding-3

        assert compliance == {"3_copies": False, "2_media_types": False, "1_offsite": False}  # FIX: C5-finding-3

    def test_module_generated_backup_id_matches_uploaded_offsite_backup(self, tmp_path, backup_config):  # FIX: C5-finding-3
        """Test the real 3-2-1 compliance check maps create_database_backup() ids to upload_to_offsite() filenames."""  # FIX: C5-finding-3
        module = _load_backup_verification_module("backup_verification_321_generated_id_issue_7_tests")  # FIX: C5-finding-3
        strategy = module.BackupStrategy(backup_region=backup_config["backup_locations"][1].split("-")[-1])  # FIX: C5-finding-3
        strategy.account_id = "123456789012"  # FIX: C5-finding-3
        strategy.local_backup_dir = str(tmp_path / "local-backups")  # FIX: C5-finding-3
        Path(strategy.local_backup_dir).mkdir(parents=True, exist_ok=True)  # FIX: C5-finding-3
        timestamp = "2026-04-25_06-30-00"  # FIX: C5-finding-3
        backup_id = f"db-{timestamp}"  # FIX: C5-finding-3
        backup_file = Path(strategy.local_backup_dir) / f"openclaw_backup_{timestamp}.sql.gz"  # FIX: C5-finding-3
        backup_file.write_bytes(b"backup")  # FIX: C5-finding-3
        (Path(f"{backup_file}.manifest.json")).write_text(module.BackupManifest(backup_id=backup_id, backup_type=module.BackupType.DATABASE.value, created_at=datetime.now(timezone.utc).isoformat(), source_system="openclaw-db-us-west-2", files={backup_file.name: "checksum"}, size_bytes=backup_file.stat().st_size, compression="gzip", encryption="none", retention_days=30).to_json(), encoding="utf-8")  # FIX: C5-finding-3
        fake_boto3, _fake_s3_client, _fake_paginator, _fake_ec2_client = _fake_boto3_with_backup_pages([{"Contents": [{"Key": f"database/2026/04/25/{backup_file.name}"}]}])  # FIX: C5-finding-3

        with patch.dict(sys.modules, {"boto3": fake_boto3}):  # FIX: C5-finding-3
            compliance = strategy.verify_3_2_1_compliance(backup_id)  # FIX: C5-finding-3

        assert compliance["1_offsite"] is True  # FIX: C5-finding-3
        assert compliance["2_media_types"] is True  # FIX: C5-finding-3
        assert compliance["3_copies"] is True  # FIX: C5-finding-3

    def test_three_copies_exist(self, backup_config):  # FIX: C5-finding-3
        """Test the real 3-2-1 compliance check reports three copies when both snapshot and offsite evidence exist."""  # FIX: C5-finding-3
        module = _load_backup_verification_module("backup_verification_321_copies_issue_7_tests")  # FIX: C5-finding-3
        strategy = module.BackupStrategy(backup_region=backup_config["backup_locations"][1].split("-")[-1])  # FIX: C5-finding-3
        strategy.account_id = "123456789012"  # FIX: C5-finding-3
        fake_boto3, _fake_s3_client, _fake_paginator, _fake_ec2_client = _fake_boto3_with_backup_pages(  # FIX: C5-finding-3
            [{"Contents": [{"Key": "database/2026/04/25/backup-2024-01-15.sql.gz"}]}],  # FIX: C5-finding-3
            [{"Description": "backup-2024-01-15 hourly snapshot", "Tags": [{"Key": "BackupId", "Value": "backup-2024-01-15"}]}],  # FIX: C5-finding-3
        )  # FIX: C5-finding-3

        with patch.dict(sys.modules, {"boto3": fake_boto3}):  # FIX: C5-finding-3
            compliance = strategy.verify_3_2_1_compliance("backup-2024-01-15")  # FIX: C5-finding-3

        assert compliance["3_copies"] is True  # FIX: C5-finding-3

    def test_two_media_types(self, backup_config):  # FIX: C5-finding-3
        """Test the real 3-2-1 compliance check reports two media types when both snapshot and offsite evidence exist."""  # FIX: C5-finding-3
        module = _load_backup_verification_module("backup_verification_321_media_issue_7_tests")  # FIX: C5-finding-3
        strategy = module.BackupStrategy(backup_region=backup_config["backup_locations"][1].split("-")[-1])  # FIX: C5-finding-3
        strategy.account_id = "123456789012"  # FIX: C5-finding-3
        fake_boto3, _fake_s3_client, _fake_paginator, _fake_ec2_client = _fake_boto3_with_backup_pages(  # FIX: C5-finding-3
            [{"Contents": [{"Key": "database/2026/04/25/backup-2024-01-15.sql.gz"}]}],  # FIX: C5-finding-3
            [{"Description": "backup-2024-01-15 hourly snapshot", "Tags": [{"Key": "Name", "Value": "backup-2024-01-15"}]}],  # FIX: C5-finding-3
        )  # FIX: C5-finding-3

        with patch.dict(sys.modules, {"boto3": fake_boto3}):  # FIX: C5-finding-3
            compliance = strategy.verify_3_2_1_compliance("backup-2024-01-15")  # FIX: C5-finding-3

        assert compliance["2_media_types"] is True  # FIX: C5-finding-3

    def test_one_offsite_copy(self, backup_config):  # FIX: C5-finding-3
        """Test the real 3-2-1 compliance check reports the offsite copy when S3 contains the backup."""  # FIX: C5-finding-3
        module = _load_backup_verification_module("backup_verification_321_offsite_issue_7_tests")  # FIX: C5-finding-3
        strategy = module.BackupStrategy(backup_region=backup_config["backup_locations"][1].split("-")[-1])  # FIX: C5-finding-3
        strategy.account_id = "123456789012"  # FIX: C5-finding-3
        fake_boto3, _fake_s3_client, fake_paginator, _fake_ec2_client = _fake_boto3_with_backup_pages([{"Contents": [{"Key": "database/2026/04/25/backup-2024-01-15.sql.gz"}]}])  # FIX: C5-finding-3

        with patch.dict(sys.modules, {"boto3": fake_boto3}):  # FIX: C5-finding-3
            compliance = strategy.verify_3_2_1_compliance("backup-2024-01-15")  # FIX: C5-finding-3

        assert compliance["1_offsite"] is True  # FIX: C5-finding-3
        assert compliance["3_copies"] is False  # FIX: C5-finding-3
        assert compliance["2_media_types"] is False  # FIX: C5-finding-3
        fake_paginator.paginate.assert_called_once()  # FIX: C5-finding-3

    def test_scans_past_first_object_in_page(self, backup_config):  # FIX: C5-finding-3
        """Test the real 3-2-1 compliance check searches all objects in a page before concluding the backup is absent."""  # FIX: C5-finding-3
        module = _load_backup_verification_module("backup_verification_321_scan_page_issue_7_tests")  # FIX: C5-finding-3
        strategy = module.BackupStrategy(backup_region=backup_config["backup_locations"][1].split("-")[-1])  # FIX: C5-finding-3
        strategy.account_id = "123456789012"  # FIX: C5-finding-3
        fake_boto3, _fake_s3_client, _fake_paginator, _fake_ec2_client = _fake_boto3_with_backup_pages([{"Contents": [{"Key": "database/2026/04/25/other-backup.sql.gz"}, {"Key": "database/2026/04/25/backup-2024-01-15.sql.gz"}]}])  # FIX: C5-finding-3

        with patch.dict(sys.modules, {"boto3": fake_boto3}):  # FIX: C5-finding-3
            compliance = strategy.verify_3_2_1_compliance("backup-2024-01-15")  # FIX: C5-finding-3

        assert compliance["1_offsite"] is True  # FIX: C5-finding-3

    def test_missing_account_id_does_not_crash(self, backup_config):  # FIX: C5-finding-3
        """Test the real 3-2-1 compliance check works without an injected account_id."""  # FIX: C5-finding-3
        module = _load_backup_verification_module("backup_verification_321_account_id_issue_7_tests")  # FIX: C5-finding-3
        strategy = module.BackupStrategy(backup_region=backup_config["backup_locations"][1].split("-")[-1])  # FIX: C5-finding-3
        fake_boto3, _fake_s3_client, fake_paginator, fake_ec2_client = _fake_boto3_with_backup_pages([{"Contents": [{"Key": "database/2026/04/25/backup-2024-01-15.sql.gz"}]}])  # FIX: C5-finding-3

        with patch.dict(sys.modules, {"boto3": fake_boto3}):  # FIX: C5-finding-3
            compliance = strategy.verify_3_2_1_compliance("backup-2024-01-15")  # FIX: C5-finding-3

        assert compliance["1_offsite"] is True  # FIX: C5-finding-3
        assert fake_paginator.paginate.call_args.kwargs == {"Bucket": strategy.s3_backup_bucket, "Prefix": "database/"}  # FIX: C5-finding-3
        fake_ec2_client.describe_snapshots.assert_called_once_with(OwnerIds=["self"])  # FIX: C5-finding-3

    def test_local_backup_and_offsite_satisfy_full_compliance(self, tmp_path, backup_config):  # FIX: C5-finding-3
        """Test the real 3-2-1 compliance check accepts a local backup archive plus offsite storage without a snapshot."""  # FIX: C5-finding-3
        module = _load_backup_verification_module("backup_verification_321_local_issue_7_tests")  # FIX: C5-finding-3
        strategy = module.BackupStrategy(backup_region=backup_config["backup_locations"][1].split("-")[-1])  # FIX: C5-finding-3
        strategy.account_id = "123456789012"  # FIX: C5-finding-3
        strategy.local_backup_dir = str(tmp_path / "local-backups")  # FIX: C5-finding-3
        Path(strategy.local_backup_dir).mkdir(parents=True, exist_ok=True)  # FIX: C5-finding-3
        (Path(strategy.local_backup_dir) / "openclaw-backup-2024-01-15.tar.gz").write_bytes(b"backup")  # FIX: C5-finding-3
        fake_boto3, _fake_s3_client, _fake_paginator, _fake_ec2_client = _fake_boto3_with_backup_pages([{"Contents": [{"Key": "database/2026/04/25/backup-2024-01-15.sql.gz"}]}])  # FIX: C5-finding-3

        with patch.dict(sys.modules, {"boto3": fake_boto3}):  # FIX: C5-finding-3
            compliance = strategy.verify_3_2_1_compliance("backup-2024-01-15")  # FIX: C5-finding-3

        assert compliance["1_offsite"] is True  # FIX: C5-finding-3
        assert compliance["2_media_types"] is True  # FIX: C5-finding-3
        assert compliance["3_copies"] is True  # FIX: C5-finding-3

    def test_invalid_backup_specific_manifest_raises_instead_of_silently_skipping(self, tmp_path, backup_config):  # FIX: C5-finding-3
        """Test the real 3-2-1 compliance check raises when backup-specific local manifest evidence cannot be parsed."""  # FIX: C5-finding-3
        module = _load_backup_verification_module("backup_verification_321_manifest_error_issue_7_tests")  # FIX: C5-finding-3
        strategy = module.BackupStrategy(backup_region=backup_config["backup_locations"][1].split("-")[-1])  # FIX: C5-finding-3
        strategy.account_id = "123456789012"  # FIX: C5-finding-3
        strategy.local_backup_dir = str(tmp_path / "local-backups")  # FIX: C5-finding-3
        manifest_dir = Path(strategy.local_backup_dir) / "backup-2024-01-15"  # FIX: C5-finding-3
        manifest_dir.mkdir(parents=True, exist_ok=True)  # FIX: C5-finding-3
        (manifest_dir / "metadata.manifest.json").write_text("{not-json", encoding="utf-8")  # FIX: C5-finding-3
        fake_boto3, _fake_s3_client, _fake_paginator, _fake_ec2_client = _fake_boto3_with_backup_pages([])  # FIX: C5-finding-3

        with patch.dict(sys.modules, {"boto3": fake_boto3}):  # FIX: C5-finding-3
            with pytest.raises(RuntimeError, match="local backup manifest"):  # FIX: C5-finding-3
                strategy.verify_3_2_1_compliance("backup-2024-01-15")  # FIX: C5-finding-3

    def test_alias_named_manifest_must_parse_before_counting_as_local_copy(self, tmp_path, backup_config):  # FIX: C5-finding-3
        """Test the real 3-2-1 compliance check does not count an alias-named manifest file unless it parses for the requested backup."""  # FIX: C5-finding-3
        module = _load_backup_verification_module("backup_verification_321_manifest_filename_bypass_issue_7_tests")  # FIX: C5-finding-3
        strategy = module.BackupStrategy(backup_region=backup_config["backup_locations"][1].split("-")[-1])  # FIX: C5-finding-3
        strategy.account_id = "123456789012"  # FIX: C5-finding-3
        strategy.local_backup_dir = str(tmp_path / "local-backups")  # FIX: C5-finding-3
        Path(strategy.local_backup_dir).mkdir(parents=True, exist_ok=True)  # FIX: C5-finding-3
        timestamp = "2026-04-25_08-15-00"  # FIX: C5-finding-3
        backup_id = f"db-{timestamp}"  # FIX: C5-finding-3
        manifest_path = Path(strategy.local_backup_dir) / f"openclaw_backup_{timestamp}.sql.gz.manifest.json"  # FIX: C5-finding-3
        manifest_path.write_text("{not-json", encoding="utf-8")  # FIX: C5-finding-3
        fake_boto3, _fake_s3_client, _fake_paginator, _fake_ec2_client = _fake_boto3_with_backup_pages(  # FIX: C5-finding-3
            [{"Contents": [{"Key": f"database/2026/04/25/openclaw_backup_{timestamp}.sql.gz"}]}]  # FIX: C5-finding-3
        )  # FIX: C5-finding-3

        with patch.dict(sys.modules, {"boto3": fake_boto3}):  # FIX: C5-finding-3
            with pytest.raises(RuntimeError, match="local backup manifest"):  # FIX: C5-finding-3
                strategy.verify_3_2_1_compliance(backup_id)  # FIX: C5-finding-3

    def test_snapshot_tag_key_match_does_not_count_as_local_snapshot_evidence(self, backup_config):  # FIX: C5-finding-3
        """Test the real 3-2-1 compliance check ignores snapshot tag keys that merely contain the backup id."""  # FIX: C5-finding-3
        module = _load_backup_verification_module("backup_verification_321_snapshot_tag_key_issue_7_tests")  # FIX: C5-finding-3
        strategy = module.BackupStrategy(backup_region=backup_config["backup_locations"][1].split("-")[-1])  # FIX: C5-finding-3
        strategy.account_id = "123456789012"  # FIX: C5-finding-3
        fake_boto3, _fake_s3_client, _fake_paginator, _fake_ec2_client = _fake_boto3_with_backup_pages(  # FIX: C5-finding-3
            [{"Contents": [{"Key": "database/2026/04/25/backup-2024-01-15.sql.gz"}]}],  # FIX: C5-finding-3
            [{"Description": "hourly snapshot", "Tags": [{"Key": "backup-2024-01-15", "Value": "unrelated"}]}],  # FIX: C5-finding-3
        )  # FIX: C5-finding-3

        with patch.dict(sys.modules, {"boto3": fake_boto3}):  # FIX: C5-finding-3
            compliance = strategy.verify_3_2_1_compliance("backup-2024-01-15")  # FIX: C5-finding-3

        assert compliance["1_offsite"] is True  # FIX: C5-finding-3
        assert compliance["2_media_types"] is False  # FIX: C5-finding-3
        assert compliance["3_copies"] is False  # FIX: C5-finding-3

    def test_matching_directory_manifest_must_parse_before_counting_as_local_copy(self, tmp_path, backup_config):  # FIX: C5-finding-3
        """Test the real 3-2-1 compliance check does not count a matching backup directory unless its manifest can be read."""  # FIX: C5-finding-3
        module = _load_backup_verification_module("backup_verification_321_directory_manifest_bypass_issue_7_tests")  # FIX: C5-finding-3
        strategy = module.BackupStrategy(backup_region=backup_config["backup_locations"][1].split("-")[-1])  # FIX: C5-finding-3
        strategy.account_id = "123456789012"  # FIX: C5-finding-3
        strategy.local_backup_dir = str(tmp_path / "local-backups")  # FIX: C5-finding-3
        matching_dir = Path(strategy.local_backup_dir) / "backup-2024-01-15"  # FIX: C5-finding-3
        matching_dir.mkdir(parents=True, exist_ok=True)  # FIX: C5-finding-3
        (matching_dir / "manifest.json").write_text("{not-json", encoding="utf-8")  # FIX: C5-finding-3
        fake_boto3, _fake_s3_client, _fake_paginator, _fake_ec2_client = _fake_boto3_with_backup_pages(  # FIX: C5-finding-3
            [{"Contents": [{"Key": "database/2026/04/25/backup-2024-01-15.sql.gz"}]}]  # FIX: C5-finding-3
        )  # FIX: C5-finding-3

        with patch.dict(sys.modules, {"boto3": fake_boto3}):  # FIX: C5-finding-3
            with pytest.raises(RuntimeError, match="local backup manifest"):  # FIX: C5-finding-3
                strategy.verify_3_2_1_compliance("backup-2024-01-15")  # FIX: C5-finding-3

    def test_offsite_manifest_object_does_not_count_as_offsite_copy(self, backup_config):  # FIX: C5-finding-3
        """Test the real 3-2-1 compliance check ignores offsite manifest objects when the backup archive itself is absent."""  # FIX: C5-finding-3
        module = _load_backup_verification_module("backup_verification_321_offsite_manifest_only_issue_7_tests")  # FIX: C5-finding-3
        strategy = module.BackupStrategy(backup_region=backup_config["backup_locations"][1].split("-")[-1])  # FIX: C5-finding-3
        strategy.account_id = "123456789012"  # FIX: C5-finding-3
        fake_boto3, _fake_s3_client, _fake_paginator, _fake_ec2_client = _fake_boto3_with_backup_pages(  # FIX: C5-finding-3
            [{"Contents": [{"Key": "database/2026/04/25/backup-2024-01-15.sql.gz.manifest.json"}]}]  # FIX: C5-finding-3
        )  # FIX: C5-finding-3

        with patch.dict(sys.modules, {"boto3": fake_boto3}):  # FIX: C5-finding-3
            compliance = strategy.verify_3_2_1_compliance("backup-2024-01-15")  # FIX: C5-finding-3

        assert compliance == {"3_copies": False, "2_media_types": False, "1_offsite": False}  # FIX: C5-finding-3

    def test_valid_manifest_without_local_archive_does_not_count_as_local_copy(self, tmp_path, backup_config):  # FIX: C5-finding-3
        """Test the real 3-2-1 compliance check does not count a manifest-only local record when the backup archive itself is missing."""  # FIX: C5-finding-3
        module = _load_backup_verification_module("backup_verification_321_manifest_without_archive_issue_7_tests")  # FIX: C5-finding-3
        strategy = module.BackupStrategy(backup_region=backup_config["backup_locations"][1].split("-")[-1])  # FIX: C5-finding-3
        strategy.account_id = "123456789012"  # FIX: C5-finding-3
        strategy.local_backup_dir = str(tmp_path / "local-backups")  # FIX: C5-finding-3
        Path(strategy.local_backup_dir).mkdir(parents=True, exist_ok=True)  # FIX: C5-finding-3
        timestamp = "2026-04-25_09-45-00"  # FIX: C5-finding-3
        backup_id = f"db-{timestamp}"  # FIX: C5-finding-3
        manifest_only_path = Path(strategy.local_backup_dir) / f"openclaw_backup_{timestamp}.sql.gz.manifest.json"  # FIX: C5-finding-3
        manifest_only_path.write_text(module.BackupManifest(backup_id=backup_id, backup_type=module.BackupType.DATABASE.value, created_at=datetime.now(timezone.utc).isoformat(), source_system="openclaw-db-us-west-2", files={f"openclaw_backup_{timestamp}.sql.gz": "checksum"}, size_bytes=123, compression="gzip", encryption="none", retention_days=30).to_json(), encoding="utf-8")  # FIX: C5-finding-3
        fake_boto3, _fake_s3_client, _fake_paginator, _fake_ec2_client = _fake_boto3_with_backup_pages(  # FIX: C5-finding-3
            [{"Contents": [{"Key": f"database/2026/04/25/openclaw_backup_{timestamp}.sql.gz"}]}]  # FIX: C5-finding-3
        )  # FIX: C5-finding-3

        with patch.dict(sys.modules, {"boto3": fake_boto3}):  # FIX: C5-finding-3
            compliance = strategy.verify_3_2_1_compliance(backup_id)  # FIX: C5-finding-3

        assert compliance["1_offsite"] is True  # FIX: C5-finding-3
        assert compliance["2_media_types"] is False  # FIX: C5-finding-3
        assert compliance["3_copies"] is False  # FIX: C5-finding-3


class TestIntegrityChecks:
    """Test backup integrity validation."""

    def test_sha256_checksum_match(self, tmp_path, backup_config):  # FIX: C5-finding-3
        """Test the real backup verifier accepts a matching SHA-256 manifest."""  # FIX: C5-finding-3
        module = _load_backup_verification_module("backup_verification_checksum_issue_7_tests")  # FIX: C5-finding-3
        backup_path = tmp_path / "backup-2024-01-15.sql.gz"  # FIX: C5-finding-3
        backup_path.write_bytes(b"backup-payload")  # FIX: C5-finding-3
        manifest = module.BackupManifest(  # FIX: C5-finding-3
            backup_id="backup-2024-01-15",  # FIX: C5-finding-3
            backup_type=module.BackupType.DATABASE.value,  # FIX: C5-finding-3
            created_at=datetime.now(timezone.utc).isoformat(),  # FIX: C5-finding-3
            source_system="openclaw-db-us-west-2",  # FIX: C5-finding-3
            files={backup_path.name: module.BackupVerifier._calculate_file_checksum(str(backup_path))},  # FIX: C5-finding-3
            size_bytes=backup_path.stat().st_size,  # FIX: C5-finding-3
            compression="gzip",  # FIX: C5-finding-3
            encryption="none",  # FIX: C5-finding-3
            retention_days=30,  # FIX: C5-finding-3
        )  # FIX: C5-finding-3
        manifest_path = backup_path.parent / f"{backup_path.name}.manifest.json"  # FIX: C5-finding-3
        manifest_path.write_text(manifest.to_json(), encoding="utf-8")  # FIX: C5-finding-3

        is_valid, errors = module.BackupVerifier().verify_backup_integrity(str(backup_path))  # FIX: C5-finding-3

        assert is_valid is True  # FIX: C5-finding-3
        assert errors == []  # FIX: C5-finding-3

    def test_offsite_upload_uses_glacier_and_encryption(self, tmp_path, backup_config):  # FIX: C5-finding-3
        """Test the real offsite upload uses archive storage and AES-256 encryption."""  # FIX: C5-finding-3
        module = _load_backup_verification_module("backup_verification_upload_issue_7_tests")  # FIX: C5-finding-3
        strategy = module.BackupStrategy(backup_region=backup_config["backup_locations"][1].split("-")[-1])  # FIX: C5-finding-3
        backup_path = tmp_path / "backup-2024-01-15.sql.gz"  # FIX: C5-finding-3
        backup_path.write_bytes(b"backup-payload")  # FIX: C5-finding-3
        (tmp_path / "backup-2024-01-15.sql.gz.manifest.json").write_text("{}", encoding="utf-8")  # FIX: C5-finding-3
        fake_boto3, fake_s3_client, _fake_paginator, _fake_ec2_client = _fake_boto3_with_backup_pages([])  # FIX: C5-finding-3

        with patch.dict(sys.modules, {"boto3": fake_boto3}):  # FIX: C5-finding-3
            s3_uri = strategy.upload_to_offsite(str(backup_path))  # FIX: C5-finding-3

        assert s3_uri.startswith(f"s3://{strategy.s3_backup_bucket}/database/")  # FIX: C5-finding-3
        first_upload_kwargs = fake_s3_client.upload_file.call_args_list[0].kwargs  # FIX: C5-finding-3
        assert first_upload_kwargs["ExtraArgs"]["ServerSideEncryption"] == "AES256"  # FIX: C5-finding-3
        assert first_upload_kwargs["ExtraArgs"]["StorageClass"] == "GLACIER"  # FIX: C5-finding-3


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
