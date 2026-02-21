#!/usr/bin/env python3
"""Config Migrator - Migrates openclaw-agent.yml between versions.

Run from repo root:
    python tools/config-migrator.py --help
"""

import argparse
import shutil
import json
from pathlib import Path
from datetime import datetime

try:
    import yaml
except ModuleNotFoundError:
    yaml = None


class ConfigMigrator:
    """Migrates configuration files between versions."""
    
    def migrate(self, config_path, from_version, to_version):
        """Migrate configuration file."""
        if yaml is None:
            return {"success": False, "error": "Missing dependency: pyyaml"}

        try:
            # Backup original
            backup_path = self._create_backup(config_path)
            
            # Load config
            with open(config_path) as f:
                config = yaml.safe_load(f)
            
            # Apply migrations
            migrated = self._apply_migrations(config, from_version, to_version)
            
            # Save migrated config
            output_path = Path(config_path).with_suffix(".v" + to_version + ".yml")
            
            with open(output_path, "w") as f:
                yaml.dump(migrated, f, default_flow_style=False, sort_keys=False)
            
            return {
                "success": True,
                "backup_path": str(backup_path),
                "output_path": str(output_path),
            }
        
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
            }
    
    def _create_backup(self, config_path):
        """Create backup of config file."""
        backup_path = Path(config_path).with_suffix(
            f".backup.{datetime.now().strftime('%Y%m%d%H%M%S')}.yml"
        )
        
        shutil.copy2(config_path, backup_path)
        
        return backup_path
    
    def _apply_migrations(self, config, from_version, to_version):
        """Apply version-specific migrations."""
        if from_version == "1.0" and to_version == "2.0":
            # Example migration: rename field
            if "old_field" in config:
                config["new_field"] = config.pop("old_field")
        
        return config


def migrate(config_path, from_version, to_version):
    """Module-level wrapper used by openclaw-cli."""
    return ConfigMigrator().migrate(config_path, from_version, to_version)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Migrate OpenClaw agent configuration versions")
    parser.add_argument(
        "--config",
        default="configs/agent-config/openclaw-agent.yml",
        help="Path to source configuration file",
    )
    parser.add_argument("--from-version", default="1.0", help="Source version")
    parser.add_argument("--to-version", default="2.0", help="Target version")
    args = parser.parse_args()

    migrator = ConfigMigrator()
    result = migrator.migrate(args.config, args.from_version, args.to_version)
    print(json.dumps(result, indent=2))
