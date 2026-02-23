"""
Configuration module for VulSolver.

Reads config.yaml from project root and provides key access via dot notation.
"""

import sys
from pathlib import Path
from typing import Any, Optional

import yaml


# Global cache for loaded configuration
_config: Optional[dict] = None


def _load_config_file() -> dict:
    """
    Load config.yaml from project root.

    Returns:
        dict: Parsed configuration dictionary.

    Raises:
        SystemExit: If configuration file is not found.
    """
    config_path = Path(__file__).parent.parent / "config.yaml"

    if not config_path.exists():
        print(f"[Config Error] Configuration file not found: {config_path}")
        sys.exit(1)

    with open(config_path, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)


def load_config(key: Optional[str] = None) -> Any:
    """
    Get configuration value by key.

    Args:
        key: Configuration key using dot notation (e.g., "llm.model").
             If None, returns the entire config dict.

    Returns:
        Any: Configuration value for the given key, or entire config dict if key is None.

    Raises:
        SystemExit: If the specified key is not found in configuration.
    """
    global _config

    if _config is None:
        _config = _load_config_file()

    if key is None:
        return _config

    # Navigate through nested keys using dot notation
    keys = key.split('.')
    value = _config

    for k in keys:
        if isinstance(value, dict) and k in value:
            value = value[k]
        else:
            print(f"[Config Error] Key not found: {key}")
            sys.exit(1)

    return value
