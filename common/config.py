"""
Configuration module for VulSolver.

Reads the project config.yaml by default, or the path selected through the
GOLD_MINER_CONFIG environment variable, and provides dot-notation key access.
"""

import os
import sys
from pathlib import Path
from typing import Any, Optional

import yaml


# Global cache for loaded configuration
_config: Optional[dict] = None

# Keys that are allowed to be missing or empty.
OPTIONAL_CONFIG_KEYS = {
    "decision_llm",
    "decision_llm.base_url",
    "decision_llm.api_key",
    "decision_llm.model",
}

CONFIG_ENV_VAR = "GOLD_MINER_CONFIG"


def get_config_path() -> Path:
    """Return the effective configuration file path."""
    configured_path = os.environ.get(CONFIG_ENV_VAR)
    if configured_path:
        return Path(configured_path).expanduser().resolve()
    return Path(__file__).parent.parent / "config.yaml"


def _load_config_file() -> dict:
    """
    Load the effective configuration file.

    Returns:
        dict: Parsed configuration dictionary.

    Raises:
        SystemExit: If configuration file is not found.
    """
    config_path = get_config_path()

    if not config_path.exists():
        from common.tui import emit_output

        emit_output(
            f"[Error] Configuration file not found: {config_path}",
            source="Config",
            level="ERROR",
        )
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

    is_optional_key = key in OPTIONAL_CONFIG_KEYS

    # Navigate through nested keys using dot notation
    keys = key.split('.')
    value = _config

    for k in keys:
        if isinstance(value, dict) and k in value:
            value = value[k]
            continue

        if is_optional_key:
            return None
        else:
            from common.tui import emit_output

            emit_output(
                f"[Error] Key not found: {key}",
                source="Config",
                level="ERROR",
            )
            sys.exit(1)

    if is_optional_key:
        if value is None:
            return None
        if isinstance(value, str) and not value.strip():
            return None

    return value
