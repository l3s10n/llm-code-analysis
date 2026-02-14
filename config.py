"""
Configuration management module for GOLD MINER.
Provides centralized configuration loading and access throughout the application.
"""

import os
import json
import yaml
from pathlib import Path
from typing import Any, Optional, Dict


# Global configuration cache
_config: Optional[Dict[str, Any]] = None
_config_path: Optional[Path] = None


def get_config_path() -> Path:
    """
    Get the path to the configuration file.

    Priority order:
    1. GOLD_MINER_CONFIG environment variable
    2. config.yaml in project root
    3. config.json in project root

    Returns:
        Path to the configuration file

    Raises:
        FileNotFoundError: If no configuration file is found
    """
    global _config_path

    if _config_path is not None:
        return _config_path

    # Check environment variable first
    env_config = os.environ.get("GOLD_MINER_CONFIG")
    if env_config:
        config_file = Path(env_config)
        if config_file.exists():
            _config_path = config_file
            return _config_path

    # Get project root directory (where this file's parent is)
    project_root = Path(__file__).parent

    # Check for YAML config
    yaml_config = project_root / "config.yaml"
    if yaml_config.exists():
        _config_path = yaml_config
        return _config_path

    # Check for JSON config
    json_config = project_root / "config.json"
    if json_config.exists():
        _config_path = json_config
        return _config_path

    raise FileNotFoundError(
        "Configuration file not found. "
        "Please create config.yaml or config.json in the project root, "
        "or set GOLD_MINER_CONFIG environment variable."
    )


def load_config(reload: bool = False) -> Dict[str, Any]:
    """
    Load configuration from file.

    Args:
        reload: If True, force reload configuration from file

    Returns:
        Dictionary containing configuration values
    """
    global _config

    if _config is not None and not reload:
        return _config

    config_path = get_config_path()

    with open(config_path, 'r', encoding='utf-8') as f:
        if config_path.suffix in ('.yaml', '.yml'):
            _config = yaml.safe_load(f)
        elif config_path.suffix == '.json':
            _config = json.load(f)
        else:
            raise ValueError(f"Unsupported config file format: {config_path.suffix}")

    # Override API key from environment variable if set
    env_api_key = os.environ.get("ANTHROPIC_API_KEY")
    if env_api_key and _config:
        if "llm" not in _config:
            _config["llm"] = {}
        _config["llm"]["api_key"] = env_api_key

    return _config


def get_config(key: str = None, default: Any = None) -> Any:
    """
    Get configuration value(s).

    This is the main function to retrieve configuration values from anywhere
    in the application.

    Args:
        key: Configuration key using dot notation (e.g., "llm.model", "exploration.max_depth")
             If None, returns the entire configuration dictionary.
        default: Default value to return if key is not found

    Returns:
        Configuration value or default if key not found

    Examples:
        >>> get_config()  # Returns entire config
        {'llm': {...}, 'exploration': {...}, ...}

        >>> get_config("llm.model")
        'claude-sonnet-4-20250514'

        >>> get_config("exploration.max_depth")
        20

        >>> get_config("nonexistent.key", "default_value")
        'default_value'
    """
    config = load_config()

    if key is None:
        return config

    # Navigate through nested keys using dot notation
    keys = key.split('.')
    value = config

    for k in keys:
        if isinstance(value, dict) and k in value:
            value = value[k]
        else:
            return default

    return value


def set_config_value(key: str, value: Any) -> None:
    """
    Set a configuration value at runtime (does not persist to file).

    Args:
        key: Configuration key using dot notation
        value: Value to set

    Example:
        >>> set_config_value("exploration.verbose", False)
    """
    global _config

    config = load_config()
    keys = key.split('.')
    current = config

    # Navigate to parent of target key
    for k in keys[:-1]:
        if k not in current:
            current[k] = {}
        current = current[k]

    # Set the value
    current[keys[-1]] = value


def reload_config() -> Dict[str, Any]:
    """
    Force reload configuration from file.

    Returns:
        Reloaded configuration dictionary
    """
    return load_config(reload=True)


def get_llm_config() -> Dict[str, Any]:
    """
    Get LLM-specific configuration.

    Returns:
        Dictionary containing LLM configuration
    """
    return get_config("llm", default={
        "api_key": "",
        "model": "claude-sonnet-4-20250514",
        "max_tokens": 4096,
        "temperature": 0.0
    })


def get_exploration_config() -> Dict[str, Any]:
    """
    Get exploration-specific configuration.

    Returns:
        Dictionary containing exploration configuration
    """
    return get_config("exploration", default={
        "max_depth": 20,
        "max_nodes": 1000,
        "verbose": True
    })


def get_sink_patterns() -> Dict[str, list]:
    """
    Get sink function patterns for vulnerability detection.

    Returns:
        Dictionary containing sink patterns grouped by vulnerability type
    """
    return get_config("sink_patterns", default={
        "path_traversal": [],
        "command_injection": []
    })


def is_verbose() -> bool:
    """
    Check if verbose logging is enabled.

    Returns:
        True if verbose logging is enabled, False otherwise
    """
    return get_config("exploration.verbose", default=False)


# Initialize configuration on module load (lazy - only when first accessed)
def _init_config():
    """Initialize configuration module."""
    try:
        get_config_path()
    except FileNotFoundError:
        pass  # Config file will be required when actually used
