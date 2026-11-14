"""Isolate offline tests from local credentials and model requests."""

import atexit
import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import claude_agent_sdk


_config_dir = tempfile.TemporaryDirectory(prefix="vulsolver-offline-")
_config_path = Path(_config_dir.name) / "test-config.yaml"
_config_path.write_text(
    json.dumps({
        "llm": {
            "model": "offline-test-model",
            "base_url": "https://example.invalid",
            "api_key": "placeholder-not-a-secret",
        },
        "agent": {"max_retries": 1, "timeout_seconds": 1},
        "exploration": {"verbose": False, "max_depth": 1},
    }),
    encoding="utf-8",
)
_config_override = patch.dict(os.environ, {"GOLD_MINER_CONFIG": str(_config_path)})
_config_override.start()
_query_guard = patch.object(
    claude_agent_sdk,
    "query",
    side_effect=AssertionError("Offline tests must not call a model"),
)
_query_guard.start()
atexit.register(_config_dir.cleanup)
atexit.register(_config_override.stop)
atexit.register(_query_guard.stop)
