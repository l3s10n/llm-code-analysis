"""Exercise validation and retry boundaries with all agent execution mocked."""

import importlib
import os
import unittest
from unittest.mock import patch


agent = importlib.import_module("common.base_claude_agent")


class AgentRetryContractTests(unittest.TestCase):
    def setUp(self):
        self.execute = self.enterContext(patch.object(agent, "_execute_with_timeout"))
        self.save = self.enterContext(patch.object(agent, "_save_cache"))
        self.enterContext(patch.object(agent, "load_config", side_effect={
            "agent.max_retries": 1, "agent.timeout_seconds": 1,
        }.__getitem__))

    def test_structurally_invalid_output_is_retried_and_never_saved(self):
        self.execute.side_effect = [("missing required marker", "key"), ("VALID: complete result", "key")]
        result = agent.base_claude_agent(
            ".", "system", "task", result_validator=lambda text: (text.startswith("VALID:"), "marker missing")
        )
        self.assertTrue(result.success)
        self.assertEqual([call.kwargs["use_cache"] for call in self.execute.call_args_list], [True, False])
        self.save.assert_called_once_with("key", "VALID: complete result")

    def test_exhausted_validation_attempts_return_failure_without_caching(self):
        self.execute.return_value = ("invalid but long enough", "key")
        result = agent.base_claude_agent(
            ".", "system", "task", result_validator=lambda text: (False, "marker missing")
        )
        self.assertFalse(result.success)
        self.assertEqual(result.error_type, "invalid_result_format")
        self.assertEqual(self.execute.call_count, 2)
        self.save.assert_not_called()

    def test_timeout_can_retry_without_reusing_cached_output(self):
        self.execute.side_effect = [TimeoutError("fixture timeout"), ("complete retry result", "key")]
        result = agent.base_claude_agent(".", "system", "task")
        self.assertTrue(result.success)
        self.assertFalse(self.execute.call_args_list[-1].kwargs["use_cache"])
        self.save.assert_called_once_with("key", "complete retry result")


class CacheIsolationTests(unittest.TestCase):
    def test_model_changes_isolate_cache_entries_while_tool_order_does_not(self):
        with patch.dict(os.environ, {"ANTHROPIC_DEFAULT_OPUS_MODEL": "test-model-a"}):
            first = agent._generate_cache_key(".", "system", "task", ["Read", "Grep"])
            reordered = agent._generate_cache_key(".", "system", "task", ["Grep", "Read"])
        with patch.dict(os.environ, {"ANTHROPIC_DEFAULT_OPUS_MODEL": "test-model-b"}):
            other_model = agent._generate_cache_key(".", "system", "task", ["Read", "Grep"])
        self.assertEqual(first, reordered)
        self.assertNotEqual(first, other_model)
