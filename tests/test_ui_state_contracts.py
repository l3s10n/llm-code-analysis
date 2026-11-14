"""Verify frontend state isolation without launching a terminal subprocess."""

import unittest

from ui.controller import TextualFrontendController


class FrontendStateTests(unittest.TestCase):
    def test_call_chain_inputs_and_snapshots_do_not_alias_controller_state(self):
        controller = TextualFrontendController()
        chain, files = ["entry", "read"], ["Entry.java", "Read.java"]
        controller.set_verify_path_info(1, 2, chain, files, "Files.readString(path)")
        chain.append("unexpected")
        files.clear()
        snapshot = controller.snapshot()
        self.assertEqual(snapshot.call_chain, ["entry", "read"])
        self.assertEqual(snapshot.call_chain_files, ["Entry.java", "Read.java"])
        snapshot.call_chain.clear()
        snapshot.logs.append("external mutation")
        self.assertEqual(controller.snapshot().call_chain, ["entry", "read"])
        self.assertNotIn("external mutation", controller.snapshot().logs)

    def test_log_and_stream_buffers_keep_recent_output_within_limits(self):
        controller = TextualFrontendController()
        for index in range(305):
            controller.log("fixture", f"message {index}")
        state = controller.snapshot()
        self.assertEqual(len(state.logs), state.max_logs)
        self.assertTrue(state.logs[0].endswith("message 5"))
        self.assertTrue(state.logs[-1].endswith("message 304"))
        controller.stream_agent_output("x" * 8100)
        self.assertEqual(len(controller.snapshot().stream_buffer), 8000)
        controller.clear_stream_buffer()
        self.assertEqual(controller.snapshot().stream_buffer, "")
