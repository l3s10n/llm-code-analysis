"""Check branch traversal and cycle identity without running exploration agents."""

import unittest

from path_explore.models import FunctionNode, InterestInfo, NodeTag
from path_explore.utils import find_first_interest_leaf, find_sink_paths, is_node_in_interest_chain


class ExplorationContractTests(unittest.TestCase):
    def test_sink_paths_keep_branches_separate_and_ignore_unfinished_leaves(self):
        root = FunctionNode(function_name="entry")
        left = FunctionNode(function_name="read")
        right = FunctionNode(function_name="execute")
        unfinished = FunctionNode(function_name="pending")
        file_sink = FunctionNode(tag=NodeTag.SINK_PATH_TRAVERSAL)
        command_sink = FunctionNode(tag=NodeTag.SINK_COMMAND_INJECTION)
        root.add_child(left)
        root.add_child(right)
        root.add_child(unfinished)
        left.add_child(file_sink)
        right.add_child(command_sink)
        paths = find_sink_paths(root)
        self.assertEqual(paths, [[root, left, file_sink], [root, right, command_sink]])
        self.assertIsNot(paths[0], paths[1])
        self.assertEqual(file_sink.get_path_to_root(), paths[0])
        self.assertIs(find_first_interest_leaf(root), unfinished)

    def test_cycle_detection_distinguishes_overloads_and_other_files(self):
        chain = [InterestInfo("read", "Controller.java", 10, 20)]
        self.assertTrue(is_node_in_interest_chain(InterestInfo("read", "Controller.java", 11, 19), chain))
        self.assertFalse(is_node_in_interest_chain(InterestInfo("read", "Controller.java", 30, 40), chain))
        self.assertFalse(is_node_in_interest_chain(InterestInfo("read", "Other.java", 10, 20), chain))

    def test_removing_a_branch_detaches_it_without_changing_its_sibling(self):
        root = FunctionNode(function_name="entry")
        left, right = FunctionNode(function_name="left"), FunctionNode(function_name="right")
        root.add_child(left)
        root.add_child(right)
        root.remove_child(left)
        self.assertIsNone(left.parent)
        self.assertEqual(root.children, [right])
        self.assertEqual(right.get_path_to_root(), [root, right])
