"""
Utility functions for the path exploration module.
Provides helper functions for tree traversal and path finding.
"""

import os
from typing import Optional
from .models import FunctionNode, NodeTag


def get_display_name(node: FunctionNode) -> str:
    """
    Get the display name for a node in the tree visualization.

    Args:
        node: The function node to get display name for

    Returns:
        Display string for the node:
        - For Interest nodes: "<filename>#<function_name>"
        - For Sink nodes: "Sink"
    """
    if node.is_sink():
        return "Sink"

    # Get just the filename from the full path
    filename = os.path.basename(node.file_path) if node.file_path else "unknown"
    function_name = node.function_name if node.function_name else "unknown"

    return f"<{filename}#{function_name}>"


def count_nodes_by_tag(root: FunctionNode) -> dict:
    """
    Count nodes in the tree by their tag type.

    Args:
        root: Root node of the tree

    Returns:
        Dictionary with counts for each tag type
    """
    counts = {tag.value: 0 for tag in NodeTag}

    def traverse(node: FunctionNode):
        counts[node.tag.value] += 1
        for child in node.children:
            traverse(child)

    traverse(root)
    return counts


def find_sink_paths(root: FunctionNode) -> list:
    """
    Find all paths from root to sink nodes.

    Args:
        root: Root node of the tree

    Returns:
        List of paths, where each path is a list of FunctionNodes
        from root to a sink node
    """
    paths = []

    def dfs(node: FunctionNode, current_path: list):
        current_path.append(node)

        if node.is_sink():
            paths.append(list(current_path))
        else:
            for child in node.children:
                dfs(child, current_path)

        current_path.pop()

    dfs(root, [])
    return paths


def find_first_interest_leaf(root: FunctionNode) -> Optional[FunctionNode]:
    """
    Find the first Interest-tagged leaf node using DFS.

    This is used to determine which node to explore next.

    Args:
        root: Root node of the tree

    Returns:
        The first Interest leaf node found, or None if no such node exists
    """
    def dfs(node: FunctionNode) -> Optional[FunctionNode]:
        # Check if this node is an Interest leaf
        if node.tag == NodeTag.INTEREST and node.is_leaf():
            return node

        # Recursively check children (DFS)
        for child in node.children:
            result = dfs(child)
            if result is not None:
                return result

        return None

    return dfs(root)


def has_unexplored_interest_nodes(root: FunctionNode) -> bool:
    """
    Check if there are any Interest-tagged leaf nodes remaining to explore.

    Args:
        root: Root node of the tree

    Returns:
        True if there are unexplored Interest nodes, False otherwise
    """
    return find_first_interest_leaf(root) is not None
