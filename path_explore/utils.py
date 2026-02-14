"""
Utility functions for the path exploration module.
Provides helper functions for tree visualization and logging.
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


def print_tree_recursive(
    node: FunctionNode,
    prefix: str = "",
    is_last: bool = True,
    is_root: bool = True
) -> None:
    """
    Recursively print the exploration tree with visual formatting.

    Args:
        node: Current node to print
        prefix: Prefix string for indentation
        is_last: Whether this node is the last child of its parent
        is_root: Whether this node is the root of the tree
    """
    # Determine the connector and new prefix
    if is_root:
        connector = ""
        new_prefix = prefix
    else:
        connector = "└── " if is_last else "├── "
        new_prefix = prefix + ("    " if is_last else "│   ")

    # Print current node
    display_name = get_display_name(node)
    tag_display = f" [{node.tag.value}]"

    print(f"{prefix}{connector}{display_name}{tag_display}")

    # Print children
    children_count = len(node.children)
    for i, child in enumerate(node.children):
        is_last_child = (i == children_count - 1)
        print_tree_recursive(child, new_prefix, is_last_child, is_root=False)


def print_exploration_tree(root: FunctionNode, modification_log: str = "") -> None:
    """
    Print the exploration tree with a modification log header.

    Args:
        root: Root node of the exploration tree
        modification_log: Description of recent modifications
    """
    print("\n" + "=" * 60)
    print("Function Exploration Tree")
    print("=" * 60)

    if modification_log:
        print(f"[Modification] {modification_log}")

    print("-" * 60)
    print_tree_recursive(root)
    print("=" * 60 + "\n")


def log_modification(action: str, details: str) -> None:
    """
    Print a modification log message.

    Args:
        action: Type of action (e.g., "Added", "Removed", "Updated")
        details: Details about the modification
    """
    print(f"[Tree Update] {action}: {details}")


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
