"""
Utility functions for the path exploration module.
Provides helper functions for tree traversal and path finding.
"""

import os
from pathlib import Path
from typing import Iterable, Optional

from .models import FunctionNode, InterestInfo, NodeTag


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

    filename = os.path.basename(node.file_path) if node.file_path else "unknown"
    function_name = node.function_name if node.function_name else "unknown"
    return f"<{filename}#{function_name}>"


def resolve_project_file(target_path: str, file_path: str) -> Path:
    """
    Resolve a project-relative file path to an absolute path.

    Args:
        target_path: Path to the target project's source code
        file_path: File path relative to the project root

    Returns:
        Absolute file path
    """

    return Path(target_path) / file_path


def clamp_line_range(target_path: str, file_path: str, start_line: int, end_line: int) -> tuple[int, int]:
    """
    Clamp a line range to the actual file boundaries.

    Args:
        target_path: Path to the target project's source code
        file_path: File path relative to the project root
        start_line: Requested start line (1-based, inclusive)
        end_line: Requested end line (1-based, inclusive)

    Returns:
        Tuple of (start_line, end_line) within file bounds
    """

    abs_path = resolve_project_file(target_path, file_path)
    lines = abs_path.read_text(encoding="utf-8").splitlines()
    if not lines:
        return 1, 1

    max_line = len(lines)
    safe_start = max(1, min(start_line, max_line))
    safe_end = max(safe_start, min(end_line, max_line))
    return safe_start, safe_end


def read_source_code_by_range(target_path: str, file_path: str, start_line: int, end_line: int) -> str:
    """
    Read source code using a 1-based inclusive line range.

    Args:
        target_path: Path to the target project's source code
        file_path: File path relative to the project root
        start_line: Start line of the function (1-based, inclusive)
        end_line: End line of the function (1-based, inclusive)

    Returns:
        Source code string within the requested line range
    """

    safe_start, safe_end = clamp_line_range(target_path, file_path, start_line, end_line)
    abs_path = resolve_project_file(target_path, file_path)
    lines = abs_path.read_text(encoding="utf-8").splitlines()
    return "\n".join(lines[safe_start - 1 : safe_end])


def count_nodes_by_tag(root: FunctionNode) -> dict:
    """
    Count nodes in the tree by their tag type.

    Args:
        root: Root node of the tree

    Returns:
        Dictionary with counts for each tag type
    """

    counts = {tag.value: 0 for tag in NodeTag}

    def traverse(node: FunctionNode) -> None:
        counts[node.tag.value] += 1
        for child in node.children:
            traverse(child)

    traverse(root)
    return counts


def line_ranges_overlap(start_a: int, end_a: int, start_b: int, end_b: int) -> bool:
    """
    Check whether two line ranges overlap.

    Args:
        start_a: Start of first range (inclusive)
        end_a: End of first range (inclusive)
        start_b: Start of second range (inclusive)
        end_b: End of second range (inclusive)

    Returns:
        True if the two ranges overlap, False otherwise
    """

    return max(start_a, start_b) <= min(end_a, end_b)


def is_same_interest_node(left: InterestInfo, right: InterestInfo) -> bool:
    """
    Determine whether two InterestInfo objects refer to the same function node.

    Args:
        left: First InterestInfo
        right: Second InterestInfo

    Returns:
        True if both nodes refer to the same file and overlapping line range
    """

    return left.file_path == right.file_path and line_ranges_overlap(
        left.start_line,
        left.end_line,
        right.start_line,
        right.end_line,
    )


def is_node_in_interest_chain(info: InterestInfo, chain: Iterable[InterestInfo]) -> bool:
    """
    Check whether an InterestInfo already appears in the current call chain.

    Args:
        info: InterestInfo to look for
        chain: Current call chain represented as InterestInfo items

    Returns:
        True if the same function node already appears in the chain
    """

    for existing in chain:
        if is_same_interest_node(info, existing):
            return True
    return False


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

    def dfs(node: FunctionNode, current_path: list) -> None:
        current_path.append(node)

        if node.is_sink():
            paths.append(list(current_path))
        else:
            for child in node.children:
                dfs(child, current_path)

        current_path.pop()

    dfs(root, [])
    return paths


def find_first_interest_leaf(root: Optional[FunctionNode]) -> Optional[FunctionNode]:
    """
    Find the first Interest-tagged leaf node using DFS.

    Args:
        root: Root node of the tree, or None if tree is empty

    Returns:
        The first Interest leaf node found, or None if no such node exists
    """

    if root is None:
        return None

    def dfs(node: FunctionNode) -> Optional[FunctionNode]:
        if node.tag == NodeTag.INTEREST and node.is_leaf():
            return node

        for child in node.children:
            result = dfs(child)
            if result is not None:
                return result

        return None

    return dfs(root)


def has_unexplored_interest_nodes(root: Optional[FunctionNode]) -> bool:
    """
    Check if there are any Interest-tagged leaf nodes remaining to explore.

    Args:
        root: Root node of the tree, or None if tree is empty

    Returns:
        True if there are unexplored Interest nodes, False otherwise
    """

    return find_first_interest_leaf(root) is not None


__all__ = [
    "clamp_line_range",
    "count_nodes_by_tag",
    "find_first_interest_leaf",
    "find_sink_paths",
    "get_display_name",
    "has_unexplored_interest_nodes",
    "is_node_in_interest_chain",
    "is_same_interest_node",
    "line_ranges_overlap",
    "read_source_code_by_range",
    "resolve_project_file",
]
