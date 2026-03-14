"""
Data models for the path exploration module.
Defines the core data structures used in vulnerability path discovery.
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import Optional, List


class NodeTag(Enum):
    """
    Enumeration of possible tags for function nodes in the exploration tree.

    INTEREST: Node represents a function that may lead to sink functions
    SINK_PATH_TRAVERSAL: Node represents a path traversal vulnerability sink
    SINK_COMMAND_INJECTION: Node represents a command injection vulnerability sink
    SINK_CODE_INJECTION: Node represents a code injection vulnerability sink
    SINK_SQL_INJECTION: Node represents a SQL injection vulnerability sink
    SINK_SSRF: Node represents a Server-Side Request Forgery vulnerability sink
    """

    INTEREST = "Interest"
    SINK_PATH_TRAVERSAL = "Sink(PathTraversal)"
    SINK_COMMAND_INJECTION = "Sink(CommandInjection)"
    SINK_CODE_INJECTION = "Sink(CodeInjection)"
    SINK_SQL_INJECTION = "Sink(SQLInjection)"
    SINK_SSRF = "Sink(SSRF)"


@dataclass(eq=False)
class FunctionNode:
    """
    Represents a node in the function exploration tree.

    Attributes:
        function_name: Name of the function (empty for sink nodes)
        file_path: Path to the file containing the function
        source_code: Source code of the function
        tag: Classification tag (Interest, Sink, etc.)
        extra_info: Additional information (e.g., call expression for sinks)
        start_line: Start line of the function in the source file (1-based, inclusive)
        end_line: End line of the function in the source file (1-based, inclusive)
        children: List of child nodes
        parent: Reference to parent node (None for root)
    """

    function_name: str = ""
    file_path: str = ""
    source_code: str = ""
    tag: NodeTag = NodeTag.INTEREST
    extra_info: str = ""
    start_line: int = 0
    end_line: int = 0
    children: List["FunctionNode"] = field(default_factory=list)
    parent: Optional["FunctionNode"] = None

    def add_child(self, child: "FunctionNode") -> None:
        """Add a child node and set parent reference."""
        child.parent = self
        self.children.append(child)

    def remove_child(self, child: "FunctionNode") -> None:
        """Remove a child node."""
        if child in self.children:
            self.children.remove(child)
            child.parent = None

    def is_leaf(self) -> bool:
        """Check if this node is a leaf node (no children)."""
        return len(self.children) == 0

    def is_sink(self) -> bool:
        """Check if this node is a sink node."""
        return self.tag in (
            NodeTag.SINK_PATH_TRAVERSAL,
            NodeTag.SINK_COMMAND_INJECTION,
            NodeTag.SINK_CODE_INJECTION,
            NodeTag.SINK_SQL_INJECTION,
            NodeTag.SINK_SSRF,
        )

    def get_path_to_root(self) -> List["FunctionNode"]:
        """Get the path from this node to the root."""
        path = [self]
        current = self.parent
        while current is not None:
            path.append(current)
            current = current.parent
        return list(reversed(path))

    def to_tree_string(self, indent: int = 0, is_last: bool = True) -> str:
        """
        Generate a tree-style string representation of this node and its children.

        Args:
            indent: Current indentation level
            is_last: Whether this node is the last child of its parent

        Returns:
            A formatted string representing the tree structure
        """
        import os

        prefix = "    " * indent
        if indent > 0:
            prefix += "└── " if is_last else "├── "

        if self.is_sink():
            node_display = "Sink"
        else:
            filename = os.path.basename(self.file_path) if self.file_path else "?"
            node_display = f"{filename}#{self.function_name}"

        result = f"{prefix}{node_display}\n"

        for i, child in enumerate(self.children):
            is_last_child = i == len(self.children) - 1
            result += child.to_tree_string(indent + 1, is_last_child)

        return result


@dataclass
class InterestInfo:
    """
    Information about an interest function.

    Attributes:
        function_name: Name of the function
        file_path: Path to the file containing the function
        start_line: Start line of the function in the source file (1-based, inclusive)
        end_line: End line of the function in the source file (1-based, inclusive)
    """

    function_name: str
    file_path: str
    start_line: int
    end_line: int


@dataclass
class SinkInfo:
    """
    Information about a sink node.

    Attributes:
        sink_expression: The sink call expression in the current function
    """

    sink_expression: str


@dataclass
class VulnerabilityPath:
    """
    Represents a complete vulnerability path from source to sink.

    Attributes:
        vulnerability_type: Type of vulnerability (PathTraversal, CommandInjection, CodeInjection, SQLInjection, or SSRF)
        sink_expression: The expression where the sink is called
        path: List of (file_path, function_name, start_line, end_line) tuples from source to sink
        interface_name: The API interface being analyzed (e.g., /api/readFile)
    """

    vulnerability_type: str
    sink_expression: str
    path: List[tuple]
    interface_name: str = ""

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "InterfaceName": self.interface_name,
            "Type": self.vulnerability_type,
            "SinkExpression": self.sink_expression,
            "Path": [
                {
                    "file_path": p[0],
                    "function_name": p[1],
                    "start_line": p[2],
                    "end_line": p[3],
                }
                for p in self.path
            ],
        }
