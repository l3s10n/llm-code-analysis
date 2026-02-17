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
    """
    INTEREST = "Interest"
    SINK_PATH_TRAVERSAL = "Sink(PathTraversal)"
    SINK_COMMAND_INJECTION = "Sink(CommandInjection)"


@dataclass
class FunctionNode:
    """
    Represents a node in the function exploration tree.

    Attributes:
        function_name: Name of the function (empty for sink nodes)
        file_path: Path to the file containing the function
        source_code: Source code of the function
        tag: Classification tag (Interest, Sink, etc.)
        extra_info: Additional information (e.g., call expression for sinks)
        children: List of child nodes
        parent: Reference to parent node (None for root)
    """
    function_name: str = ""
    file_path: str = ""
    source_code: str = ""
    tag: NodeTag = NodeTag.INTEREST
    extra_info: str = ""
    children: List['FunctionNode'] = field(default_factory=list)
    parent: Optional['FunctionNode'] = None

    def add_child(self, child: 'FunctionNode') -> None:
        """Add a child node and set parent reference."""
        child.parent = self
        self.children.append(child)

    def remove_child(self, child: 'FunctionNode') -> None:
        """Remove a child node."""
        if child in self.children:
            self.children.remove(child)
            child.parent = None

    def is_leaf(self) -> bool:
        """Check if this node is a leaf node (no children)."""
        return len(self.children) == 0

    def is_sink(self) -> bool:
        """Check if this node is a sink node."""
        return self.tag in (NodeTag.SINK_PATH_TRAVERSAL, NodeTag.SINK_COMMAND_INJECTION)

    def get_path_to_root(self) -> List['FunctionNode']:
        """Get the path from this node to the root."""
        path = [self]
        current = self.parent
        while current is not None:
            path.append(current)
            current = current.parent
        return list(reversed(path))


@dataclass
class NextHopResult:
    """
    Result from next_hop_agent containing information about next hop functions.

    Attributes:
        expression: The call expression of the next hop function
        tag: Classification of the next hop (Sink or Interest)
    """
    expression: str
    tag: NodeTag


@dataclass
class NextHopInfo:
    """
    Detailed information about a next hop function from interest_info_find_agent.

    Attributes:
        function_name: Name of the function
        file_path: Path to the file containing the function
        source_code: Source code of the function
    """
    function_name: str
    file_path: str
    source_code: str


@dataclass
class SourceInfo:
    """
    Information about the source function from source_info_find_agent.

    Attributes:
        function_name: Name of the source function
        file_path: Path to the file containing the function
        source_code: Source code of the function
    """
    function_name: str
    file_path: str
    source_code: str


@dataclass
class VulnerabilityPath:
    """
    Represents a complete vulnerability path from source to sink.

    Attributes:
        vulnerability_type: Type of vulnerability (PathTraversal or CommandInjection)
        sink_expression: The expression where the sink is called
        path: List of (file_path, function_name, source_code) tuples from source to sink
    """
    vulnerability_type: str
    sink_expression: str
    path: List[tuple]  # List of (file_path, function_name, source_code)

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "Type": self.vulnerability_type,
            "SinkExpression": self.sink_expression,
            "Path": [{"file": p[0], "name": p[1], "source_code": p[2]} for p in self.path]
        }
