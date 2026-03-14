"""
Data models for the path verification module.
Defines the core data structures used in vulnerability path verification.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, List


@dataclass
class PathNode:
    """
    Represents a single node in the vulnerability path.

    Attributes:
        file_path: Relative path to the file containing the function
        function_name: Name of the function
        start_line: Start line of the function in the source file (1-based, inclusive)
        end_line: End line of the function in the source file (1-based, inclusive)
    """

    file_path: str
    function_name: str
    start_line: int
    end_line: int

    @classmethod
    def from_dict(cls, data: dict) -> "PathNode":
        """
        Create PathNode from dictionary.

        Args:
            data: Dictionary with the new line-range fields

        Returns:
            PathNode instance
        """

        file_path = data.get("file_path", "")
        function_name = data.get("function_name", "")

        start_line = data.get("start_line", 0)
        end_line = data.get("end_line", 0)

        try:
            start_line = int(start_line)
        except (TypeError, ValueError):
            start_line = 0

        try:
            end_line = int(end_line)
        except (TypeError, ValueError):
            end_line = 0

        return cls(
            file_path=file_path,
            function_name=function_name,
            start_line=start_line,
            end_line=end_line,
        )

    def get_source_code(self, target_path: str) -> str:
        """
        Load the source code for this node.

        Args:
            target_path: Path to the target project's source code

        Returns:
            Source code string for the function
        """

        if not self.file_path or self.start_line <= 0 or self.end_line < self.start_line:
            return ""

        abs_path = Path(target_path) / self.file_path
        lines = abs_path.read_text(encoding="utf-8").splitlines()
        if not lines:
            return ""

        safe_start = max(1, min(self.start_line, len(lines)))
        safe_end = max(safe_start, min(self.end_line, len(lines)))
        return "\n".join(lines[safe_start - 1 : safe_end])

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "file_path": self.file_path,
            "function_name": self.function_name,
            "start_line": self.start_line,
            "end_line": self.end_line,
        }


@dataclass
class PotentialPath:
    """
    Represents a potential vulnerability path from source to sink.

    This is the input format loaded from path_explore's JSON output.

    Attributes:
        vulnerability_type: Type of vulnerability (PathTraversal, CommandInjection, CodeInjection, SQLInjection, or SSRF)
        sink_expression: The expression where the sink is called
        path: List of PathNode from source to sink (excluding sink marker)
        interface_name: The API interface being analyzed (e.g., /api/readFile)
    """

    vulnerability_type: str
    sink_expression: str
    path: List[PathNode] = field(default_factory=list)
    interface_name: str = ""

    @classmethod
    def from_dict(cls, data: dict) -> "PotentialPath":
        """
        Create PotentialPath from dictionary (JSON format).

        Args:
            data: Dictionary with 'InterfaceName', 'Type', 'SinkExpression', and 'Path' keys

        Returns:
            PotentialPath instance
        """

        path_nodes = [
            PathNode.from_dict(node_data)
            for node_data in data.get("Path", [])
        ]
        return cls(
            interface_name=data.get("InterfaceName", ""),
            vulnerability_type=data.get("Type", ""),
            sink_expression=data.get("SinkExpression", ""),
            path=path_nodes,
        )

    def get_call_chain_display(self) -> str:
        """
        Get a formatted string representation of the call chain.

        Returns:
            String in format: "func1 -> func2 -> ... -> sink"
        """

        names = [node.function_name for node in self.path]
        names.append("sink")
        return " -> ".join(names)


@dataclass
class DataflowInfo:
    """
    Represents dataflow information for a single node.

    Tracks which parameters, member variables, and non-local sources of a
    function flow to the sink's key semantics.

    Attributes:
        parameters: List of parameter names that flow to sink semantics
        member_variables: List of member variable names that flow to sink semantics
        non_local_sources: List of concise descriptions of non-local sources that
            flow to sink semantics
    """

    parameters: List[str] = field(default_factory=list)
    member_variables: List[str] = field(default_factory=list)
    non_local_sources: List[str] = field(default_factory=list)

    def is_empty(self) -> bool:
        """Check if parameters, member_variables, and non_local_sources are all empty."""
        return (
            len(self.parameters) == 0
            and len(self.member_variables) == 0
            and len(self.non_local_sources) == 0
        )

    def to_display(self) -> str:
        """
        Get a formatted display string.

        Returns:
            String showing parameters, member variables, and non-local sources
        """

        parts = []
        if self.parameters:
            parts.append(f"Parameters: {', '.join(self.parameters)}")
        if self.member_variables:
            parts.append(f"Member Variables: {', '.join(self.member_variables)}")
        if self.non_local_sources:
            parts.append(f"NonLocalSources: {', '.join(self.non_local_sources)}")
        return " | ".join(parts) if parts else "No dataflow"


@dataclass
class FilterLogic:
    """
    Represents a filtering logic that may prevent vulnerability exploitation.

    Attributes:
        dataflow: The specific caller-side item that ultimately becomes sink
            semantics and is affected by this logic
        description: Description of what the filtering logic does
        file_path: File path where the filtering logic is implemented
        line_range: Line number range (start, end) of the filtering logic,
                   or None if not determined
        node_index: Index of the node where this filter was found (0-based).
    """

    dataflow: str
    description: str
    file_path: str
    line_range: Optional[tuple] = None
    node_index: int = -1

    def to_display(self) -> str:
        """
        Get a formatted display string.

        Returns:
            String showing filter details
        """

        location = self.file_path
        if self.line_range:
            location += f":{self.line_range[0]}-{self.line_range[1]}"
        return f"[{location}] {self.dataflow}: {self.description}"


@dataclass
class NodeDataflowRecord:
    """
    Records the dataflow analysis result for a single node in the path.

    Attributes:
        node_index: Index of the node in the path (0-based)
        node_name: Name of the function for display purposes
        dataflow_info: DataflowInfo containing parameters, member variables,
                      and non-local sources that flow to sink semantics
    """

    node_index: int
    node_name: str
    dataflow_info: DataflowInfo


@dataclass
class VerificationResult:
    """
    Final verification result for a potential vulnerability path.

    Based on the explore module's output format with additional verification fields.
    """

    vulnerability_type: str
    sink_expression: str
    path: List[PathNode] = field(default_factory=list)
    interface_name: str = ""

    is_vulnerable: bool = False
    confidence: str = "Low"
    summary: str = ""

    dataflow_records: List[NodeDataflowRecord] = field(default_factory=list)
    filter_logics: List[FilterLogic] = field(default_factory=list)

    def to_dict(self) -> dict:
        """
        Convert to dictionary for JSON serialization.

        Returns:
            Dictionary representation suitable for JSON export
        """

        return {
            "InterfaceName": self.interface_name,
            "Type": self.vulnerability_type,
            "SinkExpression": self.sink_expression,
            "Path": [node.to_dict() for node in self.path],
            "IsVulnerable": self.is_vulnerable,
            "Confidence": self.confidence,
            "Summary": self.summary,
            "DataflowAnalysis": [
                {
                    "NodeIndex": record.node_index,
                    "NodeName": record.node_name,
                    "Parameters": record.dataflow_info.parameters,
                    "MemberVariables": record.dataflow_info.member_variables,
                    "NonLocalSources": record.dataflow_info.non_local_sources,
                }
                for record in self.dataflow_records
            ],
            "FilterLogics": [
                {
                    "Dataflow": logic.dataflow,
                    "Description": logic.description,
                    "File": logic.file_path,
                    "Lines": f"{logic.line_range[0]}-{logic.line_range[1]}"
                    if logic.line_range else "Unknown",
                }
                for logic in self.filter_logics
            ],
        }
