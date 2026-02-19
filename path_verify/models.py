"""
Data models for the path verification module.
Defines the core data structures used in vulnerability path verification.
"""

from dataclasses import dataclass, field
from typing import Optional, List


@dataclass
class PathNode:
    """
    Represents a single node in the vulnerability path.

    Attributes:
        file: Relative path to the file containing the function
        name: Name of the function
        source_code: Source code of the function
    """
    file: str
    name: str
    source_code: str

    @classmethod
    def from_dict(cls, data: dict) -> 'PathNode':
        """
        Create PathNode from dictionary.

        Args:
            data: Dictionary with 'file', 'name', and 'source_code' keys

        Returns:
            PathNode instance
        """
        return cls(
            file=data.get('file', ''),
            name=data.get('name', ''),
            source_code=data.get('source_code', '')
        )


@dataclass
class PotentialPath:
    """
    Represents a potential vulnerability path from source to sink.

    This is the input format loaded from path_explore's JSON output.

    Attributes:
        vulnerability_type: Type of vulnerability (PathTraversal or CommandInjection)
        sink_expression: The expression where the sink is called
        path: List of PathNode from source to sink (excluding sink marker)
        interface_name: The API interface being analyzed (e.g., /api/readFile)
    """
    vulnerability_type: str
    sink_expression: str
    path: List[PathNode] = field(default_factory=list)
    interface_name: str = ""

    @classmethod
    def from_dict(cls, data: dict) -> 'PotentialPath':
        """
        Create PotentialPath from dictionary (JSON format).

        Args:
            data: Dictionary with 'InterfaceName', 'Type', 'SinkExpression', and 'Path' keys

        Returns:
            PotentialPath instance
        """
        path_nodes = [
            PathNode.from_dict(node_data)
            for node_data in data.get('Path', [])
        ]
        return cls(
            interface_name=data.get('InterfaceName', ''),
            vulnerability_type=data.get('Type', ''),
            sink_expression=data.get('SinkExpression', ''),
            path=path_nodes
        )

    def get_call_chain_display(self) -> str:
        """
        Get a formatted string representation of the call chain.

        Returns:
            String in format: "func1 -> func2 -> ... -> sink"
        """
        names = [node.name for node in self.path]
        names.append("sink")
        return " -> ".join(names)


@dataclass
class DataflowInfo:
    """
    Represents dataflow information for a single node.

    Tracks which parameters and member variables of a function
    flow to the sink's key semantics (path/command).

    Attributes:
        parameters: List of parameter names that flow to sink semantics
                   Format: <param_name>.<field>.<field>...
        member_variables: List of member variable names that flow to sink semantics
                         Format: <member_name>.<field>.<field>...
    """
    parameters: List[str] = field(default_factory=list)
    member_variables: List[str] = field(default_factory=list)

    def is_empty(self) -> bool:
        """Check if both parameters and member_variables are empty."""
        return len(self.parameters) == 0 and len(self.member_variables) == 0

    def to_display(self) -> str:
        """
        Get a formatted display string.

        Returns:
            String showing parameters and member variables
        """
        parts = []
        if self.parameters:
            parts.append(f"Parameters: {', '.join(self.parameters)}")
        if self.member_variables:
            parts.append(f"Member Variables: {', '.join(self.member_variables)}")
        return " | ".join(parts) if parts else "No dataflow"


@dataclass
class FilterLogic:
    """
    Represents a filtering logic that may prevent vulnerability exploitation.

    Attributes:
        dataflow: Description of which dataflow this filter affects
                 Format: "x.<param/field> -> y.<param/field>"
        description: Description of what the filtering logic does
        file_path: File path where the filtering logic is implemented
        line_range: Line number range (start, end) of the filtering logic,
                   or None if not determined
    """
    dataflow: str
    description: str
    file_path: str
    line_range: Optional[tuple] = None

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

    This is used to store the result of one_hop_dataflow_agent for each node,
    tracking which inputs flow to the sink's key semantics.

    Attributes:
        node_index: Index of the node in the path (0-based)
        node_name: Name of the function for display purposes
        dataflow_info: DataflowInfo containing parameters and member variables
                      that flow to sink semantics
    """
    node_index: int
    node_name: str
    dataflow_info: DataflowInfo


@dataclass
class VerificationResult:
    """
    Final verification result for a potential vulnerability path.

    Based on the explore module's output format with additional verification fields.

    Attributes:
        vulnerability_type: Type of vulnerability being verified (maps to 'Type')
        sink_expression: The sink expression from the original path (maps to 'SinkExpression')
        path: List of PathNode from source to sink (maps to 'Path')
        interface_name: The API interface being analyzed (maps to 'InterfaceName')

        is_vulnerable: Whether the path contains an exploitable vulnerability
        confidence: Confidence level (High, Medium, Low)
        summary: Brief summary of the verification result

        dataflow_records: List of dataflow analysis records for each node
        filter_logics: List of filtering logics found during analysis
    """
    # Fields from explore module output
    vulnerability_type: str  # Maps to 'Type'
    sink_expression: str     # Maps to 'SinkExpression'
    path: List[PathNode] = field(default_factory=list)  # Maps to 'Path'
    interface_name: str = ""  # Maps to 'InterfaceName'

    # Verification result fields
    is_vulnerable: bool = False
    confidence: str = "Low"
    summary: str = ""

    # Analysis details
    dataflow_records: List[NodeDataflowRecord] = field(default_factory=list)
    filter_logics: List[FilterLogic] = field(default_factory=list)

    def to_dict(self) -> dict:
        """
        Convert to dictionary for JSON serialization.

        Output format is based on explore module's output with additional fields:
        {
            "InterfaceName": "/api/readFile",
            "Type": "PathTraversal",
            "SinkExpression": "...",
            "Path": [...],
            "IsVulnerable": true/false,
            "Confidence": "High/Medium/Low",
            "Summary": "...",
            "DataflowAnalysis": [...],
            "FilterLogics": [...]
        }

        Returns:
            Dictionary representation suitable for JSON export
        """
        return {
            # Fields from explore module output
            "InterfaceName": self.interface_name,
            "Type": self.vulnerability_type,
            "SinkExpression": self.sink_expression,
            "Path": [
                {
                    "file": node.file,
                    "name": node.name,
                    "source_code": node.source_code
                }
                for node in self.path
            ],
            # Verification result fields
            "IsVulnerable": self.is_vulnerable,
            "Confidence": self.confidence,
            "Summary": self.summary,
            # Analysis details
            "DataflowAnalysis": [
                {
                    "NodeIndex": record.node_index,
                    "NodeName": record.node_name,
                    "Parameters": record.dataflow_info.parameters,
                    "MemberVariables": record.dataflow_info.member_variables
                }
                for record in self.dataflow_records
            ],
            "FilterLogics": [
                {
                    "Dataflow": logic.dataflow,
                    "Description": logic.description,
                    "File": logic.file_path,
                    "Lines": f"{logic.line_range[0]}-{logic.line_range[1]}"
                            if logic.line_range else "Unknown"
                }
                for logic in self.filter_logics
            ]
        }
