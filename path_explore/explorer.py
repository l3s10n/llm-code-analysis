"""
Core exploration logic for vulnerability path discovery.
Implements the function exploration tree and DFS-based path finding algorithm.
"""

import json
import sys
import os
from typing import List, Optional

# Add parent directory to path for config import
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import get_config, is_verbose
from .models import (
    FunctionNode,
    NodeTag,
    VulnerabilityPath,
    NextHopResult,
    NextHopInfo,
    SourceInfo
)
from .agents import (
    source_info_find_agent,
    next_hop_agent,
    interest_info_agent
)
from .utils import (
    print_exploration_tree,
    log_modification,
    find_first_interest_leaf,
    has_unexplored_interest_nodes,
    find_sink_paths
)


class FunctionExplorer:
    """
    Main class for exploring function call chains to discover vulnerability paths.

    This class maintains a function exploration tree and performs DFS-based
    exploration to find all paths from source to potential vulnerability sinks.
    """

    def __init__(self, target_path: str, target_endpoint: str):
        """
        Initialize the FunctionExplorer.

        Args:
            target_path: Path to the target project's source code
            target_endpoint: The API endpoint to analyze
        """
        self.target_path = target_path
        self.target_endpoint = target_endpoint
        self.root: Optional[FunctionNode] = None
        self.vulnerability_paths: List[VulnerabilityPath] = []

        # Load configuration values
        self.max_depth = get_config("exploration.max_depth", 20)
        self.max_nodes = get_config("exploration.max_nodes", 1000)
        self.verbose = is_verbose()
        self.node_count = 0  # Track total nodes explored

    def initialize(self) -> bool:
        """
        Initialize the exploration tree with the source function.

        Uses source_info_find_agent to find the handler function for the
        target endpoint and creates the root node of the exploration tree.

        Returns:
            True if initialization successful, False otherwise
        """
        print(f"\n[Explorer] Initializing exploration for endpoint: {self.target_endpoint}")
        print(f"[Explorer] Target path: {self.target_path}")

        # Find source function information
        source_info: Optional[SourceInfo] = source_info_find_agent(
            self.target_path,
            self.target_endpoint
        )

        if source_info is None:
            print(f"[Explorer] ERROR: Could not find source function for endpoint: {self.target_endpoint}")
            return False

        # Create root node with Interest tag
        self.root = FunctionNode(
            function_name=source_info.function_name,
            file_path=source_info.file_path,
            source_code=source_info.source_code,
            tag=NodeTag.INTEREST,
            extra_info=""
        )

        log_modification("Created root node", f"{source_info.function_name} in {source_info.file_path}")
        print_exploration_tree(self.root, "Initialized exploration tree with source function")

        return True

    def explore_node(self, node: FunctionNode) -> None:
        """
        Explore a single Interest node to find its next hops.

        This method uses next_hop_agent to analyze the node and then
        processes the results to add children to the exploration tree.

        Args:
            node: The Interest node to explore
        """
        # Get the call chain from root to current node
        call_chain = node.get_path_to_root()

        print(f"\n[Explorer] Exploring node: {node.function_name}")
        print(f"[Explorer] Call chain length: {len(call_chain)}")

        # Find next hops using the agent
        next_hops: List[NextHopResult] = next_hop_agent(call_chain)

        if not next_hops:
            print(f"[Explorer] No next hops found for node: {node.function_name}")
            # No next hops - need to prune this branch
            self._prune_branch(node)
            return

        # Separate sink and interest results
        sink_hops = [nh for nh in next_hops if nh.tag in (
            NodeTag.SINK_PATH_TRAVERSAL,
            NodeTag.SINK_COMMAND_INJECTION
        )]
        interest_hops = [nh for nh in next_hops if nh.tag == NodeTag.INTEREST]

        print(f"[Explorer] Found {len(sink_hops)} sink(s) and {len(interest_hops)} interest node(s)")

        # Process sink nodes
        for sink in sink_hops:
            sink_node = FunctionNode(
                function_name="",
                file_path="",
                source_code="",
                tag=sink.tag,
                extra_info=sink.expression
            )
            node.add_child(sink_node)
            self.node_count += 1
            log_modification("Added sink node", f"{sink.tag.value}: {sink.expression}")

        # Process interest nodes - need to find their implementations
        if interest_hops:
            interest_expressions = [ih.expression for ih in interest_hops]
            interest_infos: List[NextHopInfo] = interest_info_agent(
                call_chain,
                interest_expressions
            )

            for info in interest_infos:
                interest_node = FunctionNode(
                    function_name=info.function_name,
                    file_path=info.file_path,
                    source_code=info.source_code,
                    tag=NodeTag.INTEREST,
                    extra_info=""
                )
                node.add_child(interest_node)
                self.node_count += 1
                log_modification("Added interest node", f"{info.function_name} in {info.file_path}")

        # Print updated tree
        print_exploration_tree(self.root, f"Explored {node.function_name}")

    def _prune_branch(self, node: FunctionNode) -> None:
        """
        Prune a branch from the first ancestor with no other branches.

        Removes the path from the given node up to the first ancestor
        that has other children (branches).

        Args:
            node: The leaf node to start pruning from
        """
        # Find the node to remove
        # Go up from node until we find an ancestor with multiple children
        current = node
        prune_from = node

        while current.parent is not None:
            parent = current.parent
            if len(parent.children) > 1:
                # Parent has other branches, only remove current's branch
                prune_from = current
                break
            # Parent has only this child, continue up
            prune_from = current
            current = parent

        # Remove the identified branch
        if prune_from.parent is not None:
            prune_from.parent.remove_child(prune_from)
            log_modification("Pruned branch", f"No viable paths found from {prune_from.function_name}")
            print_exploration_tree(self.root, f"Pruned dead-end branch at {prune_from.function_name}")

    def run_exploration(self) -> List[VulnerabilityPath]:
        """
        Run the complete exploration process.

        This method initializes the exploration tree and performs DFS-based
        exploration until all Interest nodes have been explored or limits are reached.

        Returns:
            List of VulnerabilityPath objects representing discovered vulnerability paths
        """
        print("\n" + "=" * 60)
        print("GOLD MINER - Vulnerability Path Discovery")
        print("=" * 60)

        # Print configuration info if verbose
        if self.verbose:
            print(f"[Config] Max depth: {self.max_depth}")
            print(f"[Config] Max nodes: {self.max_nodes}")
            print(f"[Config] Verbose: {self.verbose}")

        # Step 1: Initialize with source function
        if not self.initialize():
            print("[Explorer] Exploration failed: Could not initialize")
            return []

        self.node_count = 1  # Count root node

        # Step 2: DFS exploration loop
        iteration = 0
        while has_unexplored_interest_nodes(self.root):
            iteration += 1

            # Check node count limit
            if self.node_count >= self.max_nodes:
                print(f"[Explorer] Reached max node limit ({self.max_nodes}), stopping exploration")
                break

            print(f"\n[Explorer] --- Exploration Iteration {iteration} ---")

            # Find first Interest leaf node
            current_node = find_first_interest_leaf(self.root)

            if current_node is None:
                print("[Explorer] No more nodes to explore")
                break

            # Check depth limit
            current_depth = len(current_node.get_path_to_root()) - 1
            if current_depth >= self.max_depth:
                print(f"[Explorer] Node at max depth ({self.max_depth}), pruning: {current_node.function_name}")
                self._prune_branch(current_node)
                continue

            # Explore this node
            self.explore_node(current_node)

        # Step 3: Extract and store vulnerability paths
        self._extract_vulnerability_paths()

        # Print summary
        self._print_summary()

        return self.vulnerability_paths

    def _extract_vulnerability_paths(self) -> None:
        """
        Extract all vulnerability paths from source to sink.

        Finds all paths from root to sink nodes and converts them
        to VulnerabilityPath objects for output.
        """
        sink_paths = find_sink_paths(self.root)

        for path in sink_paths:
            # Determine vulnerability type from sink node
            sink_node = path[-1]
            if sink_node.tag == NodeTag.SINK_PATH_TRAVERSAL:
                vuln_type = "PathTraversal"
            elif sink_node.tag == NodeTag.SINK_COMMAND_INJECTION:
                vuln_type = "CommandInjection"
            else:
                continue  # Not a sink, skip

            # Build path data (file_path, source_code tuples)
            path_data = []
            for node in path:
                if not node.is_sink():  # Only include function nodes, not sink markers
                    path_data.append((node.file_path, node.source_code))

            # Create vulnerability path object
            vuln_path = VulnerabilityPath(
                vulnerability_type=vuln_type,
                sink_expression=sink_node.extra_info,
                path=path_data
            )
            self.vulnerability_paths.append(vuln_path)

    def _print_summary(self) -> None:
        """
        Print a summary of the exploration results.
        """
        print("\n" + "=" * 60)
        print("Exploration Summary")
        print("=" * 60)
        print(f"Total potential vulnerability paths found: {len(self.vulnerability_paths)}")

        # Count by type
        path_traversal_count = sum(
            1 for p in self.vulnerability_paths
            if p.vulnerability_type == "PathTraversal"
        )
        command_injection_count = sum(
            1 for p in self.vulnerability_paths
            if p.vulnerability_type == "CommandInjection"
        )

        print(f"  - Path Traversal vulnerabilities: {path_traversal_count}")
        print(f"  - Command Injection vulnerabilities: {command_injection_count}")
        print("=" * 60 + "\n")

    def export_results(self, output_path: str) -> None:
        """
        Export vulnerability paths to a JSON file.

        Args:
            output_path: Path to the output JSON file
        """
        results = [vp.to_dict() for vp in self.vulnerability_paths]

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)

        print(f"[Explorer] Results exported to: {output_path}")

    def get_results_json(self) -> str:
        """
        Get vulnerability paths as a JSON string.

        Returns:
            JSON string representation of the vulnerability paths
        """
        results = [vp.to_dict() for vp in self.vulnerability_paths]
        return json.dumps(results, indent=2, ensure_ascii=False)
