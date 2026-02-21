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

from common.config import load_config
from common.tui import (
    start_tui,
    stop_tui,
    log_info,
    log_success,
    log_error,
    log_warning,
    update_tree,
    update_stats,
    set_current_node,
    clear_current_node,
    print_summary
)
from common.agent_logger import init_logger, close_logger, append_to_log
from common.base_claude_agent import set_error_context, clear_error_context
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
    interest_info_find_agent
)
from .utils import (
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

    def __init__(self, target_path: str, target_endpoint: str, project_name: Optional[str] = None):
        """
        Initialize the FunctionExplorer.

        Args:
            target_path: Path to the target project's source code
            target_endpoint: The API endpoint to analyze
            project_name: Optional project name (derived from target_path if not provided)
        """
        self.target_path = target_path
        self.target_endpoint = target_endpoint
        self.root: Optional[FunctionNode] = None
        self.vulnerability_paths: List[VulnerabilityPath] = []

        # Load configuration values
        self.max_depth = load_config("exploration.max_depth")
        self.max_nodes = load_config("exploration.max_nodes")
        self.verbose = load_config("exploration.verbose")
        self.node_count = 0  # Track total nodes explored

        # Derive project name from target path if not provided
        from pathlib import Path
        if project_name:
            self.project_name = project_name
        else:
            target_path_obj = Path(target_path)
            self.project_name = target_path_obj.name

        # Sanitize interface name for directory naming
        self.interface_name = target_endpoint.strip('/').replace('/', '_')

    def initialize(self) -> bool:
        """
        Initialize the exploration tree with the source function.

        Uses source_info_find_agent to find the handler function for the
        target endpoint and creates the root node of the exploration tree.

        Returns:
            True if initialization successful, False otherwise
        """
        log_info("Explorer", f"Initializing exploration for endpoint: {self.target_endpoint}")
        log_info("Explorer", f"Target path: {self.target_path}")

        # Find source function information
        source_info: Optional[SourceInfo] = source_info_find_agent(
            self.target_path,
            self.target_endpoint
        )

        if source_info is None:
            log_error("Explorer", f"Could not find source function for endpoint: {self.target_endpoint}")
            return False

        # Create root node with Interest tag
        self.root = FunctionNode(
            function_name=source_info.function_name,
            file_path=source_info.file_path,
            source_code=source_info.source_code,
            tag=NodeTag.INTEREST,
            extra_info=""
        )

        log_success("Explorer", f"Created root node: {source_info.function_name} in {source_info.file_path}")
        update_tree(self.root)

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

        # Set current node for highlighting and update tree
        set_current_node(node.file_path, node.function_name)
        update_tree(self.root)

        log_info("Explorer", f"Exploring: {node.function_name}")

        # Find next hops using the agent
        next_hops: List[NextHopResult] = next_hop_agent(self.target_path, call_chain)

        if not next_hops:
            log_warning("Explorer", f"No next hops found for node: {node.function_name}")
            # No next hops - need to prune this branch
            self._prune_branch(node)
            return

        # Separate sink and interest results
        sink_hops = [nh for nh in next_hops if nh.tag in (
            NodeTag.SINK_PATH_TRAVERSAL,
            NodeTag.SINK_COMMAND_INJECTION,
            NodeTag.SINK_CODE_INJECTION,
            NodeTag.SINK_SQL_INJECTION
        )]
        interest_hops = [nh for nh in next_hops if nh.tag == NodeTag.INTEREST]

        log_success("Explorer", f"Found {len(sink_hops)} sink(s) and {len(interest_hops)} interest node(s)")

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
            log_success("Explorer", f"Added sink node: {sink.tag.value}: {sink.expression}")

        # Process interest nodes - need to find their implementations
        if interest_hops:
            interest_expressions = [ih.expression for ih in interest_hops]
            interest_infos: List[NextHopInfo] = interest_info_find_agent(
                self.target_path,
                call_chain,
                interest_expressions
            )

            if interest_infos:
                # Build a set of (function_name, file_path) tuples from the call chain
                # to filter out interests that would create cycles
                visited_in_chain = set()
                for chain_node in call_chain:
                    # Only add non-sink nodes to the visited set
                    if not chain_node.is_sink():
                        visited_in_chain.add((chain_node.function_name, chain_node.file_path))

                filtered_count = 0
                for info in interest_infos:
                    # Check if this interest is already in the call chain
                    if (info.function_name, info.file_path) in visited_in_chain:
                        log_warning("Explorer", f"Filtered cyclic interest: {info.function_name} in {info.file_path} (already in call chain)")
                        filtered_count += 1
                        continue

                    interest_node = FunctionNode(
                        function_name=info.function_name,
                        file_path=info.file_path,
                        source_code=info.source_code,
                        tag=NodeTag.INTEREST,
                        extra_info=""
                    )
                    node.add_child(interest_node)
                    self.node_count += 1
                    log_success("Explorer", f"Added interest node: {info.function_name} in {info.file_path}")

                if filtered_count > 0:
                    log_info("Explorer", f"Filtered {filtered_count} cyclic interest(s) to prevent infinite loops")
            else:
                log_warning("Explorer", f"interest_info_find_agent returned no implementations for {len(interest_hops)} interest expression(s)")

        # Check if node has no children after exploration (should be pruned)
        if node.is_leaf():
            log_warning("Explorer", f"Node {node.function_name} has no children after exploration, pruning")
            self._prune_branch(node)

        # Update tree display and clear current node highlighting
        clear_current_node()
        update_tree(self.root)

    def _prune_branch(self, node: FunctionNode) -> None:
        """
        Prune a branch from the first ancestor with no other branches.

        Removes the path from the given node up to the first ancestor
        that has other children (branches). If the entire chain is single-branch,
        clears the entire tree to end exploration.

        Args:
            node: The leaf node to start pruning from
        """
        # Find the node to remove
        # Go up from node until we find an ancestor with multiple children
        current = node
        prune_from = node
        found_multi_branch_parent = False

        while current.parent is not None:
            parent = current.parent
            if len(parent.children) > 1:
                # Parent has other branches, only remove current's branch
                prune_from = current
                found_multi_branch_parent = True
                break
            # Parent has only this child, continue up
            prune_from = current
            current = parent

        # Remove the identified branch or clear the entire tree
        if found_multi_branch_parent:
            # Found an ancestor with other branches, prune this branch
            prune_from.parent.remove_child(prune_from)
            log_warning("Explorer", f"Pruned branch: No viable paths found from {prune_from.function_name}")
            update_tree(self.root)
        else:
            # No multi-branch ancestor found, clear the entire tree
            log_warning("Explorer", "Entire exploration tree is a single chain with no viable paths, clearing tree")
            self.root = None
            update_tree(None)

    def run_exploration(self) -> List[VulnerabilityPath]:
        """
        Run the complete exploration process.

        This method initializes the exploration tree and performs DFS-based
        exploration until all Interest nodes have been explored or limits are reached.

        Returns:
            List of VulnerabilityPath objects representing discovered vulnerability paths
        """
        # Set error context for error file generation
        set_error_context(self.project_name, self.interface_name)

        # Initialize logger for this session
        init_logger(
            project_name=self.project_name,
            interface_name=self.interface_name,
            log_type="path_explore"
        )

        # Start TUI directly (no banner before TUI to avoid showing after exit)
        start_tui(
            target_path=self.target_path,
            target_endpoint=self.target_endpoint
        )

        try:
            # Log configuration info
            if self.verbose:
                log_info("Config", f"Max depth: {self.max_depth}")
                log_info("Config", f"Max nodes: {self.max_nodes}")

            # Step 1: Initialize with source function
            if not self.initialize():
                log_error("Explorer", "Exploration failed: Could not initialize")
                return []

            self.node_count = 1  # Count root node
            update_stats(self.node_count)

            # Type guard - root is guaranteed to be set after successful initialization
            assert self.root is not None

            # Step 2: DFS exploration loop
            iteration_count = 0
            while has_unexplored_interest_nodes(self.root):
                iteration_count += 1

                # Check node count limit
                if self.node_count >= self.max_nodes:
                    log_warning("Explorer", f"Reached max node limit ({self.max_nodes}), stopping")
                    break

                # Find first Interest leaf node
                current_node = find_first_interest_leaf(self.root)

                if current_node is None:
                    log_info("Explorer", "No more Interest leaf nodes to explore")
                    break

                # Check depth limit
                current_depth = len(current_node.get_path_to_root()) - 1
                if current_depth >= self.max_depth:
                    log_warning("Explorer", f"Max depth reached, pruning: {current_node.function_name}")
                    self._prune_branch(current_node)
                    continue

                # Log current exploration status
                log_info("Explorer", f"[Iteration {iteration_count}] Exploring node at depth {current_depth}: {current_node.function_name}")

                # Explore this node
                self.explore_node(current_node)
                update_stats(self.node_count)

            # Exploration loop completed
            log_info("Explorer", f"Exploration loop completed after {iteration_count} iterations")

            # Sync TUI state with final tree state before stopping
            clear_current_node()
            if self.root:
                update_tree(self.root)

            # Step 3: Extract and store vulnerability paths
            log_info("Explorer", "Extracting vulnerability paths...")
            try:
                self._extract_vulnerability_paths()
                log_info("Explorer", f"Extracted {len(self.vulnerability_paths)} vulnerability path(s)")
            except Exception as extract_error:
                log_error("Explorer", f"Error extracting paths: {extract_error}")
                # Continue with empty paths

            log_info("Explorer", "Stopping TUI...")

        except Exception as e:
            import traceback
            log_error("Explorer", f"Error: {type(e).__name__}: {str(e)}")
            # Stop TUI and print full traceback
            stop_tui()
            close_logger()
            clear_error_context()
            self._print_error_detail(e, traceback.format_exc())
            return []

        # Stop TUI and print summary
        log_info("Explorer", "Exploration phase completed successfully")
        stop_tui()

        # Append exploration result to log before closing
        if self.root:
            # Count by type
            path_traversal_count = sum(
                1 for p in self.vulnerability_paths
                if p.vulnerability_type == "PathTraversal"
            )
            command_injection_count = sum(
                1 for p in self.vulnerability_paths
                if p.vulnerability_type == "CommandInjection"
            )
            code_injection_count = sum(
                1 for p in self.vulnerability_paths
                if p.vulnerability_type == "CodeInjection"
            )
            sql_injection_count = sum(
                1 for p in self.vulnerability_paths
                if p.vulnerability_type == "SQLInjection"
            )

            result_content = f"""
{'#' * 78}
#{' ' * 76}#
#{'EXPLORATION RESULT'.center(76)}#
#{' ' * 76}#
{'#' * 78}

Exploration Tree:
{self.root.to_tree_string()}

Summary:
  Total Paths: {len(self.vulnerability_paths)}
  - PathTraversal: {path_traversal_count}
  - CommandInjection: {command_injection_count}
  - CodeInjection: {code_injection_count}
  - SQLInjection: {sql_injection_count}

{'#' * 78}
"""
            append_to_log(result_content)
            log_info("Explorer", "Exploration result appended to log")

        close_logger()
        clear_error_context()
        log_info("Explorer", "Printing summary...")
        self._print_summary()
        log_info("Explorer", "Exploration phase done, returning results")
        return self.vulnerability_paths

    def _print_error_detail(self, error: Exception, traceback_str: str) -> None:
        """Print detailed error information after TUI stops."""
        from rich.console import Console
        console = Console()
        console.print()
        console.rule("[bold red]Error Occurred[/bold red]")
        console.print(f"[red]{type(error).__name__}[/red]: {error}")
        console.print()
        console.print("[dim]Traceback:[/dim]")
        console.print(traceback_str)
        console.rule()

    def _extract_vulnerability_paths(self) -> None:
        """
        Extract all vulnerability paths from source to sink.

        Finds all paths from root to sink nodes and converts them
        to VulnerabilityPath objects for output.
        """
        # Type guard - root is guaranteed to be set after successful initialization
        if self.root is None:
            return

        sink_paths = find_sink_paths(self.root)

        for path in sink_paths:
            # Determine vulnerability type from sink node
            sink_node = path[-1]
            if sink_node.tag == NodeTag.SINK_PATH_TRAVERSAL:
                vuln_type = "PathTraversal"
            elif sink_node.tag == NodeTag.SINK_COMMAND_INJECTION:
                vuln_type = "CommandInjection"
            elif sink_node.tag == NodeTag.SINK_CODE_INJECTION:
                vuln_type = "CodeInjection"
            elif sink_node.tag == NodeTag.SINK_SQL_INJECTION:
                vuln_type = "SQLInjection"
            else:
                continue  # Not a sink, skip

            # Build path data (file_path, function_name, source_code tuples)
            path_data = []
            for node in path:
                if not node.is_sink():  # Only include function nodes, not sink markers
                    path_data.append((node.file_path, node.function_name, node.source_code))

            # Create vulnerability path object
            vuln_path = VulnerabilityPath(
                vulnerability_type=vuln_type,
                sink_expression=sink_node.extra_info,
                path=path_data,
                interface_name=self.target_endpoint
            )
            self.vulnerability_paths.append(vuln_path)

    def _print_summary(self) -> None:
        """
        Print a summary of the exploration results.
        """
        # Count by type
        path_traversal_count = sum(
            1 for p in self.vulnerability_paths
            if p.vulnerability_type == "PathTraversal"
        )
        command_injection_count = sum(
            1 for p in self.vulnerability_paths
            if p.vulnerability_type == "CommandInjection"
        )
        code_injection_count = sum(
            1 for p in self.vulnerability_paths
            if p.vulnerability_type == "CodeInjection"
        )
        sql_injection_count = sum(
            1 for p in self.vulnerability_paths
            if p.vulnerability_type == "SQLInjection"
        )

        # Use TUI to print summary
        print_summary(
            path_traversal_count=path_traversal_count,
            command_injection_count=command_injection_count,
            code_injection_count=code_injection_count,
            sql_injection_count=sql_injection_count,
            total_paths=len(self.vulnerability_paths)
        )

    def export_results(self, output_path: str) -> None:
        """
        Export vulnerability paths to a JSON file.

        Args:
            output_path: Path to the output JSON file
        """
        results = [vp.to_dict() for vp in self.vulnerability_paths]

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)

        # Use console directly for export message (after TUI is stopped)
        from rich.console import Console
        console = Console()
        console.print(f"[green]Results exported to:[/green] {output_path}")

    def get_results_json(self) -> str:
        """
        Get vulnerability paths as a JSON string.

        Returns:
            JSON string representation of the vulnerability paths
        """
        results = [vp.to_dict() for vp in self.vulnerability_paths]
        return json.dumps(results, indent=2, ensure_ascii=False)


# =============================================================================
# CLI Entry Point
# =============================================================================

if __name__ == '__main__':
    import argparse
    from pathlib import Path
    from rich.console import Console

    parser = argparse.ArgumentParser(
        description='GOLD MINER - Vulnerability Path Discovery Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m path_explore.explorer ./testProject /api/readFile
  python -m path_explore.explorer ./my-project /api/upload
        """
    )

    parser.add_argument(
        'target_path',
        type=str,
        help='Path to the target project\'s source code'
    )

    parser.add_argument(
        'target_endpoint',
        type=str,
        help='The API endpoint to analyze (e.g., /api/readFile)'
    )

    args = parser.parse_args()

    # Get project name from target path
    target_path = Path(args.target_path)
    project_name = target_path.name

    # Sanitize interface name for directory name
    interface_name = args.target_endpoint.strip('/').replace('/', '_')

    # Build output path: results/<project_name>/<interface_name>/potential_paths.json
    output_dir = Path("results") / project_name / interface_name
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / "potential_paths.json"

    # Create and run explorer
    explorer = FunctionExplorer(
        target_path=args.target_path,
        target_endpoint=args.target_endpoint,
        project_name=project_name
    )

    # Run exploration
    vulnerability_paths = explorer.run_exploration()

    # Export results to file
    explorer.export_results(str(output_file))