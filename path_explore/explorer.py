"""
Core exploration logic for vulnerability path discovery.
Implements the function exploration tree and DFS-based path finding algorithm.
"""

import json
import os
import sys
from typing import List, Optional

# Add parent directory to path for config import
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.agent_logger import append_to_log, close_logger, init_logger
from common.base_claude_agent import clear_error_context, set_error_context
from common.config import load_config
from common.tui import (
    clear_current_node,
    emit_output,
    log_error,
    log_info,
    log_success,
    log_warning,
    print_summary,
    set_current_node,
    start_tui,
    stop_tui,
    update_stats,
    update_tree,
)
from .agents import next_hop_info_find_agent, source_info_find_agent
from .models import FunctionNode, InterestInfo, NodeTag, VulnerabilityPath
from .utils import (
    find_first_interest_leaf,
    find_sink_paths,
    has_unexplored_interest_nodes,
    is_node_in_interest_chain,
    read_source_code_by_range,
)


class FunctionExplorer:
    """
    Main class for exploring function call chains to discover vulnerability paths.

    This class maintains a function exploration tree and performs DFS-based
    exploration to find all paths from source to potential vulnerability sinks.
    """

    def __init__(
        self,
        target_path: str,
        target_endpoint: str,
        project_name: Optional[str] = None,
        batch_index: int = 0,
        batch_total: int = 0,
    ):
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

        self.max_depth = load_config("exploration.max_depth")
        self.max_nodes = load_config("exploration.max_nodes")
        self.verbose = load_config("exploration.verbose")
        self.node_count = 0

        from pathlib import Path

        if project_name:
            self.project_name = project_name
        else:
            self.project_name = Path(target_path).name

        self.interface_name = target_endpoint.strip("/").replace("/", "_")
        self.batch_index = batch_index
        self.batch_total = batch_total

    def _build_function_node_from_interest(self, info: InterestInfo) -> FunctionNode:
        """
        Build a FunctionNode from InterestInfo.

        Args:
            info: InterestInfo describing the function location

        Returns:
            FunctionNode with source code populated from the local file
        """

        source_code = read_source_code_by_range(
            target_path=self.target_path,
            file_path=info.file_path,
            start_line=info.start_line,
            end_line=info.end_line,
        )
        return FunctionNode(
            function_name=info.function_name,
            file_path=info.file_path,
            source_code=source_code,
            tag=NodeTag.INTEREST,
            extra_info="",
            start_line=info.start_line,
            end_line=info.end_line,
        )

    @staticmethod
    def _build_sink_node(tag: NodeTag, sink_expression: str) -> FunctionNode:
        """
        Build a sink FunctionNode.

        Args:
            tag: Sink node tag
            sink_expression: Sink expression in the current function

        Returns:
            FunctionNode representing the sink
        """

        return FunctionNode(
            function_name="",
            file_path="",
            source_code="",
            tag=tag,
            extra_info=sink_expression,
        )

    @staticmethod
    def _function_node_to_interest_info(node: FunctionNode) -> InterestInfo:
        """
        Convert an interest FunctionNode back to InterestInfo.

        Args:
            node: FunctionNode to convert

        Returns:
            InterestInfo with file path and line-range identity
        """

        return InterestInfo(
            function_name=node.function_name,
            file_path=node.file_path,
            start_line=node.start_line,
            end_line=node.end_line,
        )

    def initialize(self) -> bool:
        """
        Initialize the exploration tree with the source function.

        Returns:
            True if initialization successful, False otherwise
        """

        log_info("Explorer", f"Initializing exploration for endpoint: {self.target_endpoint}")
        log_info("Explorer", f"Target path: {self.target_path}")

        source_info = source_info_find_agent(
            self.target_path,
            self.target_endpoint,
        )

        if source_info is None:
            log_error("Explorer", f"Could not find source function for endpoint: {self.target_endpoint}")
            return False

        self.root = self._build_function_node_from_interest(source_info)

        log_success(
            "Explorer",
            (
                f"Created root node: {source_info.function_name} in "
                f"{source_info.file_path}:{source_info.start_line}-{source_info.end_line}"
            ),
        )
        update_tree(self.root)
        return True

    def _build_interest_chain(self, node: FunctionNode) -> List[InterestInfo]:
        """
        Build InterestInfo call chain from root to current node.

        Args:
            node: Current interest node

        Returns:
            InterestInfo list representing the current call chain
        """

        chain = []
        for chain_node in node.get_path_to_root():
            if chain_node.is_sink():
                continue
            chain.append(self._function_node_to_interest_info(chain_node))
        return chain

    def explore_node(self, node: FunctionNode) -> None:
        """
        Explore a single Interest node to find its next hops.

        Args:
            node: The Interest node to explore
        """

        call_chain_infos = self._build_interest_chain(node)

        set_current_node(node.file_path, node.function_name, node.source_code)
        update_tree(self.root)

        log_info("Explorer", f"Exploring: {node.function_name}")

        interest_infos, sink_infos = next_hop_info_find_agent(
            self.target_path,
            call_chain_infos,
        )

        if not interest_infos and not sink_infos:
            log_warning("Explorer", f"No next hops found for node: {node.function_name}")
            self._prune_branch(node)
            return

        for tag, sink_info in sink_infos:
            sink_node = self._build_sink_node(tag, sink_info.sink_expression)
            node.add_child(sink_node)
            self.node_count += 1
            log_success("Explorer", f"Added sink node: {tag.value}: {sink_info.sink_expression}")

        filtered_count = 0
        for info in interest_infos:
            if is_node_in_interest_chain(info, call_chain_infos):
                log_warning(
                    "Explorer",
                    (
                        "Filtered cyclic interest: "
                        f"{info.function_name} in {info.file_path}:{info.start_line}-{info.end_line} "
                        "(already in call chain)"
                    ),
                )
                filtered_count += 1
                continue

            interest_node = self._build_function_node_from_interest(info)
            node.add_child(interest_node)
            self.node_count += 1
            log_success(
                "Explorer",
                (
                    f"Added interest node: {info.function_name} "
                    f"in {info.file_path}:{info.start_line}-{info.end_line}"
                ),
            )

        if filtered_count > 0:
            log_info("Explorer", f"Filtered {filtered_count} cyclic interest(s) to prevent infinite loops")

        if node.is_leaf():
            log_warning("Explorer", f"Node {node.function_name} has no children after exploration, pruning")
            self._prune_branch(node)

        clear_current_node()
        update_tree(self.root)

    def _prune_branch(self, node: FunctionNode) -> None:
        """
        Prune a branch from the first ancestor with no other branches.

        Args:
            node: The leaf node to start pruning from
        """

        current = node
        prune_from = node
        found_multi_branch_parent = False

        while current.parent is not None:
            parent = current.parent
            if len(parent.children) > 1:
                prune_from = current
                found_multi_branch_parent = True
                break
            prune_from = current
            current = parent

        if found_multi_branch_parent:
            assert prune_from.parent is not None
            prune_from.parent.remove_child(prune_from)
            log_warning("Explorer", f"Pruned branch: No viable paths found from {prune_from.function_name}")
            update_tree(self.root)
        else:
            log_warning("Explorer", "Entire exploration tree is a single chain with no viable paths, clearing tree")
            self.root = None
            update_tree(None)

    def run_exploration(self) -> List[VulnerabilityPath]:
        """
        Run the complete exploration process.

        Returns:
            List of VulnerabilityPath objects representing discovered vulnerability paths
        """

        try:
            set_error_context(self.project_name, self.interface_name)

            init_logger(
                project_name=self.project_name,
                interface_name=self.interface_name,
                log_type="path_explore",
            )

            start_tui(
                target_path=self.target_path,
                target_endpoint=self.target_endpoint,
                batch_index=self.batch_index,
                batch_total=self.batch_total,
            )

            try:
                if self.verbose:
                    log_info("Config", f"Max depth: {self.max_depth}")
                    log_info("Config", f"Max nodes: {self.max_nodes}")

                if not self.initialize():
                    log_error("Explorer", "Exploration failed: Could not initialize")
                    return []

                self.node_count = 1
                update_stats(self.node_count)

                assert self.root is not None

                iteration_count = 0
                while has_unexplored_interest_nodes(self.root):
                    iteration_count += 1

                    if self.node_count >= self.max_nodes:
                        log_warning("Explorer", f"Reached max node limit ({self.max_nodes}), stopping")
                        break

                    current_node = find_first_interest_leaf(self.root)
                    if current_node is None:
                        log_info("Explorer", "No more Interest leaf nodes to explore")
                        break

                    current_depth = len(current_node.get_path_to_root()) - 1
                    if current_depth >= self.max_depth:
                        log_warning("Explorer", f"Max depth reached, pruning: {current_node.function_name}")
                        self._prune_branch(current_node)
                        continue

                    log_info(
                        "Explorer",
                        f"[Iteration {iteration_count}] Exploring node at depth {current_depth}: {current_node.function_name}",
                    )

                    self.explore_node(current_node)
                    update_stats(self.node_count)

                    if self.root is None:
                        break

                log_info("Explorer", f"Exploration loop completed after {iteration_count} iterations")

                clear_current_node()
                if self.root:
                    update_tree(self.root)

                log_info("Explorer", "Extracting vulnerability paths...")
                try:
                    self._extract_vulnerability_paths()
                    log_info("Explorer", f"Extracted {len(self.vulnerability_paths)} vulnerability path(s)")
                except Exception as extract_error:
                    log_error("Explorer", f"Error extracting paths: {extract_error}")

                log_info("Explorer", "Preparing exploration summary...")

            except Exception as error:
                import traceback

                log_error("Explorer", f"Error: {type(error).__name__}: {str(error)}")
                stop_tui()
                close_logger()
                clear_error_context()
                self._print_error_detail(error, traceback.format_exc())
                return []

            log_info("Explorer", "Exploration phase completed successfully")

            if self.root:
                path_traversal_count = sum(
                    1 for path in self.vulnerability_paths if path.vulnerability_type == "PathTraversal"
                )
                command_injection_count = sum(
                    1 for path in self.vulnerability_paths if path.vulnerability_type == "CommandInjection"
                )
                code_injection_count = sum(
                    1 for path in self.vulnerability_paths if path.vulnerability_type == "CodeInjection"
                )
                sql_injection_count = sum(
                    1 for path in self.vulnerability_paths if path.vulnerability_type == "SQLInjection"
                )
                ssrf_count = sum(
                    1 for path in self.vulnerability_paths if path.vulnerability_type == "SSRF"
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
  - SSRF: {ssrf_count}

{'#' * 78}
"""
                append_to_log(result_content)
                log_info("Explorer", "Exploration result appended to log")

            log_info("Explorer", "Printing summary...")
            self._print_summary()
            log_info("Explorer", "Exploration phase done, returning results")
            return self.vulnerability_paths

        finally:
            clear_current_node()
            stop_tui()
            close_logger()
            clear_error_context()

    def _print_error_detail(self, error: Exception, traceback_str: str) -> None:
        """Print detailed error information after TUI stops."""

        emit_output("", source="Explorer", level="ERROR")
        emit_output("Error Occurred", source="Explorer", level="ERROR")
        emit_output(f"{type(error).__name__}: {error}", source="Explorer", level="ERROR")
        emit_output("Traceback:", source="Explorer", level="ERROR")
        emit_output(traceback_str, source="Explorer", level="ERROR")

    def _extract_vulnerability_paths(self) -> None:
        """
        Extract all vulnerability paths from source to sink.
        """

        if self.root is None:
            return

        sink_paths = find_sink_paths(self.root)

        for path in sink_paths:
            sink_node = path[-1]
            if sink_node.tag == NodeTag.SINK_PATH_TRAVERSAL:
                vuln_type = "PathTraversal"
            elif sink_node.tag == NodeTag.SINK_COMMAND_INJECTION:
                vuln_type = "CommandInjection"
            elif sink_node.tag == NodeTag.SINK_CODE_INJECTION:
                vuln_type = "CodeInjection"
            elif sink_node.tag == NodeTag.SINK_SQL_INJECTION:
                vuln_type = "SQLInjection"
            elif sink_node.tag == NodeTag.SINK_SSRF:
                vuln_type = "SSRF"
            else:
                continue

            path_data = []
            for node in path:
                if not node.is_sink():
                    path_data.append(
                        (
                            node.file_path,
                            node.function_name,
                            node.start_line,
                            node.end_line,
                        )
                    )

            vuln_path = VulnerabilityPath(
                vulnerability_type=vuln_type,
                sink_expression=sink_node.extra_info,
                path=path_data,
                interface_name=self.target_endpoint,
            )
            self.vulnerability_paths.append(vuln_path)

    def _print_summary(self) -> None:
        """
        Print a summary of the exploration results.
        """

        path_traversal_count = sum(
            1 for path in self.vulnerability_paths if path.vulnerability_type == "PathTraversal"
        )
        command_injection_count = sum(
            1 for path in self.vulnerability_paths if path.vulnerability_type == "CommandInjection"
        )
        code_injection_count = sum(
            1 for path in self.vulnerability_paths if path.vulnerability_type == "CodeInjection"
        )
        sql_injection_count = sum(
            1 for path in self.vulnerability_paths if path.vulnerability_type == "SQLInjection"
        )
        ssrf_count = sum(1 for path in self.vulnerability_paths if path.vulnerability_type == "SSRF")

        print_summary(
            path_traversal_count=path_traversal_count,
            command_injection_count=command_injection_count,
            code_injection_count=code_injection_count,
            sql_injection_count=sql_injection_count,
            ssrf_count=ssrf_count,
            total_paths=len(self.vulnerability_paths),
        )

    def export_results(self, output_path: str) -> None:
        """
        Export vulnerability paths to a JSON file.

        Args:
            output_path: Path to the output JSON file
        """

        results = [vulnerability_path.to_dict() for vulnerability_path in self.vulnerability_paths]

        with open(output_path, "w", encoding="utf-8") as handle:
            json.dump(results, handle, indent=2, ensure_ascii=False)

        emit_output(f"Results exported to: {output_path}", source="Explorer", level="SUCCESS")

    def get_results_json(self) -> str:
        """
        Get vulnerability paths as a JSON string.

        Returns:
            JSON string representation of the vulnerability paths
        """

        results = [vulnerability_path.to_dict() for vulnerability_path in self.vulnerability_paths]
        return json.dumps(results, indent=2, ensure_ascii=False)


# =============================================================================
# CLI Entry Point
# =============================================================================

if __name__ == "__main__":
    import argparse
    from pathlib import Path

    parser = argparse.ArgumentParser(
        description="VulSolver - Vulnerability Path Discovery Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m path_explore.explorer ./testProject /api/readFile
  python -m path_explore.explorer ./my-project /api/upload
        """,
    )

    parser.add_argument(
        "target_path",
        type=str,
        help="Path to the target project's source code",
    )

    parser.add_argument(
        "target_endpoint",
        type=str,
        help="The API endpoint to analyze (e.g., /api/readFile)",
    )

    parser.add_argument(
        "--no-tui",
        action="store_true",
        help="Disable the Textual UI and print progress directly to the terminal",
    )

    args = parser.parse_args()

    from common.tui import configure_tui

    configure_tui(enabled=not args.no_tui)

    target_path = Path(args.target_path)
    project_name = target_path.name

    interface_name = args.target_endpoint.strip("/").replace("/", "_")

    output_dir = Path("results") / project_name / interface_name
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / "potential_paths.json"

    explorer = FunctionExplorer(
        target_path=args.target_path,
        target_endpoint=args.target_endpoint,
        project_name=project_name,
    )

    explorer.run_exploration()
    explorer.export_results(str(output_file))
