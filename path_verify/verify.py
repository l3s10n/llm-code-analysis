"""
Core verification logic for vulnerability path validation.
Implements the path verification process using dataflow and filter analysis.
"""

import json
import sys
import os
from typing import List, Optional

# Add parent directory to path for config import
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.config import load_config
from common.tui import (
    TUIMode,
    start_tui,
    stop_tui,
    log_info,
    log_success,
    log_error,
    log_warning,
    set_verify_path_info,
    set_verify_stage,
    set_analyzing_node,
    update_verify_stats,
    print_verify_summary
)
from common.agent_logger import init_logger, close_logger, append_to_log
from common.base_claude_agent import set_error_context, clear_error_context

from .models import (
    PotentialPath,
    DataflowInfo,
    FilterLogic,
    NodeDataflowRecord,
    VerificationResult
)
from .agents import (
    one_hop_dataflow_agent,
    one_hop_filter_agent,
    final_decision_agent
)
from .utils import (
    load_potential_paths,
    print_stage_header,
    print_call_chain,
    print_dataflow_analysis,
    print_filter_analysis,
    print_final_result,
    print_verification_summary
)


class PathVerifier:
    """
    Main class for verifying potential vulnerability paths.

    This class analyzes potential vulnerability paths discovered by path_explore
    to determine if they contain exploitable vulnerabilities.
    """

    def __init__(
        self,
        target_path: str,
        potential_paths_file: str,
        project_name: Optional[str] = None
    ):
        """
        Initialize the PathVerifier.

        Args:
            target_path: Path to the target project's source code
            potential_paths_file: Path to the JSON file containing potential paths
            project_name: Optional project name (derived from target_path if not provided)
        """
        self.target_path = target_path
        self.potential_paths_file = potential_paths_file
        self.potential_paths: List[PotentialPath] = []
        self.verification_results: List[VerificationResult] = []

        # Statistics
        self.vulnerable_count = 0
        self.not_vulnerable_count = 0

        # Load configuration values
        self.verbose = load_config("exploration.verbose")

        # Derive project name from target path if not provided
        from pathlib import Path
        if project_name:
            self.project_name = project_name
        else:
            target_path_obj = Path(target_path)
            self.project_name = target_path_obj.name

        # Interface name will be set after loading potential paths
        self.interface_name: Optional[str] = None

    def load_paths(self) -> bool:
        """
        Load potential paths from the JSON file.

        Also extracts the interface_name from the JSON for logging and output paths.

        Returns:
            True if paths loaded successfully, False otherwise
        """
        log_info("Verifier", f"Loading potential paths from: {self.potential_paths_file}")

        try:
            self.potential_paths = load_potential_paths(self.potential_paths_file)
            log_success("Verifier", f"Loaded {len(self.potential_paths)} potential path(s)")

            # Extract interface_name from the first path for directory naming
            interface_raw = self.potential_paths[0].interface_name
            self.interface_name = interface_raw.strip('/').replace('/', '_')

            return True
        except FileNotFoundError:
            log_error("Verifier", f"File not found: {self.potential_paths_file}")
            return False
        except json.JSONDecodeError as e:
            log_error("Verifier", f"Invalid JSON format: {e}")
            return False

    def verify_path(self, path: PotentialPath, path_index: int, total_paths: int) -> VerificationResult:
        """
        Verify a single potential vulnerability path.

        This method performs the complete verification process:
        1. Dataflow analysis from sink to source
        2. Filter analysis from source to sink
        3. Final decision

        Args:
            path: PotentialPath to verify
            path_index: Index of current path (1-based)
            total_paths: Total number of paths to verify

        Returns:
            VerificationResult containing the verification outcome
        """
        call_chain_display = path.get_call_chain_display()

        # Initialize result with path info from explore module output
        result = VerificationResult(
            interface_name=path.interface_name,
            vulnerability_type=path.vulnerability_type,
            sink_expression=path.sink_expression,
            path=path.path
        )

        # Update TUI with current path info
        call_chain_names = [node.name for node in path.path]
        call_chain_files = [node.file for node in path.path]
        set_verify_path_info(path_index, total_paths, call_chain_names, call_chain_files)

        print_stage_header("Path Verification", call_chain_display)
        print_call_chain(path)

        if not path.path:
            log_warning("Verifier", "Empty path, skipping")
            result.summary = "Empty path - no functions to analyze"
            return result

        # ============================================================
        # Phase 1: Dataflow Analysis (Sink -> Source)
        # ============================================================
        set_verify_stage("dataflow")
        log_info("Verifier", "Phase 1: Dataflow Analysis (Sink -> Source)")

        dataflow_records: List[NodeDataflowRecord] = []
        next_node_dataflow: Optional[DataflowInfo] = None

        # Analyze from last node to first (sink to source)
        for i in range(len(path.path) - 1, -1, -1):
            node = path.path[i]

            # Update TUI to show which node is being analyzed
            set_analyzing_node(i)
            log_info("Verifier", f"Analyzing dataflow in node [{i}]: {node.name}")

            # Analyze dataflow for this node
            dataflow_info = one_hop_dataflow_agent(
                target_path=self.target_path,
                path=path,
                node_index=i,
                next_node_dataflow=next_node_dataflow
            )

            # Record the dataflow info
            record = NodeDataflowRecord(
                node_index=i,
                node_name=node.name,
                dataflow_info=dataflow_info
            )
            dataflow_records.insert(0, record)  # Insert at beginning to maintain order

            # Update for next iteration
            next_node_dataflow = dataflow_info

        # Clear node highlighting after dataflow phase
        set_analyzing_node(-1)
        result.dataflow_records = dataflow_records
        print_dataflow_analysis(dataflow_records)

        # ============================================================
        # Phase 2: Filter Analysis (Source -> Sink)
        # ============================================================
        set_verify_stage("filter")
        log_info("Verifier", "Phase 2: Filter Analysis (Source -> Sink)")

        all_filter_logics: List[FilterLogic] = []

        # Analyze from first node to last (source to sink)
        for i in range(len(path.path)):
            node = path.path[i]

            # Update TUI to show which node is being analyzed
            set_analyzing_node(i)
            log_info("Verifier", f"Analyzing filters in node [{i}]: {node.name}")

            # Get dataflow info for this node and next node
            x_dataflow = dataflow_records[i].dataflow_info
            y_dataflow = None
            if i + 1 < len(dataflow_records):
                y_dataflow = dataflow_records[i + 1].dataflow_info

            # Analyze filters
            filter_logics = one_hop_filter_agent(
                target_path=self.target_path,
                path=path,
                node_index=i,
                current_dataflow=x_dataflow,
                next_dataflow=y_dataflow
            )

            all_filter_logics.extend(filter_logics)

        # Clear node highlighting after filter phase
        set_analyzing_node(-1)
        result.filter_logics = all_filter_logics
        print_filter_analysis(all_filter_logics)

        # ============================================================
        # Phase 3: Final Decision
        # ============================================================
        set_verify_stage("decision")
        log_info("Verifier", "Phase 3: Final Decision")

        is_vulnerable, confidence, summary = final_decision_agent(
            target_path=self.target_path,
            path=path,
            dataflow_records=dataflow_records,
            filter_logics=all_filter_logics
        )

        result.is_vulnerable = is_vulnerable
        result.confidence = confidence
        result.summary = summary

        # Update statistics
        if is_vulnerable:
            self.vulnerable_count += 1
        else:
            self.not_vulnerable_count += 1
        update_verify_stats(self.vulnerable_count, self.not_vulnerable_count)

        print_final_result(result)

        return result

    def _format_path_header(self, path: PotentialPath, path_index: int) -> str:
        """
        Format the path information header for logging.

        Args:
            path: The potential path to format
            path_index: Current path index (1-based)

        Returns:
            Formatted string for path header
        """
        import os

        # Build call chain with arrow
        call_chain = " → ".join([node.name for node in path.path] + ["sink"])

        # Build path nodes info
        nodes_info = []
        for j, node in enumerate(path.path):
            short_file = os.path.basename(node.file) if node.file else "?"
            nodes_info.append(f"  [{j}] {node.name}")
            nodes_info.append(f"      File: {short_file}")

        content = f"""
{'#' * 78}
#{' ' * 76}#
#{f'VERIFICATION PATH #{path_index}'.center(76)}#
#{' ' * 76}#
{'#' * 78}

Type: {path.vulnerability_type}
Sink Expression: {path.sink_expression}

Call Chain:
  {call_chain}

Path Nodes:
{chr(10).join(nodes_info)}

"""
        return content

    def _format_path_result(self, result: VerificationResult, path_index: int) -> str:
        """
        Format the verification result for logging.

        Args:
            result: The verification result
            path_index: Current path index (1-based)

        Returns:
            Formatted string for result
        """
        status = "VULNERABLE" if result.is_vulnerable else "NOT VULNERABLE"

        content = f"""
{'#' * 78}
#{' ' * 76}#
#{f'VERIFICATION RESULT #{path_index}'.center(76)}#
#{' ' * 76}#
{'#' * 78}

Status: {status}
Confidence: {result.confidence}
Summary: {result.summary}

"""
        return content

    def _format_final_summary(self) -> str:
        """
        Format the final summary for logging.

        Returns:
            Formatted string for final summary
        """
        content = f"""
{'#' * 78}
#{' ' * 76}#
#{'FINAL SUMMARY'.center(76)}#
#{' ' * 76}#
{'#' * 78}

Total Analyzed: {len(self.verification_results)}
Vulnerable: {self.vulnerable_count}
Not Vulnerable: {self.not_vulnerable_count}

{'#' * 78}
"""
        return content

    def run_verification(self) -> List[VerificationResult]:
        """
        Run the complete verification process for all potential paths.

        Returns:
            List of VerificationResult objects
        """
        # Load potential paths if not already loaded
        if not self.potential_paths:
            if not self.load_paths():
                print("[Error] Failed to load potential paths")
                return []

            if not self.potential_paths:
                print("[Warning] No potential paths to verify")
                return []

        # Now initialize logger with interface_name from endpoint
        # interface_name is guaranteed to be set after load_paths()
        assert self.interface_name is not None

        # Set error context for error file generation
        set_error_context(self.project_name, self.interface_name)

        init_logger(
            project_name=self.project_name,
            interface_name=self.interface_name,
            log_type="path_verify"
        )

        # Append total paths info to log header
        total_paths_info = f"Total Paths to Verify: {len(self.potential_paths)}\n\n"
        append_to_log(total_paths_info)

        # Start TUI in verify mode
        start_tui(
            target_path=self.target_path,
            target_endpoint=self.potential_paths_file,
            mode=TUIMode.VERIFY
        )

        try:
            # Log configuration info
            if self.verbose:
                log_info("Config", f"Verbose mode enabled")

            # Verify each path
            total = len(self.potential_paths)
            for i, path in enumerate(self.potential_paths, 1):
                log_info("Verifier", f"Verifying path {i}/{total}: {path.get_call_chain_display()}")

                # Write path header to log
                path_header = self._format_path_header(path, i)
                append_to_log(path_header)

                result = self.verify_path(path, i, total)
                self.verification_results.append(result)

                # Write result to log
                result_content = self._format_path_result(result, i)
                append_to_log(result_content)

        except Exception as e:
            import traceback
            log_error("Verifier", f"Error: {type(e).__name__}: {str(e)}")
            stop_tui()
            close_logger()
            clear_error_context()
            print("\n[Error Details]")
            print(traceback.format_exc())
            return []

        # Stop TUI and print summary
        stop_tui()

        # Write final summary to log
        summary_content = self._format_final_summary()
        append_to_log(summary_content)

        close_logger()
        clear_error_context()
        print_verify_summary(self.vulnerable_count, self.not_vulnerable_count, len(self.verification_results))
        return self.verification_results

    def export_results(self, output_path: str) -> None:
        """
        Export verification results to a JSON file.

        Args:
            output_path: Path to the output JSON file
        """
        results = [r.to_dict() for r in self.verification_results]

        # Create output directory if needed
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)

        from rich.console import Console
        console = Console()
        console.print(f"[green]Verification results exported to:[/green] {output_path}")

    def get_results_json(self) -> str:
        """
        Get verification results as a JSON string.

        Returns:
            JSON string representation of the verification results
        """
        results = [r.to_dict() for r in self.verification_results]
        return json.dumps(results, indent=2, ensure_ascii=False)


# =============================================================================
# CLI Entry Point
# =============================================================================

if __name__ == '__main__':
    import argparse
    from pathlib import Path
    from rich.console import Console

    parser = argparse.ArgumentParser(
        description='GOLD MINER - Vulnerability Path Verification Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m path_verify.verify ./testProject results/testProject/api_readFile/potential_paths.json
  python -m path_verify.verify ./my-project results/myProject/example/potential_paths.json
        """
    )

    parser.add_argument(
        'target_path',
        type=str,
        help='Path to the target project\'s source code'
    )

    parser.add_argument(
        'potential_paths_file',
        type=str,
        help='Path to the JSON file containing potential paths (from path_explore)'
    )

    parser.add_argument(
        '-o', '--output',
        type=str,
        default=None,
        help='Output file path for verification results (default: auto-generated)'
    )

    args = parser.parse_args()

    # Get project name from target path
    target_path = Path(args.target_path)
    project_name = target_path.name

    # Create verifier instance
    verifier = PathVerifier(
        target_path=args.target_path,
        potential_paths_file=args.potential_paths_file,
        project_name=project_name
    )

    # Load paths first to get interface_name for determining output path
    if not verifier.load_paths():
        print("[Error] Failed to load potential paths")
        sys.exit(1)

    # Build output path if not specified
    if args.output:
        output_file = args.output
    else:
        # Output path: results/<project_name>/<interface_name>/verified_paths.json
        assert verifier.interface_name is not None
        output_dir = Path("results") / project_name / verifier.interface_name
        output_dir.mkdir(parents=True, exist_ok=True)
        output_file = str(output_dir / "verified_paths.json")

    # Run verification (paths already loaded, will use cached data)
    results = verifier.run_verification()

    # Export results
    if results:
        verifier.export_results(output_file)
