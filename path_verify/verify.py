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

    def __init__(self, target_path: str, potential_paths_file: str):
        """
        Initialize the PathVerifier.

        Args:
            target_path: Path to the target project's source code
            potential_paths_file: Path to the JSON file containing potential paths
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

    def load_paths(self) -> bool:
        """
        Load potential paths from the JSON file.

        Returns:
            True if paths loaded successfully, False otherwise
        """
        log_info("Verifier", f"Loading potential paths from: {self.potential_paths_file}")

        try:
            self.potential_paths = load_potential_paths(self.potential_paths_file)
            log_success("Verifier", f"Loaded {len(self.potential_paths)} potential path(s)")
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

    def run_verification(self) -> List[VerificationResult]:
        """
        Run the complete verification process for all potential paths.

        Returns:
            List of VerificationResult objects
        """
        # Start TUI in verify mode
        start_tui(
            target_path=self.target_path,
            target_endpoint=self.potential_paths_file,
            mode=TUIMode.VERIFY
        )

        try:
            # Load potential paths
            if not self.load_paths():
                log_error("Verifier", "Failed to load potential paths")
                return []

            if not self.potential_paths:
                log_warning("Verifier", "No potential paths to verify")
                return []

            # Log configuration info
            if self.verbose:
                log_info("Config", f"Verbose mode enabled")

            # Verify each path
            total = len(self.potential_paths)
            for i, path in enumerate(self.potential_paths, 1):
                log_info("Verifier", f"Verifying path {i}/{total}: {path.get_call_chain_display()}")

                result = self.verify_path(path, i, total)
                self.verification_results.append(result)

        except Exception as e:
            import traceback
            log_error("Verifier", f"Error: {type(e).__name__}: {str(e)}")
            stop_tui()
            print("\n[Error Details]")
            print(traceback.format_exc())
            return []

        # Stop TUI and print summary
        stop_tui()
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
  python -m path_verify.verify ./testProject results/test_project/potential_paths/api_readFile.json
  python -m path_verify.verify ./my-project results/my_project/potential_paths/example.json
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
    project_name = target_path.name if target_path.name else target_path.parent.name

    # Build output path if not specified
    if args.output:
        output_file = args.output
    else:
        # Extract endpoint name from the potential paths file
        paths_file = Path(args.potential_paths_file)
        endpoint_name = paths_file.stem  # filename without extension

        # Build output path: results/<project_name>/verified_paths/<endpoint>.json
        output_dir = Path("results") / project_name / "verified_paths"
        output_dir.mkdir(parents=True, exist_ok=True)
        output_file = str(output_dir / f"{endpoint_name}.json")

    # Create and run verifier
    verifier = PathVerifier(
        target_path=args.target_path,
        potential_paths_file=args.potential_paths_file
    )

    # Run verification
    results = verifier.run_verification()

    # Export results
    if results:
        verifier.export_results(output_file)
