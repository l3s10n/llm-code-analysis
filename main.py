"""
VulSolver - Main Entry Point

This module provides the main entry point for running the complete vulnerability
analysis pipeline, which consists of:
1. Path Exploration (path_explore): Discover potential vulnerability paths
2. Path Verification (path_verify): Verify if the paths contain exploitable vulnerabilities

Usage:
    python main.py <project_path> <interface>
    python main.py <project_path> --interface-file <file>

Examples:
    python main.py ./testProject /api/readFile
    python main.py ./my-project /example/upload
    python main.py ./my-project --interface-file ./interfaces.txt
"""

import argparse
import sys
from pathlib import Path

from common.tui import configure_tui, emit_output
from path_explore.explorer import FunctionExplorer
from path_verify.verify import PathVerifier


def analyze_single_endpoint(
    target_path: str,
    target_endpoint: str,
    project_name: str,
    output_base_dir: str = "results",
    batch_index: int = 0,
    batch_total: int = 0,
) -> bool:
    """
    Analyze a single API endpoint for vulnerabilities.

    This function runs the complete vulnerability analysis pipeline for one endpoint:
    1. Path Exploration: Discover potential vulnerability paths from source to sink
    2. Path Verification: Verify if each path contains an exploitable vulnerability

    Args:
        target_path: Path to the target project's source code
        target_endpoint: The API endpoint to analyze (e.g., /api/readFile)
        project_name: Name of the project (used for output directory)
        output_base_dir: Base directory for results (default: "results")
        batch_index: Current endpoint index in a batch (1-based, optional)
        batch_total: Total number of endpoints in the batch (optional)

    Returns:
        True if analysis completed successfully, False otherwise
    """
    # Sanitize interface name for directory name
    interface_name = target_endpoint.strip('/').replace('/', '_')

    # Define output paths: results/<project_name>/<interface_name>/
    interface_output_dir = Path(output_base_dir) / project_name / interface_name
    interface_output_dir.mkdir(parents=True, exist_ok=True)

    potential_paths_output = interface_output_dir / "potential_paths.json"

    # =========================================================================
    # Phase 1: Path Exploration
    # =========================================================================
    emit_output("\n" + "=" * 60, source="Main")
    emit_output("PHASE 1: Path Exploration - Discovering Potential Vulnerability Paths", source="Main")
    emit_output("=" * 60, source="Main")
    emit_output(f"Target Project: {target_path}", source="Main")
    emit_output(f"Target Interface: {target_endpoint}", source="Main")
    if batch_total > 0:
        emit_output(f"Batch Progress: {batch_index}/{batch_total}", source="Main")
    emit_output(f"Output: {potential_paths_output}", source="Main")
    emit_output(source="Main")

    # Create and run explorer
    explorer = FunctionExplorer(
        target_path=target_path,
        target_endpoint=target_endpoint,
        project_name=project_name,
        batch_index=batch_index,
        batch_total=batch_total,
    )

    # Run exploration
    vulnerability_paths = explorer.run_exploration()

    if not vulnerability_paths:
        emit_output("[Info] No potential vulnerability paths found.", source="Main")
        return True

    # Export exploration results
    explorer.export_results(str(potential_paths_output))

    emit_output(f"[Info] Found {len(vulnerability_paths)} potential vulnerability path(s)", source="Main")

    # =========================================================================
    # Phase 2: Path Verification
    # =========================================================================
    emit_output("\n" + "=" * 60, source="Main")
    emit_output("PHASE 2: Path Verification - Analyzing Potential Vulnerabilities", source="Main")
    emit_output("=" * 60, source="Main")
    emit_output(f"Input: {potential_paths_output}", source="Main")

    # Create verifier
    verifier = PathVerifier(
        target_path=target_path,
        potential_paths_file=str(potential_paths_output),
        project_name=project_name,
        batch_index=batch_index,
        batch_total=batch_total,
    )

    # Load paths first to get interface_name for output path
    if not verifier.load_paths():
        emit_output("[Error] Failed to load potential paths for verification", source="Main", level="ERROR")
        return False

    # Build output path from interface_name in potential_paths.json
    assert verifier.interface_name is not None
    verified_paths_output = Path(output_base_dir) / project_name / verifier.interface_name / "verified_paths.json"
    emit_output(f"Output: {verified_paths_output}", source="Main")
    emit_output(source="Main")

    # Run verification (paths already loaded)
    verification_results = verifier.run_verification()

    if verification_results:
        # Export verification results
        verifier.export_results(str(verified_paths_output))

        # Print summary
        vulnerable_count = sum(1 for r in verification_results if r.is_vulnerable)
        not_vulnerable_count = len(verification_results) - vulnerable_count

        emit_output("\n" + "=" * 60, source="Main")
        emit_output("FINAL SUMMARY", source="Main")
        emit_output("=" * 60, source="Main")
        emit_output(f"Total paths analyzed: {len(verification_results)}", source="Main")
        emit_output(f"Vulnerable paths: {vulnerable_count}", source="Main")
        emit_output(f"Non-vulnerable paths: {not_vulnerable_count}", source="Main")
        emit_output(f"Results exported to: {verified_paths_output}", source="Main")
    else:
        emit_output("[Warning] No verification results produced.", source="Main", level="WARNING")

    return True


def load_interfaces_from_file(interface_file: str) -> list[str]:
    """Load interface names from a text file, one per line."""

    interfaces: list[str] = []
    with open(interface_file, "r", encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            interfaces.append(line)
    return interfaces


def main():
    """
    Main entry point for the VulSolver CLI.

    Parses command line arguments and runs the vulnerability analysis pipeline.
    """
    parser = argparse.ArgumentParser(
        description='VulSolver - LLM-based White-box Vulnerability Discovery Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py ./testProject /api/readFile
  python main.py ./my-project /example/upload
  python main.py ./my-project --interface-file ./interfaces.txt
        """
    )

    parser.add_argument(
        'project_path',
        type=str,
        help='Path to the target project\'s source code'
    )

    parser.add_argument(
        'interface',
        type=str,
        nargs='?',
        help='The API interface to analyze (e.g., /api/readFile)'
    )

    parser.add_argument(
        '--interface-file',
        type=str,
        help='Path to a file containing one interface per line'
    )

    parser.add_argument(
        '--no-tui',
        action='store_true',
        help='Disable the Textual UI and print progress directly to the terminal'
    )

    args = parser.parse_args()

    configure_tui(enabled=not args.no_tui)

    # Check if target path exists
    if not Path(args.project_path).exists():
        emit_output(f"[Error] Project path does not exist: {args.project_path}", source="Main", level="ERROR")
        sys.exit(1)

    # Derive project name from target path
    target_path_obj = Path(args.project_path)
    project_name = target_path_obj.name

    if bool(args.interface) == bool(args.interface_file):
        emit_output(
            "[Error] Specify exactly one of <interface> or --interface-file",
            source="Main",
            level="ERROR",
        )
        sys.exit(1)

    if args.interface_file:
        interface_file_path = Path(args.interface_file)
        if not interface_file_path.exists():
            emit_output(
                f"[Error] Interface file does not exist: {args.interface_file}",
                source="Main",
                level="ERROR",
            )
            sys.exit(1)

        interfaces = load_interfaces_from_file(args.interface_file)
        if not interfaces:
            emit_output(
                f"[Error] No interfaces found in file: {args.interface_file}",
                source="Main",
                level="ERROR",
            )
            sys.exit(1)

        emit_output(f"Loaded {len(interfaces)} interface(s) from: {args.interface_file}", source="Main")

        overall_success = True
        successful_runs = 0
        for index, interface_name in enumerate(interfaces, 1):
            success = analyze_single_endpoint(
                target_path=args.project_path,
                target_endpoint=interface_name,
                project_name=project_name,
                batch_index=index,
                batch_total=len(interfaces),
            )
            overall_success = overall_success and success
            if success:
                successful_runs += 1

        emit_output("\n" + "=" * 60, source="Main")
        emit_output("BATCH SUMMARY", source="Main")
        emit_output("=" * 60, source="Main")
        emit_output(f"Interfaces processed: {len(interfaces)}", source="Main")
        emit_output(f"Successful runs: {successful_runs}", source="Main")
        emit_output(f"Failed runs: {len(interfaces) - successful_runs}", source="Main")
        success = overall_success
    else:
        success = analyze_single_endpoint(
            target_path=args.project_path,
            target_endpoint=args.interface,
            project_name=project_name
        )

    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
