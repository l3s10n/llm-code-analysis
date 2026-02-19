"""
GOLD MINER - Main Entry Point

This module provides the main entry point for running the complete vulnerability
analysis pipeline, which consists of:
1. Path Exploration (path_explore): Discover potential vulnerability paths
2. Path Verification (path_verify): Verify if the paths contain exploitable vulnerabilities

Usage:
    python main.py <project_path> <interface>

Examples:
    python main.py ./testProject /api/readFile
    python main.py ./my-project /example/upload
"""

import argparse
import sys
from pathlib import Path

from path_explore.explorer import FunctionExplorer
from path_verify.verify import PathVerifier


def analyze_single_endpoint(
    target_path: str,
    target_endpoint: str,
    project_name: str,
    output_base_dir: str = "results"
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
    print("\n" + "=" * 60)
    print("PHASE 1: Path Exploration - Discovering Potential Vulnerability Paths")
    print("=" * 60)
    print(f"Target Project: {target_path}")
    print(f"Target Interface: {target_endpoint}")
    print(f"Output: {potential_paths_output}")
    print()

    # Create and run explorer
    explorer = FunctionExplorer(
        target_path=target_path,
        target_endpoint=target_endpoint,
        project_name=project_name
    )

    # Run exploration
    vulnerability_paths = explorer.run_exploration()

    if not vulnerability_paths:
        print("\n[Warning] No potential vulnerability paths found.")
        print("[Info] Skipping verification phase.")
        return True

    # Export exploration results
    explorer.export_results(str(potential_paths_output))

    print(f"\n[Info] Found {len(vulnerability_paths)} potential vulnerability path(s)")

    # =========================================================================
    # Phase 2: Path Verification
    # =========================================================================
    print("\n" + "=" * 60)
    print("PHASE 2: Path Verification - Analyzing Potential Vulnerabilities")
    print("=" * 60)
    print(f"Input: {potential_paths_output}")

    # Create verifier
    verifier = PathVerifier(
        target_path=target_path,
        potential_paths_file=str(potential_paths_output),
        project_name=project_name
    )

    # Load paths first to get interface_name for output path
    if not verifier.load_paths():
        print("[Error] Failed to load potential paths for verification")
        return False

    # Build output path from interface_name in potential_paths.json
    assert verifier.interface_name is not None
    verified_paths_output = Path(output_base_dir) / project_name / verifier.interface_name / "verified_paths.json"
    print(f"Output: {verified_paths_output}")
    print()

    # Run verification (paths already loaded)
    verification_results = verifier.run_verification()

    if verification_results:
        # Export verification results
        verifier.export_results(str(verified_paths_output))

        # Print summary
        vulnerable_count = sum(1 for r in verification_results if r.is_vulnerable)
        not_vulnerable_count = len(verification_results) - vulnerable_count

        print("\n" + "=" * 60)
        print("FINAL SUMMARY")
        print("=" * 60)
        print(f"Total paths analyzed: {len(verification_results)}")
        print(f"Vulnerable paths: {vulnerable_count}")
        print(f"Non-vulnerable paths: {not_vulnerable_count}")
        print(f"\nResults exported to: {verified_paths_output}")
    else:
        print("\n[Warning] No verification results produced.")

    return True


def main():
    """
    Main entry point for the GOLD MINER CLI.

    Parses command line arguments and runs the vulnerability analysis pipeline.
    """
    parser = argparse.ArgumentParser(
        description='GOLD MINER - LLM-based White-box Vulnerability Discovery Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py ./testProject /api/readFile
  python main.py ./my-project /example/upload
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
        help='The API interface to analyze (e.g., /api/readFile)'
    )

    args = parser.parse_args()

    # Check if target path exists
    if not Path(args.project_path).exists():
        print(f"[Error] Project path does not exist: {args.project_path}")
        sys.exit(1)

    # Derive project name from target path
    target_path_obj = Path(args.project_path)
    project_name = target_path_obj.name

    # Run analysis
    success = analyze_single_endpoint(
        target_path=args.project_path,
        target_endpoint=args.interface,
        project_name=project_name
    )

    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
