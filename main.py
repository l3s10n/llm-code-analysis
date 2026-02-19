"""
GOLD MINER - Main Entry Point

This module provides the main entry point for running the complete vulnerability
analysis pipeline, which consists of:
1. Path Exploration (path_explore): Discover potential vulnerability paths
2. Path Verification (path_verify): Verify if the paths contain exploitable vulnerabilities

Usage:
    # Analyze a single endpoint
    python main.py <project_path> --endpoint <endpoint>

    # Analyze all endpoints in the project (not implemented yet)
    python main.py <project_path>

Examples:
    python main.py ./testProject --endpoint /api/readFile
    python main.py ./my-project --endpoint /example/upload
"""

import argparse
import sys
from pathlib import Path
from typing import Optional

from path_explore.explorer import FunctionExplorer
from path_verify.verify import PathVerifier


def analyze_single_endpoint(
    target_path: str,
    target_endpoint: str,
    project_name: str,
    output_dir: Path
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
        output_dir: Base output directory for results

    Returns:
        True if analysis completed successfully, False otherwise
    """
    # Sanitize endpoint name for filename
    endpoint_name = target_endpoint.strip('/').replace('/', '_')
    if not endpoint_name:
        endpoint_name = "root"

    # Define output paths
    potential_paths_output = output_dir / "potential_paths" / f"{endpoint_name}.json"
    verified_paths_output = output_dir / "verified_paths" / f"{endpoint_name}.json"

    # Ensure output directories exist
    potential_paths_output.parent.mkdir(parents=True, exist_ok=True)
    verified_paths_output.parent.mkdir(parents=True, exist_ok=True)

    # =========================================================================
    # Phase 1: Path Exploration
    # =========================================================================
    print("\n" + "=" * 60)
    print("PHASE 1: Path Exploration - Discovering Potential Vulnerability Paths")
    print("=" * 60)
    print(f"Target Project: {target_path}")
    print(f"Target Endpoint: {target_endpoint}")
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
    print(f"Output: {verified_paths_output}")
    print()

    # Create and run verifier
    verifier = PathVerifier(
        target_path=target_path,
        potential_paths_file=str(potential_paths_output),
        project_name=project_name
    )

    # Run verification
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


def analyze_all_endpoints(
    target_path: str,
    project_name: str,
    output_dir: Path
) -> bool:
    """
    Analyze all API endpoints in the project for vulnerabilities.

    This function discovers all endpoints in the project and runs the complete
    vulnerability analysis pipeline for each one.

    TODO: This function is not implemented yet. It will:
    1. Scan the project to discover all API endpoints
    2. For each endpoint, run analyze_single_endpoint()

    Args:
        target_path: Path to the target project's source code
        project_name: Name of the project (used for output directory)
        output_dir: Base output directory for results

    Returns:
        True if analysis completed successfully, False otherwise
    """
    print("\n" + "=" * 60)
    print("ANALYZE ALL ENDPOINTS - Not Implemented Yet")
    print("=" * 60)
    print(f"Target Project: {target_path}")
    print(f"Project Name: {project_name}")
    print()
    print("[Info] This feature is not yet implemented.")
    print("[Info] Please use --endpoint option to analyze a specific endpoint.")
    print()
    print("Planned implementation:")
    print("  1. Scan project for all API endpoints (Spring MVC, JAX-RS, etc.)")
    print("  2. For each discovered endpoint, run the analysis pipeline")
    print("  3. Aggregate results across all endpoints")
    print("=" * 60)

    # TODO: Implement endpoint discovery and batch analysis
    # Steps:
    # 1. Use an endpoint discovery agent to find all @RequestMapping, @GetMapping, etc.
    # 2. Collect all endpoints into a list
    # 3. Iterate and call analyze_single_endpoint for each

    return False


def main():
    """
    Main entry point for the GOLD MINER CLI.

    Parses command line arguments and runs the vulnerability analysis pipeline.
    Supports two modes:
    1. Single endpoint analysis: --endpoint option specified
    2. All endpoints analysis: no --endpoint option (not implemented yet)
    """
    parser = argparse.ArgumentParser(
        description='GOLD MINER - LLM-based White-box Vulnerability Discovery Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze a single endpoint
  python main.py ./testProject --endpoint /api/readFile

  # Analyze all endpoints in the project (not implemented yet)
  python main.py ./testProject
        """
    )

    parser.add_argument(
        'project_path',
        type=str,
        help='Path to the target project\'s source code'
    )

    parser.add_argument(
        '--endpoint',
        '-e',
        type=str,
        default=None,
        help='The API endpoint to analyze (e.g., /api/readFile). If not specified, all endpoints will be analyzed (not implemented yet).'
    )

    parser.add_argument(
        '--output-dir',
        '-o',
        type=str,
        default=None,
        help='Custom output directory (default: results/<project_name>)'
    )

    args = parser.parse_args()

    # Check if target path exists
    if not Path(args.project_path).exists():
        print(f"[Error] Project path does not exist: {args.project_path}")
        sys.exit(1)

    # Derive project name from target path
    target_path_obj = Path(args.project_path)
    project_name = target_path_obj.name if target_path_obj.name else target_path_obj.parent.name

    # Determine output directory
    if args.output_dir:
        output_dir = Path(args.output_dir)
    else:
        output_dir = Path("results") / project_name

    # Run appropriate analysis based on whether endpoint is specified
    if args.endpoint:
        # Single endpoint analysis
        success = analyze_single_endpoint(
            target_path=args.project_path,
            target_endpoint=args.endpoint,
            project_name=project_name,
            output_dir=output_dir
        )
    else:
        # All endpoints analysis (not implemented yet)
        success = analyze_all_endpoints(
            target_path=args.project_path,
            project_name=project_name,
            output_dir=output_dir
        )

    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
