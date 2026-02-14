"""
Agent functions for vulnerability path discovery.
These functions encapsulate Claude Code SDK calls for specific analysis tasks.

NOTE: The actual implementation logic is placeholder only.
The detailed implementation will be completed later.
"""

from typing import List, Optional
from .models import (
    SourceInfo,
    NextHopResult,
    NextHopInfo,
    NodeTag,
    FunctionNode
)


def source_info_find_agent(
    target_path: str,
    target_endpoint: str
) -> Optional[SourceInfo]:
    """
    Find the source function information for a given API endpoint.

    This agent analyzes the target project to locate the handler function
    that corresponds to the specified API endpoint.

    Args:
        target_path: Path to the target project's source code
        target_endpoint: The API endpoint to analyze (e.g., /example/readFile)

    Returns:
        SourceInfo containing function name, file path, and source code,
        or None if the endpoint cannot be found.

    Example:
        >>> info = source_info_find_agent("./testProject", "/example/readFile")
        >>> print(info.function_name)
        'readFileHandler'
    """
    # TODO: Implement actual agent logic using Claude Code SDK
    # Current implementation is a placeholder

    print(f"[source_info_find_agent] Analyzing endpoint: {target_endpoint}")
    print(f"[source_info_find_agent] Target path: {target_path}")

    # Placeholder return - actual implementation will use Claude Code SDK
    # to analyze the codebase and find the corresponding handler function
    return None


def next_hop_agent(
    call_chain: List[FunctionNode]
) -> List[NextHopResult]:
    """
    Analyze the next hop functions from the current function in the call chain.

    This agent examines the current function (last in call_chain) to identify:
    a) Functions that are direct file/command operations with user-controlled input (Sink)
    b) Functions that may eventually lead to such operations (Interest)

    Args:
        call_chain: List of FunctionNodes representing the call chain from source
                   to current function. The last node is the current function to analyze.

    Returns:
        List of NextHopResult objects, each containing:
        - expression: The call expression (e.g., "readFile(userInput)")
        - tag: NodeTag indicating Sink(PathTraversal), Sink(CommandInjection), or Interest

    Example:
        >>> results = next_hop_agent([source_node, current_node])
        >>> for r in results:
        ...     print(f"{r.expression}: {r.tag.value}")
        'FileUtils.readFile(path): Sink(PathTraversal)'
        'processFile(content): Interest'
    """
    # TODO: Implement actual agent logic using Claude Code SDK
    # Current implementation is a placeholder

    if not call_chain:
        print("[next_hop_agent] Empty call chain provided")
        return []

    current_function = call_chain[-1]
    print(f"[next_hop_agent] Analyzing function: {current_function.function_name}")
    print(f"[next_hop_agent] Call chain length: {len(call_chain)}")

    # Placeholder return - actual implementation will analyze the source code
    # to identify next hop functions and classify them
    return []


def interest_info_agent(
    call_chain: List[FunctionNode],
    interest_expressions: List[str]
) -> List[NextHopInfo]:
    """
    Find the implementation details of interest-marked next hop functions.

    This agent locates the actual implementation of functions identified as
    "Interest" by next_hop_agent. For interface types, it finds all implementation
    classes that could be called in the current call context.

    Args:
        call_chain: List of FunctionNodes representing the call chain from source
                   to current function
        interest_expressions: List of call expressions for interest-marked functions
                             (e.g., ["fileService.readFile(path)", "dataProcessor.process(data)"])

    Returns:
        List of NextHopInfo objects containing:
        - function_name: Name of the function
        - file_path: Path to the file containing the function
        - source_code: Source code of the function

        IMPORTANT: For interface types, returns ALL implementation classes that
        could be invoked in this call context, not just all implementations globally.

    Example:
        >>> infos = interest_info_agent([source_node], ["fileService.read(path)"])
        >>> for info in infos:
        ...     print(f"{info.function_name} in {info.file_path}")
        'read in ./services/FileServiceImpl.java'
        'read in ./services/SafeFileServiceImpl.java'
    """
    # TODO: Implement actual agent logic using Claude Code SDK
    # Current implementation is a placeholder

    if not call_chain or not interest_expressions:
        print("[interest_info_agent] Empty call chain or expressions provided")
        return []

    current_function = call_chain[-1]
    print(f"[interest_info_agent] Finding implementations for {len(interest_expressions)} interest functions")
    print(f"[interest_info_agent] Current function: {current_function.function_name}")
    print(f"[interest_info_agent] Interest expressions: {interest_expressions}")

    # Placeholder return - actual implementation will analyze the codebase
    # to find function implementations, handling interface resolution
    return []
