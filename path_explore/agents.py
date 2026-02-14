"""
Agent functions for vulnerability path discovery.

These functions encapsulate Claude Code SDK calls for specific analysis tasks.
Each agent performs a specialized code analysis task and returns structured results.
"""

import re
from typing import List, Optional

from common.base_claude_agent import base_claude_agent

from .models import (
    FunctionNode,
    NextHopInfo,
    NextHopResult,
    NodeTag,
    SourceInfo
)


# =============================================================================
# Constants
# =============================================================================

# Marker patterns for parsing agent responses
MARKER_FILE_PATH_START = "--- file path result start ---"
MARKER_FILE_PATH_END = "--- file path result end ---"
MARKER_FUNCTION_NAME_START = "--- function name start ---"
MARKER_FUNCTION_NAME_END = "--- function name end ---"
MARKER_FUNCTION_CODE_START = "--- function code start ---"
MARKER_FUNCTION_CODE_END = "--- function code end ---"

# Not found indicator
NOT_FOUND = "Not Found"


# =============================================================================
# Source Info Find Agent
# =============================================================================

# System prompt for source info discovery
_SOURCE_INFO_SYSTEM_PROMPT = """
You are a code analysis expert.

# Task

Analyze the current project. Based on the interface name provided by the user, locate the entry function's implementation, its name and its source code. You may analyze in any format, but the end of your output must include a summary in the following format:

```plaintext
--- file path result start ---
<file path>
--- file path result end ---

--- function name start ---
<function name>
--- function name end ---

--- function code start ---
<function code>
--- function code end ---
```

# Important Rules

* **Resolve to Impl**: Entry function should contain code. If the entry function is bound to an Interface or an abstract class in certain frameworks, locate its corresponding implementation as the entry function.
* **Stop at Entry**: Please provide the information of the entry function directly, even if the entry function is very simple (e.g., it simply encapsulates certain Service layer methods, etc.). Do not provide the next-hop information.
* <file path> should be a relative path based on the project root directory.
* <function name> should only contain the function name, excluding parameters and return values, for example: "getValue".
* <function code> should be directly excerpted from the source file, including and only including the code of entry function.
* If there are comments above the function, they must be preserved.
* If not found, write "Not Found" for <file path>, <function name>, and <function code>.

# Restrictions

* You are prohibited from performing any write operations.
""".strip()


def _parse_marked_section(text: str, start_marker: str, end_marker: str) -> Optional[str]:
    """
    Extract content between two markers from text.

    Args:
        text: The text to search in.
        start_marker: The start marker pattern.
        end_marker: The end marker pattern.

    Returns:
        The extracted content stripped of leading/trailing whitespace,
        or None if markers not found.
    """
    pattern = rf"{re.escape(start_marker)}\n(.*?)\n{re.escape(end_marker)}"
    match = re.search(pattern, text, re.DOTALL)
    return match.group(1).strip() if match else None


def _is_valid_result(failure_values: list, *values) -> bool:
    """
    Check if all values are valid (not in failure_values).

    Args:
        failure_values: List of values that indicate failure (e.g., [None, "Not Found"]).
        *values: Variable number of values to validate.

    Returns:
        True if all values are valid (not in failure_values), False otherwise.

    Example:
        >>> _is_valid_result([None, "Not Found"], "path/to/file", "myFunc", "code")
        True
        >>> _is_valid_result([None, "Not Found"], "path/to/file", None, "code")
        False
        >>> _is_valid_result([None, "Not Found"], "Not Found", "myFunc", "code")
        False
    """
    for value in values:
        if value in failure_values:
            return False
    return True


def source_info_find_agent(target_path: str, target_endpoint: str) -> Optional[SourceInfo]:
    """
    Find the source function information for a given API endpoint.

    This agent analyzes the target project to locate the handler function
    that corresponds to the specified API endpoint.

    Args:
        target_path: Path to the target project's source code.
        target_endpoint: The API endpoint to analyze (e.g., /example/readFile).

    Returns:
        SourceInfo containing function name, file path, and source code,
        or None if the endpoint cannot be found.

    Example:
        >>> info = source_info_find_agent("./testProject", "/example/readFile")
        >>> print(info.function_name)
        'readFileHandler'
    """
    print(f"[source_info_find_agent] Analyzing endpoint: {target_endpoint}")
    print(f"[source_info_find_agent] Target path: {target_path}")

    # Build prompts
    user_prompt = f"Interface name: {target_endpoint}"

    # Execute agent
    result = base_claude_agent(
        cwd=target_path,
        system_prompt=_SOURCE_INFO_SYSTEM_PROMPT,
        user_prompt=user_prompt
    )

    if result is None:
        print("[source_info_find_agent] Agent returned no result")
        return None

    # Parse response
    file_path = _parse_marked_section(result, MARKER_FILE_PATH_START, MARKER_FILE_PATH_END)
    function_name = _parse_marked_section(result, MARKER_FUNCTION_NAME_START, MARKER_FUNCTION_NAME_END)
    function_code = _parse_marked_section(result, MARKER_FUNCTION_CODE_START, MARKER_FUNCTION_CODE_END)

    # Validate and return
    if not _is_valid_result([None, NOT_FOUND], file_path, function_name, function_code):
        print(f"[source_info_find_agent] Failed to locate endpoint: {target_endpoint}")
        return None

    print(f"[source_info_find_agent] Found function: {function_name} in {file_path}")

    return SourceInfo(
        function_name=function_name,
        file_path=file_path,
        source_code=function_code
    )


# =============================================================================
# Next Hop Agent
# =============================================================================

def next_hop_agent(call_chain: List[FunctionNode]) -> List[NextHopResult]:
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


# =============================================================================
# Interest Info Agent
# =============================================================================

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
                   to current function.
        interest_expressions: List of call expressions for interest-marked functions
                             (e.g., ["fileService.readFile(path)", "dataProcessor.process(data)"]).

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