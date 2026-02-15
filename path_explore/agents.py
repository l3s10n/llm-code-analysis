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

# Markers for next hop agent
MARKER_FUNCTION_INFO_START = "--- function info start ---"
MARKER_FUNCTION_INFO_END = "--- function info end ---"
MARKER_SEPARATOR = "--- Separator ---"

# Not found indicator
NOT_FOUND = "Not Found"


# =============================================================================
# Helper Functions
# =============================================================================

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


def _parse_function_info_sections(text: str) -> list:
    """
    Parse function info sections from next hop agent response.

    Args:
        text: The agent response text.

    Returns:
        List of tuples (expression, tag) for each function info section.
        Tag is one of: "Sink(PathTraversal)", "Sink(CommandInjection)", "Interest".
    """
    # Find all function info sections
    pattern = rf"{re.escape(MARKER_FUNCTION_INFO_START)}(.*?){re.escape(MARKER_FUNCTION_INFO_END)}"
    matches = re.findall(pattern, text, re.DOTALL)

    results = []
    for match in matches:
        # Split by separator to get expression and tag
        if MARKER_SEPARATOR in match:
            parts = match.split(MARKER_SEPARATOR, 1)
            if len(parts) == 2:
                expression = parts[0].strip()
                tag_str = parts[1].strip()
                results.append((expression, tag_str))

    return results


def _tag_string_to_enum(tag_str: str) -> Optional[NodeTag]:
    """
    Convert tag string to NodeTag enum.

    Args:
        tag_str: Tag string from agent response.

    Returns:
        Corresponding NodeTag enum value, or None if invalid.
    """
    tag_map = {
        "Sink(PathTraversal)": NodeTag.SINK_PATH_TRAVERSAL,
        "Sink(CommandInjection)": NodeTag.SINK_COMMAND_INJECTION,
        "Interest": NodeTag.INTEREST
    }
    return tag_map.get(tag_str)


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
* <function code> should be directly excerpted from the source file, including and only including the code of the entry function.
* If there are comments above the function, they must be preserved.
* If not found, write "Not Found" for <file path>, <function name>, and <function code>.

# Restrictions

* You are prohibited from performing any write operations.
""".strip()


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

# System prompt for next hop discovery
_NEXT_HOP_SYSTEM_PROMPT = """
You are a security expert.

# Task

You should think from the perspective of a security engineer. Based on the last function in the call chain provided by the user (i.e., the current function), analyze the sink functions in the next hop and the next hops worth further exploration.

## sink

A sink function is defined as a function that meets the following conditions:

1. Functional requirements: The function performs file operations (read, write, delete) / command execution, with no further filtering internally. Only functions containing the aforementioned logic meet the Functional requirements. Some auxiliary methods, such as those used to generate paths/commands or to validate paths/commands, are not sink functions.
2. Data flow requirements: The path/command used by this function for its operation (which may be located in its parameters, member variables of the instance it belongs to, etc.) comes from source's user input.

For sink functions, they need to be labeled as `Sink(PathTraversal)` or `Sink(CommandInjection)` based on their type.

## Next Hop Functions Worth Exploring

A next hop function worth exploring is defined as a function that meets the following conditions:

1. Functional requirements: From a security engineer's perspective, these functions are worth further analysis to determine whether their internal logic contains the aforementioned sinks.

For next hop functions worth exploring, they need to be labeled as `Interest`.

## Output Format

You may analyze in any format, but the end of your output must include a summary in the following format:

```plaintext
--- function info start ---
<Called expression>
--- Separator ---
<Sink(PathTraversal) / Sink(CommandInjection) / Interest>
--- function info end ---

--- function info start ---
<Called expression>
--- Separator ---
<Sink(PathTraversal) / Sink(CommandInjection) / Interest>
--- function info end ---

...
```

# Steps

0. Clarify which function is the current function.
1. Disregarding data flow requirements, list all potential Sinks and Interests that are called as next hops by the current function and meet the functional requirements.
2. Analyze each of these potential Sinks individually to determine if they meet the data flow requirements.
3. Summarize and output the results according to the format above.

# Important Rules

* **Must be Next Hop**: For the call chain provided by the user, the Next Hop must be a function called by the current function. It is forbidden to provide any Sink or Interest function that is not a Next Hop!
* **Stop at Next Hop**: Your goal is to identify what the next hop is. Conducting a deeper analysis of the next hop is not your task. Therefore, you do not need to perform an in-depth analysis of the next hop at this stage. This means:
    a. If you believe a function performs file operations (read, write, delete) / command execution, but are unsure if it performs further filtering internally, you do not need to analyze further. You should directly label it as Interest.
    b. If you believe a function is worth examining in detail to see if their internal logic contains the aforementioned sinks, you do not need to confirm whether it actually does. Directly label it as Interest.
* **Data Flow Only**: The data flow requirement focuses only on the provenance of the data (i.e., from the source function's user input) and disregards any sanitization or filtering that may have been applied. You should faithfully analyze whether the data flow originates from source's user input. You do not need to concern yourself with whether security filtering occurred in the process; this is not your task.
* Any file operations (read, write, delete) / command execution implemented by code not in the current project (e.g., provided by dependencies) can be directly assumed to have no internal filtering and can be considered sink points if it satisfies the data flow requirements.
* Focus only on file operations (read, write, delete) / command execution. Do not concern yourself with other types of security risks.
* <Called expression> should be taken directly from the source code of the current function, starting with the function name, e.g., getValue(temp.getPath()).
* If the current node does not have any Sinks or Interests that meet the requirements, you do not need to return any function information in the summary.

# Restrictions

* You are prohibited from performing any write operations.
""".strip()


def next_hop_agent(target_path: str, call_chain: List[FunctionNode]) -> List[NextHopResult]:
    """
    Analyze the next hop functions from the current function in the call chain.

    This agent examines the current function (last in call_chain) to identify:
    a) Functions that are direct file/command operations with user-controlled input (Sink)
    b) Functions that may eventually lead to such operations (Interest)

    Args:
        target_path: Path to the target project's source code.
        call_chain: List of FunctionNodes representing the call chain from source
                   to current function. The last node is the current function to analyze.

    Returns:
        List of NextHopResult objects, each containing:
        - expression: The call expression (e.g., "readFile(userInput)")
        - tag: NodeTag indicating Sink(PathTraversal), Sink(CommandInjection), or Interest

    Example:
        >>> results = next_hop_agent("./project", [source_node, current_node])
        >>> for r in results:
        ...     print(f"{r.expression}: {r.tag.value}")
        'FileUtils.readFile(path): Sink(PathTraversal)'
        'processFile(content): Interest'
    """
    if not call_chain:
        print("[next_hop_agent] Empty call chain provided")
        return []

    current_function = call_chain[-1]
    print(f"[next_hop_agent] Analyzing function: {current_function.function_name}")
    print(f"[next_hop_agent] Call chain length: {len(call_chain)}")

    # Build user prompt with call chain status and node details
    call_chain_names = " -> ".join([node.function_name for node in call_chain])
    call_chain_section = f"# Call Chain\n{call_chain_names}\n\n"

    node_details = []
    for i, node in enumerate(call_chain):
        node_details.append(f"## Node {i + 1}: {node.function_name}")
        node_details.append(f"File: {node.file_path}")
        node_details.append(f"Source Code:\n```\n{node.source_code}\n```")
        node_details.append("")

    user_prompt = call_chain_section + "\n".join(node_details)

    # Execute agent
    result = base_claude_agent(
        cwd=target_path,
        system_prompt=_NEXT_HOP_SYSTEM_PROMPT,
        user_prompt=user_prompt
    )

    if result is None:
        print("[next_hop_agent] Agent returned no result")
        return []

    # Parse response
    function_info_list = _parse_function_info_sections(result)

    # Convert to NextHopResult objects
    next_hop_results = []
    for expression, tag_str in function_info_list:
        tag = _tag_string_to_enum(tag_str)
        if tag is not None:
            next_hop_results.append(NextHopResult(expression=expression, tag=tag))

    print(f"[next_hop_agent] Found {len(next_hop_results)} next hop(s)")

    return next_hop_results


# =============================================================================
# Interest Info Agent
# =============================================================================

def interest_info_agent(
    target_path: str,
    call_chain: List[FunctionNode],
    interest_expressions: List[str]
) -> List[NextHopInfo]:
    """
    Find the implementation details of interest-marked next hop functions.

    This agent locates the actual implementation of functions identified as
    "Interest" by next_hop_agent. For interface types, it finds all implementation
    classes that could be called in the current call context.

    Args:
        target_path: Path to the target project's source code.
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
        >>> infos = interest_info_agent("./project", [source_node], ["fileService.read(path)"])
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
