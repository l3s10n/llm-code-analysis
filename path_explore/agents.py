"""
Agent functions for vulnerability path discovery.

These functions encapsulate Claude Code SDK calls for specific analysis tasks.
Each agent performs a specialized code analysis task and returns structured results.
"""

import re
from typing import List, Optional

from common.base_claude_agent import base_claude_agent
from common.tui import log_info, log_success, log_error, update_agent, stream_agent, clear_stream
from common.agent_logger import log_agent_call

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


def _extract_function_name(expression: str) -> Optional[str]:
    """
    Extract function name from a call expression.

    Args:
        expression: A call expression (e.g., "readFile(userInput)" or "FileUtils.readFile(path)").

    Returns:
        The function name (part after the last "." before "(" if "." exists,
        otherwise the part before "("), or None if no "(" found.

    Example:
        >>> _extract_function_name("readFile(userInput)")
        'readFile'
        >>> _extract_function_name("FileUtils.readFile(path)")
        'readFile'
        >>> _extract_function_name("org.apache.commons.io.FileUtils.readFile(path)")
        'readFile'
        >>> _extract_function_name("noParens")
        None
    """
    if "(" not in expression:
        return None

    # Get the part before the first "("
    before_paren = expression.split("(")[0].strip()

    # If there's a ".", get the part after the last "."
    if "." in before_paren:
        return before_paren.split(".")[-1].strip()

    return before_paren


def _is_function_in_code(function_name: str, source_code: str) -> bool:
    """
    Check if a function name appears in the source code.

    Args:
        function_name: The function name to search for.
        source_code: The source code to search in.

    Returns:
        True if the function name is found in the source code, False otherwise.
    """
    if not function_name or not source_code:
        return False
    return function_name in source_code


def _build_user_prompt(call_chain: List[FunctionNode]) -> str:
    """
    Build user prompt with call chain status and node details.

    Args:
        call_chain: List of FunctionNodes representing the call chain.

    Returns:
        Formatted user prompt string.
    """
    # Build call chain names, mark last node as current function
    call_chain_names = []
    for i, node in enumerate(call_chain):
        if i == len(call_chain) - 1:
            call_chain_names.append(f"{node.function_name} (current function)")
        else:
            call_chain_names.append(node.function_name)
    call_chain_section = f"# Call Chain\n{' -> '.join(call_chain_names)}\n\n"

    node_details = []
    for i, node in enumerate(call_chain):
        # Mark last node as current function
        if i == len(call_chain) - 1:
            node_details.append(f"## Node {i + 1}: {node.function_name} (current function)")
        else:
            node_details.append(f"## Node {i + 1}: {node.function_name}")
        node_details.append(f"File: {node.file_path}")
        node_details.append(f"Source Code:\n```\n{node.source_code}\n```")
        node_details.append("")

    reminder = "\n\nThis context only includes the implementation code of functions within the call chain. If more information is required, it can be obtained by reading the file referenced by the File parameter."

    return call_chain_section + "\n".join(node_details) + reminder

def _parse_function_info_blocks(text: str) -> List[dict]:
    """
    Parse function info blocks from interest_info_find_agent response.

    Args:
        text: The agent response text.

    Returns:
        List of dictionaries with 'file_path', 'function_name', and 'source_code' keys.
    """
    results = []

    # Pattern to match function info blocks
    pattern = rf"{re.escape('--- function info start ---')}(.*?){re.escape('--- function info end ---')}"
    matches = re.findall(pattern, text, re.DOTALL)

    for match in matches:
        info = {}

        # Extract file path
        file_match = re.search(r'File:\s*(.+?)(?:\n|$)', match)
        if file_match:
            info['file_path'] = file_match.group(1).strip()

        # Extract function name
        func_match = re.search(r'Function:\s*(.+?)(?:\n|$)', match)
        if func_match:
            info['function_name'] = func_match.group(1).strip()

        # Extract source code
        code_match = re.search(r'--- code start ---\n(.*?)\n--- code end ---', match, re.DOTALL)
        if code_match:
            info['source_code'] = code_match.group(1)

        # Only add if all fields are present
        if 'file_path' in info and 'function_name' in info and 'source_code' in info:
            results.append(info)

    return results

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
* **Stop at Entry**: Please provide the information of the entry function directly, even if the entry function is very simple (e.g., it simply encapsulates certain Service layer functions, etc.). Do not provide the next-hop information.
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
    update_agent("source_info_find_agent", "running", f"Analyzing: {target_endpoint}")
    log_info("source_info_find_agent", f"Analyzing endpoint: {target_endpoint}")

    # Build prompts
    user_prompt = f"Interface name: {target_endpoint}"

    # Clear stream buffer and execute agent with streaming
    clear_stream()

    result = base_claude_agent(
        cwd=target_path,
        system_prompt=_SOURCE_INFO_SYSTEM_PROMPT,
        user_prompt=user_prompt,
        stream_callback=stream_agent
    )

    if result is None:
        update_agent("source_info_find_agent", "error", "Agent returned no result")
        log_error("source_info_find_agent", "Agent returned no result")
        # Log the failed call
        log_agent_call(
            agent_name="source_info_find_agent",
            user_prompt=user_prompt,
            model_output=None,
            parsed_result="None (agent returned no result)"
        )
        return None

    # Parse response
    file_path = _parse_marked_section(result, MARKER_FILE_PATH_START, MARKER_FILE_PATH_END)
    function_name = _parse_marked_section(result, MARKER_FUNCTION_NAME_START, MARKER_FUNCTION_NAME_END)
    function_code = _parse_marked_section(result, MARKER_FUNCTION_CODE_START, MARKER_FUNCTION_CODE_END)

    # Validate and return
    if not _is_valid_result([None, NOT_FOUND], file_path, function_name, function_code):
        update_agent("source_info_find_agent", "error", f"Failed to locate: {target_endpoint}")
        log_error("source_info_find_agent", f"Failed to locate endpoint: {target_endpoint}")
        # Log the failed call
        log_agent_call(
            agent_name="source_info_find_agent",
            user_prompt=user_prompt,
            model_output=result,
            parsed_result=f"None (validation failed - could not parse: file_path={file_path}, function_name={function_name})"
        )
        return None

    # Type assertions - we validated these are not None
    assert file_path is not None
    assert function_name is not None
    assert function_code is not None

    update_agent("source_info_find_agent", "completed", f"Found: {function_name}\nin {file_path}")
    log_success("source_info_find_agent", f"Found function: {function_name} in {file_path}")

    # Log the successful call
    source_info = SourceInfo(
        function_name=function_name,
        file_path=file_path,
        source_code=function_code
    )
    log_agent_call(
        agent_name="source_info_find_agent",
        user_prompt=user_prompt,
        model_output=result,
        parsed_result=f"SourceInfo(function_name={function_name}, file_path={file_path}, source_code=<{len(function_code)} chars>)"
    )

    return source_info


# =============================================================================
# Sink Next Hop Agent
# =============================================================================

# System prompt for sink discovery
_SINK_NEXT_HOP_SYSTEM_PROMPT = """
You are a security expert.

# Task

Based on the last function in the call chain provided by the user (i.e., the current function), analyze the sink functions in the next hop.

## Sink Function Definition

A sink function is defined as a function that meets the following conditions:

1. Basic requirements: The function must be the next hop of the current function.
2. Functional requirements: The function performs file operations (read, write, delete) / command execution. Only functions containing the aforementioned logic meet the Functional requirements. **Some auxiliary functions, such as those used to generate paths/commands or to validate paths/commands, are not sink functions**.
3. Origin requirements: The function must be implemented in an external dependency rather than within the current project. Only functions defined in third-party libraries or framework code (i.e., not implemented in the project's own source code) qualify as sink functions. Functions implemented locally within the project, even if they perform file operations (read, write, delete) / command execution, are excluded from consideration.
4. Data flow requirements: The path/command used by this function for its operation (which may be located in its parameters, member variables of the instance it belongs to, etc.) comes from source's user input.

For sink functions, they need to be labeled as `Sink(PathTraversal)` or `Sink(CommandInjection)` based on their type.

## Output Format

Analyze strictly according to the steps in the Steps section, the end of your output must include a summary in the following format:

```plaintext
--- function info start ---
<Called expression>
--- Separator ---
<Sink(PathTraversal) / Sink(CommandInjection)>
--- function info end ---

--- function info start ---
<Called expression>
--- Separator ---
<Sink(PathTraversal) / Sink(CommandInjection)>
--- function info end ---

...
```

# Steps

1. Clarify which function is the current function (last node in the call chain provided by user).
2. list all potential sink functions that are called as next hops by the current function.
3. Check whether these potential sink functions meet all the requirements:
   3.1 Basic requirements: Ensure the function currently being analyzed is the next hop of the current function.
   3.2 Functional requirements: Ensure the function performs file operations (read, write, delete) / command execution.
   3.3 Origin requirements: Ensure the sink function is not implemented in the current project. If the sink function is an interface called by the current function, analyze whether its implementation class is implemented in the current project.
   3.4 Data flow requirement: 
    a) Determine how the sink function specifies the paths/commands for its operation. 
    b) Whether the paths/commands come from the source's user input.
4. Summarize and output the results according to the format above.

# Important Rules

* **Must be Next Hop**: For the call chain provided by the user, the sink function must be a function called by the current function. It is forbidden to provide any sink function that is not a next hop!
* **Stop at Next Hop**: Your goal is to identify the sink function directly called by the current function. Do not analyze deeper into the next hop's code to find additional sink functions.
* **Data Flow Only**: The data flow requirement focuses only on the provenance of the data (i.e., from the source function's user input) and disregards any sanitization or filtering that may have been applied. You should faithfully analyze whether the data flow originates from source's user input. You do not need to concern yourself with whether security filtering occurred in the process; this is not your task.
* Focus only on file operations (read, write, delete) / command execution. Do not concern yourself with other types of security risks.
* <Called expression> should be taken directly from the source code of the current function, starting with the function name, e.g., getValue(temp.getPath()).
* If the current node does not have any Sinks that meet the requirements, do not return `--- function info start ---` or `--- function info end ---`.

# Restrictions

* You are prohibited from performing any write operations.
""".strip()


def sink_next_hop_agent(target_path: str, call_chain: List[FunctionNode]) -> List[NextHopResult]:
    """
    Find sink functions in the next hop of the current function.

    This agent examines the current function (last in call_chain) to identify
    sink functions that perform file/command operations with user-controlled input.

    Args:
        target_path: Path to the target project's source code.
        call_chain: List of FunctionNodes representing the call chain from source
                   to current function. The last node is the current function to analyze.

    Returns:
        List of NextHopResult objects containing:
        - expression: The call expression (e.g., "readFile(userInput)")
        - tag: NodeTag indicating Sink(PathTraversal) or Sink(CommandInjection)

    Note:
        Results are filtered to only include functions whose names appear in
        the current function's source code.
    """
    if not call_chain:
        log_error("sink_next_hop_agent", "Empty call chain provided")
        return []

    current_function = call_chain[-1]
    update_agent("sink_next_hop_agent", "running", f"Finding sinks in: {current_function.function_name}")
    log_info("sink_next_hop_agent", f"Analyzing function: {current_function.function_name}")

    # Build user prompt
    user_prompt = _build_user_prompt(call_chain)

    # Clear stream buffer and execute agent with streaming
    clear_stream()

    result = base_claude_agent(
        cwd=target_path,
        system_prompt=_SINK_NEXT_HOP_SYSTEM_PROMPT,
        user_prompt=user_prompt,
        stream_callback=stream_agent
    )

    if result is None:
        update_agent("sink_next_hop_agent", "error", "Agent returned no result")
        log_error("sink_next_hop_agent", "Agent returned no result")
        # Log the failed call
        log_agent_call(
            agent_name="sink_next_hop_agent",
            user_prompt=user_prompt,
            model_output=None,
            parsed_result="[] (agent returned no result)"
        )
        return []

    # Parse response
    function_info_list = _parse_function_info_sections(result)

    # Convert to NextHopResult objects and filter by code presence
    sink_results = []
    for expression, tag_str in function_info_list:
        tag = _tag_string_to_enum(tag_str)
        if tag is not None:
            # Extract function name and check if it exists in current function's code
            function_name = _extract_function_name(expression)
            if function_name and _is_function_in_code(function_name, current_function.source_code):
                sink_results.append(NextHopResult(expression=expression, tag=tag))

    update_agent("sink_next_hop_agent", "completed", f"Found {len(sink_results)} sink(s)")
    log_success("sink_next_hop_agent", f"Found {len(sink_results)} sink(s)")

    # Log the call
    parsed_result_str = str([f"NextHopResult(expression={r.expression}, tag={r.tag.value})" for r in sink_results])
    log_agent_call(
        agent_name="sink_next_hop_agent",
        user_prompt=user_prompt,
        model_output=result,
        parsed_result=parsed_result_str
    )

    return sink_results


# =============================================================================
# Interest Next Hop Agent
# =============================================================================

# System prompt for interest discovery
_INTEREST_NEXT_HOP_SYSTEM_PROMPT = """
You are a security expert.

# Task

Your task is to analyze the next hop functions based on the last function in the call chain provided by the user (i.e., the current function), and determine which ones are worth further exploration as interest functions in the current project.

Interest functions are those that:

1. Basic requirements: The next hop called by the current function.
2. Inspection requirements: during security auditing, are worth deeply exploring their internal implementations to see if they call any sink functions.
3. Origin requirements: Must be implemented within the current project, not sourced from dependencies.

## Sink Function Definition

A sink function is defined as a function that meets the following conditions:

1. The function performs file operations (read, write, delete) / command execution, with no further filtering internally. Only functions containing the aforementioned logic meet the Functional requirements. **Some auxiliary methods, such as those used to generate paths/commands or to validate paths/commands, are not sink functions**.
2. The path/command used by this function for its operation (which may be located in its parameters, member variables of the instance it belongs to, etc.) comes from source's user input.

## Output Format

Analyze strictly according to the steps in the Steps section, the end of your output must include a summary in the following format:

```plaintext
--- function info start ---
<Called expression>
--- Separator ---
Interest
--- function info end ---

--- function info start ---
<Called expression>
--- Separator ---
Interest
--- function info end ---

...
```

# Steps

0. Clarify which function is the current function (last node in the call chain provided by user).
1. list all potential interest functions that are called as next hops by the current function.
2. Check whether these potential interest functions meet all the requirements:
   2.1 Basic requirements: Ensure the function currently being analyzed is the next hop of the current function.
   2.2 Inspection requirements:
    a) Exclude any functions that have been explicitly excluded by the user (provided in the exclusion list)
    b) Exclude any functions that are unlikely to further call sink methods
    c) Keep those that may further call sink methods (including uncertain ones).
   2.3 Origin requirements: Ensure the interest function is implemented in the current project. If the interest function is an interface called by the current function, analyze whether its implementation class is implemented in the current project. (Do not conduct in-depth analysis of the logic inside the interest function!!!—that is not your task.)
3. Summarize and output the results according to the format above.

# Important Rules

* **Must be Next Hop**: For the call chain provided by the user, the interest function must be a function called by the current function. It is forbidden to provide any interest function that is not a next hop!
* **Stop at Next Hop**: Your goal is to identify the interest function directly called by the current function. Do not analyze deeper into the next hop's code to find additional interest functions or verify whether a particular interest function actually calls a sink method.
* Focus only on file operations (read, write, delete) / command execution. Do not concern yourself with other types of security risks.
* <Called expression> should be taken directly from the source code of the current function, starting with the function name, e.g., getValue(temp.getPath()).
* If the current node does not have any interest methods that meet the requirements, do not return `--- function info start ---` or `--- function info end ---`.

# Restrictions

* You are prohibited from performing any write operations.
""".strip()


def interest_next_hop_agent(
    target_path: str,
    call_chain: List[FunctionNode],
    sink_function_names: List[str]
) -> List[NextHopResult]:
    """
    Find interest functions in the next hop of the current function.

    This agent examines the current function (last in call_chain) to identify
    functions worth further exploration that are NOT already identified as sinks.

    Args:
        target_path: Path to the target project's source code.
        call_chain: List of FunctionNodes representing the call chain from source
                   to current function. The last node is the current function to analyze.
        sink_function_names: List of function names that have already been identified as sinks.
                           These will be excluded from the interest results.

    Returns:
        List of NextHopResult objects containing:
        - expression: The call expression (e.g., "processFile(content)")
        - tag: NodeTag.INTEREST
    """
    if not call_chain:
        log_error("interest_next_hop_agent", "Empty call chain provided")
        return []

    current_function = call_chain[-1]
    update_agent("interest_next_hop_agent", "running", f"Finding interests in: {current_function.function_name}")
    log_info("interest_next_hop_agent", f"Analyzing function: {current_function.function_name}")

    # Build user prompt with sink exclusion info
    base_prompt = _build_user_prompt(call_chain)

    # Add sink function exclusion information
    if sink_function_names:
        sink_info = f"\n# Functions to Exclude\nThe following functions must NOT be included in your results:\n"
        for name in sink_function_names:
            sink_info += f"- {name}\n"
        user_prompt = base_prompt + sink_info
    else:
        user_prompt = base_prompt

    # Clear stream buffer and execute agent with streaming
    clear_stream()

    result = base_claude_agent(
        cwd=target_path,
        system_prompt=_INTEREST_NEXT_HOP_SYSTEM_PROMPT,
        user_prompt=user_prompt,
        stream_callback=stream_agent
    )

    if result is None:
        update_agent("interest_next_hop_agent", "error", "Agent returned no result")
        log_error("interest_next_hop_agent", "Agent returned no result")
        # Log the failed call
        log_agent_call(
            agent_name="interest_next_hop_agent",
            user_prompt=user_prompt,
            model_output=None,
            parsed_result="[] (agent returned no result)"
        )
        return []

    # Parse response
    function_info_list = _parse_function_info_sections(result)

    # Convert to NextHopResult objects and filter by code presence
    interest_results = []
    for expression, tag_str in function_info_list:
        tag = _tag_string_to_enum(tag_str)
        if tag == NodeTag.INTEREST:
            # Extract function name
            function_name = _extract_function_name(expression)

            # Check if function exists in current function's code
            if not function_name or not _is_function_in_code(function_name, current_function.source_code):
                continue

            # Check if function is already identified as a sink
            if function_name in sink_function_names:
                continue

            interest_results.append(NextHopResult(expression=expression, tag=tag))

    update_agent("interest_next_hop_agent", "completed", f"Found {len(interest_results)} interest(s)")
    log_success("interest_next_hop_agent", f"Found {len(interest_results)} interest function(s)")

    # Log the call
    parsed_result_str = str([f"NextHopResult(expression={r.expression}, tag={r.tag.value})" for r in interest_results])
    log_agent_call(
        agent_name="interest_next_hop_agent",
        user_prompt=user_prompt,
        model_output=result,
        parsed_result=parsed_result_str
    )

    return interest_results


# =============================================================================
# Next Hop Agent (Public Interface)
# =============================================================================

def next_hop_agent(target_path: str, call_chain: List[FunctionNode]) -> List[NextHopResult]:
    """
    Analyze the next hop functions from the current function in the call chain.

    This function internally calls sink_next_hop_agent first to find sink functions,
    then calls interest_next_hop_agent to find interest functions (excluding sinks).

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
        log_error("next_hop_agent", "Empty call chain provided")
        return []

    current_function = call_chain[-1]
    log_info("next_hop_agent", f"Analyzing: {current_function.function_name}")

    # Step 1: Find sink functions
    sink_results = sink_next_hop_agent(target_path, call_chain)

    # Step 2: Extract sink function names for exclusion
    sink_function_names = []
    for result in sink_results:
        function_name = _extract_function_name(result.expression)
        if function_name:
            sink_function_names.append(function_name)

    # Step 3: Find interest functions (excluding sinks)
    interest_results = interest_next_hop_agent(target_path, call_chain, sink_function_names)

    # Combine results
    all_results = sink_results + interest_results

    log_success("next_hop_agent", f"Total: {len(all_results)} ({len(sink_results)} sinks, {len(interest_results)} interests)")

    return all_results


# =============================================================================
# Interest Info Find Agent
# =============================================================================

# System prompt for next hop info discovery
_INTEREST_INFO_FIND_SYSTEM_PROMPT = """
You are a code analysis expert.

# Task

Based on the call chain and next hop expressions provided by the user, locate the implementation of each next hop function. For each function, provide its file path, function name, and source code.

## Key Concepts

* **Call Chain**: A list of functions from source to current function. The LAST node in the call chain is the **current function**.
* **Next Hop**: A function that is directly called by the current function. The next hop expressions provided by the user are extracted from the current function's source code.
* **Your Goal**: Find the implementation of these next hop functions.

## Output Format

You may analyze in any format, but the end of your output must include a summary in the following format for EACH function found:

```plaintext
--- function info start ---
File: <file path>
Function: <function name>
--- code start ---
<function code>
--- code end ---
--- function info end ---

--- function info start ---
File: <file path>
Function: <function name>
--- code start ---
<function code>
--- code end ---
--- function info end ---

...
```

# Important Rules

* **Resolve to Implementation**: If a next hop function is called through an interface or abstract class, you must find its actual implementation class(es). Do NOT return interface definitions - only return concrete implementations.
* **Context-Aware Implementation Resolution**: When multiple implementations of an interface exist, analyze the current call chain context to determine which implementation(s) could actually be invoked. Only return implementations that could be reached in this specific call context, NOT all implementations globally.
* **Multiple Implementations**: If multiple implementations could be invoked in the current context, return all of them (one function info block per implementation).
* <file path> should be a relative path based on the project root directory.
* <function name> should only contain the function name, excluding parameters and return values, for example: "readFile".
* <function code> should be directly excerpted from the source file, including and only including the code of that function.
* If there are comments above the function, they must be preserved.
* If a function implementation cannot be found, do not output a function info block for that function.

# Restrictions

* You are prohibited from performing any write operations.
""".strip()

def interest_info_find_agent(
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
        >>> infos = interest_info_find_agent("./project", [source_node], ["fileService.read(path)"])
        >>> for info in infos:
        ...     print(f"{info.function_name} in {info.file_path}")
        'read in ./services/FileServiceImpl.java'
        'read in ./services/SafeFileServiceImpl.java'
    """
    if not call_chain or not interest_expressions:
        log_error("interest_info_find_agent", "Empty call chain or expressions provided")
        return []

    current_function = call_chain[-1]
    update_agent("interest_info_find_agent", "running", f"Finding {len(interest_expressions)} impl(s)")
    log_info("interest_info_find_agent", f"Finding implementations for {len(interest_expressions)} function(s)")

    # Build user prompt with call chain and next hop expressions
    base_prompt = _build_user_prompt(call_chain)

    # Add next hop expressions to find
    next_hop_section = "\n# Next Hops to Find\nThe following expressions are next hop functions called by the current function. Please find their implementations:\n"
    for i, expr in enumerate(interest_expressions, 1):
        next_hop_section += f"{i}. {expr}\n"

    user_prompt = base_prompt + next_hop_section

    # Clear stream buffer and execute agent with streaming
    clear_stream()

    result = base_claude_agent(
        cwd=target_path,
        system_prompt=_INTEREST_INFO_FIND_SYSTEM_PROMPT,
        user_prompt=user_prompt,
        stream_callback=stream_agent
    )

    if result is None:
        update_agent("interest_info_find_agent", "error", "Agent returned no result")
        log_error("interest_info_find_agent", "Agent returned no result")
        # Log the failed call
        log_agent_call(
            agent_name="interest_info_find_agent",
            user_prompt=user_prompt,
            model_output=None,
            parsed_result="[] (agent returned no result)"
        )
        return []

    # Parse response
    function_infos = _parse_function_info_blocks(result)

    # Convert to NextHopInfo objects
    next_hop_infos = []
    for info in function_infos:
        next_hop_infos.append(NextHopInfo(
            function_name=info['function_name'],
            file_path=info['file_path'],
            source_code=info['source_code']
        ))

    update_agent("interest_info_find_agent", "completed", f"Found {len(next_hop_infos)} impl(s)")
    log_success("interest_info_find_agent", f"Found {len(next_hop_infos)} implementation(s)")

    # Log the call
    parsed_result_str = str([f"NextHopInfo(function_name={i.function_name}, file_path={i.file_path}, source_code=<{len(i.source_code)} chars>)" for i in next_hop_infos])
    log_agent_call(
        agent_name="interest_info_find_agent",
        user_prompt=user_prompt,
        model_output=result,
        parsed_result=parsed_result_str
    )

    return next_hop_infos
