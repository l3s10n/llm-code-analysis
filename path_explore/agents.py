"""
Agent functions for vulnerability path discovery.

These functions encapsulate Claude Code SDK calls for specific analysis tasks.
Each agent performs a specialized code analysis task and returns structured results.
"""

import re
import sys
from typing import List, Optional

from common.base_claude_agent import base_claude_agent, AgentResult
from common.tui import clear_stream, log_error, log_info, log_success, stream_agent, update_agent
from common.agent_logger import log_agent_call

from .models import InterestInfo, NodeTag, SinkInfo
from .utils import read_source_code_by_range


# =============================================================================
# Constants
# =============================================================================

MARKER_FILE_PATH_START = "--- file path result start ---"
MARKER_FILE_PATH_END = "--- file path result end ---"
MARKER_FUNCTION_NAME_START = "--- function name start ---"
MARKER_FUNCTION_NAME_END = "--- function name end ---"
MARKER_START_LINE_START = "--- start line start ---"
MARKER_START_LINE_END = "--- start line end ---"
MARKER_END_LINE_START = "--- end line start ---"
MARKER_END_LINE_END = "--- end line end ---"

MARKER_INTEREST_INFO_START = "--- interest info start ---"
MARKER_INTEREST_INFO_END = "--- interest info end ---"
MARKER_SINK_INFO_START = "--- sink info start ---"
MARKER_SINK_INFO_END = "--- sink info end ---"

NOT_FOUND = "Not Found"

_SINK_TYPE_TO_TAG = {
    "PathTraversal": NodeTag.SINK_PATH_TRAVERSAL,
    "CommandInjection": NodeTag.SINK_COMMAND_INJECTION,
    "CodeInjection": NodeTag.SINK_CODE_INJECTION,
    "SQLInjection": NodeTag.SINK_SQL_INJECTION,
    "SSRF": NodeTag.SINK_SSRF,
}


# =============================================================================
# Helper Functions
# =============================================================================

def _handle_agent_failure(agent_result: AgentResult, agent_name: str) -> None:
    """
    Handle agent execution failure by creating error file and exiting.

    This function is called when base_claude_agent fails after all retries.
    It creates an error file, prints the error message and exits the program.

    Args:
        agent_result: The failed AgentResult containing error details
        agent_name: Name of the agent that failed (for logging)
    """

    from common.tui import emit_output, stop_tui
    from common.agent_logger import close_logger
    from common.base_claude_agent import create_error_file

    stop_tui()
    close_logger()

    error_file_path = create_error_file(agent_name, agent_result)

    emit_output(
        f"[Error] Agent '{agent_name}' failed: {agent_result.error_message}",
        source=agent_name,
        level="ERROR",
    )
    emit_output(
        f"[Error] Error file created at: {error_file_path}",
        source=agent_name,
        level="ERROR",
    )
    sys.exit(1)


def _parse_marked_section(text: str, start_marker: str, end_marker: str) -> Optional[str]:
    """
    Extract content between two markers from text.

    Args:
        text: The text to search in.
        start_marker: The start marker pattern.
        end_marker: The end marker pattern.

    Returns:
        The extracted content stripped of leading/trailing whitespace,
        or None if markers are not found.
    """

    pattern = rf"{re.escape(start_marker)}\n(.*?)\n{re.escape(end_marker)}"
    match = re.search(pattern, text, re.DOTALL)
    return match.group(1).strip() if match else None


def _parse_line_number(value: Optional[str]) -> Optional[int]:
    """
    Parse a line number from string.

    Args:
        value: Raw line number text

    Returns:
        Integer line number, or None if parsing fails
    """

    if value is None:
        return None

    try:
        line = int(value.strip())
    except ValueError:
        return None

    return line if line > 0 else None


def _extract_function_name(expression: str) -> Optional[str]:
    """
    Extract function name from a call expression.

    Args:
        expression: A call expression (e.g., "readFile(userInput)")

    Returns:
        The function name, or None if the expression cannot be parsed
    """

    if "(" not in expression:
        return None

    before_paren = expression.split("(", 1)[0].strip()
    if "." in before_paren:
        return before_paren.split(".")[-1].strip()
    return before_paren


def _is_expression_in_code(expression: str, source_code: str) -> bool:
    """
    Check whether a next-hop expression is present in the current function code.

    Args:
        expression: Next-hop expression returned by the agent
        source_code: Source code of the current function

    Returns:
        True if the expression or its function name appears in the code
    """

    if not source_code or not expression:
        return False

    if expression in source_code:
        return True

    function_name = _extract_function_name(expression)
    return bool(function_name and function_name in source_code)


def _is_function_name_in_code(function_name: str, source_code: str) -> bool:
    """
    Check whether a function name appears in the current function code.

    Args:
        function_name: Candidate function name
        source_code: Source code of the current function

    Returns:
        True if the function name appears in the code, False otherwise
    """

    return bool(function_name and source_code and function_name in source_code)


def _has_readable_source_code(target_path: str, info: InterestInfo) -> bool:
    """
    Check whether InterestInfo points to readable source code.

    Args:
        target_path: Path to the target project's source code
        info: InterestInfo to validate

    Returns:
        True if the file can be read and the requested line range yields code
    """

    try:
        source_code = read_source_code_by_range(
            target_path=target_path,
            file_path=info.file_path,
            start_line=info.start_line,
            end_line=info.end_line,
        )
    except OSError:
        return False

    return bool(source_code.strip())


def _parse_interest_blocks(text: str) -> List[InterestInfo]:
    """
    Parse InterestInfo blocks from model output.

    Args:
        text: Model output text

    Returns:
        List of InterestInfo objects
    """

    pattern = rf"{re.escape(MARKER_INTEREST_INFO_START)}\n(.*?)\n{re.escape(MARKER_INTEREST_INFO_END)}"
    matches = re.findall(pattern, text, re.DOTALL)

    interests: List[InterestInfo] = []
    for block in matches:
        file_path_match = re.search(r"^File:\s*(.+)$", block, re.MULTILINE)
        function_name_match = re.search(r"^Function:\s*(.+)$", block, re.MULTILINE)
        start_line_match = re.search(r"^Start Line:\s*(.+)$", block, re.MULTILINE)
        end_line_match = re.search(r"^End Line:\s*(.+)$", block, re.MULTILINE)

        file_path = file_path_match.group(1).strip() if file_path_match else None
        function_name = function_name_match.group(1).strip() if function_name_match else None
        start_line = _parse_line_number(start_line_match.group(1) if start_line_match else None)
        end_line = _parse_line_number(end_line_match.group(1) if end_line_match else None)

        if not file_path or not function_name or start_line is None or end_line is None:
            continue

        interests.append(
            InterestInfo(
                function_name=function_name,
                file_path=file_path,
                start_line=start_line,
                end_line=end_line,
            )
        )

    return interests


def _parse_sink_blocks(text: str) -> List[tuple[NodeTag, SinkInfo]]:
    """
    Parse sink blocks from model output.

    Args:
        text: Model output text

    Returns:
        List of (NodeTag, SinkInfo) tuples
    """

    pattern = rf"{re.escape(MARKER_SINK_INFO_START)}\n(.*?)\n{re.escape(MARKER_SINK_INFO_END)}"
    matches = re.findall(pattern, text, re.DOTALL)

    sinks: List[tuple[NodeTag, SinkInfo]] = []
    for block in matches:
        type_match = re.search(r"^Type:\s*(.+)$", block, re.MULTILINE)
        expression_match = re.search(r"^Expression:\s*(.+)$", block, re.MULTILINE)

        sink_type = type_match.group(1).strip() if type_match else None
        sink_expression = expression_match.group(1).strip() if expression_match else None
        tag = _SINK_TYPE_TO_TAG.get(sink_type or "")

        if tag is None or not sink_expression:
            continue

        sinks.append((tag, SinkInfo(sink_expression=sink_expression)))

    return sinks


def _deduplicate_interest_infos(interest_infos: List[InterestInfo]) -> List[InterestInfo]:
    """
    Deduplicate InterestInfo objects by exact file path and line range.

    Args:
        interest_infos: InterestInfo list to deduplicate

    Returns:
        Deduplicated InterestInfo list preserving original order
    """

    unique: List[InterestInfo] = []
    for info in interest_infos:
        exists = False
        for existing in unique:
            if (
                existing.file_path == info.file_path
                and max(existing.start_line, info.start_line) <= min(existing.end_line, info.end_line)
            ):
                exists = True
                break
        if not exists:
            unique.append(info)
    return unique


def _deduplicate_sinks(sinks: List[tuple[NodeTag, SinkInfo]]) -> List[tuple[NodeTag, SinkInfo]]:
    """
    Deduplicate sinks by tag and expression.

    Args:
        sinks: Sink list to deduplicate

    Returns:
        Deduplicated sink list preserving original order
    """

    unique: List[tuple[NodeTag, SinkInfo]] = []
    seen: set[tuple[str, str]] = set()
    for tag, sink_info in sinks:
        key = (tag.value, sink_info.sink_expression)
        if key in seen:
            continue
        seen.add(key)
        unique.append((tag, sink_info))
    return unique


# =============================================================================
# Source Info Find Agent
# =============================================================================

_SOURCE_INFO_SYSTEM_PROMPT = """
You are a code analysis expert.

# Task

Analyze the current project. Based on the interface name provided by the user, locate the entry function's concrete implementation and return its exact file path, function name, start line, and end line.

# Output Format

At the end of your response, provide a summary in the following format:

```plaintext
--- file path result start ---
<relative file path>
--- file path result end ---

--- function name start ---
<function name>
--- function name end ---

--- start line start ---
<start line>
--- start line end ---

--- end line start ---
<end line>
--- end line end ---
```

# Important Rules

* **Resolve to Concrete Implementation**: The returned entry function must have real code implementation. If framework routing binds to an interface or abstract class, resolve to the concrete implementation actually serving the endpoint.
* **Stop at Entry**: Return only the entry function itself. Do not provide next-hop information.
* <relative file path> must be relative to the project root.
* <function name> should only contain the function name, excluding parameters and return values.
* <start line> and <end line> must point to the concrete function implementation in the file.
* If there are comments immediately above the function and they belong to the function declaration, include them in the line range.
* If not found, write "Not Found" for all fields.

# Restrictions

* You are prohibited from performing any write operations.
""".strip()


def source_info_find_agent(target_path: str, target_endpoint: str) -> Optional[InterestInfo]:
    """
    Find the source function information for a given API endpoint.

    Args:
        target_path: Path to the target project's source code.
        target_endpoint: The API endpoint to analyze.

    Returns:
        InterestInfo describing the concrete entry implementation,
        or None if the endpoint cannot be found.
    """

    update_agent("source_info_find_agent", "running", f"Analyzing: {target_endpoint}")
    log_info("source_info_find_agent", f"Analyzing endpoint: {target_endpoint}")

    user_prompt = f"Interface name: {target_endpoint}"

    clear_stream()

    agent_result = base_claude_agent(
        cwd=target_path,
        system_prompt=_SOURCE_INFO_SYSTEM_PROMPT,
        user_prompt=user_prompt,
        stream_callback=stream_agent,
    )

    if not agent_result.success:
        _handle_agent_failure(agent_result, "source_info_find_agent")

    result = agent_result.result

    file_path = _parse_marked_section(result, MARKER_FILE_PATH_START, MARKER_FILE_PATH_END)
    function_name = _parse_marked_section(result, MARKER_FUNCTION_NAME_START, MARKER_FUNCTION_NAME_END)
    start_line = _parse_line_number(_parse_marked_section(result, MARKER_START_LINE_START, MARKER_START_LINE_END))
    end_line = _parse_line_number(_parse_marked_section(result, MARKER_END_LINE_START, MARKER_END_LINE_END))

    if (
        file_path in (None, NOT_FOUND)
        or function_name in (None, NOT_FOUND)
        or start_line is None
        or end_line is None
        or end_line < start_line
    ):
        update_agent("source_info_find_agent", "error", f"Failed to locate: {target_endpoint}")
        log_error("source_info_find_agent", f"Failed to locate endpoint: {target_endpoint}")
        log_agent_call(
            agent_name="source_info_find_agent",
            user_prompt=user_prompt,
            model_output=result,
            parsed_result=(
                "None (validation failed - could not parse: "
                f"file_path={file_path}, function_name={function_name}, "
                f"start_line={start_line}, end_line={end_line})"
            ),
        )
        return None

    assert file_path is not None
    assert function_name is not None

    source_info = InterestInfo(
        function_name=function_name,
        file_path=file_path,
        start_line=start_line,
        end_line=end_line,
    )

    if not _has_readable_source_code(target_path, source_info):
        update_agent("source_info_find_agent", "error", f"Unreadable result: {target_endpoint}")
        log_error(
            "source_info_find_agent",
            (
                "Failed to validate endpoint result: "
                f"{file_path}:{start_line}-{end_line} cannot be read as concrete source code"
            ),
        )
        log_agent_call(
            agent_name="source_info_find_agent",
            user_prompt=user_prompt,
            model_output=result,
            parsed_result=(
                "None (validation failed - unreadable source range: "
                f"{file_path}:{start_line}-{end_line})"
            ),
        )
        return None

    update_agent(
        "source_info_find_agent",
        "completed",
        f"Found: {function_name}\nin {file_path}:{start_line}-{end_line}",
    )
    log_success(
        "source_info_find_agent",
        f"Found function: {function_name} in {file_path}:{start_line}-{end_line}",
    )

    log_agent_call(
        agent_name="source_info_find_agent",
        user_prompt=user_prompt,
        model_output=result,
        parsed_result=(
            f"InterestInfo(function_name={function_name}, file_path={file_path}, "
            f"start_line={start_line}, end_line={end_line})"
        ),
    )

    return source_info


# =============================================================================
# Next Hop Info Find Agent
# =============================================================================

_NEXT_HOP_INFO_FIND_SYSTEM_PROMPT = """
You are a security code analysis expert.

# Task

Analyze the current function (the last function in the call chain provided by the user) and identify direct next-hop nodes that should be treated as either sink nodes or interest nodes.

There may be zero, one, or multiple valid sink nodes and interest nodes.

# Sink Node Definition

A sink node must satisfy all of the following:

1. It is a direct next-hop call made by the current function.
2. **It is NOT implemented in the current project.** (IMPORTANT)
3. It directly performs one of the following categories of operation:
   - file path based file operation, only care about file creation, deletion, reading, and writing operations
   - command execution
   - code execution
   - SQL query execution
   - outbound HTTP request / URL request
4. Functions that only construct, transform, validate, normalize, parse, or inspect the file path, command, code, SQL, or request target are not sink nodes unless they directly execute one of the sink operations listed above.
5. The file path, command, code, SQL, or request target is not a compile-time constant. For SQL execution, exclude queries whose structure is fixed and whose inputs are supplied only through parameter binding or precompiled placeholders (for example, prepared statements or MyBatis `#{}`).

# Interest Node Definition

An interest node must satisfy all of the following:

1. It is a direct next-hop call made by the current function.
2. **It has a concrete implementation inside the current project.** (IMPORTANT)
3. Its implementation is a meaningful next exploration target for sink discovery: it may directly or indirectly reach sink functions.
4. Apply the following filtering rules:
  a) Be selective: return only high-value direct callees for further sink discovery, and avoid low-signal or marginal candidates.
  b) Exclude functions that are clearly unlikely to lead to sink calls, including logging, metrics, simple getters/setters, pure formatting, trivial validation, simple data mapping, and other obviously side-effect-free helpers.
  c) Keep functions that are clearly likely to perform sink-related operations, or whose internal logic appears non-trivial and therefore worth exploring for possible sink calls.

# Important Rules

* **Direct Next Hop Only**: Return only functions directly called by the current function. Do not go deeper.
* **Sink Must Be Out-of-Project**: Every sink node must not be implemented inside the current project.
* **Interest Must Be In-Project**: Every interest node must have concrete code inside the current project.
* **No Extra Security Reasoning**: Do not judge exploitability, sanitization, validation, filtering, or whether user input reaches the sink.
* **Avoid Reading Earlier Chain Functions Unless Necessary**: Normally, do not read functions earlier than the current function in the call chain.
* **Special Case - Interface / Abstract Dispatch Resolution**:
  - Only when the current function calls an interface method or abstract method that should be returned as an interest node, you may read earlier functions in the call chain.
  - Use those earlier functions only to resolve which concrete implementation(s) are actually invoked on this specific chain. Do not blindly return all implementations of an interface.
* **Expression Fidelity**: Sink expressions must be taken directly from the current function code, starting from the called function name.
* **Line Precision**: For each interest node, return the exact file path and exact start/end line of the concrete implementation.

# Output Format

At the end of your response, provide the results in the following format:

```plaintext
--- interest info start ---
File: <relative file path>
Function: <function name>
Start Line: <start line>
End Line: <end line>
--- interest info end ---

--- sink info start ---
Type: <PathTraversal / CommandInjection / CodeInjection / SQLInjection / SSRF>
Expression: <called expression>
--- sink info end ---
```

Output one block per result.
If there are multiple sink nodes, output multiple `--- sink info start ---` blocks.
If there are multiple interest nodes, output multiple `--- interest info start ---` blocks.
If there are no sink nodes, do not output any `--- sink info start ---` block.
If there are no interest nodes, do not output any `--- interest info start ---` block.

# Restrictions

* You are prohibited from performing any write operations.
""".strip()


def next_hop_info_find_agent(
    target_path: str,
    call_chain: List[InterestInfo],
) -> tuple[List[InterestInfo], List[tuple[NodeTag, SinkInfo]]]:
    """
    Find next-hop interest and sink nodes for the current function.

    Args:
        target_path: Path to the target project's source code.
        call_chain: InterestInfo list representing the current call chain.

    Returns:
        A tuple of:
        - InterestInfo list for in-project concrete next-hop functions
        - (NodeTag, SinkInfo) list for out-of-project sink calls
    """

    if not call_chain:
        log_error("next_hop_info_find_agent", "Empty call chain provided")
        return [], []

    current_info = call_chain[-1]
    current_source_code = read_source_code_by_range(
        target_path=target_path,
        file_path=current_info.file_path,
        start_line=current_info.start_line,
        end_line=current_info.end_line,
    )

    update_agent(
        "next_hop_info_find_agent",
        "running",
        f"Analyzing: {current_info.function_name}",
    )
    log_info(
        "next_hop_info_find_agent",
        f"Analyzing function: {current_info.function_name}",
    )

    chain_lines = []
    for index, info in enumerate(call_chain):
        suffix = " (current function)" if index == len(call_chain) - 1 else ""
        chain_lines.append(
            f"[{index}] {info.function_name}{suffix} | {info.file_path}:{info.start_line}-{info.end_line}"
        )

    user_prompt = f"""# Call Chain
{chr(10).join(chain_lines)}

# Current Function
Function: {current_info.function_name}
File: {current_info.file_path}
Lines: {current_info.start_line}-{current_info.end_line}
Source Code:
```
{current_source_code}
```

# Reminder
Normally, only analyze the current function and the files needed to resolve its direct next-hop calls.
Only read earlier functions in the call chain if you must precisely resolve an interface or abstract dispatch to the concrete implementation(s) used on this specific chain.
"""

    clear_stream()

    agent_result = base_claude_agent(
        cwd=target_path,
        system_prompt=_NEXT_HOP_INFO_FIND_SYSTEM_PROMPT,
        user_prompt=user_prompt,
        stream_callback=stream_agent,
    )

    if not agent_result.success:
        _handle_agent_failure(agent_result, "next_hop_info_find_agent")

    result = agent_result.result

    interest_infos = _parse_interest_blocks(result)
    interest_infos = [
        info for info in interest_infos
        if (
            info.file_path
            and info.function_name
            and info.start_line > 0
            and info.end_line >= info.start_line
            and _is_function_name_in_code(info.function_name, current_source_code)
            and _has_readable_source_code(target_path, info)
        )
    ]
    interest_infos = _deduplicate_interest_infos(interest_infos)

    sink_infos = _parse_sink_blocks(result)
    sink_infos = [
        (tag, sink_info)
        for tag, sink_info in sink_infos
        if _is_expression_in_code(sink_info.sink_expression, current_source_code)
    ]
    sink_infos = _deduplicate_sinks(sink_infos)

    update_agent(
        "next_hop_info_find_agent",
        "completed",
        f"Found {len(interest_infos)} interest(s), {len(sink_infos)} sink(s)",
    )
    log_success(
        "next_hop_info_find_agent",
        f"Found {len(interest_infos)} interest(s) and {len(sink_infos)} sink(s)",
    )

    parsed_interest = [
        (
            f"InterestInfo(function_name={info.function_name}, file_path={info.file_path}, "
            f"start_line={info.start_line}, end_line={info.end_line})"
        )
        for info in interest_infos
    ]
    parsed_sinks = [
        f"SinkInfo(tag={tag.value}, sink_expression={sink_info.sink_expression})"
        for tag, sink_info in sink_infos
    ]
    parsed_result_str = f"interests={parsed_interest}, sinks={parsed_sinks}"

    log_agent_call(
        agent_name="next_hop_info_find_agent",
        user_prompt=user_prompt,
        model_output=result,
        parsed_result=parsed_result_str,
    )

    return interest_infos, sink_infos
