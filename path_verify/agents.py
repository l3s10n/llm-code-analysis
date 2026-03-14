"""
Agent functions for vulnerability path verification.

These functions encapsulate Claude Code SDK calls for specific verification tasks.
Each agent performs a specialized analysis task and returns structured results.
"""

import re
import sys
from typing import List, Optional

from common.agent_logger import log_agent_call
from common.base_claude_agent import AgentResult, base_claude_agent
from common.tui import clear_stream, log_error, log_info, log_success, log_warning, stream_agent, update_agent

from .models import DataflowInfo, FilterLogic, NodeDataflowRecord, PathNode, PotentialPath
from .utils import read_source_code_by_range


# =============================================================================
# Helper Functions
# =============================================================================

def _handle_agent_failure(agent_result: AgentResult, agent_name: str) -> None:
    """
    Handle agent execution failure by printing error and exiting.

    This function is called when base_claude_agent fails after all retries.
    It prints the error message and exits the program.

    Args:
        agent_result: The failed AgentResult containing error details
        agent_name: Name of the agent that failed (for logging)
    """
    from common.agent_logger import close_logger
    from common.base_claude_agent import create_error_file
    from common.tui import emit_output, stop_tui

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


# =============================================================================
# Constants
# =============================================================================

MARKER_DATAFLOW_RECORD_START = "--- dataflow record start ---"
MARKER_DATAFLOW_RECORD_END = "--- dataflow record end ---"
MARKER_NODE_INDEX_START = "--- node index start ---"
MARKER_NODE_INDEX_END = "--- node index end ---"
MARKER_NODE_NAME_START = "--- node name start ---"
MARKER_NODE_NAME_END = "--- node name end ---"
MARKER_PARAMS_START = "--- parameters start ---"
MARKER_PARAMS_END = "--- parameters end ---"
MARKER_MEMBERS_START = "--- member variables start ---"
MARKER_MEMBERS_END = "--- member variables end ---"
MARKER_NON_LOCAL_SOURCES_START = "--- non-local sources start ---"
MARKER_NON_LOCAL_SOURCES_END = "--- non-local sources end ---"

MARKER_FILTER_START = "--- filter logic start ---"
MARKER_FILTER_END = "--- filter logic end ---"
MARKER_AFFECTED_ITEM_START = "--- affected item start ---"
MARKER_AFFECTED_ITEM_END = "--- affected item end ---"
MARKER_DESCRIPTION_START = "--- description start ---"
MARKER_DESCRIPTION_END = "--- description end ---"
MARKER_FILE_START = "--- file start ---"
MARKER_FILE_END = "--- file end ---"
MARKER_LINES_START = "--- lines start ---"
MARKER_LINES_END = "--- lines end ---"

MARKER_DECISION_START = "--- decision start ---"
MARKER_DECISION_END = "--- decision end ---"
MARKER_CONFIDENCE_START = "--- confidence start ---"
MARKER_CONFIDENCE_END = "--- confidence end ---"
MARKER_SUMMARY_START = "--- summary start ---"
MARKER_SUMMARY_END = "--- summary end ---"


# =============================================================================
# Generic Parsers
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
        or None if markers are not found.
    """

    pattern = rf"{re.escape(start_marker)}\n(.*?)\n{re.escape(end_marker)}"
    match = re.search(pattern, text, re.DOTALL)
    return match.group(1).strip() if match else None


def _parse_list_section(text: str, start_marker: str, end_marker: str) -> List[str]:
    """
    Extract a list of items from a marked section.

    Args:
        text: The text to search in.
        start_marker: The start marker pattern.
        end_marker: The end marker pattern.

    Returns:
        List of items (non-empty lines), or empty list if markers not found.
    """

    content = _parse_marked_section(text, start_marker, end_marker)
    if content is None or content.lower() == "none":
        return []

    items = [line.strip().lstrip("- ").strip() for line in content.split("\n")]
    return [item for item in items if item]


def _parse_line_range(text: str) -> Optional[tuple]:
    """
    Parse a line range string like "10-20" or "15" into a tuple.

    Args:
        text: Line range string

    Returns:
        Tuple of (start, end) or None if parsing fails
    """

    if not text or text.lower() == "unknown":
        return None

    text = text.strip()
    if "-" in text:
        parts = text.split("-")
        if len(parts) == 2:
            try:
                return (int(parts[0].strip()), int(parts[1].strip()))
            except ValueError:
                return None
    else:
        try:
            line = int(text)
            return (line, line)
        except ValueError:
            return None

    return None


def _build_call_chain_display(path: List[PathNode]) -> str:
    """
    Build a display string for the call chain.

    Args:
        path: List of PathNode from source to sink

    Returns:
        String like "source -> func1 -> func2 -> sink"
    """

    names = [node.function_name for node in path]
    names.append("sink")
    return " -> ".join(names)


def _format_dataflow_items(info: DataflowInfo) -> str:
    """
    Format a DataflowInfo object for prompts.

    Args:
        info: DataflowInfo to format

    Returns:
        Multi-line string describing the dataflow items
    """

    params = "\n".join([f"  - {item}" for item in info.parameters]) if info.parameters else "  (None)"
    members = "\n".join([f"  - {item}" for item in info.member_variables]) if info.member_variables else "  (None)"
    non_local_sources = (
        "\n".join([f"  - {item}" for item in info.non_local_sources])
        if info.non_local_sources else "  (None)"
    )

    return f"""Parameters:
{params}

Member Variables:
{members}

NonLocalSources:
{non_local_sources}
"""


# =============================================================================
# Dataflow Agent
# =============================================================================

_DATAFLOW_SYSTEM_PROMPT = """
You are a security expert specializing in precise data flow analysis.

# Key Concepts

* **Sink Semantics**: The critical data that determines the security impact:
  - For PathTraversal: the data that determines the file path being accessed
  - For CommandInjection: the data that determines the command being executed
  - For CodeInjection: the data that determines the code being executed
  - For SQLInjection: the data that determines the SQL query being executed
  - For SSRF: the data that determines the request target (URL, domain, IP, host, etc.)

* **Indirect Semantics**: A parameter may carry path/command/code/sql/url semantic indirectly. For example, in `Runtime.exec("sh -c $CMD", envp)`, even though `envp` is "just environment variables", it actually carries the **command semantic** because the fixed command template references and executes `$CMD`. * **Indirect Semantics**: A parameter may carry path/command/code/sql/url semantic indirectly. For example, in `Runtime.exec("sh -c $CMD", envp)`, even though `envp` is "just environment variables", it actually carries the **command semantic** because the fixed command template references and executes `$CMD`. Do not overlook such cases when identifying sink semantics.

# Task

Analyze the COMPLETE call chain from sink to source and determine, for EVERY method in the chain, which contents of the method finally become the sink's key semantics.

# For Each Method, You MUST Return Exactly These Three Kinds of Information

1. **Parameters**: Which parameters of THIS method finally become sink semantics.
   - Use only parameter names from this method definition.
   - Do NOT use deep field paths.
2. **Member Variables**: Which member variables of THIS method finally become sink semantics.
   - Use only `this.<memberName>` format.
   - Do NOT use deep field paths.
3. **NonLocalSources**: Data flow can exist outside direct argument passing. If a function reads data from configuration, database, file, cache, environment variable, external response, or any other non-local source, and that value later becomes sink semantics, you must record it under `NonLocalSources`.
   - This includes reads from configuration, database, file, cache, environment variables, external responses, and similar non-local inputs.
   - Keep each description extremely concise, but specific about what was read.
   - Required format:
     `This method reads <specific content> from <non-local source>, which ultimately becomes the sink semantics`
   - Good examples:
     `This method reads the storage.root configuration value from application.yml, which ultimately becomes the sink semantics`
     `This method reads the avatar_path field value from the users table, which ultimately becomes the sink semantics`
     `This method reads the cached value for download:path from Redis, which ultimately becomes the sink semantics`
     `This method sends a request to http://example.com/path, and the response value ultimately becomes the sink semantics`

# Output Format

First, provide your analysis. Then, at the END of your response, provide a summary in this EXACT format:

```plaintext
--- dataflow record start ---
--- node index start ---
<node index>
--- node index end ---

--- node name start ---
<method name>
--- node name end ---

--- parameters start ---
<param_name>
<param_name>
--- parameters end ---

--- member variables start ---
<this.memberName>
<this.otherMember>
--- member variables end ---

--- non-local sources start ---
This method reads <specific content> from <non-local source>, which ultimately becomes the sink semantics
This method reads <specific content> from <non-local source>, which ultimately becomes the sink semantics
--- non-local sources end ---
--- dataflow record end ---
```

Output one `--- dataflow record start ---` block for EVERY method in the call chain.
If a section has no result, write `None` in that section.

# Important Rules

* **Whole Chain at Once**: Analyze the entire chain in one pass, from sink to source, without omitting any method.
* **Be Complete**: You must list, for every method, all parameters, member variables, and non-local sources that become sink semantics, without any omissions.
* **Method Scope**: For a method's NonLocalSources, include all non-local data reads that occur within the method itself, as well as in any methods it directly or indirectly calls, up to the point where execution reaches the next method in the chain.
* **Do Not Analyze Filtering**: Perform data flow analysis faithfully. Do NOT analyze sanitization or exploitability here.
* **No Deep Field Requirement**: Do not output `param.field.subfield`; only output the method parameter name itself. For members, only output `this.member`.

# Restrictions

* You are prohibited from performing any write operations.
""".strip()


def dataflow_agent(target_path: str, path: PotentialPath) -> List[NodeDataflowRecord]:
    """
    Analyze dataflow for the complete call chain.

    Args:
        target_path: Path to the target project's source code.
        path: PotentialPath containing the call chain.

    Returns:
        List of NodeDataflowRecord, one per method in the call chain
    """

    if not path.path:
        log_warning("dataflow_agent", "Empty path provided")
        return []

    update_agent("dataflow_agent", "running", f"Analyzing {len(path.path)} node(s)")
    log_info("dataflow_agent", f"Analyzing full-chain dataflow for {len(path.path)} node(s)")

    call_chain_display = _build_call_chain_display(path.path)
    user_prompt = f"""# Analysis Context

**Vulnerability Type**: {path.vulnerability_type}
**Sink Expression**: {path.sink_expression}

## Call Chain
{call_chain_display}

"""

    for index, node in enumerate(path.path):
        source_code = read_source_code_by_range(target_path, node)
        user_prompt += f"""## Node {index} - `{node.function_name}`
File: {node.file_path}
Lines: {node.start_line}-{node.end_line}
Source Code:
```
{source_code}
```

"""

    user_prompt += """# Your Task

Analyze the chain from sink to source and output one dataflow record for each node.
For each node, return only:
- method parameter names
- `this.<member>` member variable names
- concise `NonLocalSources` descriptions in the required format
"""

    clear_stream()

    agent_result = base_claude_agent(
        cwd=target_path,
        system_prompt=_DATAFLOW_SYSTEM_PROMPT,
        user_prompt=user_prompt,
        stream_callback=stream_agent,
    )

    if not agent_result.success:
        _handle_agent_failure(agent_result, "dataflow_agent")

    result = agent_result.result
    records = _parse_dataflow_records(result, path)

    update_agent("dataflow_agent", "completed", f"Found {len(records)} dataflow record(s)")
    log_success("dataflow_agent", f"Found {len(records)} dataflow record(s)")

    log_agent_call(
        agent_name="dataflow_agent",
        user_prompt=user_prompt,
        model_output=result,
        parsed_result=str(
            [
                (
                    f"NodeDataflowRecord(node_index={record.node_index}, "
                    f"node_name={record.node_name}, "
                    f"parameters={record.dataflow_info.parameters}, "
                    f"member_variables={record.dataflow_info.member_variables}, "
                    f"non_local_sources={record.dataflow_info.non_local_sources})"
                )
                for record in records
            ]
        ),
    )

    return records


def _parse_dataflow_records(text: str, path: PotentialPath) -> List[NodeDataflowRecord]:
    """
    Parse dataflow records from agent response.

    Args:
        text: Agent response text
        path: PotentialPath used to validate node indices

    Returns:
        List of NodeDataflowRecord objects
    """

    results = []
    pattern = rf"{re.escape(MARKER_DATAFLOW_RECORD_START)}(.*?){re.escape(MARKER_DATAFLOW_RECORD_END)}"
    matches = re.findall(pattern, text, re.DOTALL)

    for match in matches:
        node_index_text = _parse_marked_section(match, MARKER_NODE_INDEX_START, MARKER_NODE_INDEX_END)
        node_name = _parse_marked_section(match, MARKER_NODE_NAME_START, MARKER_NODE_NAME_END) or ""
        parameters = _parse_list_section(match, MARKER_PARAMS_START, MARKER_PARAMS_END)
        member_variables = _parse_list_section(match, MARKER_MEMBERS_START, MARKER_MEMBERS_END)
        non_local_sources = _parse_list_section(
            match,
            MARKER_NON_LOCAL_SOURCES_START,
            MARKER_NON_LOCAL_SOURCES_END,
        )

        try:
            node_index = int(node_index_text) if node_index_text is not None else -1
        except ValueError:
            continue

        if node_index < 0 or node_index >= len(path.path):
            continue

        if not node_name:
            node_name = path.path[node_index].function_name

        results.append(
            NodeDataflowRecord(
                node_index=node_index,
                node_name=node_name,
                dataflow_info=DataflowInfo(
                    parameters=parameters,
                    member_variables=member_variables,
                    non_local_sources=non_local_sources,
                ),
            )
        )

    results.sort(key=lambda item: item.node_index)
    return results


# =============================================================================
# One Hop Filter Agent
# =============================================================================

_ONE_HOP_FILTER_SYSTEM_PROMPT = """
You are a security expert specializing in vulnerability exploitation analysis.

# Key Concepts

* **Sink Semantics**: The critical data that determines the security impact:
  - For PathTraversal: the data that determines the file path being accessed
  - For CommandInjection: the data that determines the command being executed
  - For CodeInjection: the data that determines the code being executed
  - For SQLInjection: the data that determines the SQL query being executed
  - For SSRF: the data that determines the request target (URL, domain, IP, host, etc.)

# Task

Given the caller-side items in the current function that ultimately become sink semantics, analyze whether there exists any logic that could prevent the vulnerability from being exploited before the next function is called (or before the sink is reached directly), regardless of whether that logic was designed for security purposes or not.

# Background Context

You will be given:
1. **Caller-side sink-semantics items in current function**: Specific parameters/member variables/non-local sources in the current function that ultimately become sink semantics
2. The source code of current function - THIS IS WHAT YOU ANALYZE
3. The identity of the next hop (next function or sink), so you know where your analysis scope ends

Your job is to examine the full execution scope from the moment the current function begins until the exact point where the next function is called (or the sink is invoked directly), including any project-internal methods directly or indirectly executed within that scope, and identify any logic that could prevent exploitation for each caller-side sink-semantics item.

# Output Format

First, provide your analysis. Then, at the END of your response, output ONE block per filter logic found:

```plaintext
--- filter logic start ---
--- affected item start ---
<caller-side item that ultimately becomes sink semantics>
--- affected item end ---

--- description start ---
<What the logic does and how it might prevent exploitation>
--- description end ---

--- file start ---
<file path>
--- file end ---

--- lines start ---
<start_line>-<end_line> or just <line_number>
--- lines end ---
--- filter logic end ---
```

Each block must describe exactly one filter logic.
If no filter logic is found, do not output any `--- filter logic start ---` or `--- filter logic end ---` block.

# What Could Prevent Exploitation (Not Limited to Security Logic)

Look for ANY logic that could make the vulnerability unexploitable, including but NOT limited to:

1. **Security-specific logic**:
   - Input validation/sanitization
   - Path traversal detection
   - Command blacklist/whitelist

2. **Business logic that may incidentally block exploitation**:
   - Data transformation/formatting that changes the value
   - String operations (concatenation, replacement, encoding)
   - Type conversions that alter the data
   - Default values or constants being prepended/appended
   - Conditional branches that skip the vulnerable path
   - Exception handling that prevents reaching the sink
   - Configuration or environment checks
   - Any other logic that affects the data flow

3. **Data flow disruptions**:
   - The data being combined with other fixed values
   - The data being truncated or modified
   - The vulnerable code path being conditionally unreachable

# Important Rules

* **Strict Scope**: Only analyze the execution scope from the start of current function until the exact point where next function is called (or sink is called). Do NOT analyze logic after that point.
* **Item Binding**: Every reported filter logic must be bound to the specific caller-side item (`parameter`, `this.member`, or `NonLocalSources` description) that it affects. Do not merge multiple unrelated items into one vague report.
* **Complete Trace and Full Code Coverage (MANDATORY)**: For each sink-semantics item, you MUST follow its complete data flow from the beginning of the current function to the exact next-hop call site, and read ALL project-internal code involved at any step in carrying, copying, transforming, wrapping, checking, rewriting, resolving through helper methods, or combining that item with constants.
* **Be Specific**: Provide exact file paths and line numbers.
* **Comprehensive**: Consider ALL types of logic, not just security-related ones.

# Restrictions

* You are prohibited from performing any write operations.
""".strip()


def one_hop_filter_agent(
    target_path: str,
    path: PotentialPath,
    node_index: int,
    current_dataflow: DataflowInfo,
) -> List[FilterLogic]:
    """
    Analyze caller-side filtering logic before the next hop.

    Args:
        target_path: Path to the target project's source code.
        path: PotentialPath containing the call chain.
        node_index: Index of the current node being analyzed (0-based).
        current_dataflow: DataflowInfo for current node.

    Returns:
        List of FilterLogic objects representing potential blocking logic found.
    """

    if node_index < 0 or node_index >= len(path.path):
        log_error("one_hop_filter_agent", f"Invalid node_index: {node_index}")
        return []

    current_node = path.path[node_index]
    is_last_node = node_index == len(path.path) - 1
    current_source_code = read_source_code_by_range(target_path, current_node)

    if is_last_node:
        position_info = f"{current_node.function_name} -> sink"
        next_hop_label = "sink"
        analysis_boundary = f"the sink call `{path.sink_expression}`"
        next_hop_info_block = f"""# Next Hop Info

This hop goes directly to the sink.
Use the sink call `{path.sink_expression}` only to locate the analysis boundary.
Do not analyze any logic after the sink call.
"""
    else:
        next_node = path.path[node_index + 1]
        position_info = f"{current_node.function_name} -> {next_node.function_name}"
        next_hop_label = next_node.function_name
        analysis_boundary = f"the call to `{next_node.function_name}`"
        next_source_code = read_source_code_by_range(target_path, next_node)
        next_hop_info_block = f"""# Next Hop Info

Use this only to locate the analysis boundary.
Do not analyze any logic after `{next_node.function_name}` is called.

File: {next_node.file_path}
Lines: {next_node.start_line}-{next_node.end_line}

```text
{next_source_code}
```
"""
    update_agent("one_hop_filter_agent", "running", f"Analyzing: {position_info}")
    log_info("one_hop_filter_agent", f"Analyzing logic in: {current_node.function_name}")

    source_info_str = _format_dataflow_items(current_dataflow)

    user_prompt = f"""# Context

Vulnerability Type: {path.vulnerability_type}
Sink Expression: {path.sink_expression}
Current Function: {current_node.function_name}
Next Hop: {next_hop_label}
Analysis Boundary: from the entry of `{current_node.function_name}` to {analysis_boundary}

# Current Function Source

File: {current_node.file_path}
Lines: {current_node.start_line}-{current_node.end_line}

```text
{current_source_code}
```

{next_hop_info_block}

# Caller-Side Items That Become Sink Semantics

{source_info_str}
"""

    clear_stream()

    agent_result = base_claude_agent(
        cwd=target_path,
        system_prompt=_ONE_HOP_FILTER_SYSTEM_PROMPT,
        user_prompt=user_prompt,
        stream_callback=stream_agent,
    )

    if not agent_result.success:
        _handle_agent_failure(agent_result, "one_hop_filter_agent")

    result = agent_result.result
    filter_logics = _parse_filter_logics(result, node_index)

    update_agent("one_hop_filter_agent", "completed", f"Found {len(filter_logics)} blocking logic")
    log_success("one_hop_filter_agent", f"Found {len(filter_logics)} blocking logic")

    parsed_result_str = str(
        [
            (
                f"FilterLogic(dataflow={logic.dataflow}, "
                f"description={logic.description[:50]}..., "
                f"file_path={logic.file_path}, line_range={logic.line_range})"
            )
            for logic in filter_logics
        ]
    )
    log_agent_call(
        agent_name="one_hop_filter_agent",
        user_prompt=user_prompt,
        model_output=result,
        parsed_result=parsed_result_str,
    )

    return filter_logics


def _parse_filter_logics(text: str, node_index: int = -1) -> List[FilterLogic]:
    """
    Parse filter logic blocks from agent response.

    Args:
        text: Agent response text
        node_index: Index of the node where this filter was found

    Returns:
        List of FilterLogic objects
    """

    results = []
    pattern = rf"{re.escape(MARKER_FILTER_START)}(.*?){re.escape(MARKER_FILTER_END)}"
    matches = re.findall(pattern, text, re.DOTALL)

    for match in matches:
        dataflow = _parse_marked_section(match, MARKER_AFFECTED_ITEM_START, MARKER_AFFECTED_ITEM_END)
        description = _parse_marked_section(match, MARKER_DESCRIPTION_START, MARKER_DESCRIPTION_END)
        file_path = _parse_marked_section(match, MARKER_FILE_START, MARKER_FILE_END)
        lines_str = _parse_marked_section(match, MARKER_LINES_START, MARKER_LINES_END)

        if dataflow and dataflow.lower() == "none":
            continue

        if dataflow:
            dataflow = re.split(r"\s*(?:->|→)\s*", dataflow, maxsplit=1)[0].strip()
            if not dataflow:
                continue

        if dataflow and description:
            line_range = _parse_line_range(lines_str) if lines_str else None
            results.append(
                FilterLogic(
                    dataflow=dataflow,
                    description=description,
                    file_path=file_path or "Unknown",
                    line_range=line_range,
                    node_index=node_index,
                )
            )

    return results


# =============================================================================
# Final Decision Agent
# =============================================================================

_FINAL_DECISION_SYSTEM_PROMPT = """
You are a senior security expert conducting a thorough vulnerability exploitation analysis.

# Task

Trace the complete data flow from source to sink, function by function, to determine whether this vulnerability is actually exploitable. Do NOT simply accept previous analysis results at face value - verify and think critically.

# Key Concepts

* **Sink Semantics**: The critical data that determines the security impact:
  - For PathTraversal: the data that determines the file path being accessed
  - For CommandInjection: the data that determines the command being executed
  - For CodeInjection: the data that determines the code being executed
  - For SQLInjection: the data that determines the SQL query being executed
  - For SSRF: the data that determines the request target (URL, domain, IP, host, etc.)

# Analysis Approach

You should analyze the call chain from source to sink, one function at a time:

1. **For each function in the chain**:
   - Start with the provided source code
   - Read additional files if needed to understand the full context (class members, called methods, etc.)
   - With the help of the provided analysis, trace which caller-side items in this function ultimately become sink semantics and identify any logic that might prevent exploitation before the next hop
   - Form a intermediate conclusion and carry it to the next function

2. **Be critical of provided analysis**:
   - Previous analysis identified sink-semantics items for each function that ultimately become sink semantics and potential blocking logic affecting those items before each hop
   - These may be incomplete or incorrect - verify them yourself
   - A "blocking logic" identified earlier might be bypassable

3. **Think about exploitability**:
   - Can user input actually control the sink's key semantic (path/command/code/sql/url)?
      - **Indirect Semantics**: A parameter may carry path/command/code/sql/url semantic indirectly. For example, in `Runtime.exec("sh -c $CMD", envp)`, even though `envp` is "just environment variables", it actually carries the **command semantic** because the fixed command template references and executes `$CMD`. * **Indirect Semantics**: A parameter may carry path/command/code/sql/url semantic indirectly. For example, in `Runtime.exec("sh -c $CMD", envp)`, even though `envp` is "just environment variables", it actually carries the **command semantic** because the fixed command template references and executes `$CMD`. Do not overlook such cases when identifying sink semantics.
      - **Out-of-Band Data Flow**: Data flow can exist outside direct code paths. If user writes to persistent storage (env var, config, file, database) that is later read and used as path/command/code/sql/url, this creates an implicit data flow. Consider these channels when analyzing. Note: Such data flows may exist outside the current call chain; for example, if a database field read in the current call chain is used as a file write path, check if other endpoints allow users to set that field, making the current call chain exploitable. Ensure the analysis focuses on the exploitability of the current call chain.
   - Are there any conditions, transformations, or logic that prevent exploitation?
   - Is the blocking logic effective, or can it be bypassed?

4. **Check the Mistake Notebook (MANDATORY)**:
   - Repeating the same mistakes is STRICTLY PROHIBITED.

# Output Format

First, provide your complete analysis. Then, at the END of your response, provide a summary in this EXACT format:

```plaintext
--- decision start ---
<VULNERABLE / NOT VULNERABLE>
--- decision end ---

--- confidence start ---
<High / Medium / Low>
--- confidence end ---

--- summary start ---
<One sentence summary of the finding>
--- summary end ---
```

## Decision Guidelines

* **VULNERABLE**: User input can reach and control the sink's key semantic with no effective blocking, OR blocking logic can be bypassed.
* **NOT VULNERABLE**: There is effective logic that prevents exploitation and cannot be bypassed.

## Confidence Levels

* **High**: Clear evidence, thorough analysis, minimal ambiguity.
* **Medium**: Some uncertainty exists, but evidence leans in one direction.
* **Low**: Significant uncertainty, manual review strongly recommended.

# Important Rules

* **Think Step by Step**: Analyze function by function from source to sink.
* **Do Your Own Analysis**: Do not blindly trust the provided dataflow/blocking logic analysis. Verify and think critically.
* **Read Files When Needed**: If you need more context, read the relevant files. Make sure you have enough code information.
* **Consider Bypass**: Even if blocking logic exists, consider whether it can be bypassed.
* **Stay Focused**: Only analyze THIS specific call chain and THIS vulnerability type. Do NOT investigate other potential vulnerabilities, other code paths, or unrelated security issues.
* **Check Mistake Notebook**: Check the Mistake Notebook. **Do NOT repeat the same mistakes documented there**.
* **Strict Output Format**: Your final summary MUST be in the EXACT format specified at the end of your response. Any deviation from the required format is unacceptable.

# Mistake Notebook

This section documents some typical mistakes you have made in the past. You MUST avoid repeating them:

- Mistake: Incorrectly assumed that in new java.io.File(xxx, "/yyy"), supplying an absolute path as the second argument causes the first argument xxx to be ignored, so the result was treated as always resolving to /yyy.
- Correction: In reality, the path resolves to xxx/yyy.

- Mistake: Believed that HTTP header names cannot contain special characters.
- Correction: HTTP header names are able to contain arbitrary strings, including special characters.

- Mistake: Incorrectly assumed that the second parameter (the `envp` array parameter) of Runtime.exec could not be used to set specific environment variables.
- Correction: In reality, if the second parameter is controllable, arbitrary environment variables can be set to arbitrary values via entries in the form X=Y.

- Mistake: Incorrectly assumed that filtering `.` or `./` was insufficient because path traversal could still be achieved through inputs like `..` or `../`.
- Correction: Inputs containing `.` or `./` have already been filtered, so sequences such as `..` or `../` containing `.` or `./` cannot pass through that code path.
- Generalization: If a string is filtered in a way that cannot be bypassed, then any payload containing that substring is also invalid.

These corrections are empirically verified facts. Do NOT waste any time questioning or doubting them—accept them as absolute truth, even if you believe otherwise.

# Restrictions

* You are prohibited from performing any write operations.
""".strip()


def final_decision_agent(
    target_path: str,
    path: PotentialPath,
    dataflow_records: List[NodeDataflowRecord],
    filter_logics: List[FilterLogic],
) -> tuple:
    """
    Make the final vulnerability determination.

    Args:
        target_path: Path to the target project's source code.
        path: PotentialPath containing the call chain.
        dataflow_records: List of dataflow analysis records for each node.
        filter_logics: List of filtering logics found during analysis.

    Returns:
        Tuple of (is_vulnerable: bool, confidence: str, summary: str)
    """

    update_agent("final_decision_agent", "running", "Making final determination")
    log_info("final_decision_agent", "Making final vulnerability determination")

    call_chain_display = _build_call_chain_display(path.path)

    user_prompt = f"""# Vulnerability Path Analysis

**Vulnerability Type**: {path.vulnerability_type}
**Sink Expression**: {path.sink_expression}

## Call Chain

{call_chain_display}

---

"""

    for i, node in enumerate(path.path):
        current_record = None
        for record in dataflow_records:
            if record.node_index == i:
                current_record = record
                break

        node_filters = [logic for logic in filter_logics if logic.node_index == i]
        source_code = read_source_code_by_range(target_path, node)

        user_prompt += f"""## Node {i}: `{node.function_name}`

### a) Basic Information

**File:** {node.file_path}
**Lines:** {node.start_line}-{node.end_line}

**Source Code:**
```
{source_code}
```

"""

        if current_record:
            current_info_text = _format_dataflow_items(current_record.dataflow_info)
            user_prompt += f"""### b) Items in `{node.function_name}` that eventually become sink semantics

{current_info_text}

### c) Potential blocking logic

"""

            if node_filters:
                for logic in node_filters:
                    location = logic.file_path
                    if logic.line_range:
                        location += f" (lines {logic.line_range[0]}-{logic.line_range[1]})"
                    user_prompt += f"""- Affected Item: {logic.dataflow}
Description: {logic.description}
Location: {location}

"""
            else:
                user_prompt += """None identified.

"""

        user_prompt += "---\n\n"

    clear_stream()

    agent_result = base_claude_agent(
        cwd=target_path,
        system_prompt=_FINAL_DECISION_SYSTEM_PROMPT,
        user_prompt=user_prompt,
        stream_callback=stream_agent,
    )

    if not agent_result.success:
        _handle_agent_failure(agent_result, "final_decision_agent")

    result = agent_result.result

    decision_str = _parse_marked_section(result, MARKER_DECISION_START, MARKER_DECISION_END)
    confidence = _parse_marked_section(result, MARKER_CONFIDENCE_START, MARKER_CONFIDENCE_END)
    summary = _parse_marked_section(result, MARKER_SUMMARY_START, MARKER_SUMMARY_END)

    is_vulnerable = False
    if decision_str:
        is_vulnerable = decision_str.upper().strip() == "VULNERABLE"

    if confidence:
        confidence = confidence.capitalize()
        if confidence not in ["High", "Medium", "Low"]:
            confidence = "Low"
    else:
        confidence = "Low"

    summary = summary or "No summary provided"

    decision_text = "VULNERABLE" if is_vulnerable else "NOT VULNERABLE"
    update_agent("final_decision_agent", "completed", f"Decision: {decision_text} ({confidence})")
    log_success("final_decision_agent", f"Decision: {decision_text} (confidence: {confidence})")

    log_agent_call(
        agent_name="final_decision_agent",
        user_prompt=user_prompt,
        model_output=result,
        parsed_result=f"(is_vulnerable={is_vulnerable}, confidence='{confidence}', summary='{summary}')",
    )

    return (is_vulnerable, confidence, summary)
