"""
Agent functions for vulnerability path verification.

These functions encapsulate Claude Code SDK calls for specific verification tasks.
Each agent performs a specialized analysis task and returns structured results.
"""

import re
from typing import List, Optional

from common.base_claude_agent import base_claude_agent
from common.tui import log_info, log_success, log_error, update_agent, stream_agent, clear_stream
from common.agent_logger import log_agent_call

from .models import (
    PathNode,
    PotentialPath,
    DataflowInfo,
    FilterLogic,
    NodeDataflowRecord
)


# =============================================================================
# Constants
# =============================================================================

# Marker patterns for parsing agent responses
MARKER_PARAMS_START = "--- parameters start ---"
MARKER_PARAMS_END = "--- parameters end ---"
MARKER_MEMBERS_START = "--- member variables start ---"
MARKER_MEMBERS_END = "--- member variables end ---"

# Markers for filter logic
MARKER_FILTER_START = "--- filter logic start ---"
MARKER_FILTER_END = "--- filter logic end ---"
MARKER_DATAFLOW_START = "--- dataflow start ---"
MARKER_DATAFLOW_END = "--- dataflow end ---"
MARKER_DESCRIPTION_START = "--- description start ---"
MARKER_DESCRIPTION_END = "--- description end ---"
MARKER_FILE_START = "--- file start ---"
MARKER_FILE_END = "--- file end ---"
MARKER_LINES_START = "--- lines start ---"
MARKER_LINES_END = "--- lines end ---"

# Markers for final decision
MARKER_DECISION_START = "--- decision start ---"
MARKER_DECISION_END = "--- decision end ---"
MARKER_CONFIDENCE_START = "--- confidence start ---"
MARKER_CONFIDENCE_END = "--- confidence end ---"
MARKER_SUMMARY_START = "--- summary start ---"
MARKER_SUMMARY_END = "--- summary end ---"
MARKER_REASONING_START = "--- reasoning start ---"
MARKER_REASONING_END = "--- reasoning end ---"


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

    # Split by newlines and filter empty lines
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
    names = [node.name for node in path]
    names.append("sink")
    return " -> ".join(names)


def _build_path_info_section(path: List[PathNode]) -> str:
    """
    Build a formatted section with path information.

    Args:
        path: List of PathNode from source to sink

    Returns:
        Formatted string with each node's details
    """
    sections = []
    for i, node in enumerate(path):
        section = f"""## Node {i}: {node.name}
File: {node.file}
Source Code:
```
{node.source_code}
```"""
        sections.append(section)
    return "\n\n".join(sections)


# =============================================================================
# One Hop Dataflow Agent
# =============================================================================

# System prompt for dataflow analysis
_ONE_HOP_DATAFLOW_SYSTEM_PROMPT = """
You are a security expert specializing in precise data flow analysis.

# Task

Analyze the data flow from the current function to the next function (or directly to sink), determining which **specific fields** of parameters and member variables of the current function flow to the sink's key semantics.

# Key Concepts

* **Sink Semantics**: The critical data that determines the security impact - this refers to the INPUT (parameter or member variable) that carries the path/command semantic, not a parameter named "path" or "command":
  - For PathTraversal: The input that determines the file path being accessed
  - For CommandInjection: The input that determines the command being executed
* **Precise Field Tracking**: You must trace data flow to the most granular field level possible, not just parameter/member names.

# Output Format

First, provide your analysis. Then, at the END of your response, provide a summary in this EXACT format:

```plaintext
--- parameters start ---
<param.subfield1.subfield2>
<param2.nestedField>
--- parameters end ---

--- member variables start ---
<this.member.nestedField.deepField>
<this.anotherMember>
--- member variables end ---
```

If there are no parameters or member variables that flow to sink semantics, write "None" in that section.

# Format Requirements (CRITICAL)

* **Be Granular**: Always trace to the deepest field level that flows to sink semantics.
  - Good: `request.path`, `user.profile.homeDir`, `config.basePath.prefix`
  - Bad: `request`, `user`, `config` (too coarse-grained)
* **Parameter Format**: `<paramName>.<field>.<field>.<field>` - trace through all nested accesses
* **Member Variable Format**: `this.<memberName>.<field>.<field>.<field>` - include `this.` prefix
* **For Static Methods**: Member variables are not applicable, focus only on parameters

# Analysis Approach

1. **Check Known Dataflow First**: The input provides information about what specific fields in the next function (or sink) flows to sink semantics. Your analysis should be completed based on this information.
2. **Trace Backwards**: Starting from those fields in the next function, trace back through the current function's code to find which specific fields of the current function's parameters/member variables provide that data.
3. **Follow Field Accesses**: When you see code like `param.getField().getSubField()`, the dataflow is `param.field.subField`, not just `param`.
4. **Read Necessary Code**: You may need to read specific files to understand function implementations, class member variables, etc., to confirm how data is propagated or to be granular.
5. **Handle Transformations**: Even if data is transformed (e.g., `param.getPath()` becomes `Paths.get(path)`), trace the original source field.

# Important Rules

* **Data Flow Only**: Track where data comes from. Do NOT consider security filtering or sanitization.
* **Be Precise**: Only list the specific fields that actually flow to sink semantics.
* **Match the Target**: Your output should map to the known dataflow from the next function to sink.
* **Scope Limited**: The specific fields in result must be parameters or member variables of the current function. Do not return anything that is not a parameter or member variable of the current function.

# Restrictions

* You are prohibited from performing any write operations.
""".strip()


def one_hop_dataflow_agent(
    target_path: str,
    path: PotentialPath,
    node_index: int,
    next_node_dataflow: Optional[DataflowInfo] = None
) -> DataflowInfo:
    """
    Analyze dataflow from a node to the sink.

    This agent analyzes which parameters and member variables of the node at
    node_index flow to the sink's key semantics.

    Args:
        target_path: Path to the target project's source code.
        path: PotentialPath containing the call chain.
        node_index: Index of the current node being analyzed (0-based).
        next_node_dataflow: DataflowInfo from the next node's analysis.
                           For the sink's direct caller, this is None.

    Returns:
        DataflowInfo containing parameters and member variables that flow to sink.

    Note:
        For the last node (sink's direct caller), next_node_dataflow should be None,
        indicating we analyze what flows to the sink's key parameter directly.
    """
    if node_index < 0 or node_index >= len(path.path):
        log_error("one_hop_dataflow_agent", f"Invalid node_index: {node_index}")
        return DataflowInfo()

    current_node = path.path[node_index]

    # Determine if this is the last node (direct caller of sink)
    is_last_node = (node_index == len(path.path) - 1)

    # Build agent display info
    position_info = "sink caller" if is_last_node else f"node[{node_index}]"
    update_agent("one_hop_dataflow_agent", "running", f"Analyzing: {current_node.name} ({position_info})")
    log_info("one_hop_dataflow_agent", f"Analyzing dataflow for: {current_node.name}")

    # Build call chain from current node to sink only
    remaining_chain = [node.name for node in path.path[node_index:]]
    remaining_chain.append("sink")
    call_chain_to_sink = " -> ".join(remaining_chain)

    # Build user prompt
    # Build the base prompt - Sink Expression only shown when next hop is sink
    if is_last_node:
        user_prompt = f"""# Analysis Context

**Vulnerability Type**: {path.vulnerability_type}
**Sink Expression**: {path.sink_expression}

## Call Chain (from current to sink)
{call_chain_to_sink}

## Current Function - `{current_node.name}`
File: {current_node.file}
Source Code:
```
{current_node.source_code}
```
"""
    else:
        user_prompt = f"""# Analysis Context

**Vulnerability Type**: {path.vulnerability_type}

## Call Chain (from current to sink)
{call_chain_to_sink}

## Current Function - `{current_node.name}`
File: {current_node.file}
Source Code:
```
{current_node.source_code}
```
"""

    # Add next function info if not the last node
    if not is_last_node:
        next_node = path.path[node_index + 1]
        user_prompt += f"""
## Next Function - `{next_node.name}`
File: {next_node.file}
Source Code:
```
{next_node.source_code}
```
"""
        # Add dataflow info from next node's analysis - make this prominent
        if next_node_dataflow:
            params_str = '\n'.join([f"  - {p}" for p in next_node_dataflow.parameters]) if next_node_dataflow.parameters else "  (None)"
            members_str = '\n'.join([f"  - {m}" for m in next_node_dataflow.member_variables]) if next_node_dataflow.member_variables else "  (None)"

            # Build member variable hint if there are member variables
            member_hint = ""
            if next_node_dataflow.member_variables:
                member_hint = f"""
**Note on `this` reference:** The `this` in the member variables above refers to the instance of {next_node.name}.
In `{current_node.name}`'s code, identify what object this instance corresponds to:
  - If called as xxx.{next_node.name}(...), then xxx is the instance of {next_node.name}
  - If called as this.{next_node.name}(...) or directly {next_node.name}(...), then {current_node.name} and {next_node.name} share the same this instance (e.g., methods in the same class)
You need to determine in {current_node.name}'s code exactly which object corresponds to this of {next_node.name}.
"""

            user_prompt += f"""
## *** CRITICAL: Known Dataflow from `{next_node.name}` (Next Function) to Sink ***

The following fields in `{next_node.name}` have been confirmed to flow to the sink's key semantics.
Your task is to find which specific fields in `{current_node.name}` flow into THESE fields:

**Parameters in `{next_node.name}` that reach sink:**
{params_str}

**Member Variables in `{next_node.name}` that reach sink:**
{members_str}
{member_hint}

The overall dataflow path is: 

{current_node.name}.??? -> {next_node.name}.above_fields -> ... -> sink.

Your task is to trace the first part of this path: 

{current_node.name}.??? -> {next_node.name}.above_fields
"""
        else:
            user_prompt += f"""
## Known Dataflow from `{next_node.name}` to Sink

(No specific dataflow information available)
"""
    else:
        # This is the last node - directly analyze what flows to sink
        user_prompt += f"""
## *** Sink Direct Caller ***

This function directly calls the sink: `{path.sink_expression}`

Your task is to find which specific fields in `{current_node.name}` flow to the sink's key semantic input (the data that determines the path/command, which could be a parameter or member variable of the sink).

>>> For PathTraversal: trace which fields become the file path semantic
>>> For CommandInjection: trace which fields become the command semantic
"""

    user_prompt += f"""
# Your Task

Trace the data flow from `{current_node.name}` to the known sink-bound fields listed above.
Output the specific fields (param.field.subfield or this.member.field.subfield) that flow to sink.
"""

    # Clear stream buffer and execute agent with streaming
    clear_stream()

    result = base_claude_agent(
        cwd=target_path,
        system_prompt=_ONE_HOP_DATAFLOW_SYSTEM_PROMPT,
        user_prompt=user_prompt,
        stream_callback=stream_agent
    )

    if result is None:
        update_agent("one_hop_dataflow_agent", "error", "Agent returned no result")
        log_error("one_hop_dataflow_agent", "Agent returned no result")
        # Log the failed call
        log_agent_call(
            agent_name="one_hop_dataflow_agent",
            user_prompt=user_prompt,
            model_output=None,
            parsed_result="DataflowInfo() (agent returned no result)"
        )
        return DataflowInfo()

    # Parse response
    parameters = _parse_list_section(result, MARKER_PARAMS_START, MARKER_PARAMS_END)
    member_variables = _parse_list_section(result, MARKER_MEMBERS_START, MARKER_MEMBERS_END)

    dataflow_info = DataflowInfo(
        parameters=parameters,
        member_variables=member_variables
    )

    update_agent("one_hop_dataflow_agent", "completed",
                 f"Found: {len(parameters)} params, {len(member_variables)} members")
    log_success("one_hop_dataflow_agent",
                f"Dataflow: {len(parameters)} params, {len(member_variables)} members")

    # Log the call
    log_agent_call(
        agent_name="one_hop_dataflow_agent",
        user_prompt=user_prompt,
        model_output=result,
        parsed_result=f"DataflowInfo(parameters={parameters}, member_variables={member_variables})"
    )

    return dataflow_info


# =============================================================================
# One Hop Filter Agent
# =============================================================================

# System prompt for filter analysis
_ONE_HOP_FILTER_SYSTEM_PROMPT = """
You are a security expert specializing in vulnerability exploitation analysis.

# Task

Given a known data flow from current function to next function (or directly to sink), analyze whether there exists any logic that could prevent the vulnerability from being exploited, regardless of whether that logic was designed for security purposes or not.

# Background Context

You will be given:
1. **Source fields in current function**: Specific fields (parameters/member variables) that flow to sink
2. **Target fields in next function**: Specific fields (parameters/member variables) that receive the data and eventually flow to sink
3. The source code of current function - THIS IS WHAT YOU ANALYZE

Your job is to examine the code path from source fields to target fields and identify any logic that could prevent exploitation.

# Output Format

First, provide your analysis. Then, at the END of your response, provide a summary for EACH logic found (or a single "no logic found" entry):

```plaintext
--- filter logic start ---
--- dataflow start ---
<sourceField -> targetField>
--- dataflow end ---

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

**IMPORTANT**: The `<sourceField -> targetField>` must use the EXACT field names provided in the input:
- `sourceField` must be one of the source fields listed for current function
- `targetField` must be one of the target fields listed for next function (or "sink" if direct call)

If no logic is found that could prevent exploitation, output:

```plaintext
--- filter logic start ---
--- dataflow start ---
None
--- dataflow end ---

--- description start ---
No blocking logic found
--- description end ---

--- file start ---
None
--- file end ---

--- lines start ---
None
--- lines end ---
--- filter logic end ---
```

# What Could Prevent Exploitation (Not Limited to Security Logic)

Look for ANY logic that could make the vulnerability unexploitable, including but NOT limited to:

1. **Security-specific logic** (designed for security):
   - Input validation/sanitization
   - Path traversal detection
   - Command blacklist/whitelist

2. **Business logic that may incidentally blocks exploitation**:
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

**KEY POINT**: Do NOT only look for "security filters". Many vulnerabilities become unexploitable due to ordinary business logic that was never designed with security in mind. Report ALL logic that could prevent exploitation.

# Important Rules

* **Scope**: Only analyze the current function's code. Do NOT analyze the next function's internal logic. Analyzing the next function's code will NOT help you complete this task - your goal is to find blocking logic in the current function, before the call to the next function.
* **Relevance**: Only report logic that affects the specified source-to-target data flow.
* **Be Specific**: Provide exact file paths and line numbers.
* **Comprehensive**: Consider ALL types of logic, not just security-related ones.
* **Conservative**: When uncertain if something could prevent exploitation, include it.
* **Read When Needed**: If understanding the data flow requires reading other files, read them. Do not guess or assume.

# Restrictions

* You are prohibited from performing any write operations.
""".strip()


def one_hop_filter_agent(
    target_path: str,
    path: PotentialPath,
    node_index: int,
    current_dataflow: DataflowInfo,
    next_dataflow: Optional[DataflowInfo] = None
) -> List[FilterLogic]:
    """
    Analyze filtering logic between two adjacent nodes.

    This agent analyzes the code in the current node to find any logic
    (security-related or not) that could prevent exploitation in the
    data flow from current function's fields to next function's fields.

    Args:
        target_path: Path to the target project's source code.
        path: PotentialPath containing the call chain.
        node_index: Index of the current node being analyzed (0-based).
        current_dataflow: DataflowInfo for current node (which fields flow to sink).
        next_dataflow: DataflowInfo for next node (which fields flow to sink).
                      For the sink's direct caller, this is None.

    Returns:
        List of FilterLogic objects representing potential blocking logic found.
    """
    if node_index < 0 or node_index >= len(path.path):
        log_error("one_hop_filter_agent", f"Invalid node_index: {node_index}")
        return []

    current_node = path.path[node_index]

    # Determine if this is the last node (direct caller of sink)
    is_last_node = (node_index == len(path.path) - 1)

    # Build agent display info with actual function names
    if is_last_node:
        position_info = f"{current_node.name} -> sink"
    else:
        next_node = path.path[node_index + 1]
        position_info = f"{current_node.name} -> {next_node.name}"
    update_agent("one_hop_filter_agent", "running", f"Analyzing: {position_info}")
    log_info("one_hop_filter_agent", f"Analyzing logic in: {current_node.name}")

    # Build source fields strings (separate parameters and member variables)
    source_params_str = '\n'.join([f"  - {p}" for p in current_dataflow.parameters]) if current_dataflow.parameters else "  (None)"
    source_members_str = '\n'.join([f"  - {m}" for m in current_dataflow.member_variables]) if current_dataflow.member_variables else "  (None)"

    # Build user prompt
    if is_last_node:
        # Direct call to sink
        user_prompt = f"""# Analysis Context

**Vulnerability Type**: {path.vulnerability_type}

## Data Flow to Analyze

The following fields in `{current_node.name}` have been confirmed to flow to the sink `{path.sink_expression}`:

**Source Fields (in `{current_node.name}`):**

Parameters:
{source_params_str}

Member Variables:
{source_members_str}

**Target:** sink (the input carrying the path/command semantic, which could be a parameter or member variable)

## Current Function - `{current_node.name}`
File: {current_node.file}
Source Code:
```
{current_node.source_code}
```

# Your Task

Analyze the code in `{current_node.name}` to find ANY logic that could prevent the vulnerability from being exploited.

**Do NOT limit your analysis to security-specific code.** Look for ALL logic that could block exploitation, including:
- Security validation/sanitization (if any)
- Business logic that transforms or restricts the data
- Conditional branches that might skip the sink call
- Data operations that change the value
- Any other logic affecting the data flow

Output your findings in the specified format. The dataflow in output should be: `<sourceField -> sink>`
"""
    else:
        next_node = path.path[node_index + 1]

        # Build target fields strings (separate parameters and member variables)
        target_params_str = '\n'.join([f"  - {p}" for p in next_dataflow.parameters]) if next_dataflow and next_dataflow.parameters else "  (None)"
        target_members_str = '\n'.join([f"  - {m}" for m in next_dataflow.member_variables]) if next_dataflow and next_dataflow.member_variables else "  (None)"

        # Build member variable hint if there are member variables in target
        member_hint = ""
        if next_dataflow and next_dataflow.member_variables:
            member_hint = f"""
**Note on `this` reference:** The `this` in the member variables above refers to the instance of {next_node.name}.
In `{current_node.name}`'s code, identify what object this instance corresponds to:
  - If called as xxx.{next_node.name}(...), then xxx is the instance of {next_node.name}
  - If called as this.{next_node.name}(...) or directly {next_node.name}(...), then {current_node.name} and {next_node.name} share the same this instance (e.g., methods in the same class)
You need to determine in {current_node.name}'s code exactly which object corresponds to this of {next_node.name}.
"""

        user_prompt = f"""# Analysis Context

**Vulnerability Type**: {path.vulnerability_type}

## *** CRITICAL: Known Data Flow ***

The following data flow has been confirmed through previous analysis:

**Source Fields (in `{current_node.name}`) that flow to sink:**

Parameters:
{source_params_str}

Member Variables:
{source_members_str}

**Target Fields (in `{next_node.name}`) that receive the data and eventually flow to sink:**

Parameters:
{target_params_str}

Member Variables:
{target_members_str}
{member_hint}
This means: `{current_node.name}`.sourceFields -> `{next_node.name}`.targetFields -> ... -> sink

## Current Function - `{current_node.name}` (Analyze This)
File: {current_node.file}
Source Code:
```
{current_node.source_code}
```

## Next Function - `{next_node.name}` (Reference Only)
File: {next_node.file}
Source Code:
```
{next_node.source_code}
```

# Your Task

Analyze the code in `{current_node.name}` to find ANY logic that could prevent the vulnerability from being exploited.

**Do NOT limit your analysis to security-specific code.** Look for ALL logic that could block exploitation, including:
- Security validation/sanitization (if any)
- Business logic that transforms or restricts the data before passing to `{next_node.name}`
- Conditional branches that might skip the call to `{next_node.name}`
- Data operations (concatenation, encoding, transformation) that change the value
- Any other logic affecting the source-to-target data flow

Output your findings in the specified format. The dataflow in output should be: `<sourceField -> targetField>`
where sourceField is from the source fields list and targetField is from the target fields list.
"""

    # Clear stream buffer and execute agent with streaming
    clear_stream()

    result = base_claude_agent(
        cwd=target_path,
        system_prompt=_ONE_HOP_FILTER_SYSTEM_PROMPT,
        user_prompt=user_prompt,
        stream_callback=stream_agent
    )

    if result is None:
        update_agent("one_hop_filter_agent", "error", "Agent returned no result")
        log_error("one_hop_filter_agent", "Agent returned no result")
        # Log the failed call
        log_agent_call(
            agent_name="one_hop_filter_agent",
            user_prompt=user_prompt,
            model_output=None,
            parsed_result="[] (agent returned no result)"
        )
        return []

    # Parse filter logic blocks
    filter_logics = _parse_filter_logics(result)

    update_agent("one_hop_filter_agent", "completed", f"Found {len(filter_logics)} blocking logic")
    log_success("one_hop_filter_agent", f"Found {len(filter_logics)} blocking logic")

    # Log the call
    parsed_result_str = str([f"FilterLogic(dataflow={f.dataflow}, description={f.description[:50]}..., file_path={f.file_path}, line_range={f.line_range})" for f in filter_logics])
    log_agent_call(
        agent_name="one_hop_filter_agent",
        user_prompt=user_prompt,
        model_output=result,
        parsed_result=parsed_result_str
    )

    return filter_logics


def _parse_filter_logics(text: str) -> List[FilterLogic]:
    """
    Parse filter logic blocks from agent response.

    Args:
        text: Agent response text

    Returns:
        List of FilterLogic objects
    """
    results = []

    # Find all filter logic blocks
    pattern = rf"{re.escape(MARKER_FILTER_START)}(.*?){re.escape(MARKER_FILTER_END)}"
    matches = re.findall(pattern, text, re.DOTALL)

    for match in matches:
        dataflow = _parse_marked_section(match, MARKER_DATAFLOW_START, MARKER_DATAFLOW_END)
        description = _parse_marked_section(match, MARKER_DESCRIPTION_START, MARKER_DESCRIPTION_END)
        file_path = _parse_marked_section(match, MARKER_FILE_START, MARKER_FILE_END)
        lines_str = _parse_marked_section(match, MARKER_LINES_START, MARKER_LINES_END)

        # Skip "None" entries
        if dataflow and dataflow.lower() == "none":
            continue

        if dataflow and description:
            line_range = _parse_line_range(lines_str) if lines_str else None
            results.append(FilterLogic(
                dataflow=dataflow,
                description=description,
                file_path=file_path or "Unknown",
                line_range=line_range
            ))

    return results


# =============================================================================
# Final Decision Agent
# =============================================================================

# System prompt for final decision
_FINAL_DECISION_SYSTEM_PROMPT = """
You are a senior security expert conducting a thorough vulnerability exploitation analysis.

# Task

Trace the complete data flow from source to sink, function by function, to determine whether this vulnerability is actually exploitable. Do NOT simply accept previous analysis results at face value - verify and think critically.

# Analysis Approach

You should analyze the call chain from source to sink, one function at a time:

1. **For each function in the chain**:
   - Start with the provided source code
   - Read additional files if needed to understand the full context (class members, called methods, etc.)
   - With the help of the provided analysis, trace how data flows through this function and identify any logic that might prevent exploitation
   - Form a intermediate conclusion and carry it to the next function

2. **Be critical of provided analysis**:
   - Previous analysis identified dataflows and potential blocking logic
   - These may be incomplete or incorrect - verify them yourself
   - A "blocking logic" identified earlier might be bypassable

3. **Think about exploitability**:
   - Can user input actually control the sink's key semantic (path/command)?
   - Are there any conditions, transformations, or logic that prevent exploitation?
   - Is the blocking logic effective, or can it be bypassed?

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

# Decision Guidelines

* **VULNERABLE**: User input can reach and control the sink's key semantic with no effective blocking, OR blocking logic can be bypassed.
* **NOT VULNERABLE**: There is effective logic that prevents exploitation and cannot be bypassed.

# Confidence Levels

* **High**: Clear evidence, thorough analysis, minimal ambiguity.
* **Medium**: Some uncertainty exists, but evidence leans in one direction.
* **Low**: Significant uncertainty, manual review strongly recommended.

# Important Rules

* **Do Your Own Analysis**: Do not blindly trust the provided dataflow/blocking logic analysis. Verify and think critically.
* **Read Files When Needed**: If you need more context, read the relevant files.
* **Think Step by Step**: Analyze function by function from source to sink.
* **Consider Bypass**: Even if blocking logic exists, consider whether it can be bypassed.
* **Stay Focused**: Only analyze THIS specific call chain and THIS vulnerability type. Do NOT investigate other potential vulnerabilities, other code paths, or unrelated security issues.

# Restrictions

* You are prohibited from performing any write operations.
""".strip()


def final_decision_agent(
    target_path: str,
    path: PotentialPath,
    dataflow_records: List[NodeDataflowRecord],
    filter_logics: List[FilterLogic]
) -> tuple:
    """
    Make the final vulnerability determination.

    This agent analyzes all collected information to determine whether
    the path represents an exploitable vulnerability.

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

    # Build call chain display with function names
    call_chain_display = _build_call_chain_display(path.path)

    # Build user prompt - organize by node, each with its own info
    user_prompt = f"""# Vulnerability Path Analysis

**Vulnerability Type**: {path.vulnerability_type}
**Sink Expression**: {path.sink_expression}

## Call Chain

{call_chain_display}

---

"""

    # Build per-node information
    for i, node in enumerate(path.path):
        # Find corresponding dataflow record
        record = None
        for r in dataflow_records:
            if r.node_index == i:
                record = r
                break

        # Find filter logics for this node
        node_filters = [f for f in filter_logics if any(
            node.name in f.dataflow or f.dataflow.startswith(f"<{node.name}") or f"->{node.name}" in f.dataflow.replace(" ", "")
            for _ in [1]
        )]
        # Actually find filters where the source is from this node
        node_filters = []
        if record:
            for f in filter_logics:
                # Check if any of this node's fields are in the dataflow
                for field in record.dataflow_info.parameters + record.dataflow_info.member_variables:
                    if field in f.dataflow:
                        node_filters.append(f)
                        break

        user_prompt += f"""## Node {i}: `{node.name}`

**File:** {node.file}

**Source Code:**
```
{node.source_code}
```

"""

        if record:
            # Build member variable hint if there are member variables with `this.`
            member_hint = ""
            if record.dataflow_info.member_variables:
                member_hint = f"""
**Note on `this`:** In the Dataflow below, `this` after `->` refers to the instance of the called function. E.g., `xxx.func()` means `this` = `xxx`; `this.func()` or direct `func()` means `this` = current function's instance. You need to determine what `this` actually refers to in this context."""

            user_prompt += f"""**Fields that flow to sink:**
- Parameters: {', '.join(record.dataflow_info.parameters) if record.dataflow_info.parameters else 'None'}
- Member Variables: {', '.join(record.dataflow_info.member_variables) if record.dataflow_info.member_variables else 'None'}
{member_hint}
"""

            if node_filters:
                user_prompt += f"""**Potential blocking logic in this function:**
(Dataflow format: `currentField -> nextField`, where nextField is from the NEXT node's fields that flow to sink)
"""
                for f in node_filters:
                    location = f.file_path
                    if f.line_range:
                        location += f" (lines {f.line_range[0]}-{f.line_range[1]})"
                    user_prompt += f"""- Dataflow: {f.dataflow}
  Description: {f.description}
  Location: {location}

"""
            else:
                user_prompt += """**Potential blocking logic in this function:** None identified

"""

        user_prompt += "---\n\n"

    user_prompt += f"""# Your Task

Starting from `{path.path[0].name}` (the source), trace the data flow function by function to the sink.

For each function:
1. Read the provided source code
2. Read additional files if you need more context
3. With the help of the provided analysis, verify how data flows through this function and Check if any identified blocking logic is actually effective (or bypassable)
4. Form a conclusion for this hop and proceed to the next

At the end, provide your final decision in the specified format.

**Remember:**
- Do not blindly trust the provided analysis - verify it yourself
- Blocking logic might be bypassable - think critically
- If you need more context, read the relevant files
"""

    # Clear stream buffer and execute agent with streaming
    clear_stream()

    result = base_claude_agent(
        cwd=target_path,
        system_prompt=_FINAL_DECISION_SYSTEM_PROMPT,
        user_prompt=user_prompt,
        stream_callback=stream_agent
    )

    if result is None:
        update_agent("final_decision_agent", "error", "Agent returned no result")
        log_error("final_decision_agent", "Agent returned no result")
        # Log the failed call
        log_agent_call(
            agent_name="final_decision_agent",
            user_prompt=user_prompt,
            model_output=None,
            parsed_result="(False, 'Low', 'Agent failed to produce result')"
        )
        return (False, "Low", "Agent failed to produce result")

    # Parse response
    decision_str = _parse_marked_section(result, MARKER_DECISION_START, MARKER_DECISION_END)
    confidence = _parse_marked_section(result, MARKER_CONFIDENCE_START, MARKER_CONFIDENCE_END)
    summary = _parse_marked_section(result, MARKER_SUMMARY_START, MARKER_SUMMARY_END)

    # Parse decision
    is_vulnerable = False
    if decision_str:
        is_vulnerable = decision_str.upper().strip() == "VULNERABLE"

    # Normalize confidence
    if confidence:
        confidence = confidence.capitalize()
        if confidence not in ["High", "Medium", "Low"]:
            confidence = "Low"
    else:
        confidence = "Low"

    # Handle None values
    summary = summary or "No summary provided"

    decision_text = "VULNERABLE" if is_vulnerable else "NOT VULNERABLE"
    update_agent("final_decision_agent", "completed", f"Decision: {decision_text} ({confidence})")
    log_success("final_decision_agent", f"Decision: {decision_text} (confidence: {confidence})")

    # Log the call
    log_agent_call(
        agent_name="final_decision_agent",
        user_prompt=user_prompt,
        model_output=result,
        parsed_result=f"(is_vulnerable={is_vulnerable}, confidence='{confidence}', summary='{summary}')"
    )

    return (is_vulnerable, confidence, summary)
