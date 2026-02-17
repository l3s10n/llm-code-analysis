"""
Agent functions for vulnerability path verification.

These functions encapsulate Claude Code SDK calls for specific verification tasks.
Each agent performs a specialized analysis task and returns structured results.
"""

import re
from typing import List, Optional

from common.base_claude_agent import base_claude_agent
from common.tui import log_info, log_success, log_error, update_agent, stream_agent, clear_stream

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
You are a security expert specializing in data flow analysis.

# Task

Analyze the data flow from the current function to the sink, determining which parameters and member variables of the current function flow to the sink's key semantics (path for PathTraversal, command for CommandInjection).

# Important Concepts

* **Current Function**: The function you are analyzing, which calls the next function in the chain.
* **Next Function**: The function that is directly called by the current function, leading eventually to the sink.
* **Sink Semantics**: The critical data that determines the security impact:
  - For PathTraversal: The file path being accessed
  - For CommandInjection: The command being executed

# Input Format

You will receive:
1. The vulnerability type (PathTraversal or CommandInjection)
2. The sink expression
3. The call chain with function names
4. Information about what in the next function flows to sink semantics (from previous analysis)
5. Source code of current function and next function

# Output Format

Analyze the data flow and output your findings in this format:

```plaintext
--- parameters start ---
<parameter1>
<parameter2>
--- parameters end ---

--- member variables start ---
<memberVariable1>
<memberVariable2>
--- member variables end ---
```

If there are no parameters or member variables that flow to sink semantics, write "None" in that section.

# Parameter/Member Variable Format

Use the following format for each item:
- For parameters: `paramName` or `paramName.field.subfield` if accessing nested fields
- For member variables: `this.memberName` or `this.memberName.field.subfield`
- For static methods, you can ignore member variables

# Important Rules

* **Focus on Current -> Next**: Only analyze how the current function's inputs flow to the next function's inputs. Do not re-verify next -> ... -> sink.
* **Data Flow Only**: Track where data comes from. Do not consider security filtering or sanitization.
* **Complete Tracing**: Trace all paths from the current function's inputs to the identified inputs of the next function.
* **Be Precise**: Only list parameters and member variables that actually flow to sink semantics.
* **Edge Case for Sink**: If the current function is directly the sink's caller (last hop before sink), analyze what in it flows to the sink's key parameter.

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

    # Build the call chain display
    call_chain_display = _build_call_chain_display(path.path)

    # Mark current position in the chain
    chain_parts = call_chain_display.split(" -> ")
    chain_parts[node_index] = f"{current_node.name} (current)"
    if node_index + 1 < len(chain_parts):
        chain_parts[node_index + 1] = f"{path.path[node_index + 1].name if node_index + 1 < len(path.path) else 'sink'} (next)" if not is_last_node else "sink"
    current_chain_display = " -> ".join(chain_parts)

    # Build user prompt
    user_prompt = f"""# Analysis Context

**Vulnerability Type**: {path.vulnerability_type}
**Sink Expression**: {path.sink_expression}

## Current Call Chain
{current_chain_display}

## Full Call Chain
{call_chain_display}

## Current Function - `{current_node.name}` (Node {node_index})
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
## Next Function - `{next_node.name}` (Node {node_index + 1})
File: {next_node.file}
Source Code:
```
{next_node.source_code}
```
"""
        # Add dataflow info from next node's analysis
        if next_node_dataflow:
            user_prompt += f"""
## What in `{next_node.name}` Flows to Sink Semantics
From previous analysis, the following in `{next_node.name}` flow to sink semantics:
- Parameters: {', '.join(next_node_dataflow.parameters) if next_node_dataflow.parameters else 'None'}
- Member Variables: {', '.join(next_node_dataflow.member_variables) if next_node_dataflow.member_variables else 'None'}
"""
    else:
        # This is the last node - directly analyze what flows to sink
        user_prompt += f"""
## Sink Information
This function directly calls the sink: `{path.sink_expression}`
Analyze which parameters and member variables of `{current_node.name}` flow to the sink's key semantics (path/command).
"""

    user_prompt += f"""
# Your Task

Analyze the data flow and determine which parameters and member variables of `{current_node.name}` flow to the sink's key semantics.
Output your findings in the specified format.
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

    return dataflow_info


# =============================================================================
# One Hop Filter Agent
# =============================================================================

# System prompt for filter analysis
_ONE_HOP_FILTER_SYSTEM_PROMPT = """
You are a security expert specializing in vulnerability analysis.

# Task

Analyze the code in the current function (the calling function) to identify any filtering or sanitization logic that could prevent the vulnerability from being exploited.

# Input Format

You will receive:
1. The vulnerability type (PathTraversal or CommandInjection)
2. The data flow information (which inputs of the current function flow to the sink)
3. Source code of the current function (the calling function) - ANALYZE THIS
4. Source code of the next function (the called function) - FOR REFERENCE ONLY

# Important Concepts

* **Current Function Analysis**: Focus ONLY on the code in the current function before and during the call to the next function.
* **Filter Logic**: Any code that could:
  - Validate or sanitize the input
  - Restrict the range of acceptable values
  - Transform the input in a way that prevents exploitation
  - Check conditions that might prevent the vulnerable path from being reached

# Output Format

For EACH filtering logic found, output:

```plaintext
--- filter logic start ---
--- dataflow start ---
<currentFunction.field -> nextFunction.field>
--- dataflow end ---

--- description start ---
<What the filter does and how it might prevent exploitation>
--- description end ---

--- file start ---
<file path>
--- file end ---

--- lines start ---
<start_line>-<end_line> or just <line_number>
--- lines end ---
--- filter logic end ---
```

If no filtering logic is found that could prevent exploitation, output:

```plaintext
--- filter logic start ---
--- dataflow start ---
None
--- dataflow end ---

--- description start ---
No filtering logic found
--- description end ---

--- file start ---
None
--- file end ---

--- lines start ---
None
--- lines end ---
--- filter logic end ---
```

# Important Rules

* **Scope Limitation**: Only analyze the current function's code. The next function's code is provided for reference only - do not analyze its internal logic.
* **Call Site Focus**: Focus on code before the call to the next function and at the call site itself.
* **Relevance**: Only report filters that affect the data flow from the current function to the next function.
* **Be Specific**: Provide exact file paths and line numbers when possible.
* **Conservative Approach**: When in doubt, include potential filters rather than exclude them.

# Restrictions

* You are prohibited from performing any write operations.
""".strip()


def one_hop_filter_agent(
    target_path: str,
    path: PotentialPath,
    node_index: int,
    x_dataflow: DataflowInfo,
    y_dataflow: Optional[DataflowInfo] = None
) -> List[FilterLogic]:
    """
    Analyze filtering logic between two adjacent nodes.

    This agent analyzes the code in the current node to find any filtering
    logic that could prevent exploitation between it and the next node.

    Args:
        target_path: Path to the target project's source code.
        path: PotentialPath containing the call chain.
        node_index: Index of the current node being analyzed (0-based).
        x_dataflow: DataflowInfo for current node (what flows to sink).
        y_dataflow: DataflowInfo for next node (what flows to sink).
                   For the sink's direct caller, this is None.

    Returns:
        List of FilterLogic objects representing potential filters found.
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
    log_info("one_hop_filter_agent", f"Analyzing filters in: {current_node.name}")

    # Build user prompt
    user_prompt = f"""# Analysis Context

**Vulnerability Type**: {path.vulnerability_type}
**Sink Expression**: {path.sink_expression}

## Current Analysis: `{current_node.name}` -> `{'sink' if is_last_node else path.path[node_index + 1].name}`

You are analyzing `{current_node.name}` and its call to the `{'sink' if is_last_node else path.path[node_index + 1].name}`.

## Data Flow Information

The following in `{current_node.name}` flow to the sink's key semantics:
- Parameters: {', '.join(x_dataflow.parameters) if x_dataflow.parameters else 'None'}
- Member Variables: {', '.join(x_dataflow.member_variables) if x_dataflow.member_variables else 'None'}

## Current Function - `{current_node.name}` (Source Code to Analyze)
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
## Next Function - `{next_node.name}` (Reference Only - Do Not Analyze Internals)
File: {next_node.file}
Source Code:
```
{next_node.source_code}
```
"""
        if y_dataflow:
            user_prompt += f"""
Note: The following in `{next_node.name}` were identified as flowing to sink:
- Parameters: {', '.join(y_dataflow.parameters) if y_dataflow.parameters else 'None'}
- Member Variables: {', '.join(y_dataflow.member_variables) if y_dataflow.member_variables else 'None'}
"""
    else:
        user_prompt += """
## Note
This function directly calls the sink. Analyze the code for any filtering before the sink call.
"""

    user_prompt += f"""
# Your Task

Analyze the code in `{current_node.name}` to find any filtering or sanitization logic that could prevent exploitation.
Focus on the data flow identified above.
Output your findings in the specified format.
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
        return []

    # Parse filter logic blocks
    filter_logics = _parse_filter_logics(result)

    update_agent("one_hop_filter_agent", "completed", f"Found {len(filter_logics)} filter(s)")
    log_success("one_hop_filter_agent", f"Found {len(filter_logics)} filtering logic")

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
You are a senior security expert making the final determination on whether a vulnerability is exploitable.

# Task

Based on the complete analysis of a potential vulnerability path, determine whether the vulnerability is actually exploitable.

# Input Format

You will receive:
1. The vulnerability type and sink expression
2. The complete call chain with source code
3. Dataflow analysis for each node
4. Filtering logic found during analysis

# Output Format

Provide your final decision in this format:

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

--- reasoning start ---
<Detailed reasoning for the decision, considering:
1. Whether user input reaches the sink
2. Whether any filters effectively prevent exploitation
3. Any other relevant security considerations>
--- reasoning end ---
```

# Decision Guidelines

* **VULNERABLE**: User input reaches the sink with NO effective filtering that prevents exploitation.
* **NOT VULNERABLE**: Either user input does not reach the sink, OR there is effective filtering that prevents exploitation.

# Confidence Levels

* **High**: Clear evidence one way or the other, minimal ambiguity.
* **Medium**: Some uncertainty exists, but the evidence leans in one direction.
* **Low**: Significant uncertainty, manual review strongly recommended.

# Important Rules

* **Focus on This Path**: Only analyze THIS specific call chain and THIS vulnerability type.
* **Consider All Filters**: Evaluate whether the identified filters are effective.
* **Be Decisive**: Make a clear decision; do not hedge.
* **Document Reasoning**: Provide clear reasoning that can be followed by a human reviewer.

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
        Tuple of (is_vulnerable: bool, confidence: str, summary: str, reasoning: str)
    """
    update_agent("final_decision_agent", "running", "Making final determination")
    log_info("final_decision_agent", "Making final vulnerability determination")

    # Build call chain display
    call_chain_display = _build_call_chain_display(path.path)

    # Build user prompt
    user_prompt = f"""# Vulnerability Path Analysis

**Vulnerability Type**: {path.vulnerability_type}
**Sink Expression**: {path.sink_expression}
**Call Chain**: {call_chain_display}

## Complete Call Chain with Source Code

{_build_path_info_section(path.path)}

## Dataflow Analysis Results

"""

    for record in dataflow_records:
        user_prompt += f"""### Node [{record.node_index}]: {record.node_name}
- Parameters flowing to sink: {', '.join(record.dataflow_info.parameters) if record.dataflow_info.parameters else 'None'}
- Member variables flowing to sink: {', '.join(record.dataflow_info.member_variables) if record.dataflow_info.member_variables else 'None'}

"""

    user_prompt += """## Filtering Logic Found

"""
    if filter_logics:
        for i, logic in enumerate(filter_logics, 1):
            location = logic.file_path
            if logic.line_range:
                location += f" (lines {logic.line_range[0]}-{logic.line_range[1]})"
            user_prompt += f"""### Filter #{i}
- Dataflow affected: {logic.dataflow}
- Description: {logic.description}
- Location: {location}

"""
    else:
        user_prompt += "No filtering logic was identified.\n\n"

    user_prompt += """# Your Task

Based on all the information above, make a final determination on whether this vulnerability path is exploitable.
Consider:
1. Does user input actually reach the sink?
2. Are there any effective filters that prevent exploitation?
3. What is your confidence level in this determination?

Output your decision in the specified format.
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
        return (False, "Low", "Agent failed to produce result", "")

    # Parse response
    decision_str = _parse_marked_section(result, MARKER_DECISION_START, MARKER_DECISION_END)
    confidence = _parse_marked_section(result, MARKER_CONFIDENCE_START, MARKER_CONFIDENCE_END)
    summary = _parse_marked_section(result, MARKER_SUMMARY_START, MARKER_SUMMARY_END)
    reasoning = _parse_marked_section(result, MARKER_REASONING_START, MARKER_REASONING_END)

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
    reasoning = reasoning or "No reasoning provided"

    decision_text = "VULNERABLE" if is_vulnerable else "NOT VULNERABLE"
    update_agent("final_decision_agent", "completed", f"Decision: {decision_text} ({confidence})")
    log_success("final_decision_agent", f"Decision: {decision_text} (confidence: {confidence})")

    return (is_vulnerable, confidence, summary, reasoning)
