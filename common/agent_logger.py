"""
Agent Logger module for GOLD MINER.

Provides logging functionality for recording base_claude_agent input/output
during path_explore and path_verify operations.
"""

import os
from datetime import datetime
from pathlib import Path
from typing import Optional
from threading import Lock


# =============================================================================
# Global Logger Instance
# =============================================================================

_logger_instance: Optional['AgentLogger'] = None
_logger_lock = Lock()


# =============================================================================
# AgentLogger Class
# =============================================================================

class AgentLogger:
    """
    Logger for recording agent calls and their results.

    This logger creates log files that record each agent call with:
    - Agent name
    - User prompt (input)
    - Model output
    - Parsed return value

    Log files are stored at:
    - path_explore: logs/<project_name>/path_explore_logs/<interface_name>_<timestamp>.log
    - path_verify: logs/<project_name>/path_verify_logs/<interface_name>_<timestamp>.log
    """

    # Large separator between different agent calls
    CALL_SEPARATOR = "\n\n" + "=" * 80 + "\n" + "=" * 80 + "\n\n"

    # Separator within a single agent call
    SECTION_SEPARATOR = "\n" + "-" * 80 + "\n"

    def __init__(
        self,
        project_name: str,
        interface_name: str,
        log_type: str,
        base_dir: str = "logs"
    ):
        """
        Initialize the AgentLogger.

        Args:
            project_name: Name of the target project
            interface_name: Name of the target interface/endpoint
            log_type: Type of logging - either "path_explore" or "path_verify"
            base_dir: Base directory for logs (default: "logs")
        """
        self.project_name = project_name
        self.interface_name = interface_name
        self.log_type = log_type
        self.base_dir = base_dir

        # Generate timestamp for this session
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Build log file path
        self.log_file_path = self._build_log_path()

        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(self.log_file_path), exist_ok=True)

        # Initialize log file with header
        self._write_header()

    def _build_log_path(self) -> str:
        """
        Build the log file path based on log type.

        Returns:
            Full path to the log file
        """
        # Sanitize interface name for filename
        safe_interface_name = self.interface_name.strip('/').replace('/', '_')
        if not safe_interface_name:
            safe_interface_name = "root"

        # Build path based on log type
        if self.log_type == "path_explore":
            log_subdir = "path_explore_logs"
        elif self.log_type == "path_verify":
            log_subdir = "path_verify_logs"
        else:
            log_subdir = f"{self.log_type}_logs"

        # Filename: <interface_name>_<timestamp>.log
        filename = f"{safe_interface_name}_{self.timestamp}.log"

        # Full path: logs/<project_name>/<log_subdir>/<filename>
        log_path = Path(self.base_dir) / self.project_name / log_subdir / filename

        return str(log_path)

    def _write_header(self) -> None:
        """Write the header to the log file."""
        header = f"""GOLD MINER Agent Log
{'=' * 80}
Project: {self.project_name}
Interface: {self.interface_name}
Log Type: {self.log_type}
Timestamp: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
{'=' * 80}

"""
        with open(self.log_file_path, 'w', encoding='utf-8') as f:
            f.write(header)

    def log_agent_call(
        self,
        agent_name: str,
        user_prompt: str,
        model_output: Optional[str],
        parsed_result: str
    ) -> None:
        """
        Log a single agent call.

        Args:
            agent_name: Name of the agent function (e.g., "source_info_find_agent")
            user_prompt: The user prompt sent to the agent
            model_output: The raw output from the model (can be None if failed)
            parsed_result: The parsed result returned by the agent function
        """
        # Format the log entry
        entry = self._format_log_entry(agent_name, user_prompt, model_output, parsed_result)

        # Append to log file
        with open(self.log_file_path, 'a', encoding='utf-8') as f:
            f.write(entry)

    def _format_log_entry(
        self,
        agent_name: str,
        user_prompt: str,
        model_output: Optional[str],
        parsed_result: str
    ) -> str:
        """
        Format a log entry for a single agent call.

        Args:
            agent_name: Name of the agent
            user_prompt: The user prompt
            model_output: The model's raw output
            parsed_result: The parsed result

        Returns:
            Formatted log entry string
        """
        # Handle None model output
        model_output_str = model_output if model_output else "(No output - agent returned None)"

        # Build entry with explicit line control for clean formatting
        # Note: SECTION_SEPARATOR has leading newline, so no \n needed after labels
        entry = (
            f"{self.CALL_SEPARATOR}"
            f"AGENT CALL: {agent_name}"
            f"{self.SECTION_SEPARATOR}"
            f">>> USER PROMPT (INPUT):"
            f"{self.SECTION_SEPARATOR}"
            f"{user_prompt}"
            f"{self.SECTION_SEPARATOR}"
            f">>> MODEL OUTPUT:"
            f"{self.SECTION_SEPARATOR}"
            f"{model_output_str}"
            f"{self.SECTION_SEPARATOR}"
            f">>> PARSED RESULT:"
            f"{self.SECTION_SEPARATOR}"
            f"{parsed_result}"
            f"{self.SECTION_SEPARATOR}"
        )
        return entry


# =============================================================================
# Public Functions
# =============================================================================

def init_logger(
    project_name: str,
    interface_name: str,
    log_type: str
) -> AgentLogger:
    """
    Initialize the global logger instance.

    This function should be called once at the start of path_explore or path_verify.

    Args:
        project_name: Name of the target project
        interface_name: Name of the target interface/endpoint
        log_type: Type of logging - either "path_explore" or "path_verify"

    Returns:
        The initialized AgentLogger instance
    """
    global _logger_instance

    with _logger_lock:
        _logger_instance = AgentLogger(
            project_name=project_name,
            interface_name=interface_name,
            log_type=log_type
        )

    return _logger_instance


def get_logger() -> Optional[AgentLogger]:
    """
    Get the current global logger instance.

    Returns:
        The current AgentLogger instance, or None if not initialized
    """
    return _logger_instance


def log_agent_call(
    agent_name: str,
    user_prompt: str,
    model_output: Optional[str],
    parsed_result: str
) -> None:
    """
    Log an agent call using the global logger.

    This is a convenience function that uses the global logger instance.
    If the logger is not initialized, this function does nothing.

    Args:
        agent_name: Name of the agent function
        user_prompt: The user prompt sent to the agent
        model_output: The raw output from the model
        parsed_result: The parsed result returned by the agent function
    """
    global _logger_instance

    if _logger_instance is not None:
        _logger_instance.log_agent_call(
            agent_name=agent_name,
            user_prompt=user_prompt,
            model_output=model_output,
            parsed_result=parsed_result
        )


def close_logger() -> None:
    """
    Close and clear the global logger instance.

    This should be called when the logging session is complete.
    """
    global _logger_instance

    with _logger_lock:
        _logger_instance = None
