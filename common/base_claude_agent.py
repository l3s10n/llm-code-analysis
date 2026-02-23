"""
Base Claude Agent module for VulSolver.

Provides a wrapper around Claude Agent SDK for executing AI-powered analysis tasks.
Supports streaming output via callback function, result caching, timeout handling,
and automatic retry on failure.
"""

import asyncio
import hashlib
import json
import os
import time
import warnings
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional, Callable, List

from claude_agent_sdk import query, ClaudeAgentOptions
from claude_agent_sdk.types import StreamEvent

from .config import load_config


# =============================================================================
# Agent Result Data Class
# =============================================================================

@dataclass
class AgentResult:
    """
    Result from base_claude_agent execution.

    Attributes:
        result: The agent's output string, or None if failed
        success: Whether the agent execution was successful
        error_type: Type of error if failed (timeout, empty_result, agent_failure)
        error_message: Detailed error message if failed
    """
    result: Optional[str]
    success: bool
    error_type: Optional[str] = None
    error_message: Optional[str] = None


# =============================================================================
# Environment Initialization
# =============================================================================

os.environ["ANTHROPIC_AUTH_TOKEN"] = load_config("llm.api_key")
os.environ["ANTHROPIC_BASE_URL"] = load_config("llm.base_url")
os.environ["API_TIMEOUT_MS"] = "3000000"
os.environ["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"] = "1"
os.environ["CLAUDE_CODE_DISABLE_BANNER"] = "1"
os.environ["NO_BANNER"] = "1"  # Generic banner disable
os.environ["ANTHROPIC_DEFAULT_HAIKU_MODEL"] = load_config("llm.model")
os.environ["ANTHROPIC_DEFAULT_SONNET_MODEL"] = load_config("llm.model")
os.environ["ANTHROPIC_DEFAULT_OPUS_MODEL"] = load_config("llm.model")


# =============================================================================
# Default Configuration
# =============================================================================

DEFAULT_ALLOWED_TOOLS = ['Bash', 'Read', 'Glob', 'Grep']
DEFAULT_MODEL = 'Opus'
CACHE_DIR = Path("cache")

# Global context for error file generation
# These are set by path_explore/explorer.py and path_verify/verify.py
_error_context_project: Optional[str] = None
_error_context_interface: Optional[str] = None


# =============================================================================
# Error Context Management
# =============================================================================

def set_error_context(project_name: str, interface_name: str) -> None:
    """
    Set the global context for error file generation.

    This function should be called by path_explore and path_verify modules
    before starting their main execution to enable proper error file generation.

    Args:
        project_name: Name of the project being analyzed
        interface_name: Name of the interface/endpoint being analyzed
    """
    global _error_context_project, _error_context_interface
    _error_context_project = project_name
    _error_context_interface = interface_name


def clear_error_context() -> None:
    """
    Clear the global error context.

    Should be called after analysis is complete.
    """
    global _error_context_project, _error_context_interface
    _error_context_project = None
    _error_context_interface = None


def create_error_file(agent_name: str, agent_result: AgentResult) -> Path:
    """
    Create an error file in the results directory.

    This function is called when agent execution fails after all retries,
    to record the failure for debugging and analysis purposes.

    Args:
        agent_name: Name of the agent that failed
        agent_result: The failed AgentResult containing error details

    Returns:
        Path to the created error file
    """
    # Determine error file path
    if _error_context_project and _error_context_interface:
        error_file_path = Path("results") / _error_context_project / _error_context_interface / "error.json"
    else:
        # Fallback: create error file in results directory with timestamp
        error_file_path = Path("results") / f"error_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

    # Ensure parent directory exists
    error_file_path.parent.mkdir(parents=True, exist_ok=True)

    # Load retry configuration for error info
    try:
        max_retries = load_config("agent.max_retries")
    except (KeyError, TypeError):
        max_retries = 3

    error_data = {
        "error": True,
        "agent_name": agent_name,
        "error_type": agent_result.error_type,
        "error_message": agent_result.error_message,
        "timestamp": datetime.now().isoformat(),
        "project_name": _error_context_project,
        "interface_name": _error_context_interface,
        "max_retries": max_retries,
        "result_preview": agent_result.result[:500] if agent_result.result else None
    }

    with open(error_file_path, 'w', encoding='utf-8') as f:
        json.dump(error_data, f, indent=2, ensure_ascii=False)

    return error_file_path


# =============================================================================
# Cache Functions
# =============================================================================

def _ensure_cache_dir() -> Path:
    """
    Ensure the cache directory exists.

    Returns:
        Path object pointing to the cache directory.
    """
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    return CACHE_DIR


def _generate_cache_key(
    cwd: str,
    system_prompt: str,
    user_prompt: str,
    allowed_tools: List[str],
    model: str
) -> str:
    """
    Generate a unique cache key based on the input parameters.

    Args:
        cwd: Working directory for the agent.
        system_prompt: System prompt text.
        user_prompt: User prompt text.
        allowed_tools: List of allowed tool names.
        model: Model name.

    Returns:
        A SHA256 hash string used as the cache key.
    """
    # Normalize the absolute path of cwd
    abs_cwd = os.path.abspath(cwd)

    # Create a deterministic string from all parameters
    # Sort allowed_tools to ensure consistent ordering
    sorted_tools = sorted(allowed_tools) if allowed_tools else []

    cache_content = json.dumps({
        "cwd": abs_cwd,
        "system_prompt": system_prompt,
        "user_prompt": user_prompt,
        "allowed_tools": sorted_tools,
        "model": model
    }, sort_keys=True, ensure_ascii=False)

    # Generate SHA256 hash
    return hashlib.sha256(cache_content.encode('utf-8')).hexdigest()


def _get_cache_file_path(cache_key: str) -> Path:
    """
    Get the file path for a given cache key.

    Args:
        cache_key: The SHA256 hash key.

    Returns:
        Path object pointing to the cache file.
    """
    return _ensure_cache_dir() / f"{cache_key}.json"


def _load_cache(cache_key: str) -> Optional[str]:
    """
    Load cached result from disk.

    Args:
        cache_key: The SHA256 hash key.

    Returns:
        The cached result string, or None if cache doesn't exist.
    """
    cache_file = _get_cache_file_path(cache_key)

    if not cache_file.exists():
        return None

    try:
        with open(cache_file, 'r', encoding='utf-8') as f:
            cache_data = json.load(f)
            return cache_data.get("result")
    except (json.JSONDecodeError, IOError, KeyError):
        # If cache file is corrupted, return None
        return None


def _save_cache(cache_key: str, result: Optional[str]) -> None:
    """
    Save result to cache.

    Args:
        cache_key: The SHA256 hash key.
        result: The result string to cache.
    """
    cache_file = _get_cache_file_path(cache_key)

    try:
        cache_data = {
            "result": result
        }
        with open(cache_file, 'w', encoding='utf-8') as f:
            json.dump(cache_data, f, ensure_ascii=False, indent=2)
    except IOError:
        # Silently fail if cache cannot be saved
        pass


# =============================================================================
# Private Implementation Function
# =============================================================================

def _base_claude_agent_impl(
    cwd: str,
    system_prompt: str,
    user_prompt: str,
    allowed_tools: Optional[list] = None,
    model: str = DEFAULT_MODEL,
    stream_callback: Optional[Callable[[str], None]] = None,
    use_cache: bool = True
) -> Optional[str]:
    """
    Execute a Claude agent with the given prompts and configuration.

    This is the internal implementation function that performs the actual
    agent execution without retry logic.

    Args:
        cwd: Working directory for the agent to operate in.
        system_prompt: System prompt to set the agent's behavior and context.
        user_prompt: User prompt containing the task to execute.
        allowed_tools: List of tools that the agent is allowed to use.
                      Defaults to ['Bash', 'Read', 'Glob', 'Grep'].
        model: Model to use for the agent. Defaults to 'Opus'.
        stream_callback: Optional callback function for streaming output.
                        Called with each text chunk as it arrives.
        use_cache: Whether to use caching. Defaults to True.

    Returns:
        Optional[str]: The result from the agent execution, or None if no result.
    """
    if allowed_tools is None:
        allowed_tools = DEFAULT_ALLOWED_TOOLS

    # Generate cache key and check cache
    cache_key = _generate_cache_key(cwd, system_prompt, user_prompt, allowed_tools, model)

    if use_cache:
        cached_result = _load_cache(cache_key)
        if cached_result is not None:
            # Notify via stream callback if provided
            if stream_callback:
                stream_callback("\n[Using cached result]\n")
            return cached_result

    async def _invoke_claude_agent() -> Optional[str]:
        """Async inner function to execute the agent."""
        # Suppress banner by providing empty stderr handler
        def _suppress_stderr(text: str) -> None:
            pass  # Do nothing - suppress all stderr output including banners

        options = ClaudeAgentOptions(
            system_prompt=system_prompt,
            allowed_tools=allowed_tools,
            permission_mode="bypassPermissions",
            cwd=cwd,
            model=model,
            include_partial_messages=True,
            stderr=_suppress_stderr  # Suppress stderr output (including banner)
        )

        result = None
        gen = query(prompt=user_prompt, options=options)

        try:
            # Consume all messages naturally (no early break)
            async for message in gen:
                if isinstance(message, StreamEvent):
                    event = message.event
                    event_type = event.get("type")

                    if event_type == "content_block_delta":
                        delta = event.get("delta", {})
                        if delta.get("type") == "text_delta":
                            text_chunk = delta.get("text", "")
                            # Call stream callback if provided
                            if stream_callback and text_chunk:
                                stream_callback(text_chunk)

                    if event_type == "content_block_start":
                        content_block = event.get("content_block", {})
                        if content_block.get("type") == "tool_use":
                            current_tool = content_block.get("name")
                            # Notify about tool usage
                            if stream_callback:
                                stream_callback(f"\n[Using tool: {current_tool}]\n")

                if hasattr(message, "result"):
                    result = message.result
        finally:
            # Close the generator
            await gen.aclose()

        return result

    # Suppress anyio ResourceWarning for unclosed streams (SDK internal behavior)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", ResourceWarning)
        result = asyncio.run(_invoke_claude_agent())

    # Save result to cache if caching is enabled
    if use_cache:
        _save_cache(cache_key, result)

    return result


# =============================================================================
# Public Function with Retry Logic
# =============================================================================

def base_claude_agent(
    cwd: str,
    system_prompt: str,
    user_prompt: str,
    allowed_tools: Optional[list] = None,
    model: str = DEFAULT_MODEL,
    stream_callback: Optional[Callable[[str], None]] = None,
    use_cache: bool = True
) -> AgentResult:
    """
    Execute a Claude agent with retry logic and timeout handling.

    This function wraps _execute_with_timeout with:
    1. Timeout enforcement - kills agents that exceed configured timeout
    2. Result validation - retries if result is None or too short (< 10 chars)
    3. Configurable retry attempts from config.yaml

    Args:
        cwd: Working directory for the agent to operate in.
        system_prompt: System prompt to set the agent's behavior and context.
        user_prompt: User prompt containing the task to execute.
        allowed_tools: List of tools that the agent is allowed to use.
                      Defaults to ['Bash', 'Read', 'Glob', 'Grep'].
        model: Model to use for the agent. Defaults to 'Opus'.
        stream_callback: Optional callback function for streaming output.
                        Called with each text chunk as it arrives.
        use_cache: Whether to use caching. Defaults to True.

    Returns:
        AgentResult: Contains result string (or None if failed), success status,
                    and error information if failed.
    """

    # Load retry configuration
    try:
        timeout_seconds = load_config("agent.timeout_seconds")
        max_retries = load_config("agent.max_retries")
    except (KeyError, TypeError):
        # Fallback to defaults if config is not available
        timeout_seconds = 300  # 5 minutes default
        max_retries = 3

    last_error_type = "unknown"
    last_error_message = "Unknown error"
    last_result = None

    for attempt in range(max_retries + 1):
        try:
            # Execute with timeout
            # On first attempt: read from cache if available
            # On retry: don't read from cache (to avoid getting same invalid result)
            use_cache_this_attempt = use_cache and (attempt == 0)

            start_time = time.time()
            result, cache_key = _execute_with_timeout(
                cwd=cwd,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                allowed_tools=allowed_tools,
                model=model,
                stream_callback=stream_callback,
                use_cache=use_cache_this_attempt,
                timeout_seconds=timeout_seconds
            )
            elapsed_time = time.time() - start_time

            # Check if result is valid (not None and has meaningful content)
            if result is None:
                last_error_type = "empty_result"
                last_error_message = "Agent returned None"
                last_result = None
                if attempt < max_retries:
                    continue
            elif len(result) < 10:
                last_error_type = "empty_result"
                last_error_message = f"Agent returned result with only {len(result)} characters (minimum 10 required)"
                last_result = result
                if attempt < max_retries:
                    continue

            # Success - save to cache if caching is enabled, then return the result
            if use_cache:
                _save_cache(cache_key, result)
            return AgentResult(result=result, success=True)

        except TimeoutError as e:
            last_error_type = "timeout"
            last_error_message = f"Agent execution exceeded timeout of {timeout_seconds} seconds"
            last_result = None
            if attempt < max_retries:
                continue

        except Exception as e:
            last_error_type = "agent_failure"
            last_error_message = f"{type(e).__name__}: {str(e)}"
            last_result = None
            if attempt < max_retries:
                continue

    # All retries exhausted - return failure result
    error_msg = f"All {max_retries + 1} attempts failed. Last error: {last_error_message}"
    return AgentResult(
        result=None,
        success=False,
        error_type=last_error_type,
        error_message=error_msg
    )


def _execute_with_timeout(
    cwd: str,
    system_prompt: str,
    user_prompt: str,
    allowed_tools: Optional[list],
    model: str,
    stream_callback: Optional[Callable[[str], None]],
    use_cache: bool,
    timeout_seconds: int
) -> tuple[Optional[str], str]:
    """
    Execute the agent with a timeout.

    This function wraps the async agent execution with a timeout mechanism
    that will cancel the operation if it exceeds the specified duration.

    Note: This function does NOT save to cache. The caller (base_claude_agent)
    is responsible for saving to cache only after validating the result.

    Args:
        cwd: Working directory for the agent.
        system_prompt: System prompt text.
        user_prompt: User prompt text.
        allowed_tools: List of allowed tool names.
        model: Model name.
        stream_callback: Optional callback for streaming output.
        use_cache: Whether to read from cache (if available).
        timeout_seconds: Maximum execution time in seconds.

    Returns:
        A tuple of (result, cache_key) where:
        - result: The result from the agent execution
        - cache_key: The cache key for this execution (for caller to save later)

    Raises:
        TimeoutError: If execution exceeds the timeout.
    """
    if allowed_tools is None:
        allowed_tools = DEFAULT_ALLOWED_TOOLS

    # Generate cache key and check cache first
    cache_key = _generate_cache_key(cwd, system_prompt, user_prompt, allowed_tools, model)

    if use_cache:
        cached_result = _load_cache(cache_key)
        if cached_result is not None:
            if stream_callback:
                stream_callback("\n[Using cached result]\n")
            return cached_result, cache_key

    async def _invoke_with_timeout() -> Optional[str]:
        """Async function to execute agent with timeout."""

        async def _run_agent() -> Optional[str]:
            """The actual agent execution."""
            def _suppress_stderr(text: str) -> None:
                pass

            options = ClaudeAgentOptions(
                system_prompt=system_prompt,
                allowed_tools=allowed_tools,
                permission_mode="bypassPermissions",
                cwd=cwd,
                model=model,
                include_partial_messages=True,
                stderr=_suppress_stderr
            )

            result = None
            gen = query(prompt=user_prompt, options=options)

            try:
                async for message in gen:
                    if isinstance(message, StreamEvent):
                        event = message.event
                        event_type = event.get("type")

                        if event_type == "content_block_delta":
                            delta = event.get("delta", {})
                            if delta.get("type") == "text_delta":
                                text_chunk = delta.get("text", "")
                                if stream_callback and text_chunk:
                                    stream_callback(text_chunk)

                        if event_type == "content_block_start":
                            content_block = event.get("content_block", {})
                            if content_block.get("type") == "tool_use":
                                current_tool = content_block.get("name")
                                if stream_callback:
                                    stream_callback(f"\n[Using tool: {current_tool}]\n")

                    if hasattr(message, "result"):
                        result = message.result
            finally:
                await gen.aclose()

            return result

        # Execute with timeout using asyncio.wait_for
        try:
            result = await asyncio.wait_for(
                _run_agent(),
                timeout=timeout_seconds
            )
            return result
        except asyncio.TimeoutError:
            raise TimeoutError(f"Agent execution exceeded timeout of {timeout_seconds} seconds")

    # Run the async function with timeout
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", ResourceWarning)
        result = asyncio.run(_invoke_with_timeout())

    # Note: We do NOT save to cache here. The caller (base_claude_agent)
    # will save to cache only after validating the result is valid.
    return result, cache_key


# =============================================================================
# Utility Functions
# =============================================================================

def clear_cache() -> int:
    """
    Clear all cached results.

    Returns:
        The number of cache files deleted.
    """
    if not CACHE_DIR.exists():
        return 0

    count = 0
    for cache_file in CACHE_DIR.glob("*.json"):
        try:
            cache_file.unlink()
            count += 1
        except IOError:
            pass

    return count


def get_cache_stats() -> dict:
    """
    Get statistics about the cache.

    Returns:
        Dictionary with cache statistics:
        - total_files: Total number of cached results
        - total_size_bytes: Total size of cache in bytes
    """
    if not CACHE_DIR.exists():
        return {"total_files": 0, "total_size_bytes": 0}

    total_files = 0
    total_size = 0

    for cache_file in CACHE_DIR.glob("*.json"):
        total_files += 1
        total_size += cache_file.stat().st_size

    return {
        "total_files": total_files,
        "total_size_bytes": total_size
    }
