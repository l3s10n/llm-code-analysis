"""
Base Claude Agent module for GOLD MINER.

Provides a wrapper around Claude Agent SDK for executing AI-powered analysis tasks.
Supports streaming output via callback function and result caching.
"""

import asyncio
import hashlib
import json
import os
import warnings
from pathlib import Path
from typing import Optional, Callable, List

from claude_agent_sdk import query, ClaudeAgentOptions
from claude_agent_sdk.types import StreamEvent

from .config import load_config


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
# Public Functions
# =============================================================================

def base_claude_agent(
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

    This function supports caching: if the same parameters are used again,
    the cached result will be returned instead of calling the agent again.

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
