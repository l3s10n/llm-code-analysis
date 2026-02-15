"""
Base Claude Agent module for GOLD MINER.

Provides a wrapper around Claude Agent SDK for executing AI-powered analysis tasks.
"""

import asyncio
import os
import warnings
from typing import Optional

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
os.environ["ANTHROPIC_DEFAULT_HAIKU_MODEL"] = load_config("llm.model")
os.environ["ANTHROPIC_DEFAULT_SONNET_MODEL"] = load_config("llm.model")
os.environ["ANTHROPIC_DEFAULT_OPUS_MODEL"] = load_config("llm.model")


# =============================================================================
# Default Configuration
# =============================================================================

DEFAULT_ALLOWED_TOOLS = ['Bash', 'Read', 'Glob', 'Grep']
DEFAULT_MODEL = 'Opus'


# =============================================================================
# Public Functions
# =============================================================================

def base_claude_agent(
    cwd: str,
    system_prompt: str,
    user_prompt: str,
    allowed_tools: Optional[list] = None,
    model: str = DEFAULT_MODEL
) -> Optional[str]:
    """
    Execute a Claude agent with the given prompts and configuration.

    Args:
        cwd: Working directory for the agent to operate in.
        system_prompt: System prompt to set the agent's behavior and context.
        user_prompt: User prompt containing the task to execute.
        allowed_tools: List of tools that the agent is allowed to use.
                      Defaults to ['Bash', 'Read', 'Glob', 'Grep'].
        model: Model to use for the agent. Defaults to 'Opus'.

    Returns:
        Optional[str]: The result from the agent execution, or None if no result.
    """
    if allowed_tools is None:
        allowed_tools = DEFAULT_ALLOWED_TOOLS

    async def _invoke_claude_agent() -> Optional[str]:
        """Async inner function to execute the agent."""
        options = ClaudeAgentOptions(
            system_prompt=system_prompt,
            allowed_tools=allowed_tools,
            permission_mode="bypassPermissions",
            cwd=cwd,
            model=model,
            include_partial_messages=True
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
                            print(delta.get("text", ""), end="", flush=True)

                    if event_type == "content_block_start":
                        content_block = event.get("content_block", {})
                        if content_block.get("type") == "tool_use":
                            current_tool = content_block.get("name")
                            print(f"[Tool: {current_tool}]", flush=True)

                if hasattr(message, "result"):
                    result = message.result
        finally:
            # Close the generator
            await gen.aclose()

        return result

    # Suppress anyio ResourceWarning for unclosed streams (SDK internal behavior)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", ResourceWarning)
        return asyncio.run(_invoke_claude_agent())
