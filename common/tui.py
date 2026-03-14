"""
Textual presentation facade for VulSolver.

This module exposes the same high-level UI functions used by the backend while
delegating all rendering to the standalone Textual frontend layer.
"""

from __future__ import annotations

import sys
import time
from typing import TYPE_CHECKING, List, Optional

from ui.controller import get_controller

if TYPE_CHECKING:
    from path_explore.models import FunctionNode


class TUIMode:
    """UI display modes."""

    EXPLORE = "explore"
    VERIFY = "verify"


_tui_enabled = True
_tui_fallback_announced = False


def _format_log_line(level: str, source: str, message: str) -> str:
    prefix = {
        "SUCCESS": "OK",
        "WARNING": "WARN",
        "ERROR": "ERR",
        "INFO": "INFO",
    }.get(level, level)
    return f"[{time.strftime('%H:%M:%S')}] [{prefix}] [{source}] {message}"


def _check_tui_health() -> None:
    global _tui_enabled, _tui_fallback_announced

    if not _tui_enabled:
        return

    controller = get_controller()
    if controller.consume_unexpected_shutdown():
        snapshot = controller.snapshot()
        controller.stop()
        _tui_enabled = False
        if not _tui_fallback_announced:
            _tui_fallback_announced = True
            project = snapshot.target_project or "-"
            target = snapshot.target_endpoint or snapshot.target_path or "-"
            print(_format_log_line("WARNING", "TUI", "TUI closed by user. Falling back to terminal logging."))
            print(_format_log_line("INFO", "TUI", f"Project: {project}"))
            print(_format_log_line("INFO", "TUI", f"Target: {target}"))
            print(_format_log_line("INFO", "TUI", "Analysis will continue without the Textual interface."))


def configure_tui(enabled: bool = True) -> None:
    """Configure whether the Textual frontend should be used."""

    global _tui_enabled, _tui_fallback_announced
    _tui_enabled = enabled
    _tui_fallback_announced = False


def get_tui():
    """Get the shared Textual controller."""

    return get_controller()


def init_tui(_unused_console=None):
    """Initialize and return the shared Textual controller."""

    return get_controller()


def is_tui_running() -> bool:
    """Return whether the Textual frontend is currently running."""

    if not _tui_enabled:
        return False
    return get_controller().is_running


def emit_output(text: str = "", source: str = "Console", level: str = "INFO") -> None:
    """
    Send plain output either to the Textual event log or stdout when no UI is active.
    """

    _check_tui_health()

    controller = get_controller()
    if _tui_enabled and controller.is_running:
        controller.emit_output(text, source=source, level=level)
        return

    if text:
        print(text)
    else:
        print()


def log_info(source: str, message: str) -> None:
    """Log an info message."""

    _check_tui_health()
    controller = get_controller()
    if _tui_enabled and controller.is_running:
        controller.log(source, message, "INFO")
        return
    print(_format_log_line("INFO", source, message))


def log_success(source: str, message: str) -> None:
    """Log a success message."""

    _check_tui_health()
    controller = get_controller()
    if _tui_enabled and controller.is_running:
        controller.log(source, message, "SUCCESS")
        return
    print(_format_log_line("SUCCESS", source, message))


def log_warning(source: str, message: str) -> None:
    """Log a warning message."""

    _check_tui_health()
    controller = get_controller()
    if _tui_enabled and controller.is_running:
        controller.log(source, message, "WARNING")
        return
    print(_format_log_line("WARNING", source, message))


def log_error(source: str, message: str) -> None:
    """Log an error message."""

    _check_tui_health()
    controller = get_controller()
    if _tui_enabled and controller.is_running:
        controller.log(source, message, "ERROR")
        return
    print(_format_log_line("ERROR", source, message), file=sys.stderr)


def update_agent(name: str, status: str, content: str) -> None:
    """Replace the current agent panel content."""

    _check_tui_health()
    if not _tui_enabled:
        return
    get_controller().update_agent(name, status, content)


def stream_agent(chunk: str) -> None:
    """Append streamed text to the agent output panel."""

    _check_tui_health()
    if not _tui_enabled:
        return
    get_controller().stream_agent_output(chunk)


def clear_stream() -> None:
    """Clear the streamed text buffer."""

    _check_tui_health()
    if not _tui_enabled:
        return
    get_controller().clear_stream_buffer()


def start_tui(
    target_path: str,
    target_endpoint: str,
    mode: str = TUIMode.EXPLORE,
    batch_index: int = 0,
    batch_total: int = 0,
) -> None:
    """Start the Textual frontend."""

    if not _tui_enabled:
        return
    get_controller().start(
        target_path=target_path,
        target_endpoint=target_endpoint,
        mode=mode,
        batch_index=batch_index,
        batch_total=batch_total,
    )


def stop_tui() -> None:
    """Stop the Textual frontend."""

    get_controller().stop()


def update_tree(root: Optional["FunctionNode"]) -> None:
    """Update the exploration tree snapshot."""

    _check_tui_health()
    if not _tui_enabled:
        return
    get_controller().update_tree(root)


def update_stats(node_count: int) -> None:
    """Update exploration statistics."""

    _check_tui_health()
    if not _tui_enabled:
        return
    get_controller().update_stats(node_count)


def set_current_node(file_path: str, function_name: str, source_code: str = "") -> None:
    """Highlight the currently explored node."""

    _check_tui_health()
    if not _tui_enabled:
        return
    get_controller().set_current_node(file_path, function_name, source_code)


def clear_current_node() -> None:
    """Clear the current exploration highlight."""

    _check_tui_health()
    if not _tui_enabled:
        return
    get_controller().clear_current_node()


def print_summary(
    path_traversal_count: int,
    command_injection_count: int,
    code_injection_count: int,
    sql_injection_count: int,
    ssrf_count: int,
    total_paths: int,
) -> None:
    """Display or print the exploration summary."""

    get_controller().show_exploration_summary(
        path_traversal_count=path_traversal_count,
        command_injection_count=command_injection_count,
        code_injection_count=code_injection_count,
        sql_injection_count=sql_injection_count,
        ssrf_count=ssrf_count,
        total_paths=total_paths,
    )


def set_verify_path_info(
    path_index: int,
    total_paths: int,
    call_chain: List[str],
    call_chain_files: List[str],
    sink_expression: str,
) -> None:
    """Update the verification path context."""

    _check_tui_health()
    if not _tui_enabled:
        return
    get_controller().set_verify_path_info(path_index, total_paths, call_chain, call_chain_files, sink_expression)


def set_verify_stage(stage: str) -> None:
    """Update the verification stage."""

    _check_tui_health()
    if not _tui_enabled:
        return
    get_controller().set_verify_stage(stage)


def set_analyzing_node(node_index: int) -> None:
    """Highlight the currently analyzed verification node."""

    _check_tui_health()
    if not _tui_enabled:
        return
    get_controller().set_analyzing_node(node_index)


def update_verify_stats(vulnerable_count: int, not_vulnerable_count: int) -> None:
    """Update verification statistics."""

    _check_tui_health()
    if not _tui_enabled:
        return
    get_controller().update_verify_stats(vulnerable_count, not_vulnerable_count)


def print_verify_summary(vulnerable_count: int, not_vulnerable_count: int, total_paths: int) -> None:
    """Display or print the verification summary."""

    get_controller().show_verification_summary(
        vulnerable_count=vulnerable_count,
        not_vulnerable_count=not_vulnerable_count,
        total_paths=total_paths,
    )
