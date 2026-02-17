"""
Terminal User Interface module for GOLD MINER.

Provides a Rich-based TUI with three panels:
- Left-top: Exploration tree visualization
- Left-bottom: Log messages
- Right: Agent output (with streaming support)

This module uses Rich's Live display for smooth, flicker-free updates.
"""

import os
import time
from typing import Optional, List, Union
from threading import Lock

from rich.console import Console, Group
from rich.panel import Panel
from rich.layout import Layout
from rich.live import Live
from rich.text import Text
from rich.tree import Tree
from rich.align import Align
from rich.table import Table

# Import models for type hints (avoid circular import)
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from path_explore.models import FunctionNode


# =============================================================================
# TUI Manager Class
# =============================================================================

class TUIManger:
    """
    Manages the Terminal User Interface for GOLD MINER.

    This class provides a three-panel layout:
    - Left-top: Exploration tree
    - Left-bottom: Log messages
    - Right: Agent output (supports streaming)

    Uses Rich's Live display with manual refresh to avoid flickering.
    """

    def __init__(self, console: Optional[Console] = None):
        """
        Initialize the TUI Manager.

        Args:
            console: Optional Rich Console instance. If None, creates a new one.
        """
        self.console = console or Console()
        self.lock = Lock()

        # State
        self._tree_root: Optional['FunctionNode'] = None
        self._logs: List[Text] = []
        self._max_logs: int = 15

        # Agent output state (for streaming)
        self._agent_name: str = "None"
        self._agent_status: str = "idle"
        self._agent_content: str = ""
        self._stream_buffer: str = ""  # Buffer for streaming content

        # Exploration stats
        self._node_count: int = 0
        self._target_endpoint: str = ""
        self._target_path: str = ""

        # Currently exploring node (for highlighting) - stores file_path#function_name
        self._current_node_key: str = ""

        # Live display
        self._live: Optional[Live] = None

        # Throttle for refresh (avoid too frequent updates)
        self._last_refresh_time: float = 0
        self._min_refresh_interval: float = 0.1  # 100ms minimum between refreshes
        self._pending_refresh: bool = False

    def start(self, target_path: str, target_endpoint: str) -> None:
        """
        Start the TUI display.

        Args:
            target_path: Path to the target project
            target_endpoint: The API endpoint being analyzed
        """
        self._target_path = target_path
        self._target_endpoint = target_endpoint

        # Initial agent content shows target info
        self._agent_content = f"Target: {target_endpoint}\nPath: {target_path}"

        # Create initial layout
        layout = self._make_layout()

        # Start live display with auto_refresh=False to prevent flickering
        # We manually control when to refresh
        self._live = Live(
            layout,
            console=self.console,
            refresh_per_second=10,  # Higher rate but we control when
            screen=True,
            vertical_overflow="ellipsis"
        )
        self._live.start()

    def stop(self) -> None:
        """Stop the TUI display."""
        if self._live:
            self._live.stop()
            self._live = None

    def update_tree(self, root: 'FunctionNode') -> None:
        """
        Update the exploration tree display.

        Args:
            root: Root node of the exploration tree
        """
        with self.lock:
            self._tree_root = root
            self._refresh_immediate()

    def log(self, source: str, message: str, level: str = "INFO") -> None:
        """
        Add a log entry.

        Args:
            source: Source of the log (e.g., "Explorer", "Agent")
            message: Log message
            level: Log level (INFO, SUCCESS, WARNING, ERROR)
        """
        with self.lock:
            timestamp = time.strftime("%H:%M:%S")

            # Color based on level
            if level == "SUCCESS":
                color = "green"
            elif level == "WARNING":
                color = "yellow"
            elif level == "ERROR":
                color = "red"
            else:
                color = "white"

            text = Text()
            text.append(f"[{timestamp}] ", style="dim")
            text.append(f"[{source}] ", style="bold blue")
            text.append(message, style=color)
            self._logs.append(text)

            # Keep only last N logs
            if len(self._logs) > self._max_logs:
                self._logs = self._logs[-self._max_logs:]

            self._refresh_immediate()

    def update_agent(self, name: str, status: str, content: str) -> None:
        """
        Update the agent output panel (non-streaming).

        Args:
            name: Name of the agent
            status: Status ("running", "completed", "error", "idle")
            content: Output content
        """
        with self.lock:
            self._agent_name = name if name else "System"
            self._agent_status = status if status else "idle"
            self._agent_content = content if content else ""
            self._stream_buffer = ""  # Clear stream buffer
            self._refresh_immediate()

    def stream_agent_output(self, chunk: str) -> None:
        """
        Stream output to the agent panel (called during agent execution).

        Args:
            chunk: Text chunk to append to the output
        """
        with self.lock:
            self._stream_buffer += chunk
            # Keep only last 2000 chars to prevent memory issues
            if len(self._stream_buffer) > 2000:
                self._stream_buffer = self._stream_buffer[-2000:]
            self._refresh_throttled()

    def clear_stream_buffer(self) -> None:
        """Clear the streaming buffer."""
        with self.lock:
            self._stream_buffer = ""

    def update_stats(self, node_count: int) -> None:
        """
        Update exploration statistics.

        Args:
            node_count: Total nodes explored
        """
        with self.lock:
            self._node_count = node_count
            self._refresh_immediate()

    def set_current_node(self, file_path: str, function_name: str) -> None:
        """
        Set the currently exploring node for highlighting.

        Args:
            file_path: File path of the node being explored
            function_name: Function name of the node being explored
        """
        with self.lock:
            filename = os.path.basename(file_path) if file_path else "unknown"
            self._current_node_key = f"{filename}#{function_name}"
            self._refresh_immediate()

    def clear_current_node(self) -> None:
        """Clear the current node highlighting."""
        with self.lock:
            self._current_node_key = ""
            self._refresh_immediate()

    def _refresh_immediate(self) -> None:
        """Immediately refresh the display."""
        if self._live:
            layout = self._make_layout()
            self._live.update(layout)

    def _refresh_throttled(self) -> None:
        """Refresh with throttling to prevent flickering."""
        if not self._live:
            return

        current_time = time.time()
        time_since_last = current_time - self._last_refresh_time

        if time_since_last >= self._min_refresh_interval:
            # Enough time has passed, refresh now
            self._last_refresh_time = current_time
            layout = self._make_layout()
            self._live.update(layout)
        else:
            # Too soon, mark as pending
            self._pending_refresh = True

    def _make_layout(self) -> Layout:
        """Create the main layout with three panels."""
        layout = Layout()

        # Split into left (2/3) and right (1/3) - HORIZONTAL
        layout.split_row(
            Layout(name="left", ratio=2),
            Layout(name="right", ratio=1)
        )

        # Split left into tree and logs - VERTICAL
        layout["left"].split_column(
            Layout(name="tree", ratio=3),
            Layout(name="logs", ratio=2)
        )

        # Build titles
        tree_title = Text()
        tree_title.append("Exploration Tree", style="bold cyan")
        tree_title.append(f" | Nodes: {self._node_count}", style="dim")

        agent_title = Text()
        agent_title.append("Agent Output", style="bold blue")
        if self._agent_name and self._agent_name != "System":
            agent_title.append(f" | {self._agent_name}", style="dim")

        # Update panels
        layout["tree"].update(
            Panel(
                self._render_tree(),
                title=tree_title,
                border_style="cyan",
                padding=(0, 1)
            )
        )
        layout["logs"].update(
            Panel(
                self._render_logs(),
                title="[bold green]Logs[/bold green]",
                border_style="green",
                padding=(0, 1)
            )
        )
        layout["right"].update(
            Panel(
                self._render_agent(),
                title=agent_title,
                border_style="blue",
                padding=(0, 1)
            )
        )

        return layout

    def _render_tree(self) -> Union[Tree, Align]:
        """Render the exploration tree."""
        if self._tree_root is None:
            return Align.center("[dim]Waiting for exploration to start...[/dim]", vertical="middle")

        return self._build_rich_tree(self._tree_root)

    def _build_rich_tree(self, node: 'FunctionNode', parent_tree: Optional[Tree] = None) -> Tree:
        """
        Build a Rich Tree from a FunctionNode.

        Args:
            node: The function node to render
            parent_tree: Parent tree node (None for root)

        Returns:
            Rich Tree object
        """
        # Get display name and style based on tag
        if node.is_sink():
            if node.tag.value == "Sink(PathTraversal)":
                label = f"[bold red]Sink[/bold red] [[red]{node.tag.value}[/red]]"
            else:
                label = f"[bold magenta]Sink[/bold magenta] [[magenta]{node.tag.value}[/magenta]]"
        else:
            filename = os.path.basename(node.file_path) if node.file_path else "unknown"
            func_name = node.function_name if node.function_name else "unknown"
            node_key = f"{filename}#{func_name}"

            # Check if this is the currently exploring node (exact match)
            is_current = (self._current_node_key and node_key == self._current_node_key)

            if is_current:
                # Highlight current node with yellow background
                label = f"[black on yellow]<{filename}#{func_name}>[/black on yellow] [[yellow]{node.tag.value}[/yellow]] [bold white]◄ exploring[/bold white]"
            else:
                label = f"[cyan]<{filename}#{func_name}>[/cyan] [[yellow]{node.tag.value}[/yellow]]"

        # Create tree node
        if parent_tree is None:
            tree_node = Tree(label)
        else:
            tree_node = parent_tree.add(label)

        # Recursively add children
        for child in node.children:
            self._build_rich_tree(child, tree_node)

        return tree_node

    def _render_logs(self) -> Union[Group, Align]:
        """Render the logs panel."""
        if not self._logs:
            return Align.center("[dim]Waiting for logs...[/dim]", vertical="middle")

        return Group(*self._logs)

    def _render_agent(self) -> Group:
        """Render the agent output panel."""
        lines = []

        # Agent name and status
        status_color = "green" if self._agent_status == "completed" else "yellow" if self._agent_status == "running" else "red" if self._agent_status == "error" else "dim"

        lines.append(Text())
        header = Text()
        header.append("  Agent:   ", style="dim")
        header.append(self._agent_name, style="bold blue")
        lines.append(header)

        status_line = Text()
        status_line.append("  Status:  ", style="dim")
        status_line.append(self._agent_status, style=status_color)
        lines.append(status_line)

        lines.append(Text())
        lines.append(Text("  " + "-" * 36, style="dim"))
        lines.append(Text())

        # Content - combine static content with stream buffer
        full_content = self._agent_content
        if self._stream_buffer:
            if full_content:
                full_content = full_content + "\n\n" + "--- Streaming ---\n" + self._stream_buffer
            else:
                full_content = self._stream_buffer

        if full_content:
            for line in full_content.split('\n')[-25:]:  # Show last 25 lines
                # Don't truncate - show full content
                lines.append(Text(f"  {line}", style="white"))
        else:
            lines.append(Text("  [dim]No content[/dim]"))

        return Group(*lines)

    def print_summary(self, path_traversal_count: int, command_injection_count: int,
                      total_paths: int) -> None:
        """
        Print a summary of exploration results.

        Args:
            path_traversal_count: Number of path traversal vulnerabilities found
            command_injection_count: Number of command injection vulnerabilities found
            total_paths: Total number of vulnerability paths found
        """
        # Stop live display
        if self._live:
            self._live.stop()
            self._live = None

        # Clear current node highlighting for final display
        self._current_node_name = ""

        self.console.print()

        # Print exploration tree first
        if self._tree_root:
            self.console.rule("[bold cyan]Final Exploration Tree[/bold cyan]")
            tree = self._build_rich_tree(self._tree_root)
            self.console.print(tree)
            self.console.print()

        # Print summary table
        self.console.rule("[bold yellow]Exploration Summary[/bold yellow]")

        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("Metric", style="dim")
        table.add_column("Value", justify="right")

        table.add_row("Total Vulnerability Paths", str(total_paths))
        table.add_row("Path Traversal", f"[red]{path_traversal_count}[/red]")
        table.add_row("Command Injection", f"[magenta]{command_injection_count}[/magenta]")
        table.add_row("Nodes Explored", str(self._node_count))

        self.console.print(table)
        self.console.rule()


# =============================================================================
# Global TUI Manager Instance
# =============================================================================

_tui_manager: Optional[TUIManger] = None


def get_tui() -> TUIManger:
    """Get the global TUI Manager instance."""
    global _tui_manager
    if _tui_manager is None:
        _tui_manager = TUIManger()
    return _tui_manager


def init_tui(console: Optional[Console] = None) -> TUIManger:
    """Initialize the global TUI Manager instance."""
    global _tui_manager
    _tui_manager = TUIManger(console)
    return _tui_manager


# =============================================================================
# Convenience Functions
# =============================================================================

def log_info(source: str, message: str) -> None:
    """Log an info message."""
    get_tui().log(source, message, "INFO")


def log_success(source: str, message: str) -> None:
    """Log a success message."""
    get_tui().log(source, message, "SUCCESS")


def log_warning(source: str, message: str) -> None:
    """Log a warning message."""
    get_tui().log(source, message, "WARNING")


def log_error(source: str, message: str) -> None:
    """Log an error message."""
    get_tui().log(source, message, "ERROR")


def update_tree(root: 'FunctionNode') -> None:
    """Update the exploration tree display."""
    get_tui().update_tree(root)


def update_agent(name: str, status: str, content: str) -> None:
    """Update the agent output panel."""
    get_tui().update_agent(name, status, content)


def stream_agent(chunk: str) -> None:
    """Stream output to agent panel."""
    get_tui().stream_agent_output(chunk)


def clear_stream() -> None:
    """Clear the streaming buffer."""
    get_tui().clear_stream_buffer()


def update_stats(node_count: int) -> None:
    """Update exploration statistics."""
    get_tui().update_stats(node_count)


def set_current_node(file_path: str, function_name: str) -> None:
    """Set the currently exploring node for highlighting."""
    get_tui().set_current_node(file_path, function_name)


def clear_current_node() -> None:
    """Clear the current node highlighting."""
    get_tui().clear_current_node()


def start_tui(target_path: str, target_endpoint: str) -> None:
    """Start the TUI display."""
    get_tui().start(target_path, target_endpoint)


def stop_tui() -> None:
    """Stop the TUI display."""
    get_tui().stop()


def print_summary(path_traversal_count: int, command_injection_count: int,
                  total_paths: int) -> None:
    """Print exploration summary."""
    get_tui().print_summary(path_traversal_count, command_injection_count, total_paths)
