"""
Terminal User Interface module for GOLD MINER.

Provides a Rich-based TUI with three panels:
- Left-top: Exploration tree (explore mode) or Call Chain (verify mode)
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
# TUI Mode Enum
# =============================================================================

class TUIMode:
    """TUI display modes."""
    EXPLORE = "explore"
    VERIFY = "verify"


# =============================================================================
# TUI Manager Class
# =============================================================================

class TUIManger:
    """
    Manages the Terminal User Interface for GOLD MINER.

    This class provides a three-panel layout:
    - Left-top: Exploration tree (explore mode) or Call Chain (verify mode)
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

        # Mode: "explore" or "verify"
        self._mode: str = TUIMode.EXPLORE

        # State for explore mode
        self._tree_root: Optional['FunctionNode'] = None
        self._node_count: int = 0

        # State for verify mode
        self._call_chain: List[str] = []  # List of function names
        self._call_chain_files: List[str] = []  # List of file paths
        self._current_analyzing_index: int = -1  # Index of node being analyzed
        self._verify_stage: str = ""  # "dataflow", "filter", "decision"
        self._path_index: int = 0  # Current path index (for multiple paths)
        self._total_paths: int = 0  # Total paths to verify
        self._vulnerable_count: int = 0  # Count of vulnerable paths
        self._not_vulnerable_count: int = 0  # Count of not vulnerable paths

        # Common state
        self._logs: List[Text] = []
        self._max_logs: int = 15

        # Agent output state (for streaming)
        self._agent_name: str = "None"
        self._agent_status: str = "idle"
        self._agent_content: str = ""
        self._stream_buffer: str = ""  # Buffer for streaming content

        # Target info
        self._target_endpoint: str = ""
        self._target_path: str = ""

        # Currently exploring node (for highlighting in explore mode) - stores file_path#function_name
        self._current_node_key: str = ""

        # Live display
        self._live: Optional[Live] = None

        # Throttle for refresh (avoid too frequent updates)
        self._last_refresh_time: float = 0
        self._min_refresh_interval: float = 0.1  # 100ms minimum between refreshes
        self._pending_refresh: bool = False

    def start(self, target_path: str, target_endpoint: str, mode: str = TUIMode.EXPLORE) -> None:
        """
        Start the TUI display.

        Args:
            target_path: Path to the target project
            target_endpoint: The API endpoint being analyzed
            mode: TUI mode ("explore" or "verify")
        """
        self._target_path = target_path
        self._target_endpoint = target_endpoint
        self._mode = mode

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

    # =========================================================================
    # Explore Mode Methods
    # =========================================================================

    def update_tree(self, root: 'FunctionNode') -> None:
        """
        Update the exploration tree display.

        Args:
            root: Root node of the exploration tree
        """
        with self.lock:
            self._tree_root = root
            self._refresh_immediate()

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

    # =========================================================================
    # Verify Mode Methods
    # =========================================================================

    def set_verify_path_info(self, path_index: int, total_paths: int,
                             call_chain: List[str], call_chain_files: List[str]) -> None:
        """
        Set the current path information for verification display.

        Args:
            path_index: Index of current path (1-based)
            total_paths: Total number of paths to verify
            call_chain: List of function names in the call chain
            call_chain_files: List of file paths corresponding to each function
        """
        with self.lock:
            self._path_index = path_index
            self._total_paths = total_paths
            self._call_chain = call_chain
            self._call_chain_files = call_chain_files
            self._refresh_immediate()

    def set_verify_stage(self, stage: str) -> None:
        """
        Set the current verification stage.

        Args:
            stage: Stage name ("dataflow", "filter", "decision")
        """
        with self.lock:
            self._verify_stage = stage
            self._refresh_immediate()

    def set_analyzing_node(self, node_index: int) -> None:
        """
        Set the index of the node currently being analyzed.

        Args:
            node_index: Index of the node (0-based), or -1 to clear
        """
        with self.lock:
            self._current_analyzing_index = node_index
            self._refresh_immediate()

    def update_verify_stats(self, vulnerable_count: int, not_vulnerable_count: int) -> None:
        """
        Update verification statistics.

        Args:
            vulnerable_count: Number of vulnerable paths found
            not_vulnerable_count: Number of not vulnerable paths found
        """
        with self.lock:
            self._vulnerable_count = vulnerable_count
            self._not_vulnerable_count = not_vulnerable_count
            self._refresh_immediate()

    # =========================================================================
    # Common Methods
    # =========================================================================

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

        # Split left into tree/chain and logs - VERTICAL
        layout["left"].split_column(
            Layout(name="tree", ratio=3),
            Layout(name="logs", ratio=2)
        )

        # Build titles and content based on mode
        if self._mode == TUIMode.VERIFY:
            # Verify mode: show call chain
            chain_title = Text()
            chain_title.append("Call Chain", style="bold cyan")
            if self._total_paths > 0:
                chain_title.append(f" | Path {self._path_index}/{self._total_paths}", style="dim")
            if self._verify_stage:
                stage_color = "yellow" if self._verify_stage == "dataflow" else "blue" if self._verify_stage == "filter" else "green"
                chain_title.append(f" | {self._verify_stage.upper()}", style=stage_color)

            layout["tree"].update(
                Panel(
                    self._render_call_chain(),
                    title=chain_title,
                    border_style="cyan",
                    padding=(0, 1)
                )
            )
        else:
            # Explore mode: show tree
            tree_title = Text()
            tree_title.append("Exploration Tree", style="bold cyan")
            tree_title.append(f" | Nodes: {self._node_count}", style="dim")

            layout["tree"].update(
                Panel(
                    self._render_tree(),
                    title=tree_title,
                    border_style="cyan",
                    padding=(0, 1)
                )
            )

        # Agent title
        agent_title = Text()
        agent_title.append("Agent Output", style="bold blue")
        if self._agent_name and self._agent_name != "System":
            agent_title.append(f" | {self._agent_name}", style="dim")

        # Update panels
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

    # =========================================================================
    # Render Methods
    # =========================================================================

    def _render_tree(self) -> Union[Tree, Align]:
        """Render the exploration tree (explore mode) with smart pruning for large trees."""
        if self._tree_root is None:
            return Align.center("[dim]Waiting for exploration to start...[/dim]", vertical="middle")

        # Calculate max visible nodes based on console height
        try:
            total_height = self.console.height
            # Tree panel is roughly 60% of total height, minus borders
            panel_height = int(total_height * 0.6) - 3
            # Reserve ~3 lines for fixed elements
            available_lines = panel_height - 3
            # Each tree node uses ~2 lines on average
            max_visible_nodes = max(3, available_lines // 2)
            # Cap at reasonable maximum
            max_visible_nodes = min(max_visible_nodes, 10)
        except:
            max_visible_nodes = 5  # Safe default

        return self._build_rich_tree(self._tree_root, max_nodes=max_visible_nodes)

    def _find_current_node_path(self, node: 'FunctionNode', path: list) -> bool:
        """
        Find the path from root to the currently exploring node.

        Args:
            node: Current node being checked
            path: List to store the path (modified in place)

        Returns:
            True if current node is found in this subtree, False otherwise
        """
        path.append(node)

        # Check if this is the current node
        filename = os.path.basename(node.file_path) if node.file_path else "unknown"
        func_name = node.function_name if node.function_name else "unknown"
        node_key = f"{filename}#{func_name}"

        if self._current_node_key and node_key == self._current_node_key:
            return True

        # Check children
        for child in node.children:
            if self._find_current_node_path(child, path):
                return True

        path.pop()
        return False

    def _build_rich_tree(self, node: 'FunctionNode', parent_tree: Optional[Tree] = None,
                         max_nodes: int = 10, nodes_rendered: Optional[List[int]] = None) -> Tree:
        """
        Build a Rich Tree from a FunctionNode with smart pruning.

        Args:
            node: The function node to render
            parent_tree: Parent tree node (None for root)
            max_nodes: Maximum number of nodes to render
            nodes_rendered: Counter for nodes rendered (passed by reference)

        Returns:
            Rich Tree object
        """
        if nodes_rendered is None:
            nodes_rendered = [0]

        # Get display name and style based on tag
        if node.is_sink():
            if node.tag.value == "Sink(PathTraversal)":
                label = f"[bold red]Sink[/bold red] [[red]{node.tag.value}[/red]]"
            elif node.tag.value == "Sink(CommandInjection)":
                label = f"[bold magenta]Sink[/bold magenta] [[magenta]{node.tag.value}[/magenta]]"
            elif node.tag.value == "Sink(CodeInjection)":
                label = f"[bold yellow]Sink[/bold yellow] [[yellow]{node.tag.value}[/yellow]]"
            elif node.tag.value == "Sink(SQLInjection)":
                label = f"[bold blue]Sink[/bold blue] [[blue]{node.tag.value}[/blue]]"
            else:
                label = f"[bold red]Sink[/bold red] [[red]{node.tag.value}[/red]]"
        else:
            filename = os.path.basename(node.file_path) if node.file_path else "unknown"
            func_name = node.function_name if node.function_name else "unknown"
            node_key = f"{filename}#{func_name}"

            # Check if this is the currently exploring node (exact match)
            is_current = (self._current_node_key and node_key == self._current_node_key)

            if is_current:
                label = f"[black on yellow]<{filename}#{func_name}>[/black on yellow] [[yellow]{node.tag.value}[/yellow]] [bold white]◄ exploring[/bold white]"
            else:
                label = f"[cyan]<{filename}#{func_name}>[/cyan] [[yellow]{node.tag.value}[/yellow]]"

        # Create tree node
        if parent_tree is None:
            tree_node = Tree(label)
        else:
            tree_node = parent_tree.add(label)

        nodes_rendered[0] += 1

        # Find path to current node for smart rendering
        current_path = []
        if self._current_node_key:
            self._find_current_node_path(self._tree_root, current_path)

        # Determine which children to show
        # Always show children if we're on the path to current node
        # Otherwise, respect the max_nodes limit
        node_in_path = node in current_path

        children_to_show = []
        hidden_children_count = 0

        for child in node.children:
            if nodes_rendered[0] >= max_nodes and not node_in_path:
                # We've hit the limit and this node is not on the path to current
                hidden_children_count += 1
            elif child in current_path:
                # Child is on the path to current node, always show it
                children_to_show.append(child)
            elif nodes_rendered[0] < max_nodes:
                # Under the limit, show this child
                children_to_show.append(child)
            else:
                hidden_children_count += 1

        # Recursively add visible children
        for child in children_to_show:
            self._build_rich_tree(child, tree_node, max_nodes, nodes_rendered)

        # Add ellipsis for hidden children
        if hidden_children_count > 0:
            hidden_label = f"[dim italic]... ({hidden_children_count} more)[/dim italic]"
            tree_node.add(hidden_label)

        return tree_node

    def _render_call_chain(self) -> Union[Group, Align]:
        """Render the call chain (verify mode) with smart windowing for long chains."""
        if not self._call_chain:
            return Align.center("[dim]Waiting for verification to start...[/dim]", vertical="middle")

        lines = []
        lines.append(Text())  # Empty line at top

        total_nodes = len(self._call_chain)
        current_idx = self._current_analyzing_index

        # Calculate available height for call chain panel
        # Layout: left side split into tree (ratio=3) and logs (ratio=2)
        # Call chain panel is about 3/5 of left side
        # For a 24-line terminal: ~14 lines for tree panel, minus borders ~11 usable
        # Each node takes ~3-4 lines, fixed elements ~5-6 lines
        # Conservative estimate: show at most 3 nodes to ensure visibility
        try:
            total_height = self.console.height
            # Call chain panel is roughly 60% of total height, minus borders
            panel_height = int(total_height * 0.6) - 3
            # Reserve ~5 lines for fixed elements (sink, stats, etc.)
            available_lines = panel_height - 5
            # Each node uses ~3 lines on average (name + file + arrow, simplified)
            max_visible_nodes = max(1, available_lines // 3)
            # Cap at 3 to ensure everything fits comfortably
            max_visible_nodes = min(max_visible_nodes, 3)
        except:
            max_visible_nodes = 2  # Safe default

        # Calculate how many nodes to show before and after current node
        if current_idx < 0:
            # No node being analyzed, show from beginning
            context_before = 0
            context_after = max_visible_nodes - 1
        else:
            # Try to center current node
            ideal_context_each_side = (max_visible_nodes - 1) // 2

            # Adjust for edge cases
            nodes_before_current = current_idx
            nodes_after_current = total_nodes - current_idx - 1

            if nodes_before_current < ideal_context_each_side:
                context_before = nodes_before_current
                context_after = min(max_visible_nodes - 1 - context_before, nodes_after_current)
            elif nodes_after_current < ideal_context_each_side:
                context_after = nodes_after_current
                context_before = min(max_visible_nodes - 1 - context_after, nodes_before_current)
            else:
                context_before = ideal_context_each_side
                context_after = max_visible_nodes - 1 - context_before

        # Determine window boundaries
        window_start = max(0, current_idx - context_before) if current_idx >= 0 else 0
        window_end = min(total_nodes, window_start + max_visible_nodes)

        # Adjust window if we can't fill it
        if window_end - window_start < max_visible_nodes and window_start > 0:
            window_start = max(0, window_end - max_visible_nodes)

        show_indices = list(range(window_start, window_end))
        show_ellipsis_top = show_indices[0] > 0
        show_ellipsis_bottom = show_indices[-1] < total_nodes - 1

        # Show ellipsis at top if there are hidden nodes above
        if show_ellipsis_top:
            hidden_count = show_indices[0]
            ellipsis_line = Text()
            ellipsis_line.append(f"  ... ({hidden_count} more)", style="dim italic")
            lines.append(ellipsis_line)

            arrow_line = Text()
            arrow_line.append("          │", style="dim")
            lines.append(arrow_line)
            arrow_line2 = Text()
            arrow_line2.append("          ▼", style="dim")
            lines.append(arrow_line2)

        # Render visible nodes
        for i in show_indices:
            func_name = self._call_chain[i]

            short_file = ""
            if i < len(self._call_chain_files) and self._call_chain_files[i]:
                short_file = os.path.basename(self._call_chain_files[i])

            is_analyzing = (current_idx == i)
            is_last_visible = (i == show_indices[-1])

            if is_analyzing:
                line = Text()
                line.append("  >>> ", style="bold yellow")
                line.append(f"[{i}] ", style="dim")
                line.append(f"{func_name}", style="black on yellow")
                line.append(" ◄ analyzing", style="bold white")
                lines.append(line)
            else:
                line = Text()
                line.append("      ", style="dim")
                line.append(f"[{i}] ", style="dim")
                line.append(f"{func_name}", style="cyan")
                lines.append(line)

            if short_file:
                file_line = Text()
                file_line.append(f"          {short_file}", style="dim")
                lines.append(file_line)

            # Add arrow to next node or sink
            if not is_last_visible:
                arrow_line = Text()
                arrow_line.append("          │", style="dim")
                lines.append(arrow_line)
                arrow_line2 = Text()
                arrow_line2.append("          ▼", style="dim")
                lines.append(arrow_line2)
            elif show_ellipsis_bottom:
                arrow_line = Text()
                arrow_line.append("          │", style="dim")
                lines.append(arrow_line)
                arrow_line2 = Text()
                arrow_line2.append("          ▼", style="dim")
                lines.append(arrow_line2)
            else:
                arrow_line = Text()
                arrow_line.append("          │", style="dim")
                lines.append(arrow_line)
                arrow_line2 = Text()
                arrow_line2.append("          ▼", style="dim")
                lines.append(arrow_line2)

        # Show ellipsis at bottom if there are hidden nodes below
        if show_ellipsis_bottom:
            hidden_count = total_nodes - show_indices[-1] - 1
            ellipsis_line = Text()
            ellipsis_line.append(f"  ... ({hidden_count} more)", style="dim italic")
            lines.append(ellipsis_line)

            arrow_line = Text()
            arrow_line.append("          │", style="dim")
            lines.append(arrow_line)
            arrow_line2 = Text()
            arrow_line2.append("          ▼", style="dim")
            lines.append(arrow_line2)

        # Add sink at the end
        sink_line = Text()
        sink_line.append("      ", style="dim")
        sink_line.append("[sink]", style="bold red")
        lines.append(sink_line)

        # Show total chain length for context
        if show_ellipsis_top or show_ellipsis_bottom:
            total_line = Text()
            total_line.append(f"  Chain: {total_nodes} nodes total", style="dim italic")
            lines.append(total_line)

        lines.append(Text())  # Empty line at bottom

        # Add verification stats if available
        if self._vulnerable_count > 0 or self._not_vulnerable_count > 0:
            lines.append(Text("  " + "─" * 30, style="dim"))
            stats_line = Text()
            stats_line.append("  Vulnerable: ", style="dim")
            stats_line.append(f"{self._vulnerable_count}", style="bold red")
            stats_line.append("  |  Not Vulnerable: ", style="dim")
            stats_line.append(f"{self._not_vulnerable_count}", style="bold green")
            lines.append(stats_line)

        return Group(*lines)

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

    def print_summary(self, path_traversal_count: int = 0, command_injection_count: int = 0,
                      code_injection_count: int = 0, sql_injection_count: int = 0,
                      total_paths: int = 0) -> None:
        """
        Print a summary of results.

        Args:
            path_traversal_count: Number of path traversal vulnerabilities found (explore mode)
            command_injection_count: Number of command injection vulnerabilities found (explore mode)
            code_injection_count: Number of code injection vulnerabilities found (explore mode)
            sql_injection_count: Number of SQL injection vulnerabilities found (explore mode)
            total_paths: Total number of paths (explore mode)
        """
        # Stop live display
        if self._live:
            self._live.stop()
            self._live = None

        self.console.print()

        if self._mode == TUIMode.EXPLORE:
            # Explore mode summary
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
            table.add_row("Code Injection", f"[yellow]{code_injection_count}[/yellow]")
            table.add_row("SQL Injection", f"[blue]{sql_injection_count}[/blue]")
            table.add_row("Nodes Explored", str(self._node_count))

            self.console.print(table)
        else:
            # Verify mode summary
            self.console.rule("[bold yellow]Verification Summary[/bold yellow]")

            table = Table(show_header=True, header_style="bold cyan")
            table.add_column("Metric", style="dim")
            table.add_column("Value", justify="right")

            table.add_row("Total Paths Analyzed", str(self._total_paths))
            table.add_row("Vulnerable", f"[red]{self._vulnerable_count}[/red]")
            table.add_row("Not Vulnerable", f"[green]{self._not_vulnerable_count}[/green]")

            self.console.print(table)

        self.console.rule()

    def print_verify_summary(self, vulnerable_count: int, not_vulnerable_count: int,
                            total_paths: int) -> None:
        """
        Print a summary of verification results.

        Args:
            vulnerable_count: Number of vulnerable paths found
            not_vulnerable_count: Number of not vulnerable paths found
            total_paths: Total number of paths analyzed
        """
        # Stop live display
        if self._live:
            self._live.stop()
            self._live = None

        self.console.print()
        self.console.rule("[bold yellow]Verification Summary[/bold yellow]")

        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("Metric", style="dim")
        table.add_column("Value", justify="right")

        table.add_row("Total Paths Analyzed", str(total_paths))
        table.add_row("Vulnerable", f"[red]{vulnerable_count}[/red]")
        table.add_row("Not Vulnerable", f"[green]{not_vulnerable_count}[/green]")

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
# Convenience Functions - Common
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


def update_agent(name: str, status: str, content: str) -> None:
    """Update the agent output panel."""
    get_tui().update_agent(name, status, content)


def stream_agent(chunk: str) -> None:
    """Stream output to agent panel."""
    get_tui().stream_agent_output(chunk)


def clear_stream() -> None:
    """Clear the streaming buffer."""
    get_tui().clear_stream_buffer()


def start_tui(target_path: str, target_endpoint: str, mode: str = TUIMode.EXPLORE) -> None:
    """Start the TUI display."""
    get_tui().start(target_path, target_endpoint, mode)


def stop_tui() -> None:
    """Stop the TUI display."""
    get_tui().stop()


# =============================================================================
# Convenience Functions - Explore Mode
# =============================================================================

def update_tree(root: 'FunctionNode') -> None:
    """Update the exploration tree display."""
    get_tui().update_tree(root)


def update_stats(node_count: int) -> None:
    """Update exploration statistics."""
    get_tui().update_stats(node_count)


def set_current_node(file_path: str, function_name: str) -> None:
    """Set the currently exploring node for highlighting."""
    get_tui().set_current_node(file_path, function_name)


def clear_current_node() -> None:
    """Clear the current node highlighting."""
    get_tui().clear_current_node()


def print_summary(path_traversal_count: int, command_injection_count: int,
                  code_injection_count: int, sql_injection_count: int,
                  total_paths: int) -> None:
    """Print exploration summary."""
    get_tui().print_summary(path_traversal_count, command_injection_count,
                           code_injection_count, sql_injection_count, total_paths)


# =============================================================================
# Convenience Functions - Verify Mode
# =============================================================================

def set_verify_path_info(path_index: int, total_paths: int,
                         call_chain: List[str], call_chain_files: List[str]) -> None:
    """Set the current path information for verification display."""
    get_tui().set_verify_path_info(path_index, total_paths, call_chain, call_chain_files)


def set_verify_stage(stage: str) -> None:
    """Set the current verification stage."""
    get_tui().set_verify_stage(stage)


def set_analyzing_node(node_index: int) -> None:
    """Set the index of the node currently being analyzed."""
    get_tui().set_analyzing_node(node_index)


def update_verify_stats(vulnerable_count: int, not_vulnerable_count: int) -> None:
    """Update verification statistics."""
    get_tui().update_verify_stats(vulnerable_count, not_vulnerable_count)


def print_verify_summary(vulnerable_count: int, not_vulnerable_count: int,
                         total_paths: int) -> None:
    """Print verification summary."""
    get_tui().print_verify_summary(vulnerable_count, not_vulnerable_count, total_paths)
