"""
Textual application for VulSolver.
"""

from __future__ import annotations

import json
import os
import textwrap
from dataclasses import dataclass, field
from pathlib import Path
from typing import List

from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import Static


@dataclass
class UISnapshot:
    mode: str = "explore"
    target_path: str = ""
    target_endpoint: str = ""
    target_project: str = ""
    batch_index: int = 0
    batch_total: int = 0
    status_text: str = "Idle"
    should_exit: bool = False
    tree_text: str = "Waiting for exploration to start..."
    explore_nodes: int = 0
    current_node_key: str = ""
    call_chain_text: str = "Waiting for verification to start..."
    verify_stage: str = ""
    path_index: int = 0
    total_paths: int = 0
    vulnerable_count: int = 0
    not_vulnerable_count: int = 0
    current_analyzing_index: int = -1
    call_chain: List[str] = field(default_factory=list)
    call_chain_files: List[str] = field(default_factory=list)
    sink_expression: str = ""
    logs: List[str] = field(default_factory=list)
    max_logs: int = 300
    agent_name: str = "System"
    agent_status: str = "idle"
    agent_content: str = ""
    stream_buffer: str = ""
    summary_title: str = ""
    summary_lines: List[str] = field(default_factory=list)
    footer_note: str = ""


@dataclass
class FocusView:
    title: str
    subtitle: str
    text: str


@dataclass
class PanelView:
    title: str
    subtitle: str
    text: str


class VulSolverTextualApp(App):
    """Standalone Textual frontend for VulSolver analysis runs."""

    CSS_PATH = "vulsolver.tcss"
    TITLE = "VulSolver"
    SUB_TITLE = "Analysis Console"

    def __init__(self, state_file: str) -> None:
        super().__init__()
        self.state_file = Path(state_file)
        self._last_snapshot: UISnapshot | None = None

    def compose(self) -> ComposeResult:
        yield Static(id="window-bar")
        with Vertical(id="shell"):
            with Horizontal(id="workspace"):
                with Vertical(id="left-column"):
                    with Vertical(id="focus-card", classes="panel-frame panel-focus"):
                        yield Static(id="focus-title", classes="panel-title")
                        with VerticalScroll(id="focus-scroll", classes="panel-content panel-scroll"):
                            yield Static(id="focus-content", classes="body-text mono")

                    with Vertical(id="log-card", classes="panel-frame panel-log"):
                        yield Static(id="log-title", classes="panel-title")
                        with VerticalScroll(id="log-scroll", classes="panel-content panel-scroll"):
                            yield Static(id="log-content", classes="body-text mono")

                with Vertical(id="stream-card", classes="panel-frame panel-stream"):
                    yield Static(id="stream-title", classes="panel-title")
                    with VerticalScroll(id="stream-scroll", classes="panel-content panel-scroll"):
                        yield Static(id="stream-content", classes="body-text mono wrap-text")

            with Vertical(id="footer"):
                yield Static(id="status-line")
                yield Static(id="summary-line")

    def on_mount(self) -> None:
        self.set_interval(0.1, self.refresh_from_state)

    def refresh_from_state(self) -> None:
        snapshot = self._load_snapshot()
        if snapshot is None:
            return
        if snapshot.should_exit:
            self.exit()
            return
        if snapshot == self._last_snapshot:
            return
        self._last_snapshot = snapshot

        focus = self._render_focus(snapshot)
        logs = self._render_logs(snapshot)
        stream = self._render_agent(snapshot)

        self.query_one("#window-bar", Static).update(self._render_window_bar(snapshot))
        self.query_one("#focus-title", Static).update(self._render_panel_title(focus))
        self.query_one("#log-title", Static).update(self._render_panel_title(logs))
        self.query_one("#stream-title", Static).update(self._render_panel_title(stream))
        self.query_one("#focus-content", Static).update(focus.text)
        self.query_one("#log-content", Static).update(logs.text)
        self.query_one("#stream-content", Static).update(stream.text)
        self.query_one("#status-line", Static).update(self._render_status_line(snapshot))
        self.query_one("#summary-line", Static).update(self._render_summary_line(snapshot))
        self._sync_scroll_positions(snapshot)

    def _load_snapshot(self) -> UISnapshot | None:
        try:
            raw = self.state_file.read_text(encoding="utf-8")
            payload = json.loads(raw)
            filtered = {key: payload[key] for key in UISnapshot.__dataclass_fields__ if key in payload}
            return UISnapshot(**filtered)
        except FileNotFoundError:
            return None
        except json.JSONDecodeError:
            return self._last_snapshot

    @staticmethod
    def _render_window_bar(snapshot: UISnapshot) -> str:
        project = snapshot.target_project or "-"
        endpoint = snapshot.target_endpoint or "-"
        target = endpoint
        if snapshot.batch_total > 0:
            target = f"{target}   {snapshot.batch_index}/{snapshot.batch_total}"
        return f" VulSolver   {project}   {target} "

    @staticmethod
    def _render_panel_title(panel: PanelView | FocusView) -> str:
        if panel.subtitle:
            return f"  {panel.title}   {panel.subtitle}  "
        return f"  {panel.title}  "

    def _focus_lines(self, snapshot: UISnapshot) -> List[str]:
        raw = snapshot.tree_text if snapshot.mode == "explore" else snapshot.call_chain_text
        default = "Waiting for exploration to start..." if snapshot.mode == "explore" else "Waiting for verification to start..."
        lines = raw.splitlines() if raw.strip() else [default]

        if snapshot.mode == "verify":
            lines = [
                line for line in lines
                if line.strip()
                and not line.startswith("Path ")
                and not line.startswith("Stage:")
                and not line.startswith("Vulnerable:")
            ]

        return lines

    def _render_focus(self, snapshot: UISnapshot) -> FocusView:
        lines = self._focus_lines(snapshot)

        width = self._content_width("#focus-scroll", fallback=72)
        wrapped_lines = self._soft_wrap_lines(lines, width)
        text = "\n".join(wrapped_lines)
        active_line = self._build_active_line(snapshot)

        if active_line:
            active_wrapped = "\n".join(self._soft_wrap_lines([active_line], width))
            text = f"{active_wrapped}\n\n{text}"

        total = len(lines)
        subtitle = f"{total} lines"
        if snapshot.mode == "explore":
            title = "Execution Graph"
            subtitle = (
                f"{snapshot.target_endpoint or '-'}   {total} lines"
                f"   {snapshot.explore_nodes} nodes"
            )
            subtitle += "   full context"
        else:
            stage = (snapshot.verify_stage or "-").replace("_", " ").upper()
            title = "Call Chain"
            subtitle = (
                f"path {snapshot.path_index}/{snapshot.total_paths or 0}"
                f"   {stage}"
                f"   {total} lines"
            )
            subtitle += "   full context"

        return FocusView(title=title, subtitle=subtitle, text=text)

    def _sync_scroll_positions(self, snapshot: UISnapshot) -> None:
        try:
            self.query_one("#log-scroll", VerticalScroll).scroll_end(
                animate=False,
                immediate=True,
                x_axis=False,
            )
        except Exception:
            pass

        try:
            self.query_one("#stream-scroll", VerticalScroll).scroll_end(
                animate=False,
                immediate=True,
                x_axis=False,
            )
        except Exception:
            pass

        try:
            focus_scroll = self.query_one("#focus-scroll", VerticalScroll)
            focus_scroll.scroll_to(
                y=self._focus_scroll_target(snapshot),
                animate=False,
                immediate=True,
                force=True,
            )
        except Exception:
            pass

    def _focus_scroll_target(self, snapshot: UISnapshot) -> int:
        lines = self._focus_lines(snapshot)
        anchor = self._find_anchor(lines)
        width = self._content_width("#focus-scroll", fallback=72)
        height = self._content_height("#focus-scroll", fallback=18)

        wrapped_before_anchor = len(self._soft_wrap_lines(lines[:anchor], width))
        active_line = self._build_active_line(snapshot)
        prefix_lines = 0
        if active_line:
            prefix_lines = len(self._soft_wrap_lines([active_line], width)) + 2

        context_lines = max(0, height // 3)
        return max(0, prefix_lines + wrapped_before_anchor - context_lines)

    def _render_logs(self, snapshot: UISnapshot) -> PanelView:
        if not snapshot.logs:
            return PanelView(title="Logs", subtitle="waiting for events", text="No events yet.")

        width = self._content_width("#log-scroll", fallback=72)
        wrapped = self._soft_wrap_lines(snapshot.logs, width)
        text = "\n".join(wrapped)
        subtitle = f"{len(snapshot.logs)} events"
        return PanelView(title="Logs", subtitle=subtitle, text=text)

    def _render_agent(self, snapshot: UISnapshot) -> PanelView:
        content = snapshot.agent_content.strip()
        stream = snapshot.stream_buffer.strip()

        chunks: List[str] = []
        if content:
            chunks.append(content)
        if stream:
            if chunks:
                chunks.append("")
            chunks.append(stream)
        if not chunks:
            chunks.append("Waiting for model output...")

        raw_lines = "\n".join(chunks).splitlines() or ["Waiting for model output..."]
        width = self._content_width("#stream-scroll", fallback=44)
        wrapped = self._soft_wrap_lines(raw_lines, width)
        text = "\n".join(wrapped)
        subtitle = snapshot.agent_name or "System"
        title = "Agent Output"
        return PanelView(title=title, subtitle=subtitle, text=text)

    def _render_status_line(self, snapshot: UISnapshot) -> str:
        if snapshot.mode == "explore":
            return snapshot.status_text or "Exploration running"
        return (
            f"{snapshot.status_text or 'Verification running'}"
            f"  ·  {snapshot.vulnerable_count} vulnerable"
            f"  ·  {snapshot.not_vulnerable_count} safe"
            f"  ·  path {snapshot.path_index}/{snapshot.total_paths or 0}"
        )

    def _render_summary_line(self, snapshot: UISnapshot) -> str:
        if snapshot.summary_lines:
            width = self._content_width("#footer", fallback=120)
            return self._clip_lines(["  ·  ".join(snapshot.summary_lines)], width)[0]
        if snapshot.mode == "explore":
            return f"{snapshot.explore_nodes} nodes discovered"
        return f"{snapshot.vulnerable_count} vulnerable  ·  {snapshot.not_vulnerable_count} safe"

    @staticmethod
    def _find_anchor(lines: List[str]) -> int:
        for index, line in enumerate(lines):
            if "> " in line or line.startswith(">"):
                return index
        return max(0, len(lines) - 1)

    @staticmethod
    def _build_active_line(snapshot: UISnapshot) -> str:
        if snapshot.mode == "explore":
            if not snapshot.current_node_key:
                return ""
            node_ref = snapshot.current_node_key.split("#", 2)
            if len(node_ref) >= 2:
                return f"Analyzing now: {node_ref[0]}#{node_ref[1]}"
            return ""

        if snapshot.current_analyzing_index < 0:
            return ""
        if snapshot.current_analyzing_index < len(snapshot.call_chain):
            func_name = snapshot.call_chain[snapshot.current_analyzing_index]
            short_file = ""
            if snapshot.current_analyzing_index < len(snapshot.call_chain_files):
                file_path = snapshot.call_chain_files[snapshot.current_analyzing_index]
                short_file = os.path.basename(file_path) if file_path else ""
            file_part = f" ({short_file})" if short_file else ""
            return f"Analyzing now: [{snapshot.current_analyzing_index}] {func_name}{file_part}"
        return "Analyzing now: Sink"

    @staticmethod
    def _soft_wrap_lines(lines: List[str], width: int) -> List[str]:
        width = max(18, width)
        wrapped: List[str] = []
        for line in lines:
            if not line:
                wrapped.append("")
                continue
            wrapped.extend(
                textwrap.wrap(
                    line,
                    width=width,
                    break_long_words=True,
                    break_on_hyphens=False,
                    replace_whitespace=False,
                    drop_whitespace=False,
                )
                or [line]
            )
        return wrapped

    @staticmethod
    def _clip_lines(lines: List[str], width: int) -> List[str]:
        width = max(12, width)
        clipped = []
        for line in lines:
            if len(line) <= width:
                clipped.append(line)
            else:
                clipped.append(f"{line[: width - 3]}...")
        return clipped

    def _content_height(self, selector: str, fallback: int) -> int:
        try:
            return max(1, self.query_one(selector).size.height)
        except Exception:
            return fallback

    def _content_width(self, selector: str, fallback: int) -> int:
        try:
            return max(12, self.query_one(selector).size.width - 6)
        except Exception:
            return fallback
