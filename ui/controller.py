"""
Process-based controller for the Textual frontend.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import List, Optional


def _timestamp() -> str:
    return time.strftime("%H:%M:%S")


def _format_log_line(level: str, source: str, message: str) -> str:
    prefix = {
        "SUCCESS": "OK",
        "WARNING": "WARN",
        "ERROR": "ERR",
        "INFO": "INFO",
    }.get(level, level)
    return f"[{_timestamp()}] [{prefix}] [{source}] {message}"


@dataclass
class FrontendState:
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


class TextualFrontendController:
    """Shared state and lifecycle management for the standalone Textual app."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._state = FrontendState()
        self._process: Optional[subprocess.Popen] = None
        self._state_file: Optional[Path] = None
        self._root = None
        self._is_running = False
        self._stop_requested = False
        self._unexpected_shutdown = False

    @property
    def is_running(self) -> bool:
        with self._lock:
            if self._process is not None and self._process.poll() is not None:
                if self._is_running and not self._stop_requested:
                    self._unexpected_shutdown = True
                self._is_running = False
                self._process = None
            return self._is_running

    def start(
        self,
        target_path: str,
        target_endpoint: str,
        mode: str,
        batch_index: int = 0,
        batch_total: int = 0,
    ) -> None:
        with self._lock:
            if self.is_running:
                self.stop()

            self._state = FrontendState(
                mode=mode,
                target_path=target_path,
                target_endpoint=target_endpoint,
                target_project=Path(target_path).name if target_path else "",
                batch_index=batch_index,
                batch_total=batch_total,
                status_text="Starting analysis...",
                tree_text="Waiting for exploration to start...",
                call_chain_text="Waiting for verification to start...",
                agent_content=f"Target: {target_endpoint}\nPath: {target_path}",
                footer_note="Press Ctrl+C to stop the analysis process.",
            )
            self._root = None
            self._stop_requested = False
            self._unexpected_shutdown = False
            state_dir = Path("cache") / "ui"
            state_dir.mkdir(parents=True, exist_ok=True)
            state_name = f"state-{os.getpid()}-{int(time.time() * 1000)}.json"
            self._state_file = state_dir / state_name
            self._write_state_locked()
            self._process = subprocess.Popen(
                [sys.executable, "-m", "ui.launcher", str(self._state_file)],
                cwd=os.getcwd(),
            )
            self._is_running = True

        time.sleep(0.2)

    def stop(self) -> None:
        with self._lock:
            state_file = self._state_file
            process = self._process
            self._stop_requested = True
            if state_file is not None:
                self._state.should_exit = True
                self._write_state_locked()

        if process is not None:
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.terminate()
                try:
                    process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=1)

        with self._lock:
            self._is_running = False
            self._process = None
            self._state_file = None
            self._state.should_exit = False
            self._stop_requested = False
            self._unexpected_shutdown = False

        if state_file is not None:
            state_file.unlink(missing_ok=True)

    def consume_unexpected_shutdown(self) -> bool:
        with self._lock:
            self.is_running
            if not self._unexpected_shutdown:
                return False
            self._unexpected_shutdown = False
            return True

    def snapshot(self) -> FrontendState:
        with self._lock:
            return FrontendState(**asdict(self._state))

    def emit_output(self, text: str, source: str = "Console", level: str = "INFO") -> None:
        if not text:
            self.log(source, "", level)
            return
        for line in text.splitlines():
            self.log(source, line, level)

    def log(self, source: str, message: str, level: str = "INFO") -> None:
        with self._lock:
            self._state.logs.append(_format_log_line(level, source, message))
            if len(self._state.logs) > self._state.max_logs:
                self._state.logs = self._state.logs[-self._state.max_logs :]
            self._state.status_text = f"{source}: {message}" if message else source
            self._write_state_locked()

    def update_agent(self, name: str, status: str, content: str) -> None:
        with self._lock:
            self._state.agent_name = name or "System"
            self._state.agent_status = status or "idle"
            self._state.agent_content = content or ""
            self._state.stream_buffer = ""
            self._write_state_locked()

    def stream_agent_output(self, chunk: str) -> None:
        if not chunk:
            return
        with self._lock:
            self._state.stream_buffer += chunk
            if len(self._state.stream_buffer) > 8000:
                self._state.stream_buffer = self._state.stream_buffer[-8000:]
            self._write_state_locked()

    def clear_stream_buffer(self) -> None:
        with self._lock:
            self._state.stream_buffer = ""
            self._write_state_locked()

    def update_tree(self, root) -> None:
        with self._lock:
            self._root = root
            self._state.tree_text = self._render_tree_locked()
            self._write_state_locked()

    def update_stats(self, node_count: int) -> None:
        with self._lock:
            self._state.explore_nodes = node_count
            self._write_state_locked()

    def set_current_node(self, file_path: str, function_name: str, source_code: str = "") -> None:
        with self._lock:
            self._state.current_node_key = self._build_node_key(file_path, function_name, source_code)
            self._state.tree_text = self._render_tree_locked()
            self._write_state_locked()

    def clear_current_node(self) -> None:
        with self._lock:
            self._state.current_node_key = ""
            self._state.tree_text = self._render_tree_locked()
            self._write_state_locked()

    def set_verify_path_info(
        self,
        path_index: int,
        total_paths: int,
        call_chain: List[str],
        call_chain_files: List[str],
        sink_expression: str,
    ) -> None:
        with self._lock:
            self._state.path_index = path_index
            self._state.total_paths = total_paths
            self._state.call_chain = list(call_chain)
            self._state.call_chain_files = list(call_chain_files)
            self._state.sink_expression = sink_expression
            self._state.call_chain_text = self._render_call_chain_locked()
            self._write_state_locked()

    def set_verify_stage(self, stage: str) -> None:
        with self._lock:
            self._state.verify_stage = stage
            self._state.call_chain_text = self._render_call_chain_locked()
            self._write_state_locked()

    def set_analyzing_node(self, node_index: int) -> None:
        with self._lock:
            self._state.current_analyzing_index = node_index
            self._state.call_chain_text = self._render_call_chain_locked()
            self._write_state_locked()

    def update_verify_stats(self, vulnerable_count: int, not_vulnerable_count: int) -> None:
        with self._lock:
            self._state.vulnerable_count = vulnerable_count
            self._state.not_vulnerable_count = not_vulnerable_count
            self._state.call_chain_text = self._render_call_chain_locked()
            self._write_state_locked()

    def show_exploration_summary(
        self,
        path_traversal_count: int,
        command_injection_count: int,
        code_injection_count: int,
        sql_injection_count: int,
        ssrf_count: int,
        total_paths: int,
    ) -> None:
        lines = [
            f"Total Paths: {total_paths}",
            f"Path Traversal: {path_traversal_count}",
            f"Command Injection: {command_injection_count}",
            f"Code Injection: {code_injection_count}",
            f"SQL Injection: {sql_injection_count}",
            f"SSRF: {ssrf_count}",
            f"Nodes Explored: {self.snapshot().explore_nodes}",
        ]
        self._show_summary("Exploration Summary", lines, source="Explorer")

    def show_verification_summary(self, vulnerable_count: int, not_vulnerable_count: int, total_paths: int) -> None:
        lines = [
            f"Total Paths Analyzed: {total_paths}",
            f"Vulnerable: {vulnerable_count}",
            f"Not Vulnerable: {not_vulnerable_count}",
        ]
        self._show_summary("Verification Summary", lines, source="Verifier")

    def _show_summary(self, title: str, lines: List[str], source: str) -> None:
        with self._lock:
            self._state.summary_title = title
            self._state.summary_lines = list(lines)
            self._state.status_text = title
            for line in lines:
                self._state.logs.append(_format_log_line("SUCCESS", source, line))
            if len(self._state.logs) > self._state.max_logs:
                self._state.logs = self._state.logs[-self._state.max_logs :]
            self._write_state_locked()

        if self.is_running:
            time.sleep(0.3)
        else:
            print()
            print(title)
            for line in lines:
                print(f"  {line}")

    def _write_state_locked(self) -> None:
        if self._state_file is None:
            return
        payload = asdict(self._state)
        temp_path = self._state_file.with_suffix(".tmp")
        with open(temp_path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2)
        os.replace(temp_path, self._state_file)

    @staticmethod
    def _build_node_key(file_path: str, function_name: str, source_code: str = "") -> str:
        filename = os.path.basename(file_path) if file_path else "unknown"
        source_digest = hashlib.sha1(source_code.strip().encode("utf-8")).hexdigest()[:12] if source_code else "nosrc"
        return f"{filename}#{function_name}#{source_digest}"

    def _render_tree_locked(self) -> str:
        if self._root is None:
            return "Waiting for exploration to start..."

        lines: List[str] = []

        def visit(node, prefix: str = "", is_last: bool = True) -> None:
            connector = "└─ " if prefix else ""
            if prefix:
                connector = "└─ " if is_last else "├─ "
            lines.append(f"{prefix}{connector}{self._format_tree_node(node)}")
            child_prefix = prefix + ("   " if is_last else "│  ")
            for index, child in enumerate(node.children):
                visit(child, child_prefix, index == len(node.children) - 1)

        visit(self._root)
        return "\n".join(lines)

    def _format_tree_node(self, node) -> str:
        if node.is_sink():
            return f"● {node.tag.value} :: {node.extra_info}"

        filename = os.path.basename(node.file_path) if node.file_path else "unknown"
        func_name = node.function_name if node.function_name else "unknown"
        node_key = self._build_node_key(node.file_path, func_name, node.source_code)
        marker = "> " if self._state.current_node_key and node_key == self._state.current_node_key else "· "
        return f"{marker}{filename}#{func_name} [{node.tag.value}]"

    def _render_call_chain_locked(self) -> str:
        if not self._state.call_chain:
            return "Waiting for verification to start..."

        lines = []
        if self._state.total_paths:
            lines.append(f"Path {self._state.path_index}/{self._state.total_paths}")
        if self._state.verify_stage:
            lines.append(f"Stage: {self._state.verify_stage}")
        lines.append("")

        for index, func_name in enumerate(self._state.call_chain):
            short_file = ""
            if index < len(self._state.call_chain_files) and self._state.call_chain_files[index]:
                short_file = os.path.basename(self._state.call_chain_files[index])
            marker = ">" if self._state.current_analyzing_index == index else "-"
            line = f"{marker} [{index}] {func_name}"
            if short_file:
                line += f"  ({short_file})"
            lines.append(line)
        if self._state.sink_expression:
            lines.append(f"- Sink  ::  {self._state.sink_expression}")
        else:
            lines.append("- Sink")
        lines.append("")
        lines.append(f"Vulnerable: {self._state.vulnerable_count} | Not Vulnerable: {self._state.not_vulnerable_count}")
        return "\n".join(line for line in lines if line)


_controller: Optional[TextualFrontendController] = None


def get_controller() -> TextualFrontendController:
    global _controller
    if _controller is None:
        _controller = TextualFrontendController()
    return _controller
