"""Launch the standalone Textual frontend."""

from __future__ import annotations

import os
import sys

from ui.textual_app import VulSolverTextualApp


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: python -m ui.launcher <state-file>")
        return 1
    app = VulSolverTextualApp(sys.argv[1], parent_pid=os.getppid())
    app.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
