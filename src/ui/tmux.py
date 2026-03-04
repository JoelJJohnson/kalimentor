"""tmux integration — split layout and pane capture for KaliMentor."""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import sys

TMUX_PANE_ENV = "KALIMENTOR_TMUX_PANE"


def is_in_tmux() -> bool:
    return "TMUX" in os.environ


def setup_tmux_layout() -> str | None:
    """Set up a tmux split layout for KaliMentor.

    Returns the right-pane ID (e.g. "%3") to use for capture, or None if
    tmux is unavailable.

    Behaviour:
    - If KALIMENTOR_TMUX_PANE is already set (re-exec path): return it.
    - If inside an existing tmux session: split the current window right.
    - If outside tmux: create a new session with a split and re-exec inside it.
    """
    if pane_id := os.environ.get(TMUX_PANE_ENV):
        return pane_id

    if not shutil.which("tmux"):
        return None

    if is_in_tmux():
        return _split_current_window()
    else:
        _launch_in_new_session()
        # _launch_in_new_session calls os.execvp which never returns normally.
        return None


def _split_current_window() -> str:
    """Split the current tmux window to the right (40 % for bash).

    Returns the pane ID of the new right-hand bash pane.
    """
    # Remember which pane we are in now
    current = subprocess.run(
        ["tmux", "display-message", "-p", "#{pane_id}"],
        capture_output=True, text=True,
    ).stdout.strip()

    # Create the right pane
    subprocess.run(
        ["tmux", "split-window", "-h", "-p", "40", "bash"],
        check=True,
    )

    # The active pane is now the new right one — grab its ID
    new_pane = subprocess.run(
        ["tmux", "display-message", "-p", "#{pane_id}"],
        capture_output=True, text=True,
    ).stdout.strip()

    # Return focus to left pane (where Textual will run)
    subprocess.run(["tmux", "select-pane", "-t", current])

    return new_pane


def _launch_in_new_session() -> None:
    """Create a fresh tmux session with a split and re-exec kalimentor in it."""
    session = "kalimentor"

    # Remove any stale session
    subprocess.run(["tmux", "kill-session", "-t", session], capture_output=True)

    # New detached session (left pane starts with a shell)
    subprocess.run(["tmux", "new-session", "-d", "-s", session], check=True)

    # Split right — 40 % for bash
    subprocess.run(
        ["tmux", "split-window", "-h", "-p", "40", "-t", f"{session}:0.0", "bash"],
        check=True,
    )

    # Find out what pane ID was assigned to the right pane
    right_pane = subprocess.run(
        ["tmux", "display-message", "-t", f"{session}:0.1", "-p", "#{pane_id}"],
        capture_output=True, text=True,
    ).stdout.strip()

    # Re-exec ourselves inside the left pane with the right-pane ID exported
    original_cmd = " ".join(shlex.quote(a) for a in sys.argv)
    full_cmd = f"export {TMUX_PANE_ENV}={right_pane} && {original_cmd}"
    subprocess.run(
        ["tmux", "send-keys", "-t", f"{session}:0.0", full_cmd, "Enter"],
        check=True,
    )

    # Attach (replaces this process with the tmux client)
    os.execvp("tmux", ["tmux", "attach-session", "-t", session])


def capture_pane(pane_id: str) -> str:
    """Return the visible text content of a tmux pane."""
    result = subprocess.run(
        ["tmux", "capture-pane", "-t", pane_id, "-p"],
        capture_output=True, text=True,
    )
    return result.stdout.strip()
