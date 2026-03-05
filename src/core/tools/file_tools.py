"""File tools — read, write, list, search, and grep operations.

All tools are registered as SAFE risk level (no confirmation needed).
"""

from __future__ import annotations

import fnmatch
import os
import re
from pathlib import Path

from .registry import ToolRegistry, ToolRiskLevel


def register_file_tools(registry: ToolRegistry) -> None:
    """Register all file tools into *registry*."""

    # ── read_file ──────────────────────────────────────────────────────────

    @registry.register(
        name="read_file",
        description=(
            "Read the contents of a file. Optionally specify a line range "
            "like '10-50' to read only those lines."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Absolute or relative file path."},
                "line_range": {
                    "type": "string",
                    "description": "Optional line range, e.g. '10-50'. 1-indexed, inclusive.",
                },
            },
            "required": ["path"],
        },
        risk=ToolRiskLevel.SAFE,
    )
    async def read_file(path: str, line_range: str | None = None) -> str:
        p = Path(path)
        if not p.exists():
            return f"[ERROR] File not found: {path}"
        if not p.is_file():
            return f"[ERROR] Not a file: {path}"
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            return f"[ERROR] Could not read file: {e}"

        if line_range:
            lines = text.splitlines()
            try:
                start_s, end_s = line_range.split("-")
                start = max(1, int(start_s)) - 1
                end = int(end_s)
                selected = lines[start:end]
                text = "\n".join(
                    f"{start + i + 1:>6}  {line}" for i, line in enumerate(selected)
                )
            except (ValueError, IndexError):
                return f"[ERROR] Invalid line_range '{line_range}'. Use format '10-50'."

        return text

    # ── write_file ─────────────────────────────────────────────────────────

    @registry.register(
        name="write_file",
        description="Write content to a file, creating parent directories if needed. Overwrites existing content.",
        input_schema={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Absolute or relative file path."},
                "content": {"type": "string", "description": "Text content to write."},
            },
            "required": ["path", "content"],
        },
        risk=ToolRiskLevel.CONFIRM,
    )
    async def write_file(path: str, content: str) -> str:
        p = Path(path)
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8")
            return f"[OK] Written {len(content)} chars to {path}"
        except Exception as e:
            return f"[ERROR] Could not write file: {e}"

    # ── list_directory ─────────────────────────────────────────────────────

    @registry.register(
        name="list_directory",
        description="List files and directories up to 2 levels deep.",
        input_schema={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Directory path to list. Defaults to current directory.",
                },
            },
            "required": [],
        },
        risk=ToolRiskLevel.SAFE,
    )
    async def list_directory(path: str = ".") -> str:
        p = Path(path)
        if not p.exists():
            return f"[ERROR] Path not found: {path}"
        if not p.is_dir():
            return f"[ERROR] Not a directory: {path}"

        lines: list[str] = [str(p.resolve())]

        def _walk(current: Path, prefix: str, depth: int) -> None:
            if depth > 2:
                return
            try:
                entries = sorted(current.iterdir(), key=lambda e: (e.is_file(), e.name))
            except PermissionError:
                lines.append(f"{prefix}[permission denied]")
                return
            for i, entry in enumerate(entries):
                connector = "└── " if i == len(entries) - 1 else "├── "
                size = f"  ({entry.stat().st_size} B)" if entry.is_file() else ""
                lines.append(f"{prefix}{connector}{entry.name}{size}")
                if entry.is_dir() and depth < 2:
                    extension = "    " if i == len(entries) - 1 else "│   "
                    _walk(entry, prefix + extension, depth + 1)

        _walk(p, "", 1)
        return "\n".join(lines)

    # ── search_files ───────────────────────────────────────────────────────

    @registry.register(
        name="search_files",
        description=(
            "Search for files by name pattern (glob or regex) under a directory. "
            "Returns matching file paths."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Glob (e.g. '*.py') or regex pattern for filenames.",
                },
                "path": {
                    "type": "string",
                    "description": "Root directory to search. Defaults to '.'.",
                },
                "regex": {
                    "type": "boolean",
                    "description": "If true, treat pattern as a Python regex. Default false (glob).",
                },
            },
            "required": ["pattern"],
        },
        risk=ToolRiskLevel.SAFE,
    )
    async def search_files(pattern: str, path: str = ".", regex: bool = False) -> str:
        root = Path(path)
        if not root.exists():
            return f"[ERROR] Path not found: {path}"

        matches: list[str] = []
        if regex:
            try:
                rx = re.compile(pattern)
            except re.error as e:
                return f"[ERROR] Invalid regex: {e}"
            for entry in root.rglob("*"):
                if entry.is_file() and rx.search(entry.name):
                    matches.append(str(entry))
        else:
            for entry in root.rglob(pattern):
                if entry.is_file():
                    matches.append(str(entry))

        if not matches:
            return f"No files matching '{pattern}' under {path}"
        return "\n".join(sorted(matches))

    # ── grep_tool ──────────────────────────────────────────────────────────

    @registry.register(
        name="grep_tool",
        description=(
            "Search file contents for a pattern (like ripgrep). "
            "Returns matching lines with file path and line number."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Python regex pattern to search for.",
                },
                "path": {
                    "type": "string",
                    "description": "File or directory to search. Defaults to '.'.",
                },
                "include": {
                    "type": "string",
                    "description": "Glob filter for filenames, e.g. '*.py'. Defaults to '*'.",
                },
                "case_sensitive": {
                    "type": "boolean",
                    "description": "Case-sensitive search. Defaults to true.",
                },
                "max_results": {
                    "type": "integer",
                    "description": "Maximum number of matching lines to return. Defaults to 200.",
                },
            },
            "required": ["pattern"],
        },
        risk=ToolRiskLevel.SAFE,
    )
    async def grep_tool(
        pattern: str,
        path: str = ".",
        include: str = "*",
        case_sensitive: bool = True,
        max_results: int = 200,
    ) -> str:
        try:
            flags = 0 if case_sensitive else re.IGNORECASE
            rx = re.compile(pattern, flags)
        except re.error as e:
            return f"[ERROR] Invalid regex: {e}"

        root = Path(path)
        if not root.exists():
            return f"[ERROR] Path not found: {path}"

        results: list[str] = []

        def _search_file(fp: Path) -> None:
            try:
                for lineno, line in enumerate(
                    fp.read_text(encoding="utf-8", errors="replace").splitlines(), start=1
                ):
                    if rx.search(line):
                        results.append(f"{fp}:{lineno}: {line}")
                        if len(results) >= max_results:
                            return
            except (PermissionError, IsADirectoryError):
                pass

        if root.is_file():
            _search_file(root)
        else:
            for fp in root.rglob("*"):
                if fp.is_file() and fnmatch.fnmatch(fp.name, include):
                    _search_file(fp)
                    if len(results) >= max_results:
                        results.append(f"[truncated at {max_results} results]")
                        break

        if not results:
            return f"No matches for '{pattern}' in {path}"
        return "\n".join(results)
