"""Plan tool — TODO list management for the agentic loop.

The LLM calls ``update_plan`` to track engagement progress.
After every tool execution, the agent loop injects the current plan as a
system reminder so the LLM never loses track of its objective.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .registry import ToolRegistry, ToolRiskLevel


class TaskStatus(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    DONE = "done"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class PlanTask:
    id: str
    task: str
    status: TaskStatus = TaskStatus.PENDING
    phase: str = ""
    priority: int = 1          # 1 = highest


class PlanStore:
    """In-memory TODO list for the current session.

    One instance per agent session, held in session state.
    """

    def __init__(self) -> None:
        self._tasks: dict[str, PlanTask] = {}

    def update(self, tasks: list[dict[str, Any]]) -> None:
        """Upsert tasks. Each dict must have 'id' and 'task'; other fields optional."""
        for raw in tasks:
            tid = str(raw["id"])
            if tid in self._tasks:
                existing = self._tasks[tid]
                existing.task = raw.get("task", existing.task)
                existing.status = TaskStatus(raw.get("status", existing.status.value))
                existing.phase = raw.get("phase", existing.phase)
                existing.priority = int(raw.get("priority", existing.priority))
            else:
                self._tasks[tid] = PlanTask(
                    id=tid,
                    task=raw["task"],
                    status=TaskStatus(raw.get("status", TaskStatus.PENDING.value)),
                    phase=raw.get("phase", ""),
                    priority=int(raw.get("priority", 1)),
                )

    def as_reminder(self) -> str:
        """Short inline reminder injected into the system prompt after every tool result.

        Format: [Plan Status] ✓ 3 done | ► 1 in progress | ○ 4 pending | Next: {task}
        """
        if not self._tasks:
            return ""
        done = sum(1 for t in self._tasks.values() if t.status == TaskStatus.DONE)
        in_prog = [t for t in self._tasks.values() if t.status == TaskStatus.IN_PROGRESS]
        pending = sorted(
            [t for t in self._tasks.values() if t.status == TaskStatus.PENDING],
            key=lambda t: t.priority,
        )
        failed = sum(1 for t in self._tasks.values() if t.status == TaskStatus.FAILED)

        next_task = in_prog[0].task if in_prog else (pending[0].task if pending else "—")

        parts = [
            f"[Plan Status] {done} done",
            f"{len(in_prog)} in progress",
            f"{len(pending)} pending",
        ]
        if failed:
            parts.append(f"{failed} failed")
        parts.append(f"Next: {next_task[:80]}")
        return " | ".join(parts)

    def as_table(self) -> "Table":
        """Full plan table for the /plan slash command — returns a Rich Table."""
        from rich.table import Table as RichTable

        tbl = RichTable(title="Engagement Plan", show_lines=True, expand=False)
        tbl.add_column("ID", style="dim", width=8)
        tbl.add_column("", width=3)   # status icon
        tbl.add_column("Phase", style="cyan", max_width=20)
        tbl.add_column("Task")
        tbl.add_column("Pri", width=4, justify="right")

        _icon_color = {
            TaskStatus.PENDING:     ("[ ]", "white"),
            TaskStatus.IN_PROGRESS: ("[>]", "yellow"),
            TaskStatus.DONE:        ("[+]", "green"),
            TaskStatus.FAILED:      ("[!]", "red"),
            TaskStatus.SKIPPED:     ("[-]", "dim"),
        }

        if not self._tasks:
            tbl.add_row("—", "", "", "[dim]No tasks yet[/dim]", "")
            return tbl

        for t in sorted(self._tasks.values(), key=lambda x: (x.priority, x.id)):
            icon, color = _icon_color.get(t.status, ("?", "white"))
            tbl.add_row(
                t.id,
                f"[{color}]{icon}[/{color}]",
                t.phase[:18] if t.phase else "",
                t.task,
                str(t.priority),
            )
        return tbl

    def to_dict(self) -> list[dict[str, Any]]:
        return [
            {
                "id": t.id,
                "task": t.task,
                "status": t.status.value,
                "phase": t.phase,
                "priority": t.priority,
            }
            for t in self._tasks.values()
        ]


# Module-level singleton — replaced per session by the agent
_store = PlanStore()


def get_plan_store() -> PlanStore:
    return _store


def set_plan_store(store: PlanStore) -> None:
    global _store
    _store = store


def register_plan_tool(registry: ToolRegistry) -> None:
    """Register the ``update_plan`` tool into *registry*."""

    @registry.register(
        name="update_plan",
        description=(
            "Update the engagement TODO list. Pass an array of task objects to create "
            "or update tasks. Each object: {id, task, status?, phase?, priority?}. "
            "status values: pending | in_progress | done | failed | skipped."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "tasks": {
                    "type": "array",
                    "description": "Array of task objects to upsert.",
                    "items": {
                        "type": "object",
                        "properties": {
                            "id": {"type": "string", "description": "Unique task ID."},
                            "task": {"type": "string", "description": "Task description."},
                            "status": {
                                "type": "string",
                                "enum": ["pending", "in_progress", "done", "failed", "skipped"],
                            },
                            "phase": {"type": "string", "description": "Engagement phase name."},
                            "priority": {
                                "type": "integer",
                                "description": "Priority (1=highest). Affects display order.",
                            },
                        },
                        "required": ["id", "task"],
                    },
                },
            },
            "required": ["tasks"],
        },
        risk=ToolRiskLevel.SAFE,
    )
    async def update_plan(tasks: list[dict[str, Any]]) -> str:
        store = get_plan_store()
        store.update(tasks)
        return store.as_reminder()
