"""Session manager — persistence, state tracking, and export."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from .models import (
    ActionResult,
    AttackPlan,
    Finding,
    Phase,
    ProposedAction,
    SessionState,
    TargetInfo,
    AgentMode,
    LLMProvider,
    ChallengeType,
)

SESSIONS_DIR = Path.home() / ".kalimentor" / "sessions"


class SessionManager:
    """Manages the lifecycle of a learning session."""

    def __init__(self, state: SessionState | None = None):
        self.state = state or SessionState()
        SESSIONS_DIR.mkdir(parents=True, exist_ok=True)

    # ── Creation ───────────────────────────────────────────────────────

    @classmethod
    def new(
        cls,
        objective: str,
        target_ip: str | None = None,
        target_url: str | None = None,
        challenge_type: str = "machine",
        mode: str = "interactive",
        llm_provider: str = "ollama",
        llm_model: str = "",
    ) -> "SessionManager":
        target = TargetInfo(ip=target_ip, url=target_url, challenge_type=challenge_type)
        state = SessionState(
            objective=objective,
            target=target,
            mode=mode,
            llm_provider=llm_provider,
            llm_model=llm_model,
        )
        mgr = cls(state)
        mgr.save()
        return mgr

    @classmethod
    def load(cls, session_id: str) -> "SessionManager":
        path = SESSIONS_DIR / f"{session_id}.json"
        if not path.exists():
            raise FileNotFoundError(f"Session {session_id} not found at {path}")
        data = json.loads(path.read_text())
        state = SessionState(**data)
        return cls(state)

    @classmethod
    def list_sessions(cls) -> list[dict]:
        sessions = []
        for path in sorted(SESSIONS_DIR.glob("*.json"), reverse=True):
            try:
                data = json.loads(path.read_text())
                sessions.append({
                    "id": data["id"],
                    "objective": data.get("objective", ""),
                    "target_ip": data.get("target", {}).get("ip", ""),
                    "phase": data.get("current_phase", ""),
                    "access": data.get("access_level", "none"),
                    "provider": data.get("llm_provider", ""),
                    "updated": data.get("updated_at", ""),
                })
            except Exception:
                continue
        return sessions

    # ── Persistence ────────────────────────────────────────────────────

    @property
    def session_dir(self) -> Path:
        """Per-session directory for memory files and message history."""
        d = SESSIONS_DIR / self.state.id
        d.mkdir(parents=True, exist_ok=True)
        return d

    def save(self) -> Path:
        self.state.updated_at = datetime.utcnow()
        path = SESSIONS_DIR / f"{self.state.id}.json"
        path.write_text(self.state.model_dump_json(indent=2))
        return path

    def load_messages(self) -> list:
        """Load conversation history from messages.jsonl."""
        path = self.session_dir / "messages.jsonl"
        if not path.exists():
            return []
        messages = []
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                try:
                    messages.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return messages

    def append_message(self, message: dict) -> None:
        """Append a single message to messages.jsonl."""
        path = self.session_dir / "messages.jsonl"
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(message) + "\n")

    def save_messages(self, messages: list) -> None:
        """Overwrite messages.jsonl with the given message list."""
        path = self.session_dir / "messages.jsonl"
        with path.open("w", encoding="utf-8") as f:
            for msg in messages:
                f.write(json.dumps(msg) + "\n")

    # ── State Updates ──────────────────────────────────────────────────

    def add_finding(self, finding: Finding) -> None:
        self.state.findings.append(finding)
        if finding.category == "port":
            if finding.key not in self.state.open_ports:
                self.state.open_ports.append(finding.key)
        elif finding.category == "service":
            self.state.services[finding.key] = finding.value
        elif finding.category == "credential":
            self.state.credentials.append({"key": finding.key, "value": finding.value})
        elif finding.category == "vulnerability":
            self.state.vulnerabilities.append({
                "key": finding.key, "value": finding.value, "tags": finding.tags,
            })
        self.save()

    def record_action(self, action: ProposedAction, result: ActionResult) -> None:
        entry = {
            "action": action.model_dump(),
            "result": result.model_dump(),
        }
        self.state.action_history.append(entry)
        for f in result.findings:
            self.add_finding(f)
        self.save()

    def advance_phase(self, phase: Phase) -> None:
        self.state.current_phase = phase
        self.save()

    def set_access_level(self, level: str) -> None:
        self.state.access_level = level
        self.save()

    def add_flag(self, flag: str) -> None:
        if flag not in self.state.flags:
            self.state.flags.append(flag)
            self.save()

    def add_note(self, note: str) -> None:
        self.state.user_notes.append(note)
        self.save()

    # ── Context for LLM ───────────────────────────────────────────────

    def get_context_summary(self) -> str:
        s = self.state
        lines = [
            f"## Session: {s.id}",
            f"Objective: {s.objective}",
            f"Target: {s.target.ip or s.target.url or 'N/A'} ({s.target.challenge_type})",
            f"Phase: {s.current_phase.value}",
            f"Access Level: {s.access_level}",
            "",
            f"### Open Ports ({len(s.open_ports)})",
            ", ".join(s.open_ports) or "None discovered yet",
            "",
            "### Services",
        ]
        for port, svc in s.services.items():
            lines.append(f"  {port}: {svc}")
        if not s.services:
            lines.append("  None identified yet")

        lines.append(f"\n### Credentials ({len(s.credentials)})")
        for c in s.credentials:
            lines.append(f"  {c['key']}: {c['value']}")

        lines.append(f"\n### Vulnerabilities ({len(s.vulnerabilities)})")
        for v in s.vulnerabilities:
            lines.append(f"  {v['key']}: {v['value']}")

        lines.append(f"\n### Flags: {len(s.flags)}")
        lines.append(f"### Actions Executed: {len(s.action_history)}")

        recent = s.action_history[-5:]
        if recent:
            lines.append("\n### Recent Actions")
            for entry in recent:
                a = entry["action"]
                r = entry["result"]
                lines.append(f"  [{r['status']}] {a['tool']}: {a['command'][:80]}")

        return "\n".join(lines)

    # ── Export ─────────────────────────────────────────────────────────

    def export_markdown(self) -> str:
        s = self.state
        lines = [
            f"# KaliMentor Session Report",
            f"",
            f"| Field | Value |",
            f"|---|---|",
            f"| Session ID | `{s.id}` |",
            f"| Created | {s.created_at.isoformat()} |",
            f"| Objective | {s.objective} |",
            f"| Target | {s.target.ip or s.target.url or 'N/A'} |",
            f"| Challenge Type | {s.target.challenge_type} |",
            f"| Final Access | {s.access_level} |",
            f"| Flags Captured | {len(s.flags)} |",
            f"| LLM Provider | {s.llm_provider} |",
            "",
            "---",
            "",
            "## Findings",
            "",
            "### Open Ports",
            ", ".join(s.open_ports) or "None",
            "",
            "### Services",
        ]
        for port, svc in s.services.items():
            lines.append(f"- **{port}**: {svc}")

        lines.append("\n### Vulnerabilities")
        for v in s.vulnerabilities:
            lines.append(f"- **{v['key']}**: {v['value']}")

        lines.append("\n---\n\n## Action Log\n")
        for i, entry in enumerate(s.action_history, 1):
            a = entry["action"]
            r = entry["result"]
            lines.append(f"### {i}. {a['tool']} [{r['status']}]")
            lines.append(f"**Phase**: {a['phase']}  |  **Risk**: {a['risk_level']}")
            lines.append(f"```bash\n{a['command']}\n```")
            lines.append(f"**Why**: {a['rationale']}")
            if r.get("stdout"):
                out = r["stdout"][:500]
                lines.append(f"<details><summary>Output</summary>\n\n```\n{out}\n```\n</details>")
            lines.append("")

        if s.user_notes:
            lines.append("## User Notes\n")
            for note in s.user_notes:
                lines.append(f"- {note}")

        return "\n".join(lines)
