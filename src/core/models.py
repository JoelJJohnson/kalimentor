"""Core data models for KaliMentor sessions, actions, and findings."""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


# ═══════════════════════════════════════════════════════════════════════════
#  ENUMS
# ═══════════════════════════════════════════════════════════════════════════

class Phase(str, Enum):
    RECON = "reconnaissance"
    ENUM = "enumeration"
    VULN_ANALYSIS = "vulnerability_analysis"
    EXPLOITATION = "exploitation"
    POST_EXPLOIT = "post_exploitation"
    INTERNAL_ENUM = "internal_enumeration"
    PRIV_ESC = "privilege_escalation"
    LATERAL_MOVE = "lateral_movement"
    DOMAIN_COMPROMISE = "domain_compromise"
    LOOT = "loot"


class RiskLevel(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ActionStatus(str, Enum):
    PROPOSED = "proposed"
    APPROVED = "approved"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class ChallengeType(str, Enum):
    MACHINE = "machine"
    WEB = "web"
    PWN = "pwn"
    REVERSING = "reversing"
    CRYPTO = "crypto"
    FORENSICS = "forensics"
    AD = "active_directory"
    MISC = "misc"


class AgentMode(str, Enum):
    INTERACTIVE = "interactive"
    SEMI_AUTO = "semi_auto"
    AUTONOMOUS = "autonomous"
    SOCRATIC = "socratic"


class LLMProvider(str, Enum):
    OLLAMA = "ollama"
    ANTHROPIC = "anthropic"
    GEMINI = "gemini"
    DEEPSEEK = "deepseek"
    OPENAI = "openai"


# ═══════════════════════════════════════════════════════════════════════════
#  ACTION MODELS
# ═══════════════════════════════════════════════════════════════════════════

class Finding(BaseModel):
    """A discrete piece of intelligence extracted from tool output."""
    category: str
    key: str
    value: str
    confidence: float = 1.0
    source_action_id: str = ""
    tags: list[str] = []


class ProposedAction(BaseModel):
    """A single action the agent proposes to the user."""
    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:8])
    phase: Phase
    tool: str
    command: str
    rationale: str
    expected_outcome: str
    risk_level: RiskLevel = RiskLevel.LOW
    prerequisites: list[str] = []
    alternatives: list[str] = []


class ActionResult(BaseModel):
    """Result of an executed action."""
    action_id: str
    status: ActionStatus
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    duration_seconds: float = 0.0
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    findings: list[Finding] = []
    notes: str = ""


# ═══════════════════════════════════════════════════════════════════════════
#  SESSION MODELS
# ═══════════════════════════════════════════════════════════════════════════

class TargetInfo(BaseModel):
    """Information about the engagement target."""
    ip: str | None = None
    hostname: str | None = None
    url: str | None = None
    os_guess: str | None = None
    challenge_type: ChallengeType = ChallengeType.MACHINE
    challenge_file: str | None = None
    platform: str = "htb"
    difficulty: str | None = None


class SessionState(BaseModel):
    """Complete state of a learning session — serializable to JSON."""
    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    # Objective
    objective: str = ""
    target: TargetInfo = Field(default_factory=TargetInfo)

    # Agent config
    mode: AgentMode = AgentMode.INTERACTIVE
    current_phase: Phase = Phase.RECON
    llm_provider: LLMProvider = LLMProvider.OLLAMA
    llm_model: str = ""

    # Knowledge base
    findings: list[Finding] = []
    open_ports: list[str] = []
    services: dict[str, str] = {}
    credentials: list[dict[str, str]] = []
    vulnerabilities: list[dict[str, Any]] = []
    flags: list[str] = []

    # Action history
    action_history: list[dict[str, Any]] = []
    pending_actions: list[ProposedAction] = []

    # Access level progression
    access_level: str = "none"

    # Notes
    user_notes: list[str] = []


# ═══════════════════════════════════════════════════════════════════════════
#  PLANNER MODELS
# ═══════════════════════════════════════════════════════════════════════════

class PlanStep(BaseModel):
    phase: Phase
    description: str
    tools: list[str]
    estimated_actions: int = 1
    depends_on: list[int] = []


class AttackPlan(BaseModel):
    objective: str
    methodology: str
    steps: list[PlanStep]
    estimated_total_actions: int = 0
    notes: str = ""


class ResearchQuery(BaseModel):
    topic: str
    context: str = ""
    depth: str = "standard"


class ResearchResult(BaseModel):
    topic: str
    summary: str
    technical_details: str = ""
    references: list[str] = []
    related_tools: list[str] = []
    mitre_attack_ids: list[str] = []
    examples: list[str] = []
