"""Planner — LLM-driven attack planning, action proposals, research, Socratic hints."""

from __future__ import annotations

from typing import Any

from .llm import LLMBackend
from .models import AttackPlan, Phase, PlanStep, ProposedAction, RiskLevel
from .session import SessionManager

# ═══════════════════════════════════════════════════════════════════════════
#  SYSTEM PROMPTS
# ═══════════════════════════════════════════════════════════════════════════

PLANNER_SYSTEM = """You are an expert penetration testing mentor inside KaliMentor, a cybersecurity learning tool running on Kali Linux.

Analyze the current session state and propose the NEXT best actions.

RULES:
1. Every action MUST include a clear educational rationale explaining WHY this step matters.
2. Propose 1-3 actions ranked by priority.
3. Never repeat completed work — check what was already done.
4. Risk levels: info (passive), low (active scan), medium (aggressive enum), high (exploitation), critical (destructive).
5. If exploitation is premature (insufficient enum), say so explicitly.
6. Commands must be complete and runnable on Kali Linux with standard tool paths.
7. Use correct wordlist paths: /usr/share/wordlists/ and /usr/share/seclists/

OUTPUT (strict JSON):
{
  "analysis": "Brief analysis of current state",
  "phase_recommendation": "reconnaissance|enumeration|vulnerability_analysis|exploitation|post_exploitation|internal_enumeration|privilege_escalation|lateral_movement|domain_compromise|loot",
  "actions": [
    {
      "tool": "tool_name",
      "command": "full runnable command",
      "rationale": "Educational explanation",
      "expected_outcome": "What we learn from this",
      "risk_level": "info|low|medium|high|critical",
      "alternatives": ["alt approach"]
    }
  ],
  "learning_notes": "Key concept for the learner"
}"""

RESEARCH_SYSTEM = """You are a cybersecurity research assistant. Given a topic (CVE, tool, technique, protocol), provide a structured educational deep-dive.

OUTPUT (strict JSON):
{
  "summary": "2-3 sentence overview",
  "technical_details": "Detailed technical explanation",
  "exploitation": "How this is exploited in practice",
  "detection": "How defenders detect this",
  "mitigation": "How to fix/prevent this",
  "references": ["url1", "url2"],
  "related_tools": ["tool1", "tool2"],
  "mitre_attack": ["T1234"],
  "practice_suggestions": "How to practice this skill"
}"""

INITIAL_PLAN_SYSTEM = """You are a penetration testing strategist. Given a target and objective, produce a high-level attack plan.

You know all standard methodologies:
- Machine compromise: recon → enum → vuln analysis → exploit → internal enum → privesc
- Web app: surface mapping → endpoint enum → input testing → logic exploitation
- Active Directory: external enum → credential capture → bloodhound → lateral move → domain compromise
- Binary exploitation: triage → static analysis → dynamic debug → exploit chain
- Reversing: behavioral analysis → deobfuscation → decompilation → algorithm reconstruction
- Crypto: algorithm ID → implementation analysis → mathematical exploitation
- Forensics: artifact ingestion → data filtering → timeline reconstruction → payload extraction

OUTPUT (strict JSON):
{
  "methodology": "Name of methodology",
  "steps": [
    {
      "phase": "phase_name",
      "description": "What to do",
      "tools": ["tool1", "tool2"],
      "estimated_actions": 3
    }
  ],
  "notes": "Special considerations"
}"""

SOCRATIC_SYSTEM = """You are a Socratic cybersecurity mentor. The learner is asking for help.

RULES:
- NEVER give direct answers or exact commands
- Ask guiding questions that lead the learner to discover the answer
- Suggest tool categories or techniques, not exact syntax
- If stuck, point toward what they haven't explored yet
- Build on what they've already found
- Reference methodology concepts to reinforce learning

Respond in natural conversational text (not JSON)."""

EXPLAIN_SYSTEM = """You are a cybersecurity instructor explaining tool output to a learner.

Explain:
1. What the output means in plain terms
2. What findings are significant and why
3. What this tells us about the target
4. What logical next steps follow

Be concise but thorough. Respond in natural text."""

TERMINAL_ANALYSIS_SYSTEM = """You are an expert penetration tester reviewing terminal output from a live pentesting session.

The user has captured their terminal screen and wants your analysis.

Analyse the output and provide:
1. Key findings — what is revealed (open ports, services, credentials, errors, paths, etc.)
2. Interesting observations — anything anomalous or significant
3. Suggested next steps — concrete follow-up actions based on what you see
4. Learning note — one educational takeaway from this output

Respond in clear natural text with sections. Be concise and actionable."""


class Planner:
    """LLM-powered planning engine."""

    def __init__(self, llm: LLMBackend):
        self.llm = llm

    async def create_initial_plan(self, session: SessionManager) -> AttackPlan:
        s = session.state
        user_msg = (
            f"Target: {s.target.ip or s.target.url or 'N/A'}\n"
            f"Challenge Type: {s.target.challenge_type}\n"
            f"Platform: {s.target.platform}\n"
            f"Objective: {s.objective}\n"
        )
        data = await self.llm.complete_json(INITIAL_PLAN_SYSTEM, user_msg)
        steps = [
            PlanStep(
                phase=st["phase"],
                description=st["description"],
                tools=st.get("tools", []),
                estimated_actions=st.get("estimated_actions", 1),
            )
            for st in data.get("steps", [])
        ]
        return AttackPlan(
            objective=s.objective,
            methodology=data.get("methodology", "General"),
            steps=steps,
            estimated_total_actions=sum(st.estimated_actions for st in steps),
            notes=data.get("notes", ""),
        )

    async def propose_next_actions(self, session: SessionManager, user_input: str = "") -> dict[str, Any]:
        ctx = session.get_context_summary()
        user_msg = f"{ctx}\n\nUser request: {user_input or 'What should I do next?'}\n\nAnalyze and propose next actions."
        return await self.llm.complete_json(PLANNER_SYSTEM, user_msg)

    async def research_topic(self, topic: str, context: str = "") -> dict[str, Any]:
        user_msg = f"Topic: {topic}\nContext: {context or 'No active session'}\n\nProvide educational deep-dive."
        return await self.llm.complete_json(RESEARCH_SYSTEM, user_msg)

    async def get_socratic_hint(self, session: SessionManager, question: str) -> str:
        ctx = session.get_context_summary()
        return await self.llm.complete(SOCRATIC_SYSTEM, f"{ctx}\n\nLearner: {question}")

    async def explain_output(self, tool: str, command: str, output: str, session: SessionManager) -> str:
        ctx = session.get_context_summary()
        user_msg = f"Tool: {tool}\nCommand: {command}\nOutput:\n{output[:3000]}\n\nSession:\n{ctx}"
        return await self.llm.complete(EXPLAIN_SYSTEM, user_msg)

    async def analyse_terminal_output(self, terminal_text: str, session_context: str = "") -> str:
        user_msg = (
            f"Session context:\n{session_context}\n\n"
            f"Terminal output to analyse:\n```\n{terminal_text[:4000]}\n```"
        )
        return await self.llm.complete(TERMINAL_ANALYSIS_SYSTEM, user_msg)
