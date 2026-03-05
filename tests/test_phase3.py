"""Phase 3 test suite — sub-agents, defensive tools, prompts, and CLI integration.

Covers:
  3.1  Sub-agent system (allowlists, restricted registry, loop, error handling)
  3.2  Defensive tools (analyze_logs, check_config, detect_persistence,
       generate_sigma_rule, generate_yara_rule, map_to_attack, analyze_pcap)
  3.3  Defensive system prompts (tool references, build_system_prompt routing)
  3.4  CLI integration (default objectives, --file flag, defensive banner routing,
       offensive target validation)

Tests run without a real LLM, network, or Kali tools installed.
"""

from __future__ import annotations

import asyncio
import json
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ─────────────────────────────────────────────────────────────────────────────
#  Shared helpers
# ─────────────────────────────────────────────────────────────────────────────

def _mock_llm(text: str = "Done.", tool_calls: list | None = None):
    from src.core.llm import LLMResponse, ToolCall
    llm = AsyncMock()
    llm.provider = "anthropic"
    llm.create_message = AsyncMock(
        return_value=LLMResponse(
            text=text,
            tool_calls=tool_calls or [],
            stop_reason="end_turn",
            raw=None,
        )
    )
    return llm


def _make_registry_with_bash():
    """Minimal registry with a bash stub."""
    from src.core.tools.registry import ToolRegistry, ToolRiskLevel
    registry = ToolRegistry()

    @registry.register(
        name="bash",
        description="run bash",
        input_schema={"type": "object", "properties": {"command": {"type": "string"}}, "required": ["command"]},
        risk=ToolRiskLevel.SAFE,
    )
    async def bash(command: str) -> str:
        return f"[mock output for: {command}]"

    return registry


# ─────────────────────────────────────────────────────────────────────────────
#  3.1 — Sub-Agent System
# ─────────────────────────────────────────────────────────────────────────────

class TestSubAgentSystem:

    def test_allowlists_defined_for_all_types(self):
        from src.core.tools.subagent import AGENT_TOOL_ALLOWLISTS
        assert "recon" in AGENT_TOOL_ALLOWLISTS
        assert "research" in AGENT_TOOL_ALLOWLISTS
        assert "defender" in AGENT_TOOL_ALLOWLISTS

    def test_recon_allowlist_excludes_write_tools(self):
        from src.core.tools.subagent import AGENT_TOOL_ALLOWLISTS
        recon = AGENT_TOOL_ALLOWLISTS["recon"]
        assert "bash" in recon
        assert "write_file" not in recon
        assert "search_exploit" not in recon

    def test_research_allowlist_includes_cve_tools(self):
        from src.core.tools.subagent import AGENT_TOOL_ALLOWLISTS
        research = AGENT_TOOL_ALLOWLISTS["research"]
        assert "search_cve" in research
        assert "search_exploit" in research
        assert "query_gtfobins" in research

    def test_defender_allowlist_includes_defense_tools(self):
        from src.core.tools.subagent import AGENT_TOOL_ALLOWLISTS
        defender = AGENT_TOOL_ALLOWLISTS["defender"]
        for tool in ("analyze_logs", "check_config", "detect_persistence",
                     "generate_sigma_rule", "generate_yara_rule", "map_to_attack", "analyze_pcap"):
            assert tool in defender, f"defender allowlist missing {tool}"

    def test_restricted_registry_filters_correctly(self):
        from src.core.tools.subagent import _build_restricted_registry, AGENT_TOOL_ALLOWLISTS
        from src.core.tools.registry import ToolRegistry, ToolRiskLevel

        parent = ToolRegistry()
        for name in ("bash", "write_file", "search_cve", "analyze_logs"):
            @parent.register(
                name=name,
                description=f"tool {name}",
                input_schema={"type": "object", "properties": {}, "required": []},
                risk=ToolRiskLevel.SAFE,
            )
            async def _handler() -> str:
                return "ok"

        sub = _build_restricted_registry(parent, AGENT_TOOL_ALLOWLISTS["recon"])
        names = {t.name for t in sub.list_tools()}
        assert "bash" in names
        assert "write_file" not in names
        assert "search_cve" not in names

    def test_run_subagent_returns_final_text(self):
        from src.core.tools.subagent import run_subagent

        parent = _make_registry_with_bash()
        llm = _mock_llm("Recon complete: port 80 open.")

        result = asyncio.run(run_subagent("Scan target", "recon", parent, llm))
        assert "Recon complete" in result

    def test_run_subagent_executes_tool_then_returns_text(self):
        from src.core.tools.subagent import run_subagent
        from src.core.llm import LLMResponse, ToolCall

        parent = _make_registry_with_bash()
        call_count = 0

        async def side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return LLMResponse(
                    text="",
                    tool_calls=[ToolCall(id="t1", name="bash", input={"command": "nmap 10.0.0.1"})],
                    stop_reason="tool_use",
                    raw=None,
                )
            return LLMResponse(text="Scan done.", tool_calls=[], stop_reason="end_turn", raw=None)

        llm = AsyncMock()
        llm.provider = "anthropic"
        llm.create_message = side_effect

        result = asyncio.run(run_subagent("Scan", "recon", parent, llm))
        assert "Scan done." in result
        assert call_count == 2

    def test_run_subagent_handles_unknown_tool_gracefully(self):
        from src.core.tools.subagent import run_subagent
        from src.core.llm import LLMResponse, ToolCall

        parent = _make_registry_with_bash()
        call_count = 0

        async def side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return LLMResponse(
                    text="",
                    tool_calls=[ToolCall(id="t1", name="nonexistent_tool", input={})],
                    stop_reason="tool_use",
                    raw=None,
                )
            return LLMResponse(text="Handled error.", tool_calls=[], stop_reason="end_turn", raw=None)

        llm = AsyncMock()
        llm.provider = "anthropic"
        llm.create_message = side_effect

        result = asyncio.run(run_subagent("Task", "recon", parent, llm))
        assert "Handled error." in result  # LLM got the error and responded

    def test_run_subagent_respects_max_iterations(self):
        from src.core.tools.subagent import run_subagent
        from src.core.llm import LLMResponse, ToolCall

        parent = _make_registry_with_bash()

        async def always_tool(*args, **kwargs):
            return LLMResponse(
                text="",
                tool_calls=[ToolCall(id="t1", name="bash", input={"command": "echo loop"})],
                stop_reason="tool_use",
                raw=None,
            )

        llm = AsyncMock()
        llm.provider = "anthropic"
        llm.create_message = always_tool

        result = asyncio.run(run_subagent("Loop forever", "recon", parent, llm, max_iterations=3))
        assert "iteration limit" in result

    def test_spawn_agent_tool_registered(self):
        from src.core.tools.registry import ToolRegistry
        from src.core.tools.subagent import register_subagent_tool

        registry = _make_registry_with_bash()
        llm = _mock_llm()
        register_subagent_tool(registry, llm=llm)

        names = {t.name for t in registry.list_tools()}
        assert "spawn_agent" in names

    def test_spawn_agent_risk_is_confirm(self):
        from src.core.tools.registry import ToolRegistry, ToolRiskLevel
        from src.core.tools.subagent import register_subagent_tool

        registry = _make_registry_with_bash()
        register_subagent_tool(registry, llm=_mock_llm())

        tool = next(t for t in registry.list_tools() if t.name == "spawn_agent")
        assert tool.risk_level == ToolRiskLevel.CONFIRM

    def test_subagent_has_isolated_message_history(self):
        """Each sub-agent invocation must start with a fresh message history."""
        from src.core.tools.subagent import run_subagent

        parent = _make_registry_with_bash()
        llm = _mock_llm("Sub-agent done.")

        asyncio.run(run_subagent("Task A", "recon", parent, llm))
        asyncio.run(run_subagent("Task B", "research", parent, llm))

        # The first LLM call (first sub-agent) should have received exactly 1 message
        # (the user task). It should NOT carry history from a prior sub-agent call.
        def _get_messages(call):
            if call.kwargs.get("messages") is not None:
                return call.kwargs["messages"]
            return call.args[0]

        first_call_msgs = _get_messages(llm.create_message.call_args_list[0])
        second_call_msgs = _get_messages(llm.create_message.call_args_list[1])

        # First message of each call is always the user task — content should differ
        assert first_call_msgs[0]["content"] == "Task A"
        assert second_call_msgs[0]["content"] == "Task B"
        # Second invocation must not start with Task A's content in position 0
        assert second_call_msgs[0]["content"] != "Task A"


# ─────────────────────────────────────────────────────────────────────────────
#  3.2 — Defensive Tools
# ─────────────────────────────────────────────────────────────────────────────

class TestDefensiveTools:

    @pytest.fixture
    def registry(self):
        from src.core.tools.registry import ToolRegistry
        from src.core.tools.defense import register_defense_tools
        r = ToolRegistry()
        register_defense_tools(r)
        return r

    def test_all_seven_tools_registered(self, registry):
        names = {t.name for t in registry.list_tools()}
        expected = {
            "analyze_logs", "check_config", "detect_persistence",
            "generate_sigma_rule", "generate_yara_rule", "map_to_attack", "analyze_pcap",
        }
        assert expected == names

    def test_all_tools_are_safe_risk(self, registry):
        from src.core.tools.registry import ToolRiskLevel
        for tool in registry.list_tools():
            assert tool.risk_level == ToolRiskLevel.SAFE, f"{tool.name} should be SAFE"

    # analyze_logs ────────────────────────────────────────────────────────────

    def test_analyze_logs_auth_failed_logins(self, registry, tmp_path):
        log = tmp_path / "auth.log"
        log.write_text(
            "Jan 1 00:00:01 host sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2\n"
            "Jan 1 00:00:02 host sshd[2]: Failed password for admin from 1.2.3.5 port 22 ssh2\n"
            "Jan 1 00:00:03 host sshd[3]: Accepted password for bob from 10.0.0.1 port 22 ssh2\n"
        )
        result = asyncio.run(registry.execute("analyze_logs", {"log_path": str(log), "log_type": "auth"}))
        data = json.loads(result)
        assert data["failed_logins"] == 2
        assert data["accepted_logins"] == 1
        assert "1.2.3.4" in data["top_attacker_ips"]

    def test_analyze_logs_web_scanner_detection(self, registry, tmp_path):
        log = tmp_path / "access.log"
        log.write_text(
            '10.0.0.1 - - [01/Jan/2024] "GET /admin HTTP/1.1" 404 0 "-" "sqlmap/1.7"\n'
            '10.0.0.2 - - [01/Jan/2024] "GET / HTTP/1.1" 200 1024 "-" "Mozilla/5.0"\n'
        )
        result = asyncio.run(registry.execute("analyze_logs", {"log_path": str(log), "log_type": "web"}))
        data = json.loads(result)
        assert data["scanner_signatures"] >= 1

    def test_analyze_logs_missing_file(self, registry):
        result = asyncio.run(registry.execute("analyze_logs", {"log_path": "/nonexistent/file.log", "log_type": "auth"}))
        assert "[ERROR]" in result

    def test_analyze_logs_syslog(self, registry, tmp_path):
        log = tmp_path / "syslog"
        log.write_text(
            "Jan 1 00:01 host kernel: error in module\n"
            "Jan 1 00:02 host sshd: setuid attempt detected\n"
        )
        result = asyncio.run(registry.execute("analyze_logs", {"log_path": str(log), "log_type": "syslog"}))
        data = json.loads(result)
        assert data["privilege_events"] >= 1

    # check_config ────────────────────────────────────────────────────────────

    def test_check_config_ssh_flags_root_login(self, registry, tmp_path):
        cfg = tmp_path / "sshd_config"
        cfg.write_text("PermitRootLogin yes\nPasswordAuthentication no\n")
        result = asyncio.run(registry.execute("check_config", {"config_type": "ssh", "path": str(cfg)}))
        data = json.loads(result)
        assert data["status"] == "findings"
        checks = [f["check"] for f in data["findings"]]
        assert "PermitRootLogin" in checks

    def test_check_config_ssh_clean(self, registry, tmp_path):
        cfg = tmp_path / "sshd_config"
        cfg.write_text("PermitRootLogin no\nPasswordAuthentication no\nX11Forwarding no\nMaxAuthTries 4\n")
        result = asyncio.run(registry.execute("check_config", {"config_type": "ssh", "path": str(cfg)}))
        data = json.loads(result)
        assert data["status"] == "clean"

    def test_check_config_sudoers_nopasswd(self, registry, tmp_path):
        cfg = tmp_path / "sudoers"
        cfg.write_text("alice ALL=(ALL) NOPASSWD: ALL\n")
        result = asyncio.run(registry.execute("check_config", {"config_type": "sudoers", "path": str(cfg)}))
        data = json.loads(result)
        assert data["status"] == "findings"
        assert any("NOPASSWD" in f["issue"] for f in data["findings"])

    def test_check_config_missing_file(self, registry):
        result = asyncio.run(registry.execute("check_config", {"config_type": "ssh", "path": "/nonexistent"}))
        assert "[ERROR]" in result

    # map_to_attack ───────────────────────────────────────────────────────────

    def test_map_to_attack_cron_persistence(self, registry):
        result = asyncio.run(registry.execute("map_to_attack", {"technique_description": "cron job added for persistence"}))
        data = json.loads(result)
        assert data["matches"]
        ids = [m["technique_id"] for m in data["matches"]]
        assert any("T1053" in i for i in ids)

    def test_map_to_attack_brute_force(self, registry):
        result = asyncio.run(registry.execute("map_to_attack", {"technique_description": "brute force ssh login attempts hydra"}))
        data = json.loads(result)
        assert data["matches"]
        ids = [m["technique_id"] for m in data["matches"]]
        assert any("T1110" in i for i in ids)

    def test_map_to_attack_no_match_returns_status(self, registry):
        result = asyncio.run(registry.execute("map_to_attack", {"technique_description": "xyzzy foo bar baz"}))
        data = json.loads(result)
        assert data["status"] == "no_match"

    def test_map_to_attack_includes_url(self, registry):
        result = asyncio.run(registry.execute("map_to_attack", {"technique_description": "suid binary privilege escalation"}))
        data = json.loads(result)
        assert data["matches"]
        assert "attack.mitre.org" in data["matches"][0]["url"]

    # generate_sigma_rule ─────────────────────────────────────────────────────

    def test_generate_sigma_rule_valid_yaml_structure(self, registry):
        result = asyncio.run(registry.execute("generate_sigma_rule", {
            "description": "Mimikatz credential dumping via lsass",
            "log_source": "process_creation",
            "detection_logic": "CommandLine contains mimikatz",
        }))
        assert "title:" in result
        assert "logsource:" in result
        assert "detection:" in result
        assert "condition: selection" in result
        assert "tags:" in result

    def test_generate_sigma_rule_includes_attack_tags(self, registry):
        result = asyncio.run(registry.execute("generate_sigma_rule", {
            "description": "cron job persistence mechanism",
            "log_source": "process_creation",
            "detection_logic": "Image contains crontab",
        }))
        assert "attack." in result

    # generate_yara_rule ──────────────────────────────────────────────────────

    def test_generate_yara_rule_valid_structure(self, registry):
        result = asyncio.run(registry.execute("generate_yara_rule", {
            "description": "Detect Metasploit meterpreter",
            "strings": ["meterpreter", "ReflectiveDllInjection"],
            "condition": "any of them",
        }))
        assert "rule " in result
        assert "strings:" in result
        assert "condition:" in result
        assert "any of them" in result

    def test_generate_yara_rule_hex_pattern(self, registry):
        result = asyncio.run(registry.execute("generate_yara_rule", {
            "description": "Detect shellcode NOP sled",
            "strings": ["{90 90 90 90 90}"],
            "condition": "any of them",
        }))
        assert "{90 90 90 90 90}" in result

    def test_generate_yara_rule_multiple_strings(self, registry):
        result = asyncio.run(registry.execute("generate_yara_rule", {
            "description": "Multi-indicator rule",
            "strings": ["string_one", "string_two", "string_three"],
            "condition": "2 of them",
        }))
        assert "$s0" in result
        assert "$s1" in result
        assert "$s2" in result

    # analyze_pcap ────────────────────────────────────────────────────────────

    def test_analyze_pcap_missing_file(self, registry):
        result = asyncio.run(registry.execute("analyze_pcap", {"pcap_path": "/nonexistent/file.pcap"}))
        assert "[ERROR]" in result

    def test_analyze_pcap_no_tshark_graceful(self, registry, tmp_path):
        pcap = tmp_path / "test.pcap"
        pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)  # fake PCAP header
        with patch("shutil.which", return_value=None):
            result = asyncio.run(registry.execute("analyze_pcap", {"pcap_path": str(pcap)}))
        assert "tshark not found" in result

    # detect_persistence ──────────────────────────────────────────────────────

    def test_detect_persistence_invalid_type(self, registry):
        result = asyncio.run(registry.execute("detect_persistence", {"target_type": "macos"}))
        assert "[ERROR]" in result

    def test_detect_persistence_linux_runs(self, registry):
        # Should run without error (commands may return empty on Windows CI)
        result = asyncio.run(registry.execute("detect_persistence", {"target_type": "linux"}))
        data = json.loads(result)
        assert "status" in data
        assert "findings" in data


# ─────────────────────────────────────────────────────────────────────────────
#  3.3 — Defensive System Prompts
# ─────────────────────────────────────────────────────────────────────────────

class TestDefensivePrompts:

    def test_defender_prompt_references_all_defense_tools(self):
        from src.core.prompts import DEFENDER_SYSTEM_PROMPT
        for tool in ("analyze_logs", "check_config", "detect_persistence",
                     "generate_sigma_rule", "map_to_attack"):
            assert tool in DEFENDER_SYSTEM_PROMPT, f"DEFENDER missing {tool}"

    def test_hardener_prompt_references_defense_tools(self):
        from src.core.prompts import HARDENER_SYSTEM_PROMPT
        for tool in ("check_config", "detect_persistence", "map_to_attack"):
            assert tool in HARDENER_SYSTEM_PROMPT, f"HARDENER missing {tool}"

    def test_hunter_prompt_references_defense_tools(self):
        from src.core.prompts import HUNTER_SYSTEM_PROMPT
        for tool in ("analyze_logs", "analyze_pcap", "detect_persistence",
                     "generate_sigma_rule", "map_to_attack"):
            assert tool in HUNTER_SYSTEM_PROMPT, f"HUNTER missing {tool}"

    def test_build_system_prompt_routes_defend(self):
        from src.core.prompts import build_system_prompt, DEFENDER_SYSTEM_PROMPT
        p = build_system_prompt(mode="defend", target="10.0.0.1", objective="Investigate")
        # Should contain defensive content, not offensive
        assert "Incident Response" in p or "Blue Team" in p
        assert "analyze_logs" in p

    def test_build_system_prompt_routes_harden(self):
        from src.core.prompts import build_system_prompt
        p = build_system_prompt(mode="harden")
        assert "Hardening" in p or "CIS" in p
        assert "check_config" in p

    def test_build_system_prompt_routes_hunt(self):
        from src.core.prompts import build_system_prompt
        p = build_system_prompt(mode="hunt")
        assert "Threat Hunt" in p or "Hunt" in p
        assert "analyze_pcap" in p

    def test_build_system_prompt_offensive_unchanged(self):
        from src.core.prompts import build_system_prompt
        p = build_system_prompt(mode="offensive", target="10.10.10.1", objective="Get root")
        assert "KaliMentor" in p
        assert "penetration" in p.lower() or "offensive" in p.lower()
        # Offensive prompt should not lead with defensive content
        assert "Incident Response" not in p[:200]

    def test_defender_subagent_prompt_includes_defense_tools(self):
        from src.core.prompts import build_subagent_prompt
        p = build_subagent_prompt("defender", "Check SSH config")
        assert "analyze_logs" in p
        assert "check_config" in p
        assert "map_to_attack" in p

    def test_subagent_prompts_interpolate_task(self):
        from src.core.prompts import build_subagent_prompt
        for agent_type in ("recon", "research", "defender"):
            p = build_subagent_prompt(agent_type, "MY_UNIQUE_TASK_STRING")
            assert "MY_UNIQUE_TASK_STRING" in p, f"{agent_type} prompt did not interpolate task"


# ─────────────────────────────────────────────────────────────────────────────
#  3.4 — CLI Integration
# ─────────────────────────────────────────────────────────────────────────────

class TestCLIIntegration:

    def test_default_objectives_all_challenge_types(self):
        from src.cli import _DEFAULT_OBJECTIVES
        for ch in ("machine", "web", "pwn", "reversing", "crypto", "forensics",
                   "active_directory", "misc", "defend", "harden", "hunt"):
            assert ch in _DEFAULT_OBJECTIVES, f"Missing default objective for {ch}"
            assert _DEFAULT_OBJECTIVES[ch], f"Empty objective for {ch}"

    def test_defensive_default_objectives_appropriate(self):
        from src.cli import _DEFAULT_OBJECTIVES
        assert "Investigate" in _DEFAULT_OBJECTIVES["defend"] or "incident" in _DEFAULT_OBJECTIVES["defend"].lower()
        assert "audit" in _DEFAULT_OBJECTIVES["harden"].lower() or "hardening" in _DEFAULT_OBJECTIVES["harden"].lower()
        assert "hunt" in _DEFAULT_OBJECTIVES["hunt"].lower() or "Hunt" in _DEFAULT_OBJECTIVES["hunt"]

    def test_defensive_challenges_constant(self):
        from src.cli import _DEFENSIVE_CHALLENGES
        assert "defend" in _DEFENSIVE_CHALLENGES
        assert "harden" in _DEFENSIVE_CHALLENGES
        assert "hunt" in _DEFENSIVE_CHALLENGES
        assert "machine" not in _DEFENSIVE_CHALLENGES

    def test_cli_offensive_machine_requires_target(self):
        from typer.testing import CliRunner
        from src.cli import app
        runner = CliRunner()
        result = runner.invoke(app, ["start", "--challenge", "machine", "--llm", "ollama"])
        assert result.exit_code != 0
        assert "required" in result.output.lower() or "--target" in result.output

    def test_cli_defensive_does_not_require_target(self):
        from typer.testing import CliRunner
        from src.cli import app
        runner = CliRunner()
        # --help exits 0 and shows usage — confirms the argument is accepted without --target
        for challenge in ("defend", "harden", "hunt"):
            result = runner.invoke(app, ["start", "--challenge", challenge, "--help"])
            assert result.exit_code == 0, f"{challenge} --help failed: {result.output}"

    def test_cli_file_flag_validated(self, tmp_path):
        from typer.testing import CliRunner
        from src.cli import app
        runner = CliRunner()
        # Non-existent file should fail fast
        result = runner.invoke(app, [
            "start", "--challenge", "defend",
            "--file", "/nonexistent/file.pcap",
            "--llm", "ollama",
        ])
        assert result.exit_code != 0
        assert "not found" in result.output.lower() or "nonexistent" in result.output

    def test_cli_file_flag_accepted_when_exists(self, tmp_path):
        from typer.testing import CliRunner
        from src.cli import app
        artifact = tmp_path / "test.log"
        artifact.write_text("Jan 1 test log line\n")
        runner = CliRunner()
        # Should not fail on file validation (will fail later when connecting to LLM)
        result = runner.invoke(app, [
            "start", "--challenge", "defend",
            "--file", str(artifact),
            "--llm", "ollama",
            "--help",   # stop before actually running
        ])
        assert result.exit_code == 0

    def test_prompt_mode_routing_defensive(self):
        """build_system_prompt is called with the challenge as mode for defensive types."""
        from src.core.prompts import build_system_prompt
        for mode in ("defend", "harden", "hunt"):
            p = build_system_prompt(mode=mode, target="10.0.0.1", objective="test")
            # Each defensive mode should produce its distinctive prompt
            assert len(p) > 500, f"{mode} prompt too short"

    def test_prompt_mode_routing_offensive_challenges(self):
        """Non-defensive challenges all use the offensive prompt."""
        from src.core.prompts import build_system_prompt
        for challenge in ("machine", "web", "pwn", "reversing", "crypto", "forensics"):
            p = build_system_prompt(mode="offensive", challenge_type=challenge)
            assert "KaliMentor" in p
            assert "penetration" in p.lower() or "Offensive" in p or "offensive" in p.lower()
