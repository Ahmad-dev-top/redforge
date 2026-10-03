"""LangGraph state graph.

Flow: scout -> strategist -> (poc loop) -> END.

The PoC loop attempts the top-priority eligible hypotheses one at a time and is
bounded on every axis so a run always terminates with predictable cost:
- priority floor: hypotheses below `poc_priority_floor` are never attempted
  (applied inside `pending_hypothesis`);
- per-hypothesis: `poc_max_retries` self-correction attempts (inside `run_poc`);
- per-run: at most `poc_max_hypotheses` hypotheses attempted;
- early exit: if `poc_stop_on_first_confirmation`, the first proven exploit ends
  the loop.

Each `poc` invocation attempts exactly one new hypothesis (appends one
Vulnerability), and `pending_hypothesis` skips already-attempted ones, so the
loop strictly makes progress and cannot spin.

Sandbox and LLM are injected into `build_graph`, so the whole graph — loop
included — is testable with stubs (no Docker, no API key).
"""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, START, StateGraph

from redforge.agents import run_poc, run_scout, run_strategist
from redforge.agents.poc_engineer import pending_hypothesis
from redforge.config import settings
from redforge.llm import LLMClient
from redforge.sandbox import SandboxRunner
from redforge.schemas import AuditState, AuditStatus


def _confirmed(state: AuditState) -> bool:
    return any(v.poc and v.poc.oracle_confirmed for v in state.vulnerabilities)


def _attempted(state: AuditState) -> int:
    return sum(1 for v in state.vulnerabilities if v.hypothesis)


def _route_after_strategist(state: AuditState) -> str:
    # No usable hypotheses -> end. Otherwise enter the PoC loop only if at least
    # one hypothesis clears the priority floor.
    if state.status == AuditStatus.FAILED or not state.hypotheses:
        return "end"
    return "poc" if pending_hypothesis(state) is not None else "end"


def _route_after_poc(state: AuditState) -> str:
    # Stop on the first proof when configured.
    if settings.poc_stop_on_first_confirmation and _confirmed(state):
        return "end"
    # Respect the per-run hypothesis budget.
    if _attempted(state) >= settings.poc_max_hypotheses:
        return "end"
    # Continue only while an eligible hypothesis remains.
    return "poc" if pending_hypothesis(state) is not None else "end"


def build_graph(
    llm: LLMClient,
    sandbox: SandboxRunner,
    checkpointer: Any | None = None,
):
    builder = StateGraph(AuditState)
    builder.add_node("scout", lambda s: run_scout(s, sandbox))
    builder.add_node("strategist", lambda s: run_strategist(s, llm))
    builder.add_node("poc", lambda s: run_poc(s, llm, sandbox))

    builder.add_edge(START, "scout")
    builder.add_edge("scout", "strategist")
    builder.add_conditional_edges(
        "strategist", _route_after_strategist, {"poc": "poc", "end": END}
    )
    builder.add_conditional_edges(
        "poc", _route_after_poc, {"poc": "poc", "end": END}
    )
    return builder.compile(checkpointer=checkpointer)
