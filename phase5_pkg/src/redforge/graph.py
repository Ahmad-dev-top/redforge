"""LangGraph state graph.

Flow: scout -> strategist -> (poc loop) -> remediation -> verification -> END.

The PoC loop attempts the top-priority eligible hypotheses one at a time and is
bounded on every axis so a run always terminates with predictable cost:
- priority floor: hypotheses below `poc_priority_floor` are never attempted;
- per-hypothesis: `poc_max_retries` self-correction attempts;
- per-run: at most `poc_max_hypotheses` hypotheses attempted;
- early exit: `poc_stop_on_first_confirmation` ends the loop on the first proof.

A confirmed exploit routes to remediation (minimal-diff patch, compile +
exploit-now-fails gate). A successful patch routes to verification (regression,
differential, Halmos symbolic proof) which sets status VERIFIED when all gates
hold, else leaves PATCHED. Any dead-end routes to END.

Sandbox and LLM are injected into `build_graph`, so the whole graph is testable
with stubs (no Docker, no API key).
"""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, START, StateGraph

from redforge.agents import (
    run_poc,
    run_remediation,
    run_scout,
    run_strategist,
    run_verification,
)
from redforge.agents.poc_engineer import pending_hypothesis
from redforge.config import settings
from redforge.llm import LLMClient
from redforge.sandbox import SandboxRunner
from redforge.schemas import AuditState, AuditStatus


def _confirmed(state: AuditState) -> bool:
    return any(v.poc and v.poc.oracle_confirmed for v in state.vulnerabilities)


def _attempted(state: AuditState) -> int:
    return sum(1 for v in state.vulnerabilities if v.hypothesis)


def _has_successful_patch(state: AuditState) -> bool:
    return any(
        v.patch and v.patch.compiles and v.patch.poc_defeated and v.verification is None
        for v in state.vulnerabilities
    )


def _route_after_strategist(state: AuditState) -> str:
    if state.status == AuditStatus.FAILED or not state.hypotheses:
        return "end"
    return "poc" if pending_hypothesis(state) is not None else "end"


def _route_after_poc(state: AuditState) -> str:
    if settings.poc_stop_on_first_confirmation and _confirmed(state):
        return "remediation"
    if _attempted(state) >= settings.poc_max_hypotheses or pending_hypothesis(state) is None:
        return "remediation" if _confirmed(state) else "end"
    return "poc"


def _route_after_remediation(state: AuditState) -> str:
    # Verify only when a patch actually landed; otherwise the run ends.
    return "verification" if _has_successful_patch(state) else "end"


def build_graph(
    llm: LLMClient,
    sandbox: SandboxRunner,
    checkpointer: Any | None = None,
):
    builder = StateGraph(AuditState)
    builder.add_node("scout", lambda s: run_scout(s, sandbox))
    builder.add_node("strategist", lambda s: run_strategist(s, llm))
    builder.add_node("poc", lambda s: run_poc(s, llm, sandbox))
    builder.add_node("remediation", lambda s: run_remediation(s, llm, sandbox))
    builder.add_node("verification", lambda s: run_verification(s, llm, sandbox))

    builder.add_edge(START, "scout")
    builder.add_edge("scout", "strategist")
    builder.add_conditional_edges(
        "strategist", _route_after_strategist, {"poc": "poc", "end": END}
    )
    builder.add_conditional_edges(
        "poc", _route_after_poc, {"poc": "poc", "remediation": "remediation", "end": END}
    )
    builder.add_conditional_edges(
        "remediation", _route_after_remediation, {"verification": "verification", "end": END}
    )
    builder.add_edge("verification", END)
    return builder.compile(checkpointer=checkpointer)
