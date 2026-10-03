"""LangGraph state graph.

Phase 2 wires two nodes: scout -> strategist. The sandbox and LLM are injected
into `build_graph` so the whole graph is testable with stubs (no Docker, no API
key). Later phases attach the PoC / remediation / verification branch at the
marked point after the strategist.

State is the Pydantic `AuditState`; nodes return partial dict updates that
LangGraph merges. Because Phase 2 runs sequentially, cost and error
accumulation is done explicitly inside the nodes.
"""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, START, StateGraph

from redforge.agents import run_scout, run_strategist
from redforge.llm import LLMClient
from redforge.sandbox import SandboxRunner
from redforge.schemas import AuditState, AuditStatus


def _route_after_strategist(state: AuditState) -> str:
    # No hypotheses -> the graph ends as FAILED. In Phase 3 the "continue"
    # branch will route to the PoC node instead of END.
    if state.status == AuditStatus.FAILED or not state.hypotheses:
        return "end"
    return "end"  # Phase 3: return "poc"


def build_graph(
    llm: LLMClient,
    sandbox: SandboxRunner,
    checkpointer: Any | None = None,
):
    builder = StateGraph(AuditState)
    builder.add_node("scout", lambda s: run_scout(s, sandbox))
    builder.add_node("strategist", lambda s: run_strategist(s, llm))

    builder.add_edge(START, "scout")
    builder.add_edge("scout", "strategist")
    builder.add_conditional_edges(
        "strategist", _route_after_strategist, {"end": END}
    )
    return builder.compile(checkpointer=checkpointer)
