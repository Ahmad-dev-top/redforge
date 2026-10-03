"""Top-level orchestration: build an `AuditState` and run the graph.

Two entry points:
- `audit_repo(url, ...)`  — clone a GitHub repo, then audit it.
- `audit_case(case, ...)` — audit one benchmark contract (used by the eval harness).

Both return the final `AuditState`. `build_audit_fn` adapts `audit_case` into the
`AuditFn` the eval harness expects.
"""

from __future__ import annotations

import shutil
import tempfile
import uuid
from pathlib import Path
from typing import Any

from langgraph.checkpoint.sqlite import SqliteSaver

from redforge.config import settings
from redforge.eval.datasets import BenchmarkCase
from redforge.eval.harness import AuditFn
from redforge.graph import build_graph
from redforge.llm import LLMClient
from redforge.repo import clone_repo, detect_project, fetch_dependencies
from redforge.sandbox import SandboxRunner
from redforge.schemas import AuditState, AuditStatus


def _run(state: AuditState, llm: LLMClient, sandbox: SandboxRunner, checkpointer: Any | None) -> AuditState:
    graph = build_graph(llm, sandbox, checkpointer=checkpointer)
    config = {"configurable": {"thread_id": state.run_id}}
    final = graph.invoke(state, config)
    return AuditState.model_validate(final)


def audit_repo(
    url: str,
    llm: LLMClient,
    sandbox: SandboxRunner | None = None,
    run_id: str | None = None,
) -> AuditState:
    sandbox = sandbox or SandboxRunner()
    run_id = run_id or uuid.uuid4().hex[:8]
    settings.ensure_dirs()
    repo = clone_repo(url, run_id)
    repo_map = detect_project(repo)
    # Compile-enabler: resolve deps on the trusted host BEFORE the no-network
    # sandbox runs, so Slither/forge can actually compile the project.
    deps = fetch_dependencies(repo, repo_map)
    state = AuditState(repo_url=url, run_id=run_id, repo_map=repo_map, status=AuditStatus.PENDING)
    if deps.warnings:
        state.errors.extend(f"deps: {w}" for w in deps.warnings)
    # Checkpoint to SQLite so runs survive crashes and can be replayed.
    db = settings.work_root / run_id / "graph.sqlite"
    db.parent.mkdir(parents=True, exist_ok=True)
    with SqliteSaver.from_conn_string(str(db)) as cp:
        return _run(state, llm, sandbox, cp)


def audit_case(
    case: BenchmarkCase,
    llm: LLMClient,
    sandbox: SandboxRunner | None = None,
) -> AuditState:
    """Audit a single benchmark contract by isolating it in a temp project."""
    sandbox = sandbox or SandboxRunner()
    run_id = uuid.uuid4().hex[:8]
    tmp = Path(tempfile.mkdtemp(prefix="redforge_case_"))
    try:
        shutil.copy(case.path, tmp / case.path.name)
        repo_map = detect_project(tmp)
        state = AuditState(
            repo_url=f"benchmark://{case.dataset}/{case.case_id}",
            run_id=run_id,
            repo_map=repo_map,
        )
        # No checkpointer for eval cases — they are short and disposable.
        return _run(state, llm, sandbox, None)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def build_audit_fn(llm: LLMClient, sandbox: SandboxRunner | None = None) -> AuditFn:
    sandbox = sandbox or SandboxRunner()
    return lambda case: audit_case(case, llm, sandbox)
