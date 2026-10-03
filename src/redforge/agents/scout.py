"""Scout agent — maps the codebase.

Deterministic on purpose: it runs Slither (in the sandbox) for candidate
findings and builds a regex source index for targetable functions. No LLM call,
so it's cheap and reproducible. Returns a partial `AuditState` update.

Signature is `run_scout(state, sandbox)` — the sandbox is injected so tests can
stub it with canned Slither output and never touch Docker.
"""

from __future__ import annotations

from pathlib import Path

from redforge.config import settings
from redforge.logging_conf import get_logger
from redforge.repo.code_index import build_index
from redforge.sandbox import SandboxRunner
from redforge.schemas import AuditState, AuditStatus
from redforge.static_analysis import run_slither

log = get_logger("scout")


def run_scout(state: AuditState, sandbox: SandboxRunner) -> dict:
    if state.repo_map is None:
        return {
            "status": AuditStatus.FAILED,
            "errors": [*state.errors, "scout: repo_map missing"],
        }

    root = Path(state.repo_map.root)
    workspace = settings.work_root / state.run_id / "scout_ws"

    functions = build_index(root, state.repo_map.contract_files)

    try:
        findings = run_slither(root, workspace, sandbox)
    except Exception as exc:  # noqa: BLE001 - static analysis is best-effort
        log.warning("slither failed: %s", exc)
        findings = []

    log.info(
        "scout: %d findings, %d functions on %s",
        len(findings), len(functions), state.repo_map.kind.value,
    )
    return {
        "functions": functions,
        "findings": findings,
        "status": AuditStatus.MAPPED,
    }
