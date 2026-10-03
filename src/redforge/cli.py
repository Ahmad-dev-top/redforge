"""Command-line entry point.

    redforge sandbox-check                 # verify the sandbox image + no network
    redforge scan <github-url>             # Phase 1: clone + detect + static analysis
    redforge audit <github-url>            # full pipeline (wired in Phase 2+)
    redforge eval  <dataset> [--limit N]   # run the benchmark harness

Phases 2+ (LangGraph graph, PoC loop, remediation, verification) are wired into
`audit` as they are built. See CURSOR.md.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path

import typer

from redforge.config import settings
from redforge.logging_conf import configure_logging, get_logger
from redforge.repo import clone_repo, detect_project
from redforge.sandbox import SandboxRunner
from redforge.schemas import Finding
from redforge.static_analysis import run_slither

app = typer.Typer(add_completion=False, help="Smart-Contract Bounty Hunter")
log = get_logger("cli")


def write_findings(run_id: str, findings: list[Finding]) -> Path:
    """Drop the scan's Finding[] JSON at reports/<run>/findings.json."""
    dest = settings.reports_root / run_id
    dest.mkdir(parents=True, exist_ok=True)
    path = dest / "findings.json"
    payload = [f.model_dump(mode="json") for f in findings]
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    log.info("wrote %d findings to %s", len(findings), path)
    return path


@app.command("sandbox-check")
def sandbox_check() -> None:
    configure_logging()
    ok = SandboxRunner().self_check()
    typer.echo("sandbox OK" if ok else "sandbox FAILED")
    raise typer.Exit(0 if ok else 1)


@app.command("scan")
def scan(url: str) -> None:
    """Phase 1 deliverable: clone, detect the toolchain, run Slither."""
    configure_logging()
    settings.ensure_dirs()
    run_id = uuid.uuid4().hex[:8]
    repo = clone_repo(url, run_id)
    rmap = detect_project(repo)
    typer.echo(f"kind={rmap.kind.value} contracts={len(rmap.contract_files)} solc={rmap.solc_version}")
    ws = settings.work_root / run_id / "ws"
    findings = run_slither(repo, ws)
    for f in findings:
        typer.echo(f"[{f.severity.value:>8}] {f.detector:<24} {f.contract}.{f.function}")
    report = write_findings(run_id, findings)
    typer.echo(f"\n{len(findings)} findings")
    typer.echo(f"report={report}")


@app.command("audit")
def audit(url: str) -> None:
    """Run the audit graph (Phase 2: scout -> strategist) and print hypotheses."""
    configure_logging()
    from redforge.llm import AnthropicLLM
    from redforge.runner import audit_repo

    state = audit_repo(url, AnthropicLLM(), SandboxRunner())
    typer.echo(
        f"status={state.status.value}  findings={len(state.findings)}  "
        f"cost=${state.token_cost_usd:.4f}"
    )
    if not state.hypotheses:
        suffix = f" — {state.errors[-1]}" if state.errors else ""
        typer.echo("no hypotheses" + suffix)
        return
    typer.echo("\nranked attack hypotheses:")
    for h in state.hypotheses:
        typer.echo(
            f"[{h.priority:>3}] {h.vuln_class.value:<16} {h.target_contract}.{h.target_function} "
            f"-> oracle={h.oracle.value}"
        )


@app.command("eval")
def eval_cmd(dataset: str, limit: int | None = typer.Option(None, "--limit")) -> None:
    """Run the benchmark harness over a dataset and print the results table."""
    configure_logging()
    from redforge.eval.harness import run_eval
    from redforge.llm import AnthropicLLM
    from redforge.runner import build_audit_fn

    audit_fn = build_audit_fn(AnthropicLLM(), SandboxRunner())
    report = run_eval(dataset, audit_fn, limit=limit)
    typer.echo(report.to_markdown())
    out = settings.reports_root / f"eval_{dataset}.json"
    report.save(out)
    typer.echo(f"saved {out}")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
