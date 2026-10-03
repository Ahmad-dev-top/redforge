# Phase 2 — Scout + Strategist in LangGraph

Drop the new files into the repo at the paths shown, then apply the three small
edits to existing files below. Nothing here overwrites your Phase 1 work
(`cli.py scan`, `fetch_benchmarks.sh`, `test_sandbox.py`, pytest markers) — the
existing-file changes are additive and targeted.

## New files (copy as-is)

```
src/redforge/llm/__init__.py          LLM injection surface
src/redforge/llm/client.py            LLMClient protocol, AnthropicLLM, StubLLM, cost pricing
src/redforge/agents/__init__.py
src/redforge/agents/scout.py          run_scout(state, sandbox) -> dict   (deterministic)
src/redforge/agents/strategist.py     run_strategist(state, llm) -> dict  (strong model)
src/redforge/repo/code_index.py       regex source indexer (works offline / no deps)
src/redforge/graph.py                 build_graph(llm, sandbox, checkpointer)
src/redforge/runner.py                audit_repo / audit_case / build_audit_fn
tests/test_code_index.py
tests/test_scout.py                   stubbed sandbox
tests/test_strategist.py              stubbed LLM (parse, rank, re-prompt, fail)
tests/test_graph.py                   end-to-end with both stubs, no Docker/API key
```

## Edit 1 — `src/redforge/schemas.py`

Add the `FunctionRef` model just before `class Finding`:

```python
class FunctionRef(BaseModel):
    """A function discovered by the Scout's source index. Built by regex, so it
    works even when the repo can't be compiled (no deps / no network). Gives the
    Strategist concrete targets independent of whether Slither produced findings."""

    contract: str
    function: str
    file: str
    signature: str = ""
```

And add one field to `AuditState` (right after `repo_map`):

```python
    functions: list[FunctionRef] = Field(default_factory=list)
```

Why this schema change: the Scout builds a regex index of contracts/functions
that does **not** require compilation. That's what lets the Strategist target
functions on a repo Slither couldn't compile (the `forge-template` empty-`[]`
case). It flows Scout -> Strategist, so it belongs on `AuditState`.

## Edit 2 — `src/redforge/cli.py`

Replace ONLY the `audit` and `eval` command bodies (keep your `scan` changes):

```python
@app.command("audit")
def audit(url: str) -> None:
    """Run the audit graph (Phase 2: scout -> strategist) and print hypotheses."""
    configure_logging()
    from redforge.llm import AnthropicLLM
    from redforge.runner import audit_repo

    state = audit_repo(url, AnthropicLLM(), SandboxRunner())
    typer.echo(f"status={state.status.value}  findings={len(state.findings)}  cost=${state.token_cost_usd:.4f}")
    if not state.hypotheses:
        typer.echo("no hypotheses" + (f" — {state.errors[-1]}" if state.errors else ""))
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
```

## Edit 3 — `pyproject.toml`

Add to `dependencies`:

```
"langgraph-checkpoint-sqlite>=2.0",
```

Then `pip install -e ".[dev]"` to pull it in.

## Verify

```bash
ruff check src tests      # clean
mypy src                  # clean
pytest -q -k "not sandbox"   # all green (adds 10 Phase 2 tests)
```

## Run

```bash
redforge audit https://github.com/OWNER/REPO          # prints ranked hypotheses
redforge eval smartbugs-curated --limit 20            # detection-rate table
```

`eval` needs `scripts/fetch_benchmarks.sh` to have cloned the datasets, and a
real `REDFORGE_ANTHROPIC_API_KEY` in `.env` (the Strategist calls the strong
model). The tests need neither — LLM and sandbox are stubbed.

## Design notes / boundaries kept

- **Typed hand-offs**: agents return partial `AuditState` updates; hypotheses
  are validated `AttackHypothesis` objects.
- **Injection**: `build_graph(llm, sandbox, checkpointer)`. Tests pass `StubLLM`
  and a stub sandbox — no Docker, no API key.
- **Model split**: Scout is deterministic (no LLM). Strategist uses
  `settings.model_strong` and adds cost to `state.token_cost_usd`.
- **Strategist failure handling**: malformed JSON -> exactly one re-prompt with
  the error -> then status `FAILED`, recorded in `state.errors`. Never crashes
  the graph. Empty hypotheses -> `FAILED`.
- **Ranking**: `priority = severity_weight × confidence × 100`; finding-backed
  hypotheses use the finding's severity/confidence, agent-only ones default to
  MEDIUM × 0.5.
- **Oracles / sandbox untouched.** No exploit-success logic moved; no sandbox
  flags relaxed.

## Phase 3 hook

`graph._route_after_strategist` currently returns `"end"` on both paths. When
the PoC node lands, change the continue-branch to return `"poc"` and add the
`poc` node + its retry self-loop. That's the only wiring change needed there.

## Known limitation to schedule (not Phase 2)

Multi-file repos whose deps live in `lib/` (Foundry submodules) or
`node_modules/` won't compile inside the no-network sandbox, so Slither yields
`[]` on them. The code index still gives the Strategist targets, but findings
will be thin. Fix is a trusted host-side dependency-fetch step before sealing
the sandbox (`repo/deps.py`): run `forge install` / `npm ci` on the host during
clone, then mount read-only with no network for execution. Preserves the safety
model. Recommend doing this before Phase 3, since the PoC engineer also needs a
compilable project.
