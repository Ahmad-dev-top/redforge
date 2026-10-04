# DVD benchmark — run the full pipeline across all challenges

Turns the single verified run into a capability table: for each Damn Vulnerable
DeFi challenge, the full pipeline runs scoped to that challenge and the result is
reported as a funnel — found → confirmed → patched → verified — with cost and
time. Reuses the Phase-1 eval harness; the only new idea is per-challenge
scoping.

## New file (copy as-is)

```
src/redforge/eval/dvd.py             DVD registry + scoped audit + funnel table
tests/tests/test_dvd_benchmark.py -> tests/test_dvd_benchmark.py
```

## Edits to existing files

### `src/redforge/schemas.py`
Add to `AuditState` (after `repo_map`):
```python
    scope_prefix: str = ""        # if set, scout keeps only files under this path
```

### `src/redforge/agents/scout.py`
Just before the final `log.info(...) / return {...}`, filter by scope:
```python
    # Benchmark scoping: when a scope_prefix is set (e.g. "src/unstoppable/"),
    # keep only findings/functions under it so each challenge is audited in
    # isolation even though Slither scanned the whole monorepo.
    if state.scope_prefix:
        p = state.scope_prefix
        findings = [f for f in findings if (f.file or "").startswith(p)]
        functions = [fn for fn in functions if fn.file.startswith(p)]
```
(and include `scope` in the log line if you like).

### `src/redforge/eval/harness.py`
1. Let `run_eval` accept pre-built cases:
```python
def run_eval(
    dataset: str,
    audit_fn: AuditFn,
    limit: int | None = None,
    cases: list[BenchmarkCase] | None = None,
) -> EvalReport:
    cases = cases if cases is not None else load_dataset(dataset)
    if limit:
        cases = cases[:limit]
    ...
```
2. Make `patched` require the exploit to be defeated, not just compile:
```python
            cr.patched = any(
                v.patch and v.patch.compiles and v.patch.poc_defeated
                for v in state.vulnerabilities
            )
```

### `src/redforge/eval/__init__.py`
Add the DVD exports (`DVD_CHALLENGES`, `challenge_table`, `load_dvd_challenges`,
`run_dvd_benchmark`) alongside the existing ones.

### `src/redforge/cli.py`
Add a `bench-dvd` command: clone DVD once, `fetch_dependencies` once, then
`run_dvd_benchmark(AnthropicLLM(), SandboxRunner(), repo, limit=...)`, print
`challenge_table(report)` and save it to `reports/dvd_benchmark.md` + `.json`.
(Full body is in the packaged cli.py diff below.)

```python
@app.command("bench-dvd")
def bench_dvd(url: str = "https://github.com/theredguild/damn-vulnerable-defi",
              limit: int | None = typer.Option(None, "--limit")) -> None:
    """Benchmark the full pipeline across Damn Vulnerable DeFi challenges."""
    configure_logging()
    settings.ensure_dirs()
    import uuid as _uuid
    from redforge.eval import challenge_table, run_dvd_benchmark
    from redforge.llm import AnthropicLLM
    from redforge.repo import clone_repo, detect_project, fetch_dependencies

    run_id = _uuid.uuid4().hex[:8]
    repo = clone_repo(url, run_id)
    fetch_dependencies(repo, detect_project(repo))
    report = run_dvd_benchmark(AnthropicLLM(), SandboxRunner(), repo, limit=limit)
    table = challenge_table(report)
    typer.echo(table)
    out = settings.reports_root / "dvd_benchmark.md"
    out.write_text(table)
    report.save(settings.reports_root / "dvd_benchmark.json")
    typer.echo(f"\nsaved {out}")
```

## Verify

```bash
ruff check src tests      # clean
mypy src                  # clean (32 files)
pytest -q -k "not sandbox"   # green; +4 benchmark tests
```

## Run it

Start SMALL to sanity-check wiring and cost, then scale:
```bash
redforge bench-dvd --limit 3     # first 3 challenges (incl. unstoppable)
redforge bench-dvd               # full suite (~15 challenges)
```

### Cost & time to expect
At ~$0.65 for a full verified challenge and less for ones that stop earlier, the
whole suite is roughly **$5–10** and a handful of minutes (Slither re-runs per
challenge dominate wall-time; LLM cost is scoped and small). To tighten cost:
```
REDFORGE_POC_MAX_HYPOTHESES=3 redforge bench-dvd
```
`poc_stop_on_first_confirmation` is already on, so confirmed challenges stop fast;
unconfirmed ones run the full (bounded) budget.

### What to expect in the results — and report honestly
RedForge will NOT verify all ~15 challenges, and that's the correct outcome to
publish. DVD is CTF-grade: several challenges need multi-transaction setups,
off-chain steps (`compromised` is a leaked-key puzzle, flagged
`needs_offchain`), or multi-contract orchestration that a single-PoC approach
with four oracles can't express yet. Expect a spread across found / confirmed /
patched / verified. The table reports exactly what happened — don't tune the
suite to inflate the number.

Paste back: the full `challenge_table` output (the markdown table + summary
line), total cost, and wall-time. That table is the deliverable.

## After the run — put it in the README

The summary line (`N/M confirmed, K/M verified · total cost $X`) plus the
per-challenge table goes in the README under the DVD showcase section, right
after the single UnstoppableVault result. One proven run shows it works; the
table shows the breadth. Commit `reports/dvd_benchmark.md` into `showcase/`.

## Note on honesty (keep this framing)

Report confirmed/verified counts with the denominator = challenges attempted,
and keep the `needs_offchain` ones in the table marked as such rather than
dropping them. "Verified K of M, with these N needing capabilities RedForge
doesn't yet have" is a stronger, more credible claim than a cherry-picked
subset — and it maps directly onto a real roadmap (multi-tx PoCs, off-chain
setup) for the project's next phase.
