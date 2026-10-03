# Phase 3 — Step 5: graph wiring (the PoC loop)

Wires the already-proven PoC node into the graph as a bounded loop. After this,
`redforge audit <repo>` runs end to end: scout → strategist → PoC loop →
confirmation. On DVD that means it stops the moment `UnstoppableVault` is proven.

This is a small, contained change: two full-file replacements plus three config
lines and two edits to the PoC agent. No sandbox/oracle changes.

## Budget (the decision, now in config)

Defaults: **top 5 hypotheses, priority floor 150, 3 retries each, stop on first
confirmation.** All four are settings, tune per surface (an interactive `audit`
can be generous; a batch `eval` across many repos should tighten the cap because
cost compounds).

## Files to replace (full)

```
src/redforge/graph.py        # PoC node + route flip + bounded self-loop
tests/test_graph.py          # loop tests (stop-on-first, advance, cap, floor)
```

Both are self-contained and safe to drop in. `graph.py` only changed from the
Phase-2 version by adding the `poc` node and the two conditional routers.

## Edit 1 — `src/redforge/config.py`

Under the agent-loop section, replace the single `poc_max_retries` line with:

```python
    # --- Agent loop --------------------------------------------------------
    poc_max_retries: int = Field(default=3)  # self-correction attempts per hypothesis
    poc_max_hypotheses: int = Field(default=5)  # hard cap on hypotheses attempted per run
    poc_priority_floor: int = Field(default=150)  # skip hypotheses below this priority
    poc_stop_on_first_confirmation: bool = Field(default=True)  # one proof ends the loop
```

Expose them via env too (append to `.env.example`):

```
SCBH_… no — use the REDFORGE_ prefix:
REDFORGE_POC_MAX_HYPOTHESES=5
REDFORGE_POC_PRIORITY_FLOOR=150
REDFORGE_POC_STOP_ON_FIRST_CONFIRMATION=true
```

## Edit 2 — `src/redforge/agents/poc_engineer.py`

In `_next_hypothesis`, add the priority-floor skip and add a public accessor the
graph router uses. Replace the whole `_next_hypothesis` function with:

```python
def _next_hypothesis(state: AuditState) -> AttackHypothesis | None:
    # run_poc exhausts all retries for a hypothesis in one call, so any
    # hypothesis already recorded in vulnerabilities is done (confirmed OR
    # exhausted). Skip those — this is what lets the graph loop advance instead
    # of re-picking the same failed hypothesis forever. Also skip anything below
    # the priority floor: on a noisy repo (1000+ findings) attempting low-value
    # guesses is pure cost. Hypotheses are priority-sorted, so the first
    # un-attempted one at/above the floor is the best eligible target.
    attempted = {v.hypothesis.id for v in state.vulnerabilities if v.hypothesis}
    for h in state.hypotheses:
        if h.id in attempted:
            continue
        if h.priority < settings.poc_priority_floor:
            continue
        return h
    return None


def pending_hypothesis(state: AuditState) -> AttackHypothesis | None:
    """Public accessor for the graph router: the next eligible, not-yet-attempted
    hypothesis at/above the priority floor, or None if none remain."""
    return _next_hypothesis(state)
```

(If you already had the attempted-skip version from the Phase 3 revision, this
just adds the floor check and the public wrapper.)

## Verify

```bash
ruff check src tests      # clean
mypy src                  # clean
pytest -q -k "not sandbox"   # green; test_graph.py now has 5 loop tests
```

## Run it for real

```bash
redforge audit https://github.com/theredguild/damn-vulnerable-defi
```

Expected on DVD: scout maps, strategist ranks (UnstoppableVault flashLoan at the
top), the loop enters `poc`, confirms on the first hypothesis, and stops —
status `exploit_confirmed`, one vulnerability recorded, cost printed.

## How termination is guaranteed

Each `poc` visit attempts exactly one *new* hypothesis (appends one
Vulnerability); `pending_hypothesis` skips attempted ones and anything below the
floor. So every iteration strictly shrinks the eligible set. The loop ends at
the first of: a confirmation (if `poc_stop_on_first_confirmation`), the
`poc_max_hypotheses` cap, or no eligible hypothesis left. Worst case (nothing
confirms) is `poc_max_hypotheses × poc_max_retries` LLM calls — bounded and
predictable. Well inside LangGraph's recursion limit.

## Also worth doing (not blocking)

- **Update `_PRICING` in `llm/client.py`** to current Console rates — the printed
  cost is about to be watched across multiple attempts, so it should be right.
- **Trim the strategist prompt**: feeding all ~1300 findings is the biggest fixed
  cost per run. Filter findings to a severity threshold before building the
  prompt (functions are already capped at 120). This lowers cost more than any
  loop tuning.

## Next phase

Phase 4 — Remediation Architect: take a confirmed vulnerability, produce a
minimal-diff patch, compile it, and require the PoC now *fails*. The graph's
"confirmed" exit currently goes to END; Phase 4 points it at a `remediation`
node instead.
