# Cost-baseline fixes (before Phase 4)

Two changes so the printed cost is accurate and the per-run cost drops before
Phase 4 adds more strong-model calls. Both are low-risk and configurable.

## 1. Correct the pricing table

`llm/client.py` — `_PRICING` had Opus at the old `$15/$75`. Current Opus 4.8 is
`$5/$25` (verified at docs.claude.com/en/docs/about-claude/pricing, Oct 2026).
Sonnet `$3/$15` and Haiku `$1/$5` were already correct. Net effect: the printed
cost now matches the Console bill (your `$4.19` becomes `~$1.40` for the same
run — exactly the ~1/3 you were seeing).

## 2. Trim the strategist prompt

The strategist's single Opus call reasons over every finding — ~1347 on DVD —
and that input is the dominant per-run cost (paid even when zero exploits are
attempted). Now the prompt uses only findings at/above a severity floor, capped
to the top N by severity x confidence. `state.findings` stays complete for the
report; anything dropped is still targetable via the code index, so recall is
preserved (DVD's confirmed hypothesis was HIGH-severity, priority 360 — well
inside the cut).

New config dials (defaults):
```
strategist_min_severity = "low"   # drops only 'info' noise
strategist_max_findings = 80      # cap after the severity sort
```
Tune `strategist_min_severity="medium"` for more savings on very noisy repos.

## Files to replace (full)

```
src/redforge/llm/client.py           # _PRICING updated
src/redforge/agents/strategist.py    # _select_findings + prompt uses it
tests/test_strategist.py             # +1 test for selection
```

## Edit — `src/redforge/config.py`

Add after the PoC loop settings (next to `poc_stop_on_first_confirmation`):

```python
    # --- Strategist prompt budget -----------------------------------------
    # The strategist's single strong-model call is the dominant per-run cost.
    # Feeding it every finding (1000+ on a big repo) is mostly noise, so cut
    # low-value findings before building the prompt. Agent-originated hypotheses
    # (via the code index) still cover anything dropped here.
    strategist_min_severity: str = Field(default="low")  # drop 'info' findings
    strategist_max_findings: int = Field(default=80)      # cap after severity sort
```

Optionally add to `.env.example`:
```
REDFORGE_STRATEGIST_MIN_SEVERITY=low
REDFORGE_STRATEGIST_MAX_FINDINGS=80
```

## Verify

```bash
ruff check src tests      # clean
mypy src                  # clean
pytest -q -k "not sandbox"   # green (+1 strategist selection test)
```

## Confirm the effect on a real run

```bash
redforge audit https://github.com/theredguild/damn-vulnerable-defi
```
Expect the same `exploit_confirmed` result as before, but a printed cost roughly
a third of the old figure (correct pricing) and a smaller strategist input
(fewer findings in the prompt). Compare the printed cost to your Console — they
should now agree.

## Next: Phase 4 (Remediation)

On a clean cost baseline. Take the confirmed `Vulnerability`, generate a
minimal-diff patch, compile it, and require the PoC now *fails*. Retry budget as
a config dial (proposed `remediation_max_retries=3`), same pattern as the PoC
loop. The graph's confirmed-exit moves from END to a new `remediation` node.
