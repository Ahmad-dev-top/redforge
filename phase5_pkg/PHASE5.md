# Phase 5 — Verification Auditor (the formal-verification layer)

Runs only on a successfully patched vulnerability and fills the
`VerificationReport`. Three checks — regression, differential, and a Halmos
symbolic proof — and on all-green sets status `VERIFIED`. This is the half that
earns the "Formal Verifier" in the project's name.

After this the full pipeline is: scout → strategist → PoC loop → remediation →
**verification** → END.

## One deliberate change from the plan (please read)

The planned gate was `verified = regression ∧ differential ∧ halmos`. While
building I hit a real wrinkle: a repo's own test suite can *encode* the
vulnerability — DVD's challenge test asserts the exploit succeeds, so after a
correct patch that test FAILS by design. Making `verified` require the existing
suite to pass would wrongly deny verification on exactly the target we built
this for.

So the gate is now:

```
verified = poc_now_fails ∧ differential_equivalent ∧ halmos_proved
```

Regression (`existing_tests_pass`) is still RUN and RECORDED in the report (and
surfaced for the human), just not a hard gate. Rationale: the differential check
already proves "non-exploit behaviour is unchanged" on arbitrary inputs — a
stronger, more general guarantee than "the repo's own hand-written tests pass" —
and existing suites can encode the vuln (CTF) or be absent entirely. If you want
the stricter gate for non-CTF targets, it's a one-line change in `verifier.py`
(add `existing_tests_pass` to the `verified` expression); say the word.

## New file (copy as-is)

```
src/redforge/agents/verifier.py      run_verification(state, llm, sandbox)
```

## Replace (full)

```
src/redforge/graph.py                # remediation now routes to verification
tests/test_graph.py                  # full-pipeline-to-VERIFIED + timeout-to-PATCHED
tests/test_verifier.py               # new: verified / timeout / counterexample / diff-fail
```

## Edits to existing files

### `src/redforge/schemas.py`
Add to `Patch`:
```python
    patched_source: str = ""      # full patched contract — re-applied for verification
```
Add to `VerificationReport` (after `halmos_counterexample`):
```python
    halmos_timed_out: bool = False        # undecided within budget (not a refutation)
```

### `src/redforge/config.py`
Add after the remediation setting:
```python
    # --- Verification ------------------------------------------------------
    halmos_timeout_s: int = Field(default=120)  # symbolic proof budget; timeout != refutation
```

### `src/redforge/agents/remediation.py`
Store the full patched source in the `Patch(...)` it builds — add this line to
the constructor (next to `attempts=attempt,`):
```python
            patched_source=patched_source,
```

### `src/redforge/foundry/forge.py`
Add two helpers just before `_to_result`:
```python
def run_forge_suite_against_patch(
    repo_ro: Path,
    workspace_rw: Path,
    contract_rel: str,
    patched_source: str,
    sandbox: SandboxRunner | None = None,
    exclude: str = "test/Exploit.t.sol",
) -> ForgeResult:
    """Run the repo's existing test suite against the patched contract, excluding
    our injected exploit. Used by verification for the regression check."""
    sandbox = sandbox or SandboxRunner()
    workspace_rw.mkdir(parents=True, exist_ok=True)
    (workspace_rw / "patched.sol").write_text(patched_source)
    cmd = (
        "rm -rf /work/target; cp -r /repo/. /work/target 2>/dev/null; "
        f"cp /work/patched.sol '/work/target/{contract_rel}' && cd /work/target && "
        f"forge test -vv --no-match-path '{exclude}' 2>&1"
    )
    return _to_result(sandbox.run(cmd, repo_ro, workspace_rw))


def run_halmos_against_patch(
    repo_ro: Path,
    workspace_rw: Path,
    contract_rel: str,
    patched_source: str,
    test_source: str,
    sandbox: SandboxRunner | None = None,
    timeout_s: int = 120,
    test_filename: str = "Verify.t.sol",
) -> ForgeResult:
    """Run a Halmos symbolic property test against the patched contract, bounded
    by `timeout_s` (the shell `timeout` returns 124 on expiry)."""
    sandbox = sandbox or SandboxRunner()
    workspace_rw.mkdir(parents=True, exist_ok=True)
    (workspace_rw / "patched.sol").write_text(patched_source)
    (workspace_rw / test_filename).write_text(test_source)
    cmd = (
        "rm -rf /work/target; cp -r /repo/. /work/target 2>/dev/null; "
        f"cp /work/patched.sol '/work/target/{contract_rel}' && "
        f"mkdir -p /work/target/test && cp /work/{test_filename} /work/target/test/{test_filename} && "
        f"cd /work/target && timeout {timeout_s} halmos --match-path 'test/{test_filename}' 2>&1"
    )
    return _to_result(sandbox.run(cmd, repo_ro, workspace_rw))
```
Update `src/redforge/foundry/__init__.py` to export both (keep the existing
exports, add `run_forge_suite_against_patch` and `run_halmos_against_patch`).

### `src/redforge/agents/__init__.py`
```python
from redforge.agents.poc_engineer import run_poc
from redforge.agents.remediation import run_remediation
from redforge.agents.scout import run_scout
from redforge.agents.strategist import run_strategist
from redforge.agents.verifier import run_verification

__all__ = ["run_poc", "run_remediation", "run_scout", "run_strategist", "run_verification"]
```

## Verify

```bash
ruff check src tests      # clean
mypy src                  # clean (31 files)
pytest -q -k "not sandbox"   # green; +8 verifier tests, graph tests extended
```

## Run for real (DVD)

```bash
redforge audit https://github.com/theredguild/damn-vulnerable-defi
```
Expected end state is `verified` IF Halmos proves the property within the
budget; otherwise `patched` with `halmos_timed_out=True` (which is fine —
timeout is "not proven", not "refuted"). Report: final status, the three check
results (`existing_tests_pass`, `differential_equivalent`, `halmos_proved` /
`halmos_timed_out`), any counterexample, and total cost.

Notes for the DVD run specifically:
- `existing_tests_pass` will likely be **False** — DVD's own challenge test
  asserts the exploit works, so it fails post-patch. That's expected and does
  NOT block `verified` (see the design note above).
- Halmos can be slow or undecided on real contracts. If it times out, you'll get
  `patched`, not `verified` — bump `REDFORGE_HALMOS_TIMEOUT_S` and retry, or
  accept `patched` as the honest outcome. Please report whichever happens; the
  real Halmos behaviour on UnstoppableVault is genuinely useful data.

## How Halmos is parsed (the new machinery)

`_parse_halmos(output, exit_code, timed_out)` returns `(proved, counterexample,
timed_out)`:
- timeout if the sandbox timed out, `exit_code == 124` (shell `timeout`), or the
  log mentions timeout → `halmos_timed_out=True`, not proved, not a refutation;
- counterexample if the log contains one → `halmos_proved=False`, recorded (the
  patch is actually unsound);
- otherwise proved if Halmos reported a pass / `0 failed` / no counterexample.

This is the symbolic analogue of `check_oracle` — the harness decides, not the
model.

## Status after this phase

The core build is COMPLETE: RedForge finds, proves, patches, and formally
verifies, end to end, bounded and crash-resumable. Remaining phases are product
layer (API + dashboard + PR-opening) and memory/RAG — enhancements, not core.
