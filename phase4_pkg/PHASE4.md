# Phase 4 — Remediation Architect

Takes a confirmed vulnerability, generates a minimal-diff patch, and gates it on
two things in the sandbox: the patch **compiles**, and the **same exploit now
fails**. Self-corrects up to 3 times; on exhaustion it records the attempt and
leaves the vuln confirmed-but-unpatched (a proven bug is still a valid result,
so the run does not fail).

After this, `redforge audit` runs: scout → strategist → PoC loop → **remediation**
→ END. On DVD it confirms UnstoppableVault, then patches it and verifies the
exploit is closed.

## New file (copy as-is)

```
src/redforge/agents/remediation.py   run_remediation(state, llm, sandbox)
```

## Replace (full)

```
src/redforge/graph.py                # confirmed-exit now routes to remediation
tests/test_graph.py                  # +2 end-to-end tests (patched / unpatchable)
tests/test_remediation.py            # new: patch success / self-correct / exhaust
```

## Edits to existing files

### `src/redforge/schemas.py`
Add one field to `PoCResult` (the exploit must be re-runnable against a patch):
```python
    test_source: str = ""         # the generated exploit itself — re-run vs a patch
```
Add two fields to `Patch`:
```python
    poc_defeated: bool = False    # the confirming exploit no longer confirms
    attempts: int = 0
```

### `src/redforge/config.py`
Add under the strategist settings:
```python
    # --- Remediation -------------------------------------------------------
    remediation_max_retries: int = Field(default=3)  # patch self-correction budget
```

### `src/redforge/foundry/forge.py`
Add `run_poc_against_patch` (just before `_to_result`):
```python
def run_poc_against_patch(
    repo_ro: Path,
    workspace_rw: Path,
    contract_rel: str,
    patched_source: str,
    test_source: str,
    sandbox: SandboxRunner | None = None,
    test_filename: str = "Exploit.t.sol",
) -> ForgeResult:
    """Apply a patched contract over the original, inject the confirming exploit,
    and run it. Used by remediation: success is this test now FAILING."""
    sandbox = sandbox or SandboxRunner()
    workspace_rw.mkdir(parents=True, exist_ok=True)
    (workspace_rw / "patched.sol").write_text(patched_source)
    (workspace_rw / test_filename).write_text(test_source)
    cmd = (
        "rm -rf /work/target; cp -r /repo/. /work/target 2>/dev/null; "
        f"cp /work/patched.sol '/work/target/{contract_rel}' && "
        f"mkdir -p /work/target/test && cp /work/{test_filename} /work/target/test/{test_filename} && "
        f"cd /work/target && forge test -vvv --match-path 'test/{test_filename}' 2>&1"
    )
    res = sandbox.run(cmd, repo_ro, workspace_rw)
    return _to_result(res)
```
Export it in `src/redforge/foundry/__init__.py`:
```python
from redforge.foundry.forge import (
    ForgeResult,
    run_forge_test,
    run_poc_against_patch,
    run_poc_test,
)

__all__ = ["ForgeResult", "run_forge_test", "run_poc_against_patch", "run_poc_test"]
```

### `src/redforge/agents/poc_engineer.py`
Two changes:
1. Store the exploit source in the result — add `test_source=test_source` to the
   `PoCResult(...)` constructor.
2. Replace the file-lookup in `_target_source` with a public `target_file` helper
   (remediation reuses it):
```python
def target_file(state: AuditState, hyp: AttackHypothesis) -> str | None:
    """Repo-relative path of the file declaring the targeted contract, or the
    first contract file as a fallback. Public — reused by the remediation node."""
    for fn in state.functions:
        if fn.contract == hyp.target_contract:
            return fn.file
    if state.repo_map and state.repo_map.contract_files:
        return state.repo_map.contract_files[0]
    return None


def _target_source(hyp: AttackHypothesis, state: AuditState) -> tuple[str, str]:
    """Return (import_path, source_text) for the targeted contract."""
    root = Path(state.repo_map.root) if state.repo_map else Path()
    rel = target_file(state, hyp)
    if rel is None:
        return hyp.target_contract, ""
    try:
        text = (root / rel).read_text(errors="ignore")[:8000]
    except OSError:
        text = ""
    return rel, text
```

### `src/redforge/agents/__init__.py`
```python
from redforge.agents.poc_engineer import run_poc
from redforge.agents.remediation import run_remediation
from redforge.agents.scout import run_scout
from redforge.agents.strategist import run_strategist

__all__ = ["run_poc", "run_remediation", "run_scout", "run_strategist"]
```

## Verify

```bash
ruff check src tests      # clean
mypy src                  # clean (30 files)
pytest -q -k "not sandbox"   # green; +7 Phase 4 tests
```

## Run for real (DVD)

```bash
redforge audit https://github.com/theredguild/damn-vulnerable-defi
```
Expected: confirms UnstoppableVault (as before), then a `remediation` step →
status `patched`, with `vulnerabilities[0].patch.compiles` and
`.poc_defeated` both True, and a unified diff recorded. Report: final status,
patch attempts, `poc_defeated`, the diff (first ~30 lines), and total cost.

## How the gate works (the elegant part)

Remediation reuses the PoC harness in reverse. `run_poc_against_patch` applies
the patched contract, injects the SAME `Exploit.t.sol` that confirmed the bug,
and runs it. `check_oracle(...)` is then checked for the OPPOSITE outcome:
`poc_defeated = not check_oracle(...)`. So "the exploit no longer confirms" is
proven by the exact same oracle that proved it in the first place — no new
verification machinery. Success = compiles AND defeated.

## Exhaustion behaviour (by design)

If `remediation_max_retries` attempts all fail to close the exploit, the patch
is recorded with `poc_defeated=False`, the vuln stays confirmed-but-unpatched,
and the run ends `exploit_confirmed` (not failed). That confirmed-but-unpatched
vulnerability is exactly what the human reviewer and the Phase 5 Verification
Auditor should see.

## Next: Phase 5 — Verification Auditor

Extends from the `remediation` node (currently → END). On a successful patch:
re-run existing tests (regression), generate a differential test (behaviour
unchanged on safe inputs), and a Halmos symbolic proof of the property. Sets the
`VerificationReport` and status `VERIFIED`.
