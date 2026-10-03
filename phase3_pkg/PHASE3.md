# Phase 3 (steps 1–2) — Compile-enabler + PoC node

> **Revision 2.** Two correctness fixes in `poc_engineer.py` since the first drop:
> 1. `_extract_solidity` now strips *any* fence language tag (``` ```sol ``` ```,
>    ``` ```solidity ```, bare) — the old regex left a stray `sol` in the code and
>    broke compilation.
> 2. `_next_hypothesis` now skips every *attempted* hypothesis, not just confirmed
>    ones — otherwise the Phase-5 graph loop would re-pick the same failed
>    hypothesis forever. Two tests added (30 pass total here).
> Integration steps are unchanged — just use these files.

Delivers the exploit-confirmation core: a host-side dependency fetch so repos
actually compile in the sandbox, and the PoC Engineer that writes `Exploit.t.sol`,
runs it, self-corrects, and lets `check_oracle()` confirm. Graph wiring (step 5)
is deliberately NOT done yet — see "Phase 3 remainder" at the bottom.

Copy the two new modules + two new tests, then apply the five small edits.
Nothing overwrites your earlier work — edits are additive.

## New files (copy as-is)

```
src/redforge/repo/deps.py            compile-enabler: plan_fetch + fetch_dependencies
src/redforge/agents/poc_engineer.py  run_poc(state, llm, sandbox) -> dict
tests/test_deps.py                   plan_fetch logic (no network)
tests/test_poc_engineer.py           confirm / self-correct / exhaust (stubbed llm+sandbox)
```

## Edit 1 — `src/redforge/repo/__init__.py`

```python
from redforge.repo.cloner import clone_repo
from redforge.repo.deps import fetch_dependencies, plan_fetch
from redforge.repo.project_detector import detect_project

__all__ = ["clone_repo", "detect_project", "fetch_dependencies", "plan_fetch"]
```

## Edit 2 — `src/redforge/foundry/forge.py`

In `run_forge_test`, replace everything from `res = sandbox.run(cmd, repo_ro, workspace_rw)`
to the end of the function with:

```python
    res = sandbox.run(cmd, repo_ro, workspace_rw)
    return _to_result(res)
```

Then add these two functions directly after `run_forge_test`:

```python
def run_poc_test(
    repo_ro: Path,
    workspace_rw: Path,
    test_source: str,
    sandbox: SandboxRunner | None = None,
    test_filename: str = "Exploit.t.sol",
) -> ForgeResult:
    """Inject a generated exploit test into the project and run just that test.

    The test is written to the host-side workspace, then the sandbox copies the
    repo into a writable target, drops the test into `test/`, and runs it. The
    original repo mount stays read-only and untouched.
    """
    sandbox = sandbox or SandboxRunner()
    workspace_rw.mkdir(parents=True, exist_ok=True)
    (workspace_rw / test_filename).write_text(test_source)
    cmd = (
        "cp -rn /repo/. /work/target 2>/dev/null; mkdir -p /work/target/test && "
        f"cp /work/{test_filename} /work/target/test/{test_filename} && "
        f"cd /work/target && forge test -vvv --match-path 'test/{test_filename}' 2>&1"
    )
    res = sandbox.run(cmd, repo_ro, workspace_rw)
    return _to_result(res)


def _to_result(res) -> ForgeResult:
    out = res.stdout + res.stderr
    # `forge test` exits non-zero on both compile failure and test failure, so
    # we separate the two by scanning the log.
    compiled = "Compiler run failed" not in out and "Compilation failed" not in out
    passed = res.exit_code == 0 and " FAIL" not in out and not res.timed_out
    return ForgeResult(
        compiled=compiled,
        passed=passed,
        exit_code=res.exit_code,
        output=out,
        timed_out=res.timed_out,
    )
```

(No behaviour change to `run_forge_test` — the parsing just moved into `_to_result`.)

## Edit 3 — `src/redforge/foundry/__init__.py`

```python
from redforge.foundry.forge import ForgeResult, run_forge_test, run_poc_test

__all__ = ["ForgeResult", "run_forge_test", "run_poc_test"]
```

## Edit 4 — `src/redforge/agents/__init__.py`

```python
from redforge.agents.poc_engineer import run_poc
from redforge.agents.scout import run_scout
from redforge.agents.strategist import run_strategist

__all__ = ["run_poc", "run_scout", "run_strategist"]
```

## Edit 5 — `src/redforge/runner.py`

Change the import line:

```python
from redforge.repo import clone_repo, detect_project, fetch_dependencies
```

In `audit_repo`, replace the clone/detect/state block with:

```python
    repo = clone_repo(url, run_id)
    repo_map = detect_project(repo)
    # Compile-enabler: resolve deps on the trusted host BEFORE the no-network
    # sandbox runs, so Slither/forge can actually compile the project.
    deps = fetch_dependencies(repo, repo_map)
    state = AuditState(repo_url=url, run_id=run_id, repo_map=repo_map, status=AuditStatus.PENDING)
    if deps.warnings:
        state.errors.extend(f"deps: {w}" for w in deps.warnings)
```

## Verify

```bash
ruff check src tests      # clean
mypy src                  # clean (29 files)
pytest -q -k "not sandbox"   # all green (adds 10 Phase 3 tests -> 28 total here)
```

## How it works

### Compile-enabler (`deps.py`)
- `plan_fetch` (pure, testable): Foundry + `.gitmodules` -> `git submodule update
  --init --recursive`; Hardhat + `package.json` -> `npm ci`; else nothing.
- `fetch_dependencies` runs those on the HOST (network + git/npm available),
  falls back `npm ci -> npm install`, and warns if `lib/forge-std` is still
  missing. It is wired into `audit_repo` before the graph runs.
- Safety model intact: dependency resolution is trusted host work; untrusted
  code still only runs in the no-network sandbox, which mounts the now-populated
  repo read-only.

### PoC node (`poc_engineer.py`)
- `run_poc(state, llm, sandbox)` picks the top unconfirmed hypothesis, builds a
  prompt (hypothesis + target source + `oracle_cheatsheet()` with the concrete
  sentinel), gets a Solidity test from the strong model, and runs it via
  `run_poc_test` in the sandbox.
- Self-correction: on compile/run failure or a missing sentinel it feeds the
  forge output back and retries, up to `settings.poc_max_retries` (3).
- Confirmation is `check_oracle(oracle, forge_passed, forge_output)` — a test
  that merely passes without emitting the proof sentinel is NOT confirmed. On
  confirmation, status -> `EXPLOIT_CONFIRMED` and a `Vulnerability`
  (finding + hypothesis + PoC) is appended.
- The model writes the exploit at runtime, in the sandbox. This module is prompt
  + harness + retry + oracle gate only; it contains no exploit code.

## Run it for real (on Damn Vulnerable DeFi, as planned)

DVD is Foundry with submodule deps, so the compile-enabler is what makes it work:

```bash
redforge audit https://github.com/theredguild/damn-vulnerable-defi
# clone -> git submodule update (host) -> scout -> strategist
# (PoC runs once the graph edge is wired — see below)
```

Note: `audit_case` (SmartBugs single files) has no forge-std harness, so PoC
won't confirm there — expected. PoC targets Foundry projects like DVD.

## Phase 3 remainder (next pass — step 5, graph wiring)

The node is graph-ready but not yet in the graph. To wire it:

1. In `graph.py`, add the node:
   ```python
   builder.add_node("poc", lambda s: run_poc(s, llm, sandbox))
   ```
2. Flip the strategist route to continue into it:
   ```python
   def _route_after_strategist(state):
       if state.status == AuditStatus.FAILED or not state.hypotheses:
           return "end"
       return "poc"
   # ...
   builder.add_conditional_edges("strategist", _route_after_strategist,
                                 {"poc": "poc", "end": END})
   ```
3. Add the PoC loop edge: after `poc`, route back to `poc` while there's another
   unconfirmed hypothesis and no confirmation yet, else to `END` (or to
   `remediation` in Phase 4). Keep a per-run attempt budget so it terminates.

I can do that wiring + the loop termination guard next, then move to Phase 4
(Remediation).
