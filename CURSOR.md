# CURSOR.md — build & operations guide for RedForge

You (Cursor) are the **implementation, testing, execution and refactoring**
engineer on this project. The architecture, schemas, safety model and phase
plan below are fixed decisions — follow them. When something is ambiguous,
prefer the option that keeps the pipeline **typed, sandboxed, and measurable**.

Read this whole file before writing code. It is the single source of truth.

---

## 0. What we are building

An autonomous multi-agent auditor for Solidity repos. Input: a GitHub URL.
Output: a verified audit report + a PR containing a proven fix.

Pipeline (top to bottom):

```
repo URL
  → Orchestrator (LangGraph, checkpointed)
  → Scout + static pre-pass (Slither/Aderyn, AST map)
  → Attack Strategist (rank findings, form hypotheses)
  → PoC Engineer (write & run Exploit.t.sol in sandbox; self-correct ≤3×)
       └─ gate: oracle confirms exploit (harness-checked, not LLM-claimed)
  → Remediation Architect (minimal-diff patch)
  → Verification Auditor (exploit now fails + diff test + Halmos proof)
       └─ gate: proof holds, no regressions
  → Human review → Audit report + PR (SARIF, gas diff, proof)
```

### Non-negotiable principles
1. **Typed hand-offs.** Every agent input/output is a Pydantic model in
   `schemas.py`. No free-form dicts crossing agent boundaries.
2. **Harness-checked success.** The LLM never decides an exploit worked. Only
   `oracles.check_oracle()` does. Never weaken this.
3. **Everything untrusted runs in the sandbox.** Cloned repos and generated
   exploits are hostile until proven otherwise. Host code only clones and
   orchestrates; it never `exec`s repo code or runs `forge`/`slither` directly.
4. **Measured every phase.** After each phase, re-run `redforge eval` and update the
   results table. If a change doesn't move a metric, question it.

---

## 1. Environment & how to run things

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env            # add REDFORGE_ANTHROPIC_API_KEY

# Build the sandbox image once (needs Docker running):
docker build -t redforge-sandbox:latest -f docker/sandbox.Dockerfile .

redforge sandbox-check              # MUST print "sandbox OK" before anything else
redforge scan https://github.com/OWNER/REPO
```

### Commands you will run constantly
```bash
pytest -q                       # run tests (fast; sandbox tests are marked)
pytest -q -k "not sandbox"      # skip Docker-dependent tests
ruff check src tests            # lint
ruff format src tests           # format
mypy src                        # type-check
```

### Definition of done for any change
- `ruff check` and `mypy src` are clean.
- `pytest -q` is green. New behaviour has a test.
- If it touches an agent boundary, the Pydantic model is updated and validated.
- If it touches the pipeline, `redforge eval smartbugs-curated --limit 10` still runs.

---

## 2. Repository map (what exists now)

| Path | Role | State |
|---|---|---|
| `config.py` | env-driven settings; the only place that reads env | done |
| `schemas.py` | typed contracts + `AuditState` shared graph state | done |
| `sandbox/runner.py` | hardened Docker runner (no net, caps dropped, non-root) | done |
| `repo/cloner.py` | validated shallow git clone | done |
| `repo/project_detector.py` | Foundry/Hardhat/Truffle + solc + files | done |
| `static_analysis/slither_runner.py` | Slither → `Finding[]` | done |
| `foundry/forge.py` | sandboxed `forge test` wrapper | done |
| `oracles/oracles.py` | success oracles (anti-cheat) | done |
| `eval/datasets.py` | benchmark registry + loader with labels | done |
| `eval/harness.py` | metrics harness + markdown table | done |
| `cli.py` | `redforge` entrypoint | scan done; audit/eval stubbed |
| `agents/` | the five agents | **you build (Phase 2+)** |
| `graph.py` | LangGraph wiring | **you build (Phase 2)** |
| `memory/` | RAG store + templates | **you build (Phase 6)** |
| `api/` + `ui/` | FastAPI + dashboard | **you build (Phase 7)** |

---

## 3. Coding conventions

- Python ≥3.11, full type hints, `from __future__ import annotations` at top.
- Pydantic v2 only. Validate at boundaries; pass models, not dicts.
- No `os.environ` outside `config.py`. Import `settings`.
- No `print`; use `logging_conf.get_logger(name)`.
- Never run untrusted code on the host. If you need to compile/run repo code or
  an exploit, it goes through `SandboxRunner`.
- Small modules, one responsibility each. No `utils.py` junk drawer.
- Every agent is a pure function `state -> state` (or `state -> partial update`)
  so the graph stays testable. Side effects (sandbox calls) are injected.
- LLM calls: cheap model (`settings.model_cheap`) for scouting/summarising,
  strong model (`settings.model_strong`) for strategy/patching. Always record
  token cost into `state.token_cost_usd`.

---

## 4. Phase plan — build in this order

Each phase lists **tasks**, the **files** to create, and **acceptance criteria**
(AC). Do not start a phase until the previous one's AC are green. After each
phase, re-run the eval and paste the table into `reports/` and the README.

### Phase 1 — Foundation & eval harness  ✅ (scaffolded)
Remaining tasks for you:
- `scripts/fetch_benchmarks.sh` — clone the three datasets in `datasets.py` into
  `benchmarks/<name>/`. Idempotent; shallow clones.
- Add `tests/test_sandbox.py` marked `@pytest.mark.sandbox` that builds nothing
  but asserts `SandboxRunner().self_check()` is True when Docker is present, and
  asserts a `--network none` container cannot reach the network (run
  `curl -m 3 https://example.com` inside and expect failure).
- Wire `redforge scan` output into a `Finding[]` JSON dropped in `reports/<run>/`.
- **AC:** `redforge sandbox-check` passes; `redforge scan <foundry-repo>` prints findings;
  `pytest -q -k "not sandbox"` green.

### Phase 2 — Scout + Strategist in LangGraph
- `graph.py`: build a `StateGraph(AuditState)` with a SQLite checkpointer
  (`langgraph.checkpoint.sqlite`). Nodes: `scout`, `strategist`. Conditional
  edge after strategist: if no hypotheses → `END` with status `FAILED`.
- `agents/scout.py`: enrich `RepoMap` with an AST/dependency summary (use
  `slither`'s printer or `solc --ast-compact-json` inside the sandbox), then
  attach the static `Finding[]`. Sets status `MAPPED`.
- `agents/strategist.py`: LLM (strong model) consumes `Finding[]` + code
  excerpts, returns `AttackHypothesis[]` (validated). Ranks by severity ×
  confidence. Sets status `HYPOTHESES_READY`.
- Wire `redforge audit` to run the graph to this point and print hypotheses.
- Give `run_eval` an `audit_fn` that runs the graph so the harness works.
- **AC:** `redforge audit <repo>` prints ranked hypotheses; graph state validates;
  `redforge eval smartbugs-curated --limit 20` produces a detection-rate table.

### Phase 3 — PoC Engineer with oracles (the core)
- `agents/poc_engineer.py`:
  - Prompt (strong model) includes: the hypothesis, relevant contract source,
    and `oracle_cheatsheet(hypothesis.oracle)`.
  - The model returns a single `Exploit.t.sol`. Write it into the run workspace
    (never the read-only repo mount).
  - Run it via `foundry.run_forge_test(match_path=...)` inside the sandbox.
  - Call `oracles.check_oracle(oracle, forge_passed, output)` → set
    `PoCResult.oracle_confirmed`.
  - **Self-correction loop:** on compile/run failure, feed `error_log` back to
    the model, up to `settings.poc_max_retries`. Increment `PoCResult.attempt`.
  - On confirmation, set status `EXPLOIT_CONFIRMED` and store the `PoCResult`.
- Graph: add `poc` node with a self-loop guarded by retry count, and a
  conditional edge — confirmed → `remediation`; exhausted → mark that
  hypothesis dead and try the next.
- **AC:** on a known reentrancy case from SmartBugs, the agent produces a test
  that the harness confirms via the `balance_increase`/`invariant_broken`
  oracle. Unit-test the retry loop with a stubbed LLM (no network).

> Safety note for Cursor: the PoC agent generates exploit code **at runtime**
> against benchmark/sandboxed targets. Do not commit generated exploits, and do
> not hand-author exploit contracts in the repo. Build the loop, prompts, and
> oracle plumbing — the agent writes the exploit.

### Phase 4 — Remediation Architect
- `agents/remediation.py`: strong model produces a **minimal unified diff** for
  the vulnerable contract only. Constraints in the prompt: preserve public
  interface and business logic; smallest change that closes the bug.
- Apply the diff to a copy in the workspace; compile in the sandbox. Set
  `Patch.compiles`. Re-run the PoC — it must now **fail** (exploit closed).
- Graph: `remediation` node; edge to `verification` only if patch compiles and
  PoC now fails, else back to remediation (bounded retries) or `NEEDS_HUMAN`.
- **AC:** for a confirmed case, produce a compiling patch that flips the PoC from
  pass→fail, with a diff under ~30 changed lines on the curated set median.

### Phase 5 — Verification Auditor
- `agents/verifier.py`:
  - **Regression:** run the repo's existing tests (if any) — must pass.
  - **Differential:** generate an invariant/fuzz test comparing original vs
    patched contract on non-exploit inputs; behaviour must match
    (`differential_equivalent`).
  - **Symbolic proof:** write a Halmos property test asserting the vulnerability
    class cannot recur (e.g. `check_` prefixed test) and run `halmos` in the
    sandbox. Parse pass / counterexample into `VerificationReport`.
  - `verified = poc_now_fails and existing_tests_pass and
    differential_equivalent and halmos_proved`.
- Graph: `verification` node; `verified` → `human_review`; else `NEEDS_HUMAN`.
- **AC:** at least the reentrancy and access-control cases reach
  `verified=True` with a real Halmos pass; counterexamples are captured when a
  patch is insufficient.

### Phase 6 — Memory
- `memory/vector_store.py`: Chroma collection of historical audit findings.
  Seed from public reports (Code4rena / Sherlock / Solodit exports you place in
  `data/findings/`). The Strategist retrieves top-k similar findings to sharpen
  hypotheses. (Do **not** use the abandoned SWC Registry as the primary source.)
- `memory/templates.py`: a growing library of PoC test skeletons that compiled,
  keyed by `VulnClass`+`OracleType`, offered to the PoC agent as few-shot.
- **AC:** ablation in the eval: detection/exploit rate with vs without memory,
  reported in the table.

### Phase 7 — Product layer
- `api/main.py`: FastAPI. `POST /audit` starts a run; `GET /audit/{id}/stream`
  streams graph events over SSE. Reuse the graph + checkpointer.
- `ui/`: a dashboard showing the live agent graph, findings, PoC traces and the
  final report. (You are full-stack — a Next.js dashboard impresses more than
  Streamlit, but Streamlit in `ui/app.py` is an acceptable fast path.)
- `integrations/github_app.py`: open a PR with patch + gas diff + SARIF.
- `reporting/sarif.py`: emit SARIF 2.1.0 so findings show in GitHub code
  scanning. `reporting/report.py`: render the audit dossier (severity,
  likelihood, impact, root cause, recommendation, proof).
- **AC:** end-to-end from URL in the UI to a draft PR on a test repo.

### Phase 8 — Showcase
- Publish the benchmark table, a 3-min demo video, the architecture diagram, and
  a write-up of what worked / what failed. Add badges and the results table to
  the README.
- **AC:** a stranger can read the README and understand what it does, how well,
  and why the design is sound.

---

## 5. The success-oracle contract (read before Phase 3)

`oracles/oracles.py` is the anti-cheat heart. The generated PoC test must prove
the oracle condition with a real Solidity assertion and only then print the
sentinel, e.g. for `balance_increase`:

```solidity
uint256 before = attacker.balance;
// ... interaction ...
assertGt(attacker.balance, before);          // real proof; reverts if false
emit log_string("REDFORGE_ORACLE_CONFIRMED:balance_increase");
```

`check_oracle()` confirms **only if** forge passed **and** the matching sentinel
is in the output. A failing assertion aborts before the sentinel prints, so the
model cannot fake success. Never move this decision into the LLM, and never add
a code path that emits a sentinel without a passing assertion in front of it.

---

## 6. Safety model (keep this intact)

- **Sandbox flags** (`sandbox/runner.py`): `--network none`, `--memory`,
  `--cpus`, `--pids-limit`, `--cap-drop=ALL`, `--security-opt=no-new-privileges`,
  `--user=1000:1000`, `--read-only` rootfs + `/tmp` tmpfs, repo mounted `:ro`,
  writable `/work` only. Do not relax any of these to "make it work" — fix the
  command instead.
- **No network for exploit code, ever.** If a fork test needs archive data, use
  a pre-fetched local fork cache mounted read-only; do not open the network.
- **Clone on host, run in sandbox.** Never execute cloned code on the host.
- **No secrets in the sandbox.** The Anthropic key stays on the host; LLM calls
  are made by host code, results passed in.
- **Human gate before any PR.** The graph must interrupt (LangGraph
  `interrupt_before=["pr"]`) so a person approves.

---

## 7. When you get stuck — decision defaults

- Test flakiness from the sandbox → mark `@pytest.mark.sandbox` and keep the
  core loop testable with a stubbed sandbox/LLM.
- LLM returns malformed JSON → validate with Pydantic, and on failure re-prompt
  once with the validation error; then fail the node cleanly (record in
  `state.errors`), never crash the graph.
- A phase's metric doesn't improve → prefer a smaller, correct step over a
  bigger speculative one. Keep the eval honest; don't tune to the test set.
- Unsure whether code is "untrusted" → treat it as untrusted. Sandbox it.

---

## 8. First tasks, in order

1. `scripts/fetch_benchmarks.sh` + `tests/test_sandbox.py` (Phase 1 remainder).
2. `graph.py` skeleton with `scout` + `strategist` nodes and SQLite checkpointer.
3. `agents/scout.py`, then `agents/strategist.py`.
4. Wire `run_eval`'s `audit_fn` to the graph; produce the first results table.

Run `pytest -q`, `ruff check`, `mypy src` after each. Keep every hand-off typed,
every untrusted run sandboxed, every phase measured.
