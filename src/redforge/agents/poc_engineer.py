"""PoC Engineer — the confirmation core.

Takes the top unconfirmed hypothesis, asks the strong model for a Foundry
`Exploit.t.sol`, runs it in the sandbox, and self-corrects on failure up to
`poc_max_retries`. Success is decided by `oracles.check_oracle()` — the harness,
never the model. On confirmation the status becomes `EXPLOIT_CONFIRMED`.

The model writes the exploit at runtime, inside the sandbox, against the target.
This module builds the prompt, harness, retry loop and oracle gate around it; it
contains no exploit code of its own.

Signature `run_poc(state, llm, sandbox)` — both dependencies injected so the
whole loop is testable with stubs (no Docker, no API key).
"""

from __future__ import annotations

import re
from pathlib import Path

from redforge.config import settings
from redforge.foundry import run_poc_test
from redforge.llm import LLMClient
from redforge.logging_conf import get_logger
from redforge.oracles import check_oracle, oracle_cheatsheet
from redforge.sandbox import SandboxRunner
from redforge.schemas import (
    AttackHypothesis,
    AuditState,
    AuditStatus,
    Finding,
    PoCResult,
    Severity,
    Vulnerability,
)

log = get_logger("poc")

_SYSTEM = """You are an elite smart-contract exploit engineer. You write a single Foundry test
(Solidity) that PROVES a specific vulnerability against the target contract.

Rules:
- Output ONLY the Solidity source for the test file. No prose, no markdown fences.
- Use forge-std: `import {Test} from "forge-std/Test.sol";` and inherit Test.
- Deploy the target contract and set up any accounts/funding with vm cheatcodes
  (vm.prank, vm.deal, makeAddr, etc.).
- Exercise exactly the hypothesised weakness in `function testExploit() public`.
- PROVE the success oracle with a real assertion (assertGt / assertTrue / vm.expectRevert …).
  The assertion must fail (reverting the test) if the exploit did NOT work.
- ONLY after the proving assertion holds, emit the sentinel with
  `emit log_string("<SENTINEL>");` — never before, never unconditionally.
- Import the target using the path given below.
"""


def _extract_solidity(text: str) -> str:
    # Handle any fenced block (```solidity, ```sol, ```): capture the body only,
    # never the language tag. A bare reply with no fences is returned as-is.
    m = re.search(r"```[a-zA-Z]*\n(.*?)```", text, re.DOTALL)
    return (m.group(1) if m else text).strip()


def _finding_for(hyp: AttackHypothesis, state: AuditState) -> Finding:
    if hyp.finding_id:
        for f in state.findings:
            if f.id == hyp.finding_id:
                return f
    # agent-originated hypothesis with no static backing: synthesise a finding
    return Finding(
        id=f"agent-{hyp.id}",
        detector=hyp.vuln_class.value,
        vuln_class=hyp.vuln_class,
        severity=Severity.MEDIUM,
        confidence=0.5,
        contract=hyp.target_contract,
        function=hyp.target_function,
        source="agent",
    )


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


def _build_prompt(hyp: AttackHypothesis, import_path: str, source: str) -> str:
    sheet = oracle_cheatsheet(hyp.oracle)
    return (
        f"TARGET CONTRACT: {hyp.target_contract}\n"
        f"TARGET FUNCTION: {hyp.target_function}\n"
        f"VULNERABILITY CLASS: {hyp.vuln_class.value}\n"
        f"HYPOTHESIS: {hyp.rationale}\n\n"
        f"IMPORT THE TARGET FROM: {import_path}\n\n"
        f"SUCCESS ORACLE — you must satisfy this exactly:\n{sheet}\n\n"
        f"TARGET SOURCE (may be truncated):\n{source}\n\n"
        "Write the Foundry test now."
    )


def run_poc(state: AuditState, llm: LLMClient, sandbox: SandboxRunner | None = None) -> dict:
    sandbox = sandbox or SandboxRunner()
    hyp = _next_hypothesis(state)
    if hyp is None or state.repo_map is None:
        return {}  # nothing to do

    finding = _finding_for(hyp, state)
    import_path, source = _target_source(hyp, state)
    base_prompt = _build_prompt(hyp, import_path, source)
    # Make the required sentinel concrete inside the system prompt.
    system = _SYSTEM.replace("<SENTINEL>", f"REDFORGE_ORACLE_CONFIRMED:{hyp.oracle.value}")

    workspace = settings.work_root / state.run_id / "poc_ws"
    repo_ro = Path(state.repo_map.root)

    cost = 0.0
    error_log = ""
    poc: PoCResult | None = None

    for attempt in range(1, settings.poc_max_retries + 1):
        prompt = base_prompt
        if error_log:
            prompt += (
                "\n\nYOUR PREVIOUS TEST FAILED. Fix it and return the corrected test only.\n"
                f"forge output (tail):\n{error_log[-2500:]}"
            )
        res = llm.complete(system=system, prompt=prompt, model=settings.model_strong)
        cost += res.cost_usd
        test_source = _extract_solidity(res.text)

        fr = run_poc_test(repo_ro, workspace, test_source, sandbox)
        confirmed = check_oracle(hyp.oracle, fr.passed, fr.output)

        poc = PoCResult(
            hypothesis_id=hyp.id,
            attempt=attempt,
            compiled=fr.compiled,
            ran=True,
            oracle=hyp.oracle,
            oracle_confirmed=confirmed,
            exit_code=fr.exit_code,
            trace_excerpt=fr.output[-1500:],
            error_log="" if confirmed else fr.output[-2000:],
            test_path=str(workspace / "Exploit.t.sol"),
            test_source=test_source,
        )
        log.info(
            "poc %s attempt %d: compiled=%s confirmed=%s",
            hyp.id, attempt, fr.compiled, confirmed,
        )
        if confirmed:
            break
        error_log = fr.output

    vuln = Vulnerability(finding=finding, hypothesis=hyp, poc=poc)
    update: dict = {
        "vulnerabilities": [*state.vulnerabilities, vuln],
        "token_cost_usd": state.token_cost_usd + cost,
    }
    if poc and poc.oracle_confirmed:
        update["status"] = AuditStatus.EXPLOIT_CONFIRMED
    return update
