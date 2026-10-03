"""Verification Auditor — the formal-verification layer.

Runs only on a successfully patched vulnerability and produces a
`VerificationReport`. Three checks:

1. Regression — the repo's existing suite (minus our exploit) still passes.
2. Differential — a generated test exercising legitimate behaviour on the
   patched contract passes, i.e. the fix didn't break normal operation.
3. Halmos — a generated `check_` property, proved symbolically, that the
   vulnerability class cannot recur for ANY input (not just our one exploit).

`verified = poc_now_fails AND differential_equivalent AND halmos_proved`.

Design note on regression: it is RECORDED but not part of the `verified` gate.
A repo's own suite can legitimately encode the vulnerability (CTF targets like
DVD assert the exploit) or be absent entirely, so it's an unreliable hard gate.
The differential check is the stronger, more general "behaviour preserved"
guarantee, and it IS gated. A failing regression is surfaced for the human.

Halmos degrades gracefully: a timeout is "not proven" (`halmos_timed_out`), not
a refutation. Only a counterexample means the patch is actually unsound.

`run_verification(state, llm, sandbox)` — dependencies injected for stub testing.
"""

from __future__ import annotations

import re
from pathlib import Path

from redforge.agents.poc_engineer import target_file
from redforge.config import settings
from redforge.foundry import (
    run_forge_suite_against_patch,
    run_halmos_against_patch,
    run_poc_against_patch,
)
from redforge.llm import LLMClient
from redforge.logging_conf import get_logger
from redforge.sandbox import SandboxRunner
from redforge.schemas import AuditState, AuditStatus, VerificationReport, Vulnerability

log = get_logger("verifier")

_DIFF_SYSTEM = """You are a smart-contract test engineer. Write a Foundry test that exercises the
LEGITIMATE behaviour of the patched contract (normal deposits, withdrawals,
transfers — NOT the exploit) and asserts it still works as expected.

Output ONLY the Solidity test source. No prose, no fences. Import forge-std Test.
"""

_HALMOS_SYSTEM = """You are a formal-verification engineer. Write a Halmos symbolic test that PROVES
the patched contract can no longer exhibit the vulnerability, for ANY symbolic
input. The function name MUST start with `check_`. Use symbolic values
(svm.createUint, symbolic addresses) and assert the safety property that the
exploit violated.

Output ONLY the Solidity test source. No prose, no fences. Import forge-std Test.
"""


def _extract_solidity(text: str) -> str:
    m = re.search(r"```[a-zA-Z]*\n(.*?)```", text, re.DOTALL)
    return (m.group(1) if m else text).strip()


def _verifiable_vuln(state: AuditState) -> Vulnerability | None:
    for v in state.vulnerabilities:
        if (
            v.patch and v.patch.compiles and v.patch.poc_defeated
            and v.verification is None
        ):
            return v
    return None


def _parse_halmos(output: str, exit_code: int | None, timed_out: bool) -> tuple[bool, str, bool]:
    """Return (proved, counterexample, timed_out)."""
    low = output.lower()
    is_timeout = timed_out or exit_code == 124 or "timeout" in low or "timed out" in low
    if is_timeout:
        return False, "", True
    if "counterexample" in low:
        m = re.search(r"(?i)counterexample.*", output)
        return False, (m.group(0)[:500] if m else "counterexample found"), False
    proved = "[pass]" in low or "0 failed" in low or "no counterexample" in low
    return proved, "", False


def _gen(llm: LLMClient, system: str, prompt: str) -> tuple[str, float]:
    res = llm.complete(system=system, prompt=prompt, model=settings.model_strong)
    return _extract_solidity(res.text), res.cost_usd


def run_verification(state: AuditState, llm: LLMClient, sandbox: SandboxRunner | None = None) -> dict:
    sandbox = sandbox or SandboxRunner()
    vuln = _verifiable_vuln(state)
    if vuln is None or state.repo_map is None or vuln.hypothesis is None or vuln.patch is None:
        return {}

    hyp = vuln.hypothesis
    contract_rel = target_file(state, hyp) or vuln.finding.file
    patched_source = vuln.patch.patched_source
    if not contract_rel or not patched_source:
        return {}

    root = Path(state.repo_map.root)
    workspace = settings.work_root / state.run_id / "verify_ws"
    try:
        original = (root / contract_rel).read_text(errors="ignore")[:8000]
    except OSError:
        original = ""
    ctx = (
        f"CONTRACT: {hyp.target_contract} ({contract_rel})\n"
        f"VULNERABILITY CLASS: {hyp.vuln_class.value}\n"
        f"PATCHED SOURCE:\n{patched_source[:8000]}\n\n"
        f"ORIGINAL (for reference):\n{original}\n"
    )
    cost = 0.0

    # 1. Regression (recorded, not gated — see module docstring).
    reg = run_forge_suite_against_patch(root, workspace, contract_rel, patched_source, sandbox)
    existing_tests_pass = reg.passed

    # 2. Differential — legitimate behaviour preserved.
    diff_test, c1 = _gen(llm, _DIFF_SYSTEM, ctx + "\nWrite the legitimate-behaviour test now.")
    cost += c1
    dres = run_poc_against_patch(
        root, workspace, contract_rel, patched_source, diff_test, sandbox, test_filename="Diff.t.sol"
    )
    differential_equivalent = dres.compiled and dres.passed

    # 3. Halmos — symbolic proof the class cannot recur.
    halmos_test, c2 = _gen(llm, _HALMOS_SYSTEM, ctx + "\nWrite the Halmos check_ property now.")
    cost += c2
    hres = run_halmos_against_patch(
        root, workspace, contract_rel, patched_source, halmos_test, sandbox,
        timeout_s=settings.halmos_timeout_s,
    )
    halmos_proved, halmos_cex, halmos_timeout = _parse_halmos(hres.output, hres.exit_code, hres.timed_out)

    verified = bool(vuln.patch.poc_defeated and differential_equivalent and halmos_proved)
    report = VerificationReport(
        finding_id=vuln.finding.id,
        poc_now_fails=vuln.patch.poc_defeated,
        existing_tests_pass=existing_tests_pass,
        differential_equivalent=differential_equivalent,
        halmos_proved=halmos_proved,
        halmos_counterexample=halmos_cex,
        halmos_timed_out=halmos_timeout,
        verified=verified,
    )
    log.info(
        "verification: regression=%s differential=%s halmos_proved=%s timeout=%s -> verified=%s",
        existing_tests_pass, differential_equivalent, halmos_proved, halmos_timeout, verified,
    )

    new_vulns = [
        v.model_copy(update={"verification": report}) if v is vuln else v
        for v in state.vulnerabilities
    ]
    update: dict = {
        "vulnerabilities": new_vulns,
        "token_cost_usd": state.token_cost_usd + cost,
    }
    if verified:
        update["status"] = AuditStatus.VERIFIED  # else stays PATCHED
    return update
