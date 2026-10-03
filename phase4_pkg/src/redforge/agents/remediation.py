"""Remediation Architect — patches a confirmed vulnerability.

Takes a confirmed `Vulnerability`, asks the strong model for a MINIMAL change to
the vulnerable contract, and gates on two things in the sandbox:
  1. the patched contract compiles, and
  2. the SAME exploit that confirmed the bug now FAILS.

Gate (2) is the mirror of confirmation: it reuses `run_poc_against_patch` +
`check_oracle`, where a *non*-confirming oracle means the hole is closed. Self-
corrects up to `remediation_max_retries`. On exhaustion it records the best
attempt honestly and leaves the vulnerability confirmed-but-unpatched — a proven
bug is a valid audit result, so the run does not fail.

`run_remediation(state, llm, sandbox)` — dependencies injected for stub testing.
The model writes the patch at runtime; this module is prompt + harness + gate.
"""

from __future__ import annotations

import difflib
import re
from pathlib import Path

from redforge.agents.poc_engineer import target_file
from redforge.config import settings
from redforge.foundry import run_poc_against_patch
from redforge.llm import LLMClient
from redforge.logging_conf import get_logger
from redforge.oracles import check_oracle
from redforge.sandbox import SandboxRunner
from redforge.schemas import AuditState, AuditStatus, Patch, Vulnerability

log = get_logger("remediation")

_SYSTEM = """You are a senior smart-contract engineer writing a security patch.
You are given a vulnerable contract and the exact exploit that defeats it.

Produce a corrected version of the WHOLE contract file that:
- closes the vulnerability so the exploit can no longer succeed;
- changes as little as possible — preserve the public interface, function
  signatures, events, and all legitimate business logic;
- compiles under the same Solidity version.

Output ONLY the full Solidity source of the patched contract file. No prose, no
markdown fences.
"""


def _extract_solidity(text: str) -> str:
    m = re.search(r"```[a-zA-Z]*\n(.*?)```", text, re.DOTALL)
    return (m.group(1) if m else text).strip()


def _unified_diff(original: str, patched: str, rel: str) -> str:
    return "".join(
        difflib.unified_diff(
            original.splitlines(keepends=True),
            patched.splitlines(keepends=True),
            fromfile=f"a/{rel}",
            tofile=f"b/{rel}",
        )
    )


def _target_vuln(state: AuditState) -> Vulnerability | None:
    for v in state.vulnerabilities:
        if v.poc and v.poc.oracle_confirmed and v.patch is None:
            return v
    return None


def _build_prompt(contract_rel: str, original: str, test_source: str) -> str:
    return (
        f"VULNERABLE CONTRACT ({contract_rel}):\n{original}\n\n"
        f"EXPLOIT THAT CONFIRMS THE BUG (must fail after your patch):\n{test_source}\n\n"
        "Return the full patched contract source now."
    )


def run_remediation(state: AuditState, llm: LLMClient, sandbox: SandboxRunner | None = None) -> dict:
    sandbox = sandbox or SandboxRunner()
    vuln = _target_vuln(state)
    if vuln is None or state.repo_map is None or vuln.hypothesis is None or vuln.poc is None:
        return {}

    hyp = vuln.hypothesis
    oracle = vuln.poc.oracle
    test_source = vuln.poc.test_source
    contract_rel = target_file(state, hyp) or vuln.finding.file
    if not contract_rel or not test_source:
        return {}  # can't locate the file to patch, or no exploit to re-run

    root = Path(state.repo_map.root)
    try:
        original = (root / contract_rel).read_text(errors="ignore")
    except OSError:
        return {}

    base_prompt = _build_prompt(contract_rel, original, test_source)
    workspace = settings.work_root / state.run_id / "remediation_ws"

    cost = 0.0
    error_log = ""
    patch: Patch | None = None

    for attempt in range(1, settings.remediation_max_retries + 1):
        prompt = base_prompt
        if error_log:
            prompt += (
                "\n\nYOUR PREVIOUS PATCH FAILED. Fix it and return the full patched "
                f"contract only.\n{error_log[-2500:]}"
            )
        res = llm.complete(system=_SYSTEM, prompt=prompt, model=settings.model_strong)
        cost += res.cost_usd
        patched_source = _extract_solidity(res.text)

        fr = run_poc_against_patch(root, workspace, contract_rel, patched_source, test_source, sandbox)
        # Defeated = the confirming exploit no longer confirms.
        defeated = not check_oracle(oracle, fr.passed, fr.output)

        patch = Patch(
            finding_id=vuln.finding.id,
            contract=hyp.target_contract,
            diff=_unified_diff(original, patched_source, contract_rel),
            explanation=f"Minimal patch closing {hyp.vuln_class.value} in "
                        f"{hyp.target_contract}.{hyp.target_function}.",
            compiles=fr.compiled,
            poc_defeated=defeated,
            attempts=attempt,
        )
        log.info(
            "remediation attempt %d: compiled=%s poc_defeated=%s",
            attempt, fr.compiled, defeated,
        )
        if fr.compiled and defeated:
            break
        error_log = (
            "Patch did not compile:\n" + fr.output
            if not fr.compiled
            else "Patch compiled but the exploit STILL succeeds — close the hole.\n" + fr.output
        )

    new_vulns = [
        v.model_copy(update={"patch": patch}) if v is vuln else v
        for v in state.vulnerabilities
    ]
    update: dict = {
        "vulnerabilities": new_vulns,
        "token_cost_usd": state.token_cost_usd + cost,
    }
    if patch and patch.compiles and patch.poc_defeated:
        update["status"] = AuditStatus.PATCHED  # else leave EXPLOIT_CONFIRMED
    return update
