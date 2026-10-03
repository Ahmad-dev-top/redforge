"""Attack Strategist — turns findings + code into ranked attack hypotheses.

Uses the strong model. Output is strictly validated into `AttackHypothesis`
objects; malformed JSON gets exactly one re-prompt with the validation error,
then the node fails cleanly (records in `state.errors`) rather than crashing the
graph. No hypotheses -> status FAILED. The LLM proposes; it never confirms
anything — confirmation is the PoC/oracle stage.
"""

from __future__ import annotations

import json
import re

from redforge.config import settings
from redforge.llm import LLMClient
from redforge.logging_conf import get_logger
from redforge.schemas import (
    AttackHypothesis,
    AuditState,
    AuditStatus,
    Finding,
    OracleType,
    Severity,
    VulnClass,
)

log = get_logger("strategist")

_SEV_WEIGHT = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}

_SYSTEM = """You are a senior smart-contract security auditor acting as an attack strategist.
Given static-analysis findings and a code index, propose concrete, testable attack hypotheses.

For each hypothesis pick the success ORACLE the exploit must satisfy:
- balance_increase: attacker ends with more funds than they started
- invariant_broken: a contract invariant (e.g. sum(balances)==totalSupply) is violated
- unauthorized_state: privileged state changes from a non-privileged caller
- funds_locked: a legitimate withdrawal path becomes impossible

Return ONLY a JSON array (no prose, no markdown fences). Each element:
{
  "finding_id": string or null,       // link to a finding id if applicable
  "target_contract": string,
  "target_function": string,
  "vuln_class": one of ["reentrancy","access_control","arithmetic","oracle_manipulation",
     "unchecked_call","front_running","denial_of_service","bad_randomness","business_logic","other"],
  "oracle": one of ["balance_increase","invariant_broken","unauthorized_state","funds_locked"],
  "rationale": string                  // one or two sentences, why it is exploitable
}
Only include hypotheses you can justify from the code. Prefer high-impact, high-confidence targets."""


def _strip_fences(text: str) -> str:
    text = text.strip()
    text = re.sub(r"^```(?:json)?", "", text).strip()
    text = re.sub(r"```$", "", text).strip()
    return text


def _confidence_for(finding_id: str | None, findings: list[Finding]) -> tuple[float, Severity]:
    for f in findings:
        if f.id == finding_id:
            return f.confidence, f.severity
    return 0.5, Severity.MEDIUM  # agent-originated, no static backing


def _select_findings(state: AuditState) -> list[Finding]:
    """Keep only findings at/above the configured severity, then the top-N by
    severity x confidence. Shrinks the prompt (the dominant cost) without losing
    the high-value findings; `state.findings` itself is left complete for the
    report. Anything dropped can still be targeted via the code index."""
    try:
        min_rank = _SEV_WEIGHT[Severity(settings.strategist_min_severity)]
    except (ValueError, KeyError):
        min_rank = _SEV_WEIGHT[Severity.LOW]
    kept = [f for f in state.findings if _SEV_WEIGHT.get(f.severity, 1) >= min_rank]
    kept.sort(key=lambda f: (_SEV_WEIGHT.get(f.severity, 1), f.confidence), reverse=True)
    return kept[: settings.strategist_max_findings]


def _build_prompt(state: AuditState) -> str:
    findings = [
        {
            "id": f.id, "detector": f.detector, "class": f.vuln_class.value,
            "severity": f.severity.value, "confidence": f.confidence,
            "contract": f.contract, "function": f.function, "desc": f.description[:300],
        }
        for f in _select_findings(state)
    ]
    functions = [
        {"contract": fn.contract, "function": fn.function, "sig": fn.signature}
        for fn in state.functions[:120]  # bound the token budget
    ]
    return (
        "FINDINGS:\n" + json.dumps(findings, indent=2)
        + "\n\nCODE INDEX (functions):\n" + json.dumps(functions, indent=2)
        + "\n\nReturn the JSON array of attack hypotheses now."
    )


def _parse(text: str) -> list[dict]:
    data = json.loads(_strip_fences(text))
    if not isinstance(data, list):
        raise ValueError("expected a JSON array")  # noqa: TRY004 (caught as ValueError upstream)
    return data


def _to_hypotheses(raw: list[dict], state: AuditState) -> list[AttackHypothesis]:
    hyps: list[AttackHypothesis] = []
    for i, item in enumerate(raw):
        conf, sev = _confidence_for(item.get("finding_id"), state.findings)
        score = int(_SEV_WEIGHT.get(sev, 3) * conf * 100)
        hyps.append(
            AttackHypothesis(
                id=f"hyp-{i}",
                finding_id=item.get("finding_id"),
                target_contract=str(item["target_contract"]),
                target_function=str(item["target_function"]),
                vuln_class=VulnClass(item["vuln_class"]),
                oracle=OracleType(item["oracle"]),
                rationale=str(item.get("rationale", ""))[:500],
                priority=score,
            )
        )
    hyps.sort(key=lambda h: h.priority, reverse=True)
    return hyps


def run_strategist(state: AuditState, llm: LLMClient) -> dict:
    prompt = _build_prompt(state)
    cost = 0.0

    res = llm.complete(system=_SYSTEM, prompt=prompt, model=settings.model_strong)
    cost += res.cost_usd
    try:
        raw = _parse(res.text)
    except (json.JSONDecodeError, ValueError) as exc:
        # one re-prompt with the error, per CURSOR.md §7
        retry = llm.complete(
            system=_SYSTEM,
            prompt=prompt + f"\n\nYour previous reply was invalid JSON: {exc}. Reply with ONLY the JSON array.",
            model=settings.model_strong,
        )
        cost += retry.cost_usd
        try:
            raw = _parse(retry.text)
        except (json.JSONDecodeError, ValueError) as exc2:
            return {
                "status": AuditStatus.FAILED,
                "errors": [*state.errors, f"strategist: unparseable LLM output: {exc2}"],
                "token_cost_usd": state.token_cost_usd + cost,
            }

    try:
        hyps = _to_hypotheses(raw, state)
    except (KeyError, ValueError) as exc:
        return {
            "status": AuditStatus.FAILED,
            "errors": [*state.errors, f"strategist: invalid hypothesis field: {exc}"],
            "token_cost_usd": state.token_cost_usd + cost,
        }

    status = AuditStatus.HYPOTHESES_READY if hyps else AuditStatus.FAILED
    log.info("strategist: %d hypotheses, status=%s", len(hyps), status.value)
    return {
        "hypotheses": hyps,
        "status": status,
        "token_cost_usd": state.token_cost_usd + cost,
    }
