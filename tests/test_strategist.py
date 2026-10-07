from redforge.agents import run_strategist
from redforge.llm import StubLLM
from redforge.schemas import (
    AuditState,
    AuditStatus,
    Finding,
    OracleType,
    Severity,
    VulnClass,
)

GOOD = """[
  {"finding_id": "slither-0", "target_contract": "Vault", "target_function": "withdraw",
   "vuln_class": "reentrancy", "oracle": "balance_increase", "rationale": "external call before state update"},
  {"finding_id": null, "target_contract": "Vault", "target_function": "setOwner",
   "vuln_class": "access_control", "oracle": "unauthorized_state", "rationale": "missing onlyOwner"}
]"""


def _state_with_finding() -> AuditState:
    return AuditState(
        repo_url="x", run_id="t", status=AuditStatus.MAPPED,
        findings=[Finding(
            id="slither-0", detector="reentrancy-eth", vuln_class=VulnClass.REENTRANCY,
            severity=Severity.HIGH, confidence=0.9,
        )],
    )


def test_parses_and_ranks():
    state = _state_with_finding()
    update = run_strategist(state, StubLLM(GOOD))
    assert update["status"] is AuditStatus.HYPOTHESES_READY
    hyps = update["hypotheses"]
    assert len(hyps) == 2
    # the finding-backed high-severity hypothesis outranks the unbacked one
    assert hyps[0].target_function == "withdraw"
    assert hyps[0].priority > hyps[1].priority
    assert hyps[0].oracle is OracleType.BALANCE_INCREASE
    assert update["token_cost_usd"] > 0


def test_empty_array_is_failed():
    update = run_strategist(_state_with_finding(), StubLLM("[]"))
    assert update["status"] is AuditStatus.FAILED
    assert update["hypotheses"] == []


def test_malformed_then_valid_reprompt():
    # first reply is junk, second (re-prompt) is valid
    llm = StubLLM(["not json at all", GOOD])
    update = run_strategist(_state_with_finding(), llm)
    assert update["status"] is AuditStatus.HYPOTHESES_READY
    assert len(llm.calls) == 2  # it re-prompted exactly once


def test_malformed_twice_fails_cleanly():
    llm = StubLLM(["nope", "still nope"])
    update = run_strategist(_state_with_finding(), llm)
    assert update["status"] is AuditStatus.FAILED
    assert any("unparseable" in e for e in update["errors"])


def test_self_assessment_ranks_unbacked_hypotheses():
    # The real-repo case: Slither produced nothing, so ranking must come from the
    # strategist's own severity/confidence, not collapse to a flat default.
    state = AuditState(repo_url="x", run_id="t", status=AuditStatus.MAPPED, findings=[])
    raw = """[
      {"finding_id": null, "target_contract": "GaugeController",
       "target_function": "vote_for_gauge_weights", "vuln_class": "access_control",
       "oracle": "unauthorized_state", "severity": "high", "confidence": 0.8,
       "rationale": "infinite voting by delegation"},
      {"finding_id": null, "target_contract": "LendingLedger", "target_function": "sync",
       "vuln_class": "other", "oracle": "balance_increase", "severity": "low",
       "confidence": 0.3, "rationale": "weak guess"}
    ]"""
    update = run_strategist(state, StubLLM(raw))
    hyps = update["hypotheses"]
    assert hyps[0].target_function == "vote_for_gauge_weights"  # high/0.8 wins
    assert hyps[0].priority == int(4 * 0.8 * 100)               # 320, clears floor 150
    assert hyps[1].priority == int(2 * 0.3 * 100)               # 60, below floor
    assert hyps[0].priority > hyps[1].priority
    assert hyps[0].confidence == 0.8


def test_static_finding_still_overrides_self_assessment():
    # When a finding backs the hypothesis, the grounded static severity wins even
    # if the model self-reports something different (DVD behaviour unchanged).
    state = _state_with_finding()  # slither-0 is HIGH / 0.9
    raw = """[
      {"finding_id": "slither-0", "target_contract": "Vault", "target_function": "withdraw",
       "vuln_class": "reentrancy", "oracle": "balance_increase", "severity": "low",
       "confidence": 0.1, "rationale": "x"}
    ]"""
    update = run_strategist(state, StubLLM(raw))
    h = update["hypotheses"][0]
    assert h.priority == int(4 * 0.9 * 100)  # 360 from the finding, not 2*0.1*100


def test_select_findings_drops_info_and_caps(monkeypatch):
    from redforge.agents.strategist import _select_findings
    from redforge.config import settings

    def mk(i, sev, conf):
        return Finding(id=f"f{i}", detector="d", vuln_class=VulnClass.OTHER,
                       severity=sev, confidence=conf)

    state = AuditState(repo_url="x", run_id="t", findings=[
        mk(0, Severity.INFO, 0.9),      # dropped by the floor
        mk(1, Severity.LOW, 0.3),
        mk(2, Severity.HIGH, 0.9),
        mk(3, Severity.CRITICAL, 0.5),
    ])
    monkeypatch.setattr(settings, "strategist_max_findings", 2)
    kept = _select_findings(state)
    ids = [f.id for f in kept]
    assert "f0" not in ids                 # INFO cut
    assert ids == ["f3", "f2"]             # top-2 by severity, highest first
    # state.findings is untouched (full record preserved)
    assert len(state.findings) == 4
