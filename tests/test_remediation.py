from pathlib import Path

import pytest

from redforge.agents import run_remediation
from redforge.config import settings
from redforge.llm import StubLLM
from redforge.oracles import ORACLE_SENTINELS
from redforge.schemas import (
    AttackHypothesis,
    AuditState,
    AuditStatus,
    Finding,
    OracleType,
    PoCResult,
    ProjectKind,
    RepoMap,
    Severity,
    VulnClass,
    Vulnerability,
)
from tests.test_poc_engineer import QueueSandbox

SENTINEL = ORACLE_SENTINELS[OracleType.BALANCE_INCREASE]
# exploit STILL works (sentinel present, test passes) -> not defeated
STILL_EXPLOITABLE = f"[PASS] testExploit()\n  {SENTINEL}\n"
# exploit now fails (assertion reverts, no sentinel) -> defeated
EXPLOIT_DEFEATED = "[FAIL: assertion failed] testExploit()\n  revert: patched\n"
PATCH_WONT_COMPILE = "Compiler run failed\nError: TypeError"


@pytest.fixture(autouse=True)
def _tmp_work(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "work_root", tmp_path / "work")


def _state_with_confirmed(tmp_path: Path) -> tuple[AuditState, Vulnerability]:
    (tmp_path / "Vault.sol").write_text(
        "contract Vault { function flashLoan() public { /* bug */ } }"
    )
    finding = Finding(id="slither-0", detector="x", vuln_class=VulnClass.LOGIC,
                      severity=Severity.HIGH, confidence=0.9, file="Vault.sol")
    hyp = AttackHypothesis(id="hyp-0", finding_id="slither-0", target_contract="Vault",
                           target_function="flashLoan", vuln_class=VulnClass.LOGIC,
                           oracle=OracleType.BALANCE_INCREASE, rationale="r", priority=360)
    poc = PoCResult(hypothesis_id="hyp-0", attempt=1, oracle=OracleType.BALANCE_INCREASE,
                    oracle_confirmed=True, compiled=True,
                    test_source="contract Exploit is Test { function testExploit() public {} }")
    vuln = Vulnerability(finding=finding, hypothesis=hyp, poc=poc)
    state = AuditState(
        repo_url="x", run_id="rem1", status=AuditStatus.EXPLOIT_CONFIRMED,
        repo_map=RepoMap(root=str(tmp_path), kind=ProjectKind.FOUNDRY, contract_files=["Vault.sol"]),
        findings=[finding],
        functions=[],  # falls back to finding.file / contract_files[0]
        hypotheses=[hyp],
        vulnerabilities=[vuln],
    )
    return state, vuln


def test_patch_succeeds_first_attempt(tmp_path):
    state, _ = _state_with_confirmed(tmp_path)
    update = run_remediation(state, StubLLM("contract Vault {}"),
                             QueueSandbox([EXPLOIT_DEFEATED], exit_codes=[1]))
    assert update["status"] is AuditStatus.PATCHED
    patch = update["vulnerabilities"][0].patch
    assert patch.compiles is True and patch.poc_defeated is True
    assert patch.attempts == 1
    assert patch.diff  # a unified diff was recorded
    assert update["token_cost_usd"] > 0


def test_patch_self_corrects(tmp_path):
    state, _ = _state_with_confirmed(tmp_path)
    llm = StubLLM(["bad patch", "good patch"])
    # attempt 1: won't compile; attempt 2: compiles and defeats the exploit
    sandbox = QueueSandbox([PATCH_WONT_COMPILE, EXPLOIT_DEFEATED], exit_codes=[1, 1])
    update = run_remediation(state, llm, sandbox)
    assert update["status"] is AuditStatus.PATCHED
    assert update["vulnerabilities"][0].patch.attempts == 2
    assert len(llm.calls) == 2


def test_patch_exhausts_records_and_continues(tmp_path):
    # every patch compiles but the exploit still works -> not defeated.
    state, _ = _state_with_confirmed(tmp_path)
    n = settings.remediation_max_retries
    llm = StubLLM(["p"] * n)
    sandbox = QueueSandbox([STILL_EXPLOITABLE] * n, exit_codes=[0] * n)
    update = run_remediation(state, llm, sandbox)
    # run is NOT failed; vuln stays confirmed-but-unpatched
    assert "status" not in update  # stays EXPLOIT_CONFIRMED
    patch = update["vulnerabilities"][0].patch
    assert patch.poc_defeated is False
    assert patch.attempts == n


def test_nothing_to_do_without_confirmed_vuln(tmp_path):
    state, _ = _state_with_confirmed(tmp_path)
    # mark it already patched
    state.vulnerabilities[0].poc.oracle_confirmed = False
    assert run_remediation(state, StubLLM("x"), QueueSandbox([EXPLOIT_DEFEATED])) == {}
