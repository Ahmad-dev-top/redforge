from pathlib import Path

import pytest

from redforge.agents import run_verification
from redforge.agents.verifier import _parse_halmos
from redforge.config import settings
from redforge.llm import StubLLM
from redforge.schemas import (
    AttackHypothesis,
    AuditState,
    AuditStatus,
    Finding,
    OracleType,
    Patch,
    PoCResult,
    ProjectKind,
    RepoMap,
    Severity,
    VulnClass,
    Vulnerability,
)
from tests.test_poc_engineer import QueueSandbox

REG_PASS = "Suite result: ok. 6 passed; 0 failed; 0 skipped\n"
DIFF_PASS = "[PASS] testLegit() (gas: 1)\nSuite result: ok. 1 passed; 0 failed\n"
HALMOS_PROVED = "[PASS] check_noLock() (paths: 24)\nSymbolic test result: 1 passed; 0 failed\n"
HALMOS_CEX = "[FAIL] check_noLock()\nCounterexample: amount=0x1 caller=0xbeef\n"
HALMOS_TIMEOUT = "halmos running...\n"  # paired with exit_code 124


@pytest.fixture(autouse=True)
def _tmp_work(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "work_root", tmp_path / "work")


def _state_patched(tmp_path: Path) -> AuditState:
    (tmp_path / "Vault.sol").write_text("contract Vault { function flashLoan() public {} }")
    finding = Finding(id="slither-0", detector="x", vuln_class=VulnClass.LOGIC,
                      severity=Severity.HIGH, confidence=0.9, file="Vault.sol")
    hyp = AttackHypothesis(id="hyp-0", finding_id="slither-0", target_contract="Vault",
                           target_function="flashLoan", vuln_class=VulnClass.LOGIC,
                           oracle=OracleType.FUNDS_LOCKED, rationale="r", priority=360)
    poc = PoCResult(hypothesis_id="hyp-0", attempt=1, oracle=OracleType.FUNDS_LOCKED,
                    oracle_confirmed=True, compiled=True, test_source="contract E {}")
    patch = Patch(finding_id="slither-0", contract="Vault", diff="--- a\n+++ b\n",
                  explanation="fix", compiles=True, poc_defeated=True, attempts=1,
                  patched_source="contract Vault { /* fixed */ }")
    vuln = Vulnerability(finding=finding, hypothesis=hyp, poc=poc, patch=patch)
    return AuditState(
        repo_url="x", run_id="ver1", status=AuditStatus.PATCHED,
        repo_map=RepoMap(root=str(tmp_path), kind=ProjectKind.FOUNDRY, contract_files=["Vault.sol"]),
        findings=[finding], hypotheses=[hyp], vulnerabilities=[vuln],
    )


def test_all_checks_pass_sets_verified(tmp_path):
    state = _state_patched(tmp_path)
    llm = StubLLM(["diff test", "halmos test"])
    sandbox = QueueSandbox([REG_PASS, DIFF_PASS, HALMOS_PROVED], exit_codes=[0, 0, 0])
    update = run_verification(state, llm, sandbox)
    assert update["status"] is AuditStatus.VERIFIED
    r = update["vulnerabilities"][0].verification
    assert r.verified is True
    assert r.poc_now_fails and r.differential_equivalent and r.halmos_proved
    assert r.existing_tests_pass is True


def test_halmos_timeout_degrades_to_patched(tmp_path):
    state = _state_patched(tmp_path)
    llm = StubLLM(["diff test", "halmos test"])
    # halmos times out: exit 124
    sandbox = QueueSandbox([REG_PASS, DIFF_PASS, HALMOS_TIMEOUT], exit_codes=[0, 0, 124])
    update = run_verification(state, llm, sandbox)
    assert "status" not in update  # stays PATCHED
    r = update["vulnerabilities"][0].verification
    assert r.verified is False
    assert r.halmos_timed_out is True and r.halmos_proved is False


def test_halmos_counterexample_not_verified(tmp_path):
    state = _state_patched(tmp_path)
    llm = StubLLM(["diff test", "halmos test"])
    sandbox = QueueSandbox([REG_PASS, DIFF_PASS, HALMOS_CEX], exit_codes=[0, 0, 1])
    update = run_verification(state, llm, sandbox)
    assert "status" not in update
    r = update["vulnerabilities"][0].verification
    assert r.verified is False
    assert r.halmos_timed_out is False
    assert "Counterexample" in r.halmos_counterexample or "counterexample" in r.halmos_counterexample.lower()


def _diff_calls(llm: StubLLM) -> list[dict[str, str]]:
    return [c for c in llm.calls if "LEGITIMATE" in c["system"]]


def test_differential_retries_then_passes(tmp_path):
    state = _state_patched(tmp_path)
    llm = StubLLM(["bad diff", "good diff", "halmos test"])
    diff_fail = "[FAIL: InvalidBalance()] test_flashLoanWithFeeAfterGrace()\n"
    sandbox = QueueSandbox(
        [REG_PASS, diff_fail, DIFF_PASS, HALMOS_PROVED],
        exit_codes=[0, 1, 0, 0],
    )
    update = run_verification(state, llm, sandbox)
    assert update["status"] is AuditStatus.VERIFIED
    assert update["vulnerabilities"][0].verification.differential_equivalent is True
    calls = _diff_calls(llm)
    assert len(calls) == 2
    assert "YOUR PREVIOUS TEST FAILED" in calls[1]["prompt"]
    assert "forge output (tail):" in calls[1]["prompt"]
    assert "InvalidBalance" in calls[1]["prompt"]


def test_halmos_compile_failure_is_retried(tmp_path):
    state = _state_patched(tmp_path)
    llm = StubLLM(["diff test", "bad halmos", "halmos test"])
    build = (
        "Compiling 32 files with Solc 0.8.25\n"
        "Error: Compiler run failed:\n"
        'Error (9582): Member "exec" not found or not visible\n'
    )
    sandbox = QueueSandbox(
        [REG_PASS, DIFF_PASS, build, HALMOS_PROVED],
        exit_codes=[0, 0, 1, 0],
    )
    update = run_verification(state, llm, sandbox)
    assert update["status"] is AuditStatus.VERIFIED
    calls = [c for c in llm.calls if "formal-verification" in c["system"]]
    assert len(calls) == 2
    assert "DID NOT RUN" in calls[1]["prompt"]
    assert "Member \"exec\" not found" in calls[1]["prompt"]


def test_halmos_setup_failure_is_retried(tmp_path):
    state = _state_patched(tmp_path)
    llm = StubLLM(["diff test", "bad halmos", "halmos test"])
    setup = (
        "Running 1 tests for test/Verify.t.sol:Check\n"
        "Error: setUp() failed: HalmosException: No successful path found in setUp()\n"
        "Symbolic test result: 0 passed; 1 failed; time: 0.29s\n"
    )
    sandbox = QueueSandbox(
        [REG_PASS, DIFF_PASS, setup, HALMOS_PROVED],
        exit_codes=[0, 0, 1, 0],
    )
    update = run_verification(state, llm, sandbox)
    assert update["status"] is AuditStatus.VERIFIED
    calls = [c for c in llm.calls if "formal-verification" in c["system"]]
    assert len(calls) == 2
    assert "No successful path found in setUp" in calls[1]["prompt"]


def test_halmos_counterexample_is_not_retried(tmp_path):
    state = _state_patched(tmp_path)
    llm = StubLLM(["diff test", "halmos test", "should not be asked"])
    sandbox = QueueSandbox([REG_PASS, DIFF_PASS, HALMOS_CEX], exit_codes=[0, 0, 1])
    update = run_verification(state, llm, sandbox)
    assert "status" not in update
    calls = [c for c in llm.calls if "formal-verification" in c["system"]]
    assert len(calls) == 1


def test_differential_failure_blocks_verified(tmp_path):
    state = _state_patched(tmp_path)
    llm = StubLLM(["bad diff", "bad diff", "bad diff", "halmos test"])
    # Every attempt fails; the budget is exhausted and the last result is kept.
    diff_fail = "[FAIL] testLegit()\n"
    sandbox = QueueSandbox(
        [REG_PASS, diff_fail, diff_fail, diff_fail, HALMOS_PROVED],
        exit_codes=[0, 1, 1, 1, 0],
    )
    update = run_verification(state, llm, sandbox)
    assert "status" not in update
    assert update["vulnerabilities"][0].verification.differential_equivalent is False
    assert len(_diff_calls(llm)) == settings.verify_max_retries


def test_regression_failure_does_not_block_verified(tmp_path):
    # CTF-style: existing tests fail (they assert the exploit), but differential +
    # halmos hold -> still VERIFIED, regression recorded as False.
    state = _state_patched(tmp_path)
    llm = StubLLM(["diff test", "halmos test"])
    reg_fail = "Suite result: FAILED. 2 passed; 1 failed\n"
    sandbox = QueueSandbox([reg_fail, DIFF_PASS, HALMOS_PROVED], exit_codes=[1, 0, 0])
    update = run_verification(state, llm, sandbox)
    assert update["status"] is AuditStatus.VERIFIED
    r = update["vulnerabilities"][0].verification
    assert r.existing_tests_pass is False and r.verified is True


def test_nothing_to_do_without_patch(tmp_path):
    state = _state_patched(tmp_path)
    state.vulnerabilities[0].patch.poc_defeated = False  # no successful patch
    assert run_verification(state, StubLLM("x"), QueueSandbox([REG_PASS])) == {}


def test_parse_halmos():
    assert _parse_halmos(HALMOS_PROVED, 0, False) == (True, "", False)
    proved, cex, to = _parse_halmos(HALMOS_CEX, 1, False)
    assert proved is False and "amount" in cex and to is False
    # A real timeout is only exit 124 or the sandbox deadline.
    assert _parse_halmos(HALMOS_TIMEOUT, 124, False) == (False, "", True)
    assert _parse_halmos("halmos running", 0, True) == (False, "", True)
    # Usage text mentions --solver-timeout-*; that is not a timeout.
    usage = (
        "usage: halmos [-h] [--solver-timeout-branching TIMEOUT]\n"
        "halmos: error: unrecognized arguments: --match-path test/Verify.t.sol\n"
    )
    assert _parse_halmos(usage, 0, False) == (False, "", False)
    assert _parse_halmos("...timed out...", 0, False) == (False, "", False)
    # A sibling-contract build failure is not a proof, a timeout, or a refutation.
    build = (
        "Compiling 219 files with Solc 0.8.25\n"
        "Error: Compiler run failed:\n"
        'Error (2904): Declaration "WETH" not found\n'
        "Build failed: ['forge', 'build', '--build-info']\n"
    )
    assert _parse_halmos(build, 0, False) == (False, "", False)
    # Forge artifact warnings contain "KeyError:"; a real pass still counts.
    proved_with_warning = (
        "Skipped console2.json due to parsing failure: KeyError: 'metadata'\n"
        "[PASS] check_flashLoanCannotBeBricked(uint256) (paths: 29, time: 5.80s)\n"
        "Symbolic test result: 1 passed; 0 failed; time: 6.79s\n"
    )
    assert _parse_halmos(proved_with_warning, 0, False) == (True, "", False)
