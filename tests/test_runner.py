from redforge.eval.datasets import BenchmarkCase
from redforge.llm import StubLLM
from redforge.runner import audit_case
from redforge.schemas import AuditStatus, VulnClass
from tests.test_scout import StubSandbox
from tests.test_strategist import GOOD


def test_audit_case_runs_graph_with_stubs(tmp_path):
    sol = tmp_path / "Vault.sol"
    sol.write_text("contract Vault { function withdraw(uint256 a) public {} }\n")
    case = BenchmarkCase(
        dataset="local",
        case_id="Vault.sol",
        path=sol,
        expected_class=VulnClass.REENTRANCY,
    )
    state = audit_case(case, StubLLM(GOOD), StubSandbox())
    assert state.status is AuditStatus.HYPOTHESES_READY
    assert len(state.findings) == 1
    assert len(state.hypotheses) == 2
    assert state.token_cost_usd > 0
