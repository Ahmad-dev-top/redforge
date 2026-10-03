from redforge.schemas import (
    AuditState,
    AuditStatus,
    Finding,
    OracleType,
    Severity,
    VulnClass,
)


def test_audit_state_defaults():
    s = AuditState(repo_url="https://github.com/x/y", run_id="abc123")
    assert s.status is AuditStatus.PENDING
    assert s.findings == []
    assert s.token_cost_usd == 0.0


def test_finding_roundtrip():
    f = Finding(
        id="slither-0",
        detector="reentrancy-eth",
        vuln_class=VulnClass.REENTRANCY,
        severity=Severity.HIGH,
        confidence=0.9,
    )
    data = f.model_dump()
    again = Finding(**data)
    assert again == f


def test_oracle_enum_complete():
    # every oracle must have a value used by the sentinel map
    assert {o.value for o in OracleType} == {
        "balance_increase",
        "invariant_broken",
        "unauthorized_state",
        "funds_locked",
    }
