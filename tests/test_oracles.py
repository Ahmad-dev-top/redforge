from redforge.oracles import ORACLE_SENTINELS, check_oracle, oracle_cheatsheet
from redforge.schemas import OracleType


def test_sentinel_required_even_when_passed():
    o = OracleType.BALANCE_INCREASE
    # forge passed but no sentinel emitted -> not confirmed
    assert check_oracle(o, forge_passed=True, forge_output="[PASS] test()") is False


def test_confirmed_needs_both():
    o = OracleType.INVARIANT_BROKEN
    out = f"[PASS] test() {ORACLE_SENTINELS[o]}"
    assert check_oracle(o, forge_passed=True, forge_output=out) is True
    # sentinel present but test failed -> not confirmed
    assert check_oracle(o, forge_passed=False, forge_output=out) is False


def test_wrong_sentinel_does_not_confirm():
    o = OracleType.FUNDS_LOCKED
    wrong = ORACLE_SENTINELS[OracleType.BALANCE_INCREASE]
    assert check_oracle(o, forge_passed=True, forge_output=wrong) is False


def test_cheatsheet_mentions_sentinel():
    text = oracle_cheatsheet(OracleType.UNAUTHORIZED_STATE)
    assert ORACLE_SENTINELS[OracleType.UNAUTHORIZED_STATE] in text
