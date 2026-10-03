"""Success oracles — the anti-cheat core of the system.

An LLM will happily write a PoC test that "passes" without proving anything.
So the LLM never gets to declare success. Instead:

1. The PoC test must *prove* the oracle condition with a real Solidity
   assertion (e.g. `assertGt(attacker.balance, before)`), and ONLY inside the
   branch where that assertion holds does it emit a sentinel log line, e.g.
       emit log_string("REDFORGE_ORACLE_CONFIRMED:balance_increase");
2. The harness (this module) inspects the forge output on the host side and
   confirms BOTH that the test passed AND that the matching sentinel is
   present. The sentinel alone is not enough; a failing assertion aborts the
   test before the sentinel is reached.

This keeps the definition of "exploited" in code we control, and makes false
positives structurally hard.
"""

from __future__ import annotations

from redforge.schemas import OracleType

_SENTINEL_PREFIX = "REDFORGE_ORACLE_CONFIRMED:"

ORACLE_SENTINELS: dict[OracleType, str] = {
    o: f"{_SENTINEL_PREFIX}{o.value}" for o in OracleType
}

# How the PoC agent must prove each oracle. This text is injected into the
# PoC engineer's prompt. It describes the *proof obligation*, not an exploit.
_ORACLE_GUIDANCE: dict[OracleType, str] = {
    OracleType.BALANCE_INCREASE: (
        "Record the attacker address balance before the interaction. After the "
        "interaction, require that it strictly increased with assertGt(after, before). "
        "Emit the sentinel only after that assertion holds."
    ),
    OracleType.INVARIANT_BROKEN: (
        "State the contract invariant that should always hold (e.g. "
        "sum(balances) == totalSupply). Assert it is FALSE after the interaction "
        "using assertTrue(!invariant). Emit the sentinel only then."
    ),
    OracleType.UNAUTHORIZED_STATE: (
        "Read the privileged state variable (owner, admin, paused, etc.). Perform "
        "the interaction from a non-privileged address. Assert the state changed to "
        "the attacker's benefit. Emit the sentinel only then."
    ),
    OracleType.FUNDS_LOCKED: (
        "Show a legitimate withdrawal path that succeeded before the interaction "
        "now reverts / cannot recover funds afterwards. Assert the revert, then "
        "emit the sentinel."
    ),
}


def oracle_cheatsheet(oracle: OracleType) -> str:
    """Return the proof obligation for the given oracle (for prompt injection)."""
    return (
        f"Oracle = {oracle.value}. Proof obligation: {_ORACLE_GUIDANCE[oracle]} "
        f'On success the test must print exactly: "{ORACLE_SENTINELS[oracle]}".'
    )


def check_oracle(oracle: OracleType, forge_passed: bool, forge_output: str) -> bool:
    """True iff the forge test passed AND the matching sentinel was emitted."""
    if not forge_passed:
        return False
    return ORACLE_SENTINELS[oracle] in forge_output
