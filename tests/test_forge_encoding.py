from redforge.foundry.forge import _normalize_halmos_source, _to_result
from redforge.oracles import check_oracle
from redforge.sandbox.runner import SandboxResult
from redforge.schemas import OracleType


def test_non_ascii_forge_output_confirms_without_crashing():
    # Forge prints UTF-8 (µs timings, box drawing). The host parser must keep
    # the ASCII sentinel and still confirm.
    output = (
        "╭─ Suite result\n"
        "finished in 885.65µs\n"
        "REDFORGE_ORACLE_CONFIRMED:balance_increase\n"
    )
    forged = _to_result(SandboxResult(exit_code=0, stdout=output, stderr="", timed_out=False))
    assert check_oracle(OracleType.BALANCE_INCREASE, forged.passed, forged.output) is True


def test_halmos_svm_address_is_rewritten():
    source = "SVM internal constant svm = SVM(address(0xf3993A62377B8f488863a07eA1E20B3D008C6c01));"
    fixed = _normalize_halmos_source(source)
    assert "0xF3993A62377BCd56AE39D773740A5390411E8BC9" in fixed
    assert "0xf3993A62377B8f488863a07eA1E20B3D008C6c01" not in fixed
