from redforge.repo.code_index import index_source

SRC = """
pragma solidity ^0.8.20;

contract Vault {
    function deposit(uint256 amount) external payable {}
    function withdraw(uint256 amount) public returns (bool) {}
}

library Math {
    function add(uint256 a, uint256 b) internal pure returns (uint256) {}
}
"""


def test_extracts_functions_with_owners():
    refs = index_source(SRC, "src/Vault.sol")
    names = {(r.contract, r.function) for r in refs}
    assert ("Vault", "deposit") in names
    assert ("Vault", "withdraw") in names
    assert ("Math", "add") in names


def test_signature_captured():
    refs = index_source(SRC, "src/Vault.sol")
    withdraw = next(r for r in refs if r.function == "withdraw")
    assert "returns (bool)" in withdraw.signature
    assert withdraw.file == "src/Vault.sol"
