from pathlib import Path

from redforge.repo.project_detector import detect_project
from redforge.schemas import ProjectKind


def _make_foundry(tmp: Path):
    (tmp / "foundry.toml").write_text('[profile.default]\nsolc = "0.8.24"\n')
    (tmp / "src").mkdir()
    (tmp / "test").mkdir()
    (tmp / "lib").mkdir()
    (tmp / "src" / "Vault.sol").write_text("pragma solidity ^0.8.20;\ncontract Vault {}\n")
    (tmp / "test" / "Vault.t.sol").write_text("contract VaultTest {}\n")
    # this should be ignored (dependency dir)
    (tmp / "lib" / "Dep.sol").write_text("contract Dep {}\n")


def test_detects_foundry_and_filters_deps(tmp_path):
    _make_foundry(tmp_path)
    rmap = detect_project(tmp_path)
    assert rmap.kind is ProjectKind.FOUNDRY
    assert rmap.solc_version == "0.8.24"
    assert "src/Vault.sol" in rmap.contract_files
    assert "test/Vault.t.sol" in rmap.test_files
    assert all("lib/" not in c for c in rmap.contract_files)


def test_unknown_when_empty(tmp_path):
    rmap = detect_project(tmp_path)
    assert rmap.kind is ProjectKind.UNKNOWN
    assert rmap.contract_files == []
