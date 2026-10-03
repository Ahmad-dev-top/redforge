from redforge.repo.deps import plan_fetch
from redforge.schemas import ProjectKind, RepoMap


def test_foundry_with_submodules_plans_update(tmp_path):
    (tmp_path / ".gitmodules").write_text("[submodule \"lib/forge-std\"]\n")
    rm = RepoMap(root=str(tmp_path), kind=ProjectKind.FOUNDRY)
    cmds = plan_fetch(rm, tmp_path)
    assert cmds == [["git", "submodule", "update", "--init", "--recursive"]]


def test_foundry_without_submodules_plans_nothing(tmp_path):
    rm = RepoMap(root=str(tmp_path), kind=ProjectKind.FOUNDRY)
    assert plan_fetch(rm, tmp_path) == []


def test_hardhat_with_package_plans_npm(tmp_path):
    (tmp_path / "package.json").write_text("{}")
    rm = RepoMap(root=str(tmp_path), kind=ProjectKind.HARDHAT)
    assert plan_fetch(rm, tmp_path) == [["npm", "ci"]]


def test_plain_plans_nothing(tmp_path):
    rm = RepoMap(root=str(tmp_path), kind=ProjectKind.PLAIN)
    assert plan_fetch(rm, tmp_path) == []
