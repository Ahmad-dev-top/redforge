from redforge.repo.deps import detect_required_solc, plan_fetch
from redforge.schemas import ProjectKind, RepoMap


def test_foundry_with_submodules_plans_update(tmp_path):
    (tmp_path / ".gitmodules").write_text('[submodule "lib/forge-std"]\n')
    rm = RepoMap(root=str(tmp_path), kind=ProjectKind.FOUNDRY)
    assert plan_fetch(rm, tmp_path) == [["git", "submodule", "update", "--init", "--recursive"]]


def test_foundry_without_deps_plans_nothing(tmp_path):
    rm = RepoMap(root=str(tmp_path), kind=ProjectKind.FOUNDRY)
    assert plan_fetch(rm, tmp_path) == []


def test_npm_runs_for_any_kind_with_package_json(tmp_path):
    # a Foundry repo that ALSO needs npm deps (e.g. @api3 / @openzeppelin via npm)
    (tmp_path / "foundry.toml").write_text("[profile.default]\n")
    (tmp_path / "package.json").write_text("{}")
    rm = RepoMap(root=str(tmp_path), kind=ProjectKind.FOUNDRY)
    assert ["npm", "ci"] in plan_fetch(rm, tmp_path)


def test_soldeer_detected_from_lockfile(tmp_path):
    (tmp_path / "soldeer.lock").write_text("")
    rm = RepoMap(root=str(tmp_path), kind=ProjectKind.FOUNDRY)
    assert ["forge", "soldeer", "install"] in plan_fetch(rm, tmp_path)


def test_soldeer_detected_from_foundry_toml(tmp_path):
    (tmp_path / "foundry.toml").write_text("[dependencies]\nopenzeppelin = \"5.0.0\"\n")
    rm = RepoMap(root=str(tmp_path), kind=ProjectKind.FOUNDRY)
    assert ["forge", "soldeer", "install"] in plan_fetch(rm, tmp_path)


def test_all_three_can_apply_together(tmp_path):
    (tmp_path / ".gitmodules").write_text("")
    (tmp_path / "package.json").write_text("{}")
    (tmp_path / "soldeer.lock").write_text("")
    rm = RepoMap(root=str(tmp_path), kind=ProjectKind.FOUNDRY)
    cmds = plan_fetch(rm, tmp_path)
    assert ["git", "submodule", "update", "--init", "--recursive"] in cmds
    assert ["npm", "ci"] in cmds
    assert ["forge", "soldeer", "install"] in cmds


def test_plain_plans_nothing(tmp_path):
    rm = RepoMap(root=str(tmp_path), kind=ProjectKind.PLAIN)
    assert plan_fetch(rm, tmp_path) == []


def test_detect_required_solc_from_repomap():
    rm = RepoMap(root="/x", kind=ProjectKind.FOUNDRY, solc_version="0.8.19")
    assert detect_required_solc(rm, "/x") == "0.8.19"


def test_detect_required_solc_from_foundry_toml(tmp_path):
    (tmp_path / "foundry.toml").write_text('[profile.default]\nsolc = "0.8.17"\n')
    rm = RepoMap(root=str(tmp_path), kind=ProjectKind.FOUNDRY)
    assert detect_required_solc(rm, tmp_path) == "0.8.17"
