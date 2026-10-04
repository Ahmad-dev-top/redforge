from redforge.agents import run_scout
from redforge.eval.dvd import challenge_table, load_dvd_challenges
from redforge.eval.harness import CaseResult, EvalReport
from redforge.schemas import AuditState, AuditStatus, ProjectKind, RepoMap
from tests.test_scout import StubSandbox


def test_scope_prefix_filters_scout_output(tmp_path):
    # two challenge dirs; scope to one
    (tmp_path / "src" / "unstoppable").mkdir(parents=True)
    (tmp_path / "src" / "naive-receiver").mkdir(parents=True)
    (tmp_path / "src" / "unstoppable" / "Vault.sol").write_text(
        "contract Vault { function withdraw() public {} }"
    )
    (tmp_path / "src" / "naive-receiver" / "Pool.sol").write_text(
        "contract Pool { function flashLoan() public {} }"
    )
    rm = RepoMap(root=str(tmp_path), kind=ProjectKind.FOUNDRY,
                 contract_files=["src/unstoppable/Vault.sol", "src/naive-receiver/Pool.sol"])

    scoped = AuditState(repo_url="x", run_id="s1", repo_map=rm,
                        scope_prefix="src/unstoppable/")
    update = run_scout(scoped, StubSandbox())
    files = {fn.file for fn in update["functions"]}
    assert files == {"src/unstoppable/Vault.sol"}      # naive-receiver filtered out
    assert update["status"] is AuditStatus.MAPPED


def test_no_scope_keeps_everything(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "A.sol").write_text("contract A { function f() public {} }")
    rm = RepoMap(root=str(tmp_path), kind=ProjectKind.FOUNDRY, contract_files=["src/A.sol"])
    state = AuditState(repo_url="x", run_id="s2", repo_map=rm)  # no scope
    update = run_scout(state, StubSandbox())
    assert any(fn.file == "src/A.sol" for fn in update["functions"])


def test_load_dvd_challenges_only_existing(tmp_path):
    (tmp_path / "src" / "unstoppable").mkdir(parents=True)
    (tmp_path / "src" / "truster").mkdir(parents=True)
    cases = load_dvd_challenges(tmp_path)
    names = {c.case_id for c in cases}
    assert names == {"unstoppable", "truster"}          # only dirs that exist
    assert all(c.dataset == "damn-vulnerable-defi" for c in cases)


def test_challenge_table_renders_funnel():
    report = EvalReport(dataset="damn-vulnerable-defi", n=2, cases=[
        CaseResult(case_id="unstoppable", detected=True, exploit_confirmed=True,
                   patched=True, verified=True, cost_usd=0.65, seconds=90),
        CaseResult(case_id="compromised", detected=True, exploit_confirmed=False,
                   patched=False, verified=False, cost_usd=0.10, seconds=20),
    ], exploit_rate=0.5, verified_patch_rate=0.5, detection_rate=1.0)
    md = challenge_table(report)
    assert "unstoppable" in md and "verified" in md
    assert "1/2 confirmed, 1/2 verified" in md
    assert "$0.75" in md  # total cost
