"""Damn Vulnerable DeFi benchmark.

DVD is one Foundry project with independent challenges under `src/<name>/`. We
audit each challenge in isolation by cloning once, then running the full pipeline
with `scope_prefix` set to that challenge's source dir (so the strategist only
sees that challenge's findings). Results are collected with the existing eval
harness and rendered as a per-challenge funnel table:

    found -> confirmed -> patched -> verified

Not every challenge fits the current oracle set (some need off-chain steps or
multi-tx orchestration beyond a single PoC); those honestly show up as
"found" or "none". The table reports what RedForge actually does, unfiltered.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from pathlib import Path

from redforge.eval.datasets import BenchmarkCase
from redforge.eval.harness import AuditFn, CaseResult, EvalReport, run_eval
from redforge.graph import build_graph
from redforge.llm import LLMClient
from redforge.repo import detect_project
from redforge.sandbox import SandboxRunner
from redforge.schemas import AuditState, VulnClass


@dataclass(frozen=True)
class DVDChallenge:
    name: str
    subdir: str                       # under src/
    expected_class: VulnClass | None = None
    oracle_friendly: bool = True      # does it plausibly fit our PoC oracle set?


# Known DVD (Foundry) challenges. expected_class is best-effort for class
# accuracy; oracle_friendly flags the ones a single-PoC approach can realistically
# confirm vs. those needing off-chain/multi-tx setups (recorded, not hidden).
DVD_CHALLENGES: list[DVDChallenge] = [
    DVDChallenge("unstoppable", "unstoppable", VulnClass.DOS, True),
    DVDChallenge("naive-receiver", "naive-receiver", VulnClass.ACCESS_CONTROL, True),
    DVDChallenge("truster", "truster", VulnClass.UNCHECKED_CALL, True),
    DVDChallenge("side-entrance", "side-entrance", VulnClass.LOGIC, True),
    DVDChallenge("the-rewarder", "the-rewarder", VulnClass.LOGIC, True),
    DVDChallenge("selfie", "selfie", VulnClass.ACCESS_CONTROL, True),
    DVDChallenge("puppet", "puppet", VulnClass.ORACLE_MANIPULATION, True),
    DVDChallenge("puppet-v2", "puppet-v2", VulnClass.ORACLE_MANIPULATION, True),
    DVDChallenge("free-rider", "free-rider", VulnClass.LOGIC, True),
    DVDChallenge("backdoor", "backdoor", VulnClass.ACCESS_CONTROL, True),
    DVDChallenge("climber", "climber", VulnClass.ACCESS_CONTROL, True),
    DVDChallenge("wallet-mining", "wallet-mining", VulnClass.LOGIC, True),
    DVDChallenge("puppet-v3", "puppet-v3", VulnClass.ORACLE_MANIPULATION, True),
    DVDChallenge("abi-smuggling", "abi-smuggling", VulnClass.ACCESS_CONTROL, True),
    DVDChallenge("compromised", "compromised", None, False),   # off-chain key leak
]


def load_dvd_challenges(repo_path: Path | str) -> list[BenchmarkCase]:
    """One BenchmarkCase per challenge whose src dir exists in the clone."""
    repo_path = Path(repo_path)
    cases: list[BenchmarkCase] = []
    for ch in DVD_CHALLENGES:
        src = repo_path / "src" / ch.subdir
        if not src.exists():
            continue
        cases.append(
            BenchmarkCase(
                dataset="damn-vulnerable-defi",
                case_id=ch.name,
                path=src,
                expected_class=ch.expected_class,
                expected_vulnerable=True,
                tags=["oracle_friendly"] if ch.oracle_friendly else ["needs_offchain"],
            )
        )
    return cases


def audit_dvd_challenge(
    case: BenchmarkCase,
    llm: LLMClient,
    sandbox: SandboxRunner,
    repo_path: Path,
) -> AuditState:
    """Run the full pipeline scoped to one challenge of an already-cloned DVD."""
    repo_map = detect_project(repo_path)
    state = AuditState(
        repo_url=f"benchmark://damn-vulnerable-defi/{case.case_id}",
        run_id=uuid.uuid4().hex[:8],
        repo_map=repo_map,
        scope_prefix=f"src/{case.case_id}/",
    )
    graph = build_graph(llm, sandbox, checkpointer=None)
    final = graph.invoke(state, {"configurable": {"thread_id": state.run_id}})
    return AuditState.model_validate(final)


def build_dvd_audit_fn(llm: LLMClient, sandbox: SandboxRunner, repo_path: Path) -> AuditFn:
    return lambda case: audit_dvd_challenge(case, llm, sandbox, repo_path)


def run_dvd_benchmark(
    llm: LLMClient,
    sandbox: SandboxRunner,
    repo_path: Path,
    limit: int | None = None,
) -> EvalReport:
    audit_fn = build_dvd_audit_fn(llm, sandbox, repo_path)
    return run_eval("damn-vulnerable-defi", audit_fn, limit=limit, cases=load_dvd_challenges(repo_path))


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #
def _status(cr: CaseResult) -> str:
    if cr.error:
        return "error"
    if cr.verified:
        return "✅ verified"
    if cr.patched:
        return "patched"
    if cr.exploit_confirmed:
        return "confirmed"
    if cr.detected:
        return "found"
    return "none"


def challenge_table(report: EvalReport) -> str:
    """Per-challenge funnel table (markdown)."""
    lines = [
        "| challenge | found | confirmed | patched | verified | cost | time |",
        "|---|:--:|:--:|:--:|:--:|--:|--:|",
    ]
    tick = lambda b: "•" if b else ""
    for cr in report.cases:
        lines.append(
            f"| {cr.case_id} | {tick(cr.detected)} | {tick(cr.exploit_confirmed)} "
            f"| {tick(cr.patched)} | {tick(cr.verified)} "
            f"| ${cr.cost_usd:.3f} | {cr.seconds:.0f}s |"
        )
    n = report.n or 1
    confirmed = sum(1 for c in report.cases if c.exploit_confirmed)
    verified = sum(1 for c in report.cases if c.verified)
    total_cost = sum(c.cost_usd for c in report.cases)
    summary = (
        f"**{confirmed}/{n} confirmed, {verified}/{n} verified** · "
        f"total cost ${total_cost:.2f} · "
        f"detection {report.detection_rate:.0%} · "
        f"exploit-confirmed {report.exploit_rate:.0%} · "
        f"verified {report.verified_patch_rate:.0%}"
    )
    lines += ["", summary]
    return "\n".join(lines)
