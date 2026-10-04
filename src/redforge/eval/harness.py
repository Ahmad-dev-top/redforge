"""Evaluation harness — the project's credibility engine.

Runs an audit callable over a benchmark dataset and produces the results table
that goes in the README: detection rate, false-positive rate, verified-patch
rate, mean cost and time per audit. Also runs a baseline (Slither alone) so the
table shows the delta your agents add.

Build this FIRST (Phase 1). Every later phase is measured by re-running it.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path

from redforge.eval.datasets import BenchmarkCase, load_dataset
from redforge.logging_conf import get_logger
from redforge.schemas import AuditState

log = get_logger("eval")

# An audit function takes a single-contract case and returns the final state.
AuditFn = Callable[[BenchmarkCase], AuditState]


@dataclass
class CaseResult:
    case_id: str
    detected: bool = False
    correct_class: bool = False
    exploit_confirmed: bool = False
    patched: bool = False
    verified: bool = False
    cost_usd: float = 0.0
    seconds: float = 0.0
    error: str | None = None


@dataclass
class EvalReport:
    dataset: str
    n: int
    detection_rate: float = 0.0
    class_accuracy: float = 0.0
    exploit_rate: float = 0.0
    verified_patch_rate: float = 0.0
    false_positive_rate: float = 0.0  # flagged on cases with no expected vuln
    mean_cost_usd: float = 0.0
    mean_seconds: float = 0.0
    cases: list[CaseResult] = field(default_factory=list)

    def to_markdown(self) -> str:
        return (
            f"### Results — {self.dataset} (n={self.n})\n\n"
            "| metric | value |\n|---|---|\n"
            f"| detection rate | {self.detection_rate:.1%} |\n"
            f"| class accuracy | {self.class_accuracy:.1%} |\n"
            f"| exploit-confirmed rate | {self.exploit_rate:.1%} |\n"
            f"| verified-patch rate | {self.verified_patch_rate:.1%} |\n"
            f"| false-positive rate | {self.false_positive_rate:.1%} |\n"
            f"| mean cost / audit | ${self.mean_cost_usd:.3f} |\n"
            f"| mean time / audit | {self.mean_seconds:.1f}s |\n"
        )

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(asdict(self), indent=2, default=str))


def run_eval(
    dataset: str,
    audit_fn: AuditFn,
    limit: int | None = None,
    cases: list[BenchmarkCase] | None = None,
) -> EvalReport:
    cases = cases if cases is not None else load_dataset(dataset)
    if limit:
        cases = cases[:limit]
    results: list[CaseResult] = []

    for case in cases:
        t0 = time.perf_counter()
        cr = CaseResult(case_id=case.case_id)
        try:
            state = audit_fn(case)
            cr.detected = bool(state.findings)
            if case.expected_class is not None:
                cr.correct_class = any(
                    f.vuln_class == case.expected_class for f in state.findings
                )
            cr.exploit_confirmed = any(
                v.poc and v.poc.oracle_confirmed for v in state.vulnerabilities
            )
            cr.patched = any(
                v.patch and v.patch.compiles and v.patch.poc_defeated
                for v in state.vulnerabilities
            )
            cr.verified = any(
                v.verification and v.verification.verified for v in state.vulnerabilities
            )
            cr.cost_usd = state.token_cost_usd
        except Exception as exc:  # noqa: BLE001 - record, don't crash the sweep
            cr.error = repr(exc)
            log.warning("case %s failed: %s", case.case_id, exc)
        cr.seconds = time.perf_counter() - t0
        results.append(cr)

    return _aggregate(dataset, cases, results)


def _aggregate(dataset, cases, results) -> EvalReport:
    n = len(results) or 1
    vuln_r = [r for c, r in zip(cases, results) if c.expected_vulnerable]
    safe_r = [r for c, r in zip(cases, results) if not c.expected_vulnerable]
    labelled = [(c, r) for c, r in zip(cases, results) if c.expected_class is not None]

    def rate(items, pred):
        items = list(items)
        return sum(1 for x in items if pred(x)) / len(items) if items else 0.0

    return EvalReport(
        dataset=dataset,
        n=len(results),
        detection_rate=rate(vuln_r, lambda r: r.detected),
        class_accuracy=rate((r for _, r in labelled), lambda r: r.correct_class),
        exploit_rate=rate(vuln_r, lambda r: r.exploit_confirmed),
        verified_patch_rate=rate(vuln_r, lambda r: r.verified),
        false_positive_rate=rate(safe_r, lambda r: r.detected),
        mean_cost_usd=sum(r.cost_usd for r in results) / n,
        mean_seconds=sum(r.seconds for r in results) / n,
        cases=results,
    )
