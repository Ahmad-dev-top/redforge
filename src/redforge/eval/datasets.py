"""Benchmark dataset registry.

We evaluate against public, known-vulnerable corpora. Each case carries a
ground-truth label so the harness can score detection precisely.

The datasets are cloned into `benchmarks/` by `scripts/fetch_benchmarks.sh`
(Cursor: create that script in Phase 1). Nothing here downloads at import time.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from redforge.config import settings
from redforge.schemas import VulnClass


@dataclass
class DatasetSpec:
    name: str
    repo: str            # git URL of the corpus
    subdir: str          # where the vulnerable contracts live
    note: str


# Curated, widely-cited benchmarks. Start with SmartBugs Curated (labelled),
# then add DVD and Ethernaut as the pipeline matures.
DATASETS: dict[str, DatasetSpec] = {
    "smartbugs-curated": DatasetSpec(
        name="smartbugs-curated",
        repo="https://github.com/smartbugs/smartbugs-curated",
        subdir="dataset",
        note="143 labelled vulnerable contracts across 10 DASP categories.",
    ),
    "damn-vulnerable-defi": DatasetSpec(
        name="damn-vulnerable-defi",
        repo="https://github.com/theredguild/damn-vulnerable-defi",
        subdir="src",
        note="Foundry CTF challenges; realistic DeFi logic bugs.",
    ),
    "ethernaut": DatasetSpec(
        name="ethernaut",
        repo="https://github.com/OpenZeppelin/ethernaut",
        subdir="contracts/src/levels",
        note="Classic level-based vulnerabilities.",
    ),
}


@dataclass
class BenchmarkCase:
    dataset: str
    case_id: str
    path: Path
    expected_class: VulnClass | None = None  # ground truth, when labelled
    expected_vulnerable: bool = True
    tags: list[str] = field(default_factory=list)


def dataset_root(name: str) -> Path:
    return settings.benchmarks_root / name


def load_dataset(name: str) -> list[BenchmarkCase]:
    """Enumerate cases from a locally-cloned dataset.

    Labels: SmartBugs Curated encodes the category in the directory name; we map
    those to `VulnClass`. For unlabelled corpora, `expected_class` stays None and
    the case is scored on detect/patch/verify success only.
    """
    spec = DATASETS[name]
    root = dataset_root(name) / spec.subdir
    if not root.exists():
        raise FileNotFoundError(
            f"{root} missing — run scripts/fetch_benchmarks.sh first"
        )
    cases: list[BenchmarkCase] = []
    for sol in sorted(root.rglob("*.sol")):
        cases.append(
            BenchmarkCase(
                dataset=name,
                case_id=str(sol.relative_to(root)),
                path=sol,
                expected_class=_infer_label(name, sol),
            )
        )
    return cases


_SMARTBUGS_DIR_TO_CLASS = {
    "reentrancy": VulnClass.REENTRANCY,
    "access_control": VulnClass.ACCESS_CONTROL,
    "arithmetic": VulnClass.ARITHMETIC,
    "unchecked_low_level_calls": VulnClass.UNCHECKED_CALL,
    "denial_of_service": VulnClass.DOS,
    "bad_randomness": VulnClass.BAD_RANDOMNESS,
    "front_running": VulnClass.FRONT_RUNNING,
}


def _infer_label(dataset: str, path: Path) -> VulnClass | None:
    if dataset != "smartbugs-curated":
        return None
    for part in path.parts:
        if part in _SMARTBUGS_DIR_TO_CLASS:
            return _SMARTBUGS_DIR_TO_CLASS[part]
    return None
