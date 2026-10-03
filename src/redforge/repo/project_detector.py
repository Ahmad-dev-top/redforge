"""Detect the toolchain and map a Solidity repository.

Fully implemented — no LLM needed. Produces a `RepoMap` the Scout agent
enriches later with AST/dependency info.
"""

from __future__ import annotations

import re
from pathlib import Path

from redforge.logging_conf import get_logger
from redforge.schemas import ProjectKind, RepoMap

log = get_logger("detector")

_SKIP_DIRS = {"node_modules", "lib", ".git", "out", "artifacts", "cache", "coverage"}
_PRAGMA_RE = re.compile(r"pragma\s+solidity\s+([^;]+);")


def _iter_sol(root: Path):
    for p in root.rglob("*.sol"):
        if any(part in _SKIP_DIRS for part in p.parts):
            continue
        yield p


def _detect_kind(root: Path) -> ProjectKind:
    if (root / "foundry.toml").exists():
        return ProjectKind.FOUNDRY
    for name in ("hardhat.config.js", "hardhat.config.ts"):
        if (root / name).exists():
            return ProjectKind.HARDHAT
    if (root / "truffle-config.js").exists() or (root / "truffle.js").exists():
        return ProjectKind.TRUFFLE
    if any(_iter_sol(root)):
        return ProjectKind.PLAIN
    return ProjectKind.UNKNOWN


def _read_remappings(root: Path) -> list[str]:
    rm = root / "remappings.txt"
    if rm.exists():
        return [ln.strip() for ln in rm.read_text().splitlines() if ln.strip()]
    return []


def _detect_solc(root: Path, sol_files: list[Path]) -> str | None:
    ft = root / "foundry.toml"
    if ft.exists():
        m = re.search(r"solc(?:_version)?\s*=\s*[\"']([^\"']+)[\"']", ft.read_text())
        if m:
            return m.group(1)
    for f in sol_files[:20]:  # sample a few pragmas
        m = _PRAGMA_RE.search(f.read_text(errors="ignore"))
        if m:
            return m.group(1).strip()
    return None


def detect_project(root: Path | str) -> RepoMap:
    root = Path(root)
    sol_files = list(_iter_sol(root))
    contract_files: list[str] = []
    test_files: list[str] = []
    for f in sol_files:
        rel = f.relative_to(root).as_posix()
        (test_files if _looks_like_test(f) else contract_files).append(rel)

    kind = _detect_kind(root)
    rmap = RepoMap(
        root=str(root),
        kind=kind,
        solc_version=_detect_solc(root, sol_files),
        contract_files=sorted(contract_files),
        test_files=sorted(test_files),
        remappings=_read_remappings(root),
    )
    log.info(
        "detected %s | %d contracts | %d tests | solc=%s",
        kind.value, len(contract_files), len(test_files), rmap.solc_version,
    )
    return rmap


def _looks_like_test(path: Path) -> bool:
    n = path.name.lower()
    return n.endswith(".t.sol") or "test" in path.parts or n.startswith("test")
