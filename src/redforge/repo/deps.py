"""Compile-enabler: fetch a repo's dependencies on the trusted host.

The sandbox has no network, so a Foundry repo whose libs live in `lib/` (git
submodules) or a Hardhat repo needing `node_modules` can't compile inside it —
Slither/forge then see nothing. We resolve deps on the HOST, where git/npm and
the network are available, BEFORE the repo is mounted read-only into the locked
sandbox. Dependency resolution is trusted host work; UNTRUSTED code still only
ever executes inside the no-network sandbox. This preserves the safety model.

`plan_fetch` is pure (returns the commands) so it's unit-testable without a
network; `fetch_dependencies` executes them.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from redforge.logging_conf import get_logger
from redforge.schemas import ProjectKind, RepoMap

log = get_logger("deps")


@dataclass
class DepsResult:
    ok: bool
    ran: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def plan_fetch(repo_map: RepoMap, repo_path: Path) -> list[list[str]]:
    """Return the commands needed to populate dependencies, or [] if none."""
    repo_path = Path(repo_path)
    cmds: list[list[str]] = []
    is_foundry = repo_map.kind is ProjectKind.FOUNDRY
    is_hardhat = repo_map.kind is ProjectKind.HARDHAT
    if is_foundry and (repo_path / ".gitmodules").exists():
        cmds.append(["git", "submodule", "update", "--init", "--recursive"])
    elif is_hardhat and (repo_path / "package.json").exists():
        cmds.append(["npm", "ci"])  # exec falls back to `npm install`
    return cmds


def _run(argv: list[str], cwd: Path, timeout_s: int) -> tuple[bool, str]:
    try:
        proc = subprocess.run(
            argv, cwd=str(cwd), capture_output=True, text=True,
            encoding="utf-8", errors="replace",
            timeout=timeout_s, check=False,
        )
        if proc.returncode != 0:
            return False, (proc.stderr or proc.stdout).strip()[:500]
        return True, ""
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        return False, str(exc)


def fetch_dependencies(
    repo_path: Path | str,
    repo_map: RepoMap,
    timeout_s: int = 1800,
) -> DepsResult:
    repo_path = Path(repo_path)
    cmds = plan_fetch(repo_map, repo_path)
    if not cmds:
        log.info("no dependency step for %s", repo_map.kind.value)
        return DepsResult(ok=True)

    result = DepsResult(ok=True)
    for argv in cmds:
        ok, err = _run(argv, repo_path, timeout_s)
        label = " ".join(argv)
        if ok:
            result.ran.append(label)
            log.info("deps: %s", label)
            continue
        # npm ci needs a lockfile; fall back to npm install once.
        if argv[:2] == ["npm", "ci"]:
            ok2, err2 = _run(["npm", "install"], repo_path, timeout_s)
            if ok2:
                result.ran.append("npm install")
                log.info("deps: npm install (ci fell back)")
                continue
            err = err2 or err
        result.ok = False
        result.warnings.append(f"{label}: {err}")
        log.warning("deps failed: %s — %s", label, err)

    # Best-effort sanity note for Foundry: did forge-std land?
    if repo_map.kind is ProjectKind.FOUNDRY and not list((repo_path / "lib").glob("forge-std*")):
        result.warnings.append("lib/forge-std not present — forge tests may not compile")
    return result
