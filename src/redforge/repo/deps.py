"""Compile-enabler: resolve a repo's dependencies on the trusted host.

The audit sandbox has no network, so anything a repo needs to compile must be in
place BEFORE the sandbox is sealed. Two kinds of dependency:

1. In-repo deps (git submodules, npm `node_modules`, soldeer `dependencies/`) —
   resolved here on the HOST, where git/npm/forge and the network are available.
   They land inside the repo dir, which is then mounted read-only into the
   sandbox, so the no-network compile finds them.
2. The solc compiler itself — a toolchain binary, not a repo file, so it can't be
   fetched this way. A range of solc versions is pre-baked into the sandbox image
   (see docker/sandbox.Dockerfile) so forge never needs to download one at audit
   time. Here we only DETECT the required version and warn if a repo pins one, so
   a still-empty Slither run is explainable rather than silent.

Dependency resolution is trusted host work; UNTRUSTED code still only ever
executes inside the no-network sandbox. This preserves the safety model.

`plan_fetch` is pure (returns the commands) so it's unit-testable without a
network; `fetch_dependencies` executes them.
"""

from __future__ import annotations

import re
import shutil
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
    required_solc: str | None = None


def _uses_soldeer(repo_path: Path) -> bool:
    if (repo_path / "soldeer.lock").exists():
        return True
    ft = repo_path / "foundry.toml"
    if ft.exists():
        txt = ft.read_text(errors="ignore")
        return "[dependencies]" in txt or "[soldeer]" in txt
    return False


def plan_fetch(repo_map: RepoMap, repo_path: Path) -> list[list[str]]:
    """Return every applicable dependency command. These are INDEPENDENT — a
    single repo can need submodules AND npm AND soldeer (e.g. a Foundry repo that
    imports @openzeppelin/@api3 via npm), so this is no longer either/or."""
    repo_path = Path(repo_path)
    cmds: list[list[str]] = []
    if (repo_path / ".gitmodules").exists():
        cmds.append(["git", "submodule", "update", "--init", "--recursive"])
    if (repo_path / "package.json").exists():
        cmds.append(["npm", "ci"])  # exec falls back to `npm install`
    if _uses_soldeer(repo_path):
        cmds.append(["forge", "soldeer", "install"])
    return cmds


def detect_required_solc(repo_map: RepoMap, repo_path: Path) -> str | None:
    """The concrete solc version the repo needs, if pinned. project_detector
    already reads foundry.toml / pragma into repo_map.solc_version; fall back to
    scanning foundry.toml here. Returns a version-ish string (may include a range)."""
    if repo_map.solc_version:
        return repo_map.solc_version
    ft = repo_path / "foundry.toml"
    if ft.exists():
        m = re.search(r"solc(?:_version)?\s*=\s*[\"']([^\"']+)[\"']", ft.read_text(errors="ignore"))
        if m:
            return m.group(1)
    return None


def _run(argv: list[str], cwd: Path, timeout_s: int) -> tuple[bool, str]:
    # Windows ships npm as npm.cmd. CreateProcess does not apply PATHEXT, so
    # resolve the executable first or `npm ci` fails with WinError 2.
    resolved = list(argv)
    exe = shutil.which(resolved[0])
    if exe:
        resolved[0] = exe
    try:
        proc = subprocess.run(
            resolved, cwd=str(cwd), capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=timeout_s, check=False,
        )
        if proc.returncode != 0:
            return False, (proc.stderr or proc.stdout).strip()[:500]
        return True, ""
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        return False, str(exc)


def fetch_dependencies(
    repo_path: Path | str,
    repo_map: RepoMap,
    timeout_s: int = 300,
) -> DepsResult:
    repo_path = Path(repo_path)
    result = DepsResult(ok=True, required_solc=detect_required_solc(repo_map, repo_path))
    if result.required_solc:
        log.info("repo pins solc %s", result.required_solc)

    cmds = plan_fetch(repo_map, repo_path)
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

    # Explainability: if Foundry and forge-std still isn't present, the compile
    # (and therefore Slither) will likely be empty — say so rather than fail quietly.
    if repo_map.kind is ProjectKind.FOUNDRY and not list((repo_path / "lib").glob("forge-std*")):
        result.warnings.append("lib/forge-std not present — forge tests may not compile")
    return result
