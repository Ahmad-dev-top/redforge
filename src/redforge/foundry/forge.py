"""Thin wrapper around `forge test`, always executed inside the sandbox.

Anvil/forge run against a LOCAL fork only. No RPC broadcast, no private keys,
no mainnet writes — the sandbox has no network at all, which enforces this.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from redforge.logging_conf import get_logger
from redforge.sandbox import SandboxRunner

log = get_logger("forge")


@dataclass
class ForgeResult:
    compiled: bool
    passed: bool
    exit_code: int
    output: str
    timed_out: bool


def run_forge_test(
    repo_ro: Path,
    workspace_rw: Path,
    match_path: str | None = None,
    match_test: str | None = None,
    sandbox: SandboxRunner | None = None,
) -> ForgeResult:
    """Copy the repo into the workspace, drop generated tests already present
    there, and run forge. `match_path`/`match_test` narrow to one test."""
    sandbox = sandbox or SandboxRunner()
    filters = ""
    if match_path:
        filters += f" --match-path '{match_path}'"
    if match_test:
        filters += f" --match-test '{match_test}'"
    cmd = (
        "cp -rn /repo/. /work/target 2>/dev/null; cd /work/target && "
        f"forge test -vvv{filters} 2>&1"
    )
    res = sandbox.run(cmd, repo_ro, workspace_rw)
    return _to_result(res)


def run_poc_test(
    repo_ro: Path,
    workspace_rw: Path,
    test_source: str,
    sandbox: SandboxRunner | None = None,
    test_filename: str = "Exploit.t.sol",
) -> ForgeResult:
    """Inject a generated exploit test into the project and run just that test.

    The test is written to the host-side workspace, then the sandbox copies the
    repo into a writable target, drops the test into `test/`, and runs it. The
    original repo mount stays read-only and untouched.
    """
    sandbox = sandbox or SandboxRunner()
    workspace_rw.mkdir(parents=True, exist_ok=True)
    (workspace_rw / test_filename).write_text(test_source, encoding="utf-8")
    cmd = (
        "cp -rn /repo/. /work/target 2>/dev/null; mkdir -p /work/target/test && "
        f"cp /work/{test_filename} /work/target/test/{test_filename} && "
        f"cd /work/target && forge test -vvv --match-path 'test/{test_filename}' 2>&1"
    )
    res = sandbox.run(cmd, repo_ro, workspace_rw)
    return _to_result(res)


def run_poc_against_patch(
    repo_ro: Path,
    workspace_rw: Path,
    contract_rel: str,
    patched_source: str,
    test_source: str,
    sandbox: SandboxRunner | None = None,
    test_filename: str = "Exploit.t.sol",
) -> ForgeResult:
    """Apply a patched contract over the original, inject the confirming exploit,
    and run it. Used by remediation: success is this test now FAILING."""
    sandbox = sandbox or SandboxRunner()
    workspace_rw.mkdir(parents=True, exist_ok=True)
    (workspace_rw / "patched.sol").write_text(patched_source, encoding="utf-8")
    (workspace_rw / test_filename).write_text(test_source, encoding="utf-8")
    cmd = (
        "rm -rf /work/target; cp -r /repo/. /work/target 2>/dev/null; "
        f"cp /work/patched.sol '/work/target/{contract_rel}' && "
        f"mkdir -p /work/target/test && cp /work/{test_filename} /work/target/test/{test_filename} && "
        f"cd /work/target && forge test -vvv --match-path 'test/{test_filename}' 2>&1"
    )
    res = sandbox.run(cmd, repo_ro, workspace_rw)
    return _to_result(res)


def run_forge_suite_against_patch(
    repo_ro: Path,
    workspace_rw: Path,
    contract_rel: str,
    patched_source: str,
    sandbox: SandboxRunner | None = None,
    exclude: str = "test/Exploit.t.sol",
) -> ForgeResult:
    """Run the repo's existing test suite against the patched contract, excluding
    our injected exploit. Used by verification for the regression check."""
    sandbox = sandbox or SandboxRunner()
    workspace_rw.mkdir(parents=True, exist_ok=True)
    (workspace_rw / "patched.sol").write_text(patched_source, encoding="utf-8")
    cmd = (
        "rm -rf /work/target; cp -r /repo/. /work/target 2>/dev/null; "
        f"cp /work/patched.sol '/work/target/{contract_rel}' && cd /work/target && "
        f"forge test -vv --no-match-path '{exclude}' 2>&1"
    )
    return _to_result(sandbox.run(cmd, repo_ro, workspace_rw))


_IMPORT_RE = re.compile(
    r"""import\s+(?:[^'";]*?\s+from\s+)?["']([^"']+)["']"""
)
_CONTRACT_RE = re.compile(
    r"(?m)^[ \t]*(?:abstract\s+)?contract\s+([A-Za-z_][A-Za-z0-9_]*)\b"
)
_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
# Halmos's SVM cheatcode. A model-invented address does not implement createUint.
# EIP-55 form of Halmos's SVM cheatcode. createUint lives here, not at the HEVM address.
_HALMOS_SVM = "0xF3993A62377BCd56AE39D773740A5390411E8BC9"
_SVM_ADDR_RE = re.compile(
    r"(SVM\s*\(\s*address\s*\(\s*)0x[a-fA-F0-9]{40}(\s*\)\s*\))"
)

# Drops sibling Foundry sources before Halmos's whole-project `forge build`.
_ISOLATE_PY = """\
import json, os, shutil
from pathlib import Path

root = Path("/work/target")
scope = json.loads(Path("/work/halmos_scope.json").read_text())
keep_dirs = set(scope.get("keep_src_dirs") or [])
keep_files = set(scope.get("keep_src_files") or [])
keep_tests = set(scope.get("keep_test_rels") or [])

def _writable(path: Path) -> None:
    if not path.exists():
        return
    for dirpath, dirnames, filenames in os.walk(path):
        os.chmod(dirpath, 0o755)
        for name in filenames:
            os.chmod(os.path.join(dirpath, name), 0o644)

src = root / "src"
if keep_dirs and src.is_dir():
    for child in list(src.iterdir()):
        drop = child.is_dir() and child.name not in keep_dirs
        drop = drop or (child.is_file() and child.suffix == ".sol" and child.name not in keep_files)
        if drop:
            _writable(child)
            if child.is_dir():
                shutil.rmtree(child)
            else:
                child.unlink()

test = root / "test"
if keep_tests and test.is_dir():
    for path in list(test.rglob("*.sol")):
        rel = path.relative_to(test).as_posix()
        if rel not in keep_tests:
            path.chmod(0o644)
            path.unlink()
"""


def _remappings(repo: Path) -> list[tuple[str, str]]:
    path = repo / "remappings.txt"
    if not path.is_file():
        return []
    pairs: list[tuple[str, str]] = []
    for line in path.read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        prefix, target = line.split("=", 1)
        pairs.append((prefix.strip(), target.strip()))
    pairs.sort(key=lambda item: len(item[0]), reverse=True)
    return pairs


def _inside(repo: Path, path: Path) -> bool:
    try:
        path.resolve().relative_to(repo.resolve())
    except (OSError, ValueError):
        return False
    return True


def _resolve_import(repo: Path, current: Path, spec: str, remaps: list[tuple[str, str]]) -> Path | None:
    for prefix, target in remaps:
        if spec.startswith(prefix):
            candidate = (repo / target / spec[len(prefix):]).resolve()
            if candidate.is_file() and _inside(repo, candidate):
                return candidate
    if spec.startswith("."):
        candidate = (current.parent / spec).resolve()
    else:
        candidate = (repo / spec).resolve()
    if candidate.is_file() and _inside(repo, candidate):
        return candidate
    return None


def _normalize_halmos_source(test_source: str) -> str:
    """Point a hand-rolled SVM interface at Halmos's cheatcode address."""
    return _SVM_ADDR_RE.sub(rf"\g<1>{_HALMOS_SVM}\2", test_source)


def _halmos_contract_name(test_source: str) -> str:
    """Contract that declares `check_`. Helpers above it are not the target."""
    marker = test_source.find("function check_")
    head = test_source[:marker] if marker >= 0 else test_source
    found = _CONTRACT_RE.findall(head)
    return found[-1] if found else ""


def _halmos_scope(
    repo: Path,
    contract_rel: str,
    patched_source: str,
    test_source: str,
    test_filename: str,
) -> dict[str, list[str] | str]:
    """Src dirs and test files the property's import graph actually needs."""
    contract_rel = contract_rel.replace("\\", "/")
    contract_path = (repo / contract_rel).resolve()
    test_path = (repo / "test" / test_filename).resolve()
    remaps = _remappings(repo)
    sources = {contract_path: patched_source, test_path: test_source}
    seen: set[Path] = set()
    queue: list[Path] = [contract_path, test_path]
    while queue:
        current = queue.pop()
        if current in seen:
            continue
        seen.add(current)
        text = sources.get(current)
        if text is None:
            if not current.is_file():
                continue
            text = current.read_text(errors="ignore")
        for spec in _IMPORT_RE.findall(text):
            resolved = _resolve_import(repo, current, spec, remaps)
            if resolved is not None and resolved not in seen:
                queue.append(resolved)

    src_root = (repo / "src").resolve()
    keep_dirs: set[str] = set()
    keep_files: set[str] = set()
    keep_tests: set[str] = {test_filename}
    rel_parts = PurePosixPath(contract_rel).parts
    if len(rel_parts) > 1 and rel_parts[0] == "src":
        keep_dirs.add(rel_parts[1])
    test_root = (repo / "test").resolve()
    for path in seen:
        try:
            src_rel = path.resolve().relative_to(src_root)
        except ValueError:
            src_rel = None
        if src_rel is not None and src_rel.parts:
            if len(src_rel.parts) == 1:
                keep_files.add(src_rel.name)
            else:
                keep_dirs.add(src_rel.parts[0])
            continue
        try:
            test_rel = path.resolve().relative_to(test_root)
        except ValueError:
            continue
        if test_rel.parts:
            keep_tests.add(test_rel.as_posix())
    contract = _halmos_contract_name(test_source)
    if not _IDENT_RE.fullmatch(contract):
        contract = ""
    return {
        "keep_src_dirs": sorted(keep_dirs),
        "keep_src_files": sorted(keep_files),
        "keep_test_rels": sorted(keep_tests),
        "contract": contract,
    }


def run_halmos_against_patch(
    repo_ro: Path,
    workspace_rw: Path,
    contract_rel: str,
    patched_source: str,
    test_source: str,
    sandbox: SandboxRunner | None = None,
    timeout_s: int = 120,
    test_filename: str = "Verify.t.sol",
) -> ForgeResult:
    """Run a Halmos symbolic property test against the patched contract, bounded
    by `timeout_s` (the shell `timeout` returns 124 on expiry).

    Halmos builds the whole Foundry project. Sibling sources that are not on
    the property's import graph are removed first, so one broken challenge
    cannot fail the build of the contract under test.

    The build targets the Paris EVM with dynamic test linking off. Foundry's
    default EVM (Osaka) emits MCOPY (opcode 0x5e), and dynamic linking rewrites
    `new Contract()` into `vm.deployCode`, neither of which Halmos 0.1.13 can
    execute. Paris still compiles solc 0.8.25, and native CREATE is what Halmos
    runs in setUp().
    """
    sandbox = sandbox or SandboxRunner()
    workspace_rw.mkdir(parents=True, exist_ok=True)
    test_source = _normalize_halmos_source(test_source)
    (workspace_rw / "patched.sol").write_text(patched_source, encoding="utf-8")
    (workspace_rw / test_filename).write_text(test_source, encoding="utf-8")
    scope = _halmos_scope(repo_ro, contract_rel, patched_source, test_source, test_filename)
    (workspace_rw / "halmos_scope.json").write_text(json.dumps(scope), encoding="utf-8")
    (workspace_rw / "halmos_isolate.py").write_text(_ISOLATE_PY, encoding="utf-8")
    contract = str(scope["contract"])
    halmos_args = f"--contract {contract} --function check_" if contract else "--function check_"
    log.info("halmos scope: contract=%s src=%s", contract or "(any)", scope["keep_src_dirs"])
    cmd = (
        "rm -rf /work/target; cp -r /repo/. /work/target 2>/dev/null; "
        f"cp /work/patched.sol '/work/target/{contract_rel}' && "
        f"mkdir -p /work/target/test && cp /work/{test_filename} /work/target/test/{test_filename} && "
        "python3 /work/halmos_isolate.py && "
        "cd /work/target && FOUNDRY_EVM_VERSION=paris FOUNDRY_DYNAMIC_TEST_LINKING=false "
        f"timeout {timeout_s} halmos {halmos_args} 2>&1"
    )
    return _to_result(sandbox.run(cmd, repo_ro, workspace_rw))


def _to_result(res) -> ForgeResult:
    out = (res.stdout or "") + (res.stderr or "")
    # `forge test` exits non-zero on both compile failure and test failure, so
    # we separate the two by scanning the log.
    compiled = "Compiler run failed" not in out and "Compilation failed" not in out
    passed = res.exit_code == 0 and " FAIL" not in out and not res.timed_out
    return ForgeResult(
        compiled=compiled,
        passed=passed,
        exit_code=res.exit_code,
        output=out,
        timed_out=res.timed_out,
    )
