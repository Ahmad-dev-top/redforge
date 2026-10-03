"""Thin wrapper around `forge test`, always executed inside the sandbox.

Anvil/forge run against a LOCAL fork only. No RPC broadcast, no private keys,
no mainnet writes — the sandbox has no network at all, which enforces this.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

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
    (workspace_rw / test_filename).write_text(test_source)
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
    (workspace_rw / "patched.sol").write_text(patched_source)
    (workspace_rw / test_filename).write_text(test_source)
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
    (workspace_rw / "patched.sol").write_text(patched_source)
    cmd = (
        "rm -rf /work/target; cp -r /repo/. /work/target 2>/dev/null; "
        f"cp /work/patched.sol '/work/target/{contract_rel}' && cd /work/target && "
        f"forge test -vv --no-match-path '{exclude}' 2>&1"
    )
    return _to_result(sandbox.run(cmd, repo_ro, workspace_rw))


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
    by `timeout_s` (the shell `timeout` returns 124 on expiry)."""
    sandbox = sandbox or SandboxRunner()
    workspace_rw.mkdir(parents=True, exist_ok=True)
    (workspace_rw / "patched.sol").write_text(patched_source)
    (workspace_rw / test_filename).write_text(test_source)
    cmd = (
        "rm -rf /work/target; cp -r /repo/. /work/target 2>/dev/null; "
        f"cp /work/patched.sol '/work/target/{contract_rel}' && "
        f"mkdir -p /work/target/test && cp /work/{test_filename} /work/target/test/{test_filename} && "
        f"cd /work/target && timeout {timeout_s} halmos --match-path 'test/{test_filename}' 2>&1"
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
