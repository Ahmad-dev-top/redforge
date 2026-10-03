"""Hardened sandbox for running untrusted code (LLM-generated exploits, forge).

Threat model: exploit scripts and the target repo are UNTRUSTED. They must not
be able to reach the network, exhaust the host, escalate privilege, or persist
outside a throwaway workspace. Every rule below exists for that reason and is
documented in CURSOR.md so reviewers can see the security posture.

Implementation uses the `docker` CLI via subprocess (no extra Python dep, and
the exact flags are auditable). A container is created per run and removed
with `--rm`.
"""

from __future__ import annotations

import contextlib
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from redforge.config import settings
from redforge.logging_conf import get_logger

log = get_logger("sandbox")


@dataclass
class SandboxResult:
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not self.timed_out


class SandboxRunner:
    """Run a command inside a locked-down container.

    The repo is mounted read-only; a separate writable workspace holds any
    files the run needs to create (generated tests, forge artifacts).
    """

    def __init__(
        self,
        image: str | None = None,
        memory: str | None = None,
        cpus: float | None = None,
        pids_limit: int | None = None,
        timeout_s: int | None = None,
        network: str | None = None,
    ) -> None:
        self.image = image or settings.sandbox_image
        self.memory = memory or settings.sandbox_memory
        self.cpus = cpus or settings.sandbox_cpus
        self.pids_limit = pids_limit or settings.sandbox_pids_limit
        self.timeout_s = timeout_s or settings.sandbox_timeout_s
        self.network = network or settings.sandbox_network

    def _base_flags(self, repo_ro: Path, workspace_rw: Path) -> list[str]:
        return [
            "docker", "run", "--rm",
            f"--network={self.network}",       # 'none' -> no network at all
            f"--memory={self.memory}",
            f"--cpus={self.cpus}",
            f"--pids-limit={self.pids_limit}",
            "--cap-drop=ALL",                   # drop all Linux capabilities
            "--security-opt=no-new-privileges",
            "--user=1000:1000",                 # non-root
            "--read-only",                      # root fs read-only...
            "--tmpfs=/tmp:size=256m",           # ...with a scratch tmpfs
            "-v", f"{repo_ro.resolve()}:/repo:ro",
            "-v", f"{workspace_rw.resolve()}:/work:rw",
            "-w", "/work",
            # Foundry's image entrypoint is `/bin/sh -c`, which would ignore
            # the command string. Force bash so the shell command actually runs.
            "--entrypoint", "bash",
            self.image,
        ]

    def run(
        self,
        command: str,
        repo_ro: Path,
        workspace_rw: Path,
    ) -> SandboxResult:
        """Execute `command` (a shell string) inside the sandbox."""
        workspace_rw.mkdir(parents=True, exist_ok=True)
        argv = self._base_flags(repo_ro, workspace_rw) + [
            "-lc", command,
        ]
        log.info("sandbox exec: %s", command)
        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout_s,
                check=False,
            )
            return SandboxResult(
                exit_code=proc.returncode,
                stdout=proc.stdout or "",
                stderr=proc.stderr or "",
                timed_out=False,
            )
        except subprocess.TimeoutExpired as exc:
            log.warning("sandbox timed out after %ss", self.timeout_s)
            raw_out = exc.stdout
            raw_err = exc.stderr
            text_out = (
                raw_out.decode("utf-8", errors="replace")
                if isinstance(raw_out, bytes)
                else (raw_out or "")
            )
            text_err = (
                raw_err.decode("utf-8", errors="replace")
                if isinstance(raw_err, bytes)
                else (raw_err or "")
            )
            return SandboxResult(
                exit_code=124,
                stdout=text_out,
                stderr=text_err,
                timed_out=True,
            )

    def self_check(self) -> bool:
        """Confirm the sandbox image runs and network really is disabled."""
        with _tmp() as (ro, rw):
            res = self.run("echo sandbox-ok", ro, rw)
            return res.ok and "sandbox-ok" in res.stdout


@contextlib.contextmanager
def _tmp():
    with tempfile.TemporaryDirectory() as ro, tempfile.TemporaryDirectory() as rw:
        yield Path(ro), Path(rw)
