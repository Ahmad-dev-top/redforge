"""Run the DVD audit and write the portfolio artifacts.

Throwaway driver. Not part of the importable package.
"""

from __future__ import annotations

from pathlib import Path

from redforge.llm import AnthropicLLM
from redforge.logging_conf import configure_logging
from redforge.runner import audit_repo
from redforge.sandbox import SandboxRunner

URL = "https://github.com/theredguild/damn-vulnerable-defi"
OUT = Path(__file__).resolve().parents[1] / "showcase" / "dvd-unstoppable"


class RecordingSandbox(SandboxRunner):
    """Same runner; keeps each command's combined output for the trace file."""

    def __init__(self) -> None:
        super().__init__()
        self.outputs: list[tuple[str, str]] = []

    def run(self, command: str, repo_ro: Path, workspace_rw: Path):
        res = super().run(command, repo_ro, workspace_rw)
        self.outputs.append((command, (res.stdout or "") + (res.stderr or "")))
        return res


def main() -> None:
    configure_logging()
    sandbox = RecordingSandbox()
    state = audit_repo(URL, AnthropicLLM(), sandbox)
    vuln = state.vulnerabilities[0]
    patch = vuln.patch
    poc = vuln.poc
    hyp = vuln.hypothesis
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "patch.diff").write_text(patch.diff if patch else "", encoding="utf-8")
    (OUT / "Exploit.t.sol").write_text(poc.test_source if poc else "", encoding="utf-8")
    poc_trace = poc.trace_excerpt if poc else ""
    rem = "\n".join(text for cmd, text in sandbox.outputs if "patched.sol" in cmd)
    (OUT / "trace_tail.txt").write_text(
        "=== poc trace (oracle present) ===\n"
        + poc_trace
        + "\n\n=== remediation forge (oracle absent) ===\n"
        + rem,
        encoding="utf-8",
    )
    summary = (
        f"# DVD Unstoppable\n\n"
        f"- status: {state.status.value}\n"
        f"- hypothesis: {hyp.id if hyp else ''} "
        f"{hyp.target_contract if hyp else ''}.{hyp.target_function if hyp else ''}\n"
        f"- oracle: {hyp.oracle.value if hyp else ''}\n"
        f"- poc attempt: {poc.attempt if poc else ''}\n"
        f"- patch attempts: {patch.attempts if patch else ''}\n"
        f"- compiles: {patch.compiles if patch else ''}\n"
        f"- poc_defeated: {patch.poc_defeated if patch else ''}\n"
        f"- printed cost: ${state.token_cost_usd:.4f}\n"
    )
    (OUT / "summary.md").write_text(summary, encoding="utf-8")
    print(summary)


if __name__ == "__main__":
    main()
