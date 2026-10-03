"""Run Slither and normalise its output into `Finding` objects.

Slither runs INSIDE the sandbox (it compiles the untrusted repo). We invoke it
with `--json -` and parse the detector list. The mapping from Slither's
impact/confidence to our `Severity`/`VulnClass` is centralised here so the rest
of the pipeline speaks one vocabulary.
"""

from __future__ import annotations

import json
from pathlib import Path

from redforge.logging_conf import get_logger
from redforge.sandbox import SandboxRunner
from redforge.schemas import Finding, Severity, VulnClass

log = get_logger("slither")

_IMPACT_TO_SEV = {
    "High": Severity.HIGH,
    "Medium": Severity.MEDIUM,
    "Low": Severity.LOW,
    "Informational": Severity.INFO,
    "Optimization": Severity.INFO,
}

_CONF = {"High": 0.9, "Medium": 0.6, "Low": 0.3}

# Slither detector check -> our taxonomy (extend as coverage grows).
_CHECK_TO_CLASS = {
    "reentrancy-eth": VulnClass.REENTRANCY,
    "reentrancy-no-eth": VulnClass.REENTRANCY,
    "reentrancy-benign": VulnClass.REENTRANCY,
    "arbitrary-send-eth": VulnClass.ACCESS_CONTROL,
    "suicidal": VulnClass.ACCESS_CONTROL,
    "unprotected-upgrade": VulnClass.ACCESS_CONTROL,
    "tx-origin": VulnClass.ACCESS_CONTROL,
    "unchecked-transfer": VulnClass.UNCHECKED_CALL,
    "unchecked-lowlevel": VulnClass.UNCHECKED_CALL,
    "weak-prng": VulnClass.BAD_RANDOMNESS,
    "divide-before-multiply": VulnClass.ARITHMETIC,
    "incorrect-equality": VulnClass.LOGIC,
}


def _classify(check: str) -> VulnClass:
    return _CHECK_TO_CLASS.get(check, VulnClass.OTHER)


def parse_slither_json(raw: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        log.warning("could not parse slither json")
        return findings
    if not data.get("success"):
        log.warning("slither reported failure")
    detectors = (data.get("results") or {}).get("detectors", [])
    for i, d in enumerate(detectors):
        elements = d.get("elements", [])
        contract = fn = file = None
        lines: list[int] = []
        if elements:
            first = elements[0]
            contract = first.get("type_specific_fields", {}).get("parent", {}).get("name")
            fn = first.get("name") if first.get("type") == "function" else fn
            src = first.get("source_mapping", {})
            file = src.get("filename_relative")
            lines = src.get("lines", []) or []
        findings.append(
            Finding(
                id=f"slither-{i}",
                detector=d.get("check", "unknown"),
                vuln_class=_classify(d.get("check", "")),
                severity=_IMPACT_TO_SEV.get(d.get("impact", "Informational"), Severity.INFO),
                confidence=_CONF.get(d.get("confidence", "Low"), 0.3),
                contract=contract,
                function=fn,
                file=file,
                lines=lines,
                description=(d.get("description") or "").strip(),
                source="static",
            )
        )
    log.info("slither produced %d findings", len(findings))
    return findings


_FRAMEWORK_MARKERS = (
    "foundry.toml",
    "hardhat.config.js",
    "hardhat.config.ts",
    "truffle-config.js",
    "truffle.js",
    "brownie-config.yaml",
)
_SKIP_DIRS = {"node_modules", "lib", ".git", "out", "artifacts", "cache", "coverage"}


def _sh_quote(text: str) -> str:
    return "'" + text.replace("'", "'\\''") + "'"


def _plain_contract_files(repo: Path) -> list[str]:
    """Relative .sol paths for a repo that is not a Foundry/Hardhat/Truffle project."""
    if any((repo / name).exists() for name in _FRAMEWORK_MARKERS):
        return []
    files: list[str] = []
    for path in repo.rglob("*.sol"):
        rel = path.relative_to(repo)
        if any(part in _SKIP_DIRS or part == "test" for part in rel.parts):
            continue
        if path.name.endswith(".t.sol") or path.name.lower().startswith("test"):
            continue
        files.append(rel.as_posix())
    return sorted(files)


def _slither_cmd(targets: list[str]) -> str:
    """One sandbox command. Logs stay in /work; stdout is a single Slither JSON object.

    A directory of unrelated contracts (SmartBugs-style, or not-so-smart-contracts)
    is not one compilation unit. Scan each file with the pragma's solc. A framework
    project is one target: `.`
    """
    # SOLC_VERSION is read by solc-select. The rootfs stays read-only.
    select = (
        "vers=$(solc-select versions | awk '{print $1}' | paste -sd, -) && "
        "mkdir -p /work/parts && rm -f /work/parts/*.json"
    )
    if len(targets) <= 1:
        target = _sh_quote(targets[0] if targets else ".")
        scan = (
            f"slither {target} --json /work/parts/0.json --solc-solcs-select \"$vers\" "
            ">/work/slither.log 2>&1 || true"
        )
    else:
        quoted = " ".join(_sh_quote(t) for t in targets)
        scan = (
            "i=0; "
            f"for f in {quoted}; do "
            "slither \"$f\" --compile-force-framework solc "
            "--json /work/parts/$i.json --solc-solcs-select \"$vers\" "
            ">/work/slither.log 2>&1 || true; "
            "i=$((i+1)); "
            "done"
        )
    merge = """python3 << 'PY'
import json
from pathlib import Path
dets = []
ok = False
for path in sorted(Path("/work/parts").glob("*.json")):
    try:
        data = json.loads(path.read_text() or "{}")
    except json.JSONDecodeError:
        continue
    ok = ok or bool(data.get("success"))
    dets.extend((data.get("results") or {}).get("detectors") or [])
print(json.dumps({"success": ok or bool(dets), "results": {"detectors": dets}}))
PY"""
    return f"cp -r /repo/. /work/target && cd /work/target && {select} && {scan}; {merge}"


def run_slither(repo_ro: Path, workspace_rw: Path, sandbox: SandboxRunner | None = None) -> list[Finding]:
    sandbox = sandbox or SandboxRunner()
    # Copy happens inside the sandbox; Slither writes its build cache under /work.
    files = _plain_contract_files(repo_ro)
    targets = files if len(files) > 1 else ["."]
    res = sandbox.run(_slither_cmd(targets), repo_ro, workspace_rw)
    return parse_slither_json(res.stdout)
