"""Lightweight Solidity source index.

Extracts contracts and their functions by regex — no compilation, so it works
offline and even when dependencies are missing. This is what lets the Strategist
target functions on a repo Slither could not compile. It is a heuristic, not a
parser: good enough to name targets, not to reason about semantics.
"""

from __future__ import annotations

import re
from pathlib import Path

from redforge.logging_conf import get_logger
from redforge.schemas import FunctionRef

log = get_logger("code_index")

_CONTRACT_RE = re.compile(r"\b(?:contract|library|interface)\s+([A-Za-z_]\w*)")
_FUNCTION_RE = re.compile(r"\bfunction\s+([A-Za-z_]\w*)\s*\(([^)]*)\)([^\{;]*)")


def index_source(text: str, rel_path: str) -> list[FunctionRef]:
    """Index a single source file's functions, attributing each to the nearest
    preceding contract/library/interface declaration."""
    refs: list[FunctionRef] = []
    # Map each function match to the contract whose declaration precedes it.
    contracts = [(m.start(), m.group(1)) for m in _CONTRACT_RE.finditer(text)]

    def owner(pos: int) -> str:
        name = "<file>"
        for start, cname in contracts:
            if start < pos:
                name = cname
            else:
                break
        return name

    for m in _FUNCTION_RE.finditer(text):
        name, params, tail = m.group(1), m.group(2).strip(), m.group(3).strip()
        sig = f"function {name}({params}) {tail}".strip()
        refs.append(
            FunctionRef(
                contract=owner(m.start()),
                function=name,
                file=rel_path,
                signature=re.sub(r"\s+", " ", sig),
            )
        )
    return refs


def build_index(root: Path | str, contract_files: list[str]) -> list[FunctionRef]:
    root = Path(root)
    out: list[FunctionRef] = []
    for rel in contract_files:
        p = root / rel
        try:
            text = p.read_text(errors="ignore")
        except OSError:
            continue
        out.extend(index_source(text, rel))
    log.info("indexed %d functions across %d files", len(out), len(contract_files))
    return out
