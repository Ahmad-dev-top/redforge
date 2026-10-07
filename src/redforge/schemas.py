"""Typed contracts shared across the whole pipeline.

Every agent consumes and produces these models. The LangGraph state
(`AuditState`) is the single source of truth that flows through the graph.
Keeping these strict makes the graph testable and every hand-off debuggable.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


# --------------------------------------------------------------------------- #
# Enums
# --------------------------------------------------------------------------- #
class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class VulnClass(str, Enum):
    REENTRANCY = "reentrancy"
    ACCESS_CONTROL = "access_control"
    ARITHMETIC = "arithmetic"  # over/underflow, rounding
    ORACLE_MANIPULATION = "oracle_manipulation"
    UNCHECKED_CALL = "unchecked_call"
    FRONT_RUNNING = "front_running"
    DOS = "denial_of_service"
    BAD_RANDOMNESS = "bad_randomness"
    LOGIC = "business_logic"
    OTHER = "other"


class OracleType(str, Enum):
    """How the harness decides an exploit actually worked. The LLM never
    decides this; the runner checks for the oracle's sentinel."""

    BALANCE_INCREASE = "balance_increase"        # attacker gained funds
    INVARIANT_BROKEN = "invariant_broken"        # e.g. sum(balances)!=totalSupply
    UNAUTHORIZED_STATE = "unauthorized_state"    # priv state changed by non-owner
    FUNDS_LOCKED = "funds_locked"                # withdrawal path bricked


class AuditStatus(str, Enum):
    PENDING = "pending"
    MAPPED = "mapped"
    HYPOTHESES_READY = "hypotheses_ready"
    EXPLOIT_CONFIRMED = "exploit_confirmed"
    PATCHED = "patched"
    VERIFIED = "verified"
    FAILED = "failed"
    NEEDS_HUMAN = "needs_human"


# --------------------------------------------------------------------------- #
# Repository / static analysis
# --------------------------------------------------------------------------- #
class ProjectKind(str, Enum):
    FOUNDRY = "foundry"
    HARDHAT = "hardhat"
    TRUFFLE = "truffle"
    PLAIN = "plain"
    UNKNOWN = "unknown"


class RepoMap(BaseModel):
    root: str
    kind: ProjectKind = ProjectKind.UNKNOWN
    solc_version: str | None = None
    contract_files: list[str] = Field(default_factory=list)
    test_files: list[str] = Field(default_factory=list)
    remappings: list[str] = Field(default_factory=list)


class FunctionRef(BaseModel):
    """A function discovered by the Scout's source index. Built by regex, so it
    works even when the repo can't be compiled (no deps / no network). Gives the
    Strategist concrete targets independent of whether Slither produced findings."""

    contract: str
    function: str
    file: str
    signature: str = ""


class Finding(BaseModel):
    """A candidate issue from a static analyser (Slither/Aderyn) or an agent."""

    id: str
    detector: str                 # e.g. "reentrancy-eth"
    vuln_class: VulnClass = VulnClass.OTHER
    severity: Severity = Severity.INFO
    confidence: float = 0.0       # 0..1
    contract: str | None = None
    function: str | None = None
    file: str | None = None
    lines: list[int] = Field(default_factory=list)
    description: str = ""
    source: str = "static"        # "static" | "agent"


# --------------------------------------------------------------------------- #
# Agent outputs
# --------------------------------------------------------------------------- #
class AttackHypothesis(BaseModel):
    id: str
    finding_id: str | None = None
    target_contract: str
    target_function: str
    vuln_class: VulnClass
    oracle: OracleType
    rationale: str
    confidence: float = 0.0       # strategist's self-assessed likelihood (0..1)
    priority: int = 0             # higher = tried first


class PoCResult(BaseModel):
    hypothesis_id: str
    attempt: int
    compiled: bool = False
    ran: bool = False
    oracle: OracleType
    oracle_confirmed: bool = False
    exit_code: int | None = None
    trace_excerpt: str = ""       # trimmed forge trace / assertion output
    error_log: str = ""           # fed back on failure for self-correction
    test_path: str | None = None  # path to generated Exploit.t.sol
    test_source: str = ""         # the generated exploit itself — re-run vs a patch


class Patch(BaseModel):
    finding_id: str
    contract: str
    diff: str                     # unified diff, minimal
    explanation: str
    compiles: bool = False
    poc_defeated: bool = False    # the confirming exploit no longer confirms
    attempts: int = 0
    patched_source: str = ""      # full patched contract — re-applied for verification


class VerificationReport(BaseModel):
    finding_id: str
    poc_now_fails: bool = False           # the exploit no longer works
    existing_tests_pass: bool = False
    differential_equivalent: bool = False  # behaviour unchanged on safe inputs
    halmos_proved: bool = False           # symbolic proof of the property
    halmos_counterexample: str = ""
    halmos_timed_out: bool = False        # undecided within budget (not a refutation)
    verified: bool = False                # all gates green


class Vulnerability(BaseModel):
    """A fully-processed vulnerability: finding + proof + fix + verification."""

    finding: Finding
    hypothesis: AttackHypothesis | None = None
    poc: PoCResult | None = None
    patch: Patch | None = None
    verification: VerificationReport | None = None


# --------------------------------------------------------------------------- #
# Shared graph state
# --------------------------------------------------------------------------- #
class AuditState(BaseModel):
    """The single object that flows through the LangGraph graph.

    Kept as a Pydantic model for validation; LangGraph can also consume it as
    a dict. Add reducer-friendly list fields rather than mutating in place.
    """

    repo_url: str
    run_id: str
    status: AuditStatus = AuditStatus.PENDING
    repo_map: RepoMap | None = None
    scope_prefix: str = ""        # if set, scout keeps only files under this path
    # When set, scout skips Slither and filters this list. None means scan.
    seed_findings: list[Finding] | None = None
    functions: list[FunctionRef] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    hypotheses: list[AttackHypothesis] = Field(default_factory=list)
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)
    token_cost_usd: float = 0.0
    errors: list[str] = Field(default_factory=list)
