"""Central configuration.

All tunables live here and are overridable via environment variables or a
`.env` file (see `.env.example`). Nothing else in the codebase should read
`os.environ` directly — import `settings` from this module instead.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="REDFORGE_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- LLM routing -------------------------------------------------------
    # Cheap model for scouting/summarising, strong model for strategy/patching.
    anthropic_api_key: str = Field(default="", description="Anthropic API key")
    model_cheap: str = Field(default="claude-haiku-4-5-20251001")
    model_strong: str = Field(default="claude-opus-4-8")
    max_tokens: int = Field(default=8192)

    # --- Sandbox -----------------------------------------------------------
    sandbox_image: str = Field(default="redforge-sandbox:latest")
    sandbox_memory: str = Field(default="2g")
    sandbox_cpus: float = Field(default=2.0)
    sandbox_pids_limit: int = Field(default=256)
    sandbox_timeout_s: int = Field(default=600)
    sandbox_network: str = Field(default="none")  # never give exploit code network

    # --- Agent loop --------------------------------------------------------
    poc_max_retries: int = Field(default=3)  # self-correction attempts per hypothesis
    poc_max_hypotheses: int = Field(default=5)  # hard cap on hypotheses attempted per run
    poc_priority_floor: int = Field(default=150)  # skip hypotheses below this priority
    poc_stop_on_first_confirmation: bool = Field(default=True)  # one proof ends the loop

    # --- Strategist prompt budget -----------------------------------------
    # The strategist's single strong-model call is the dominant per-run cost.
    # Feeding it every finding (1000+ on a big repo) is mostly noise, so cut
    # low-value findings before building the prompt. Agent-originated hypotheses
    # (via the code index) still cover anything dropped here.
    strategist_min_severity: str = Field(default="low")  # drop 'info' findings
    strategist_max_findings: int = Field(default=80)      # cap after severity sort

    # --- Remediation -------------------------------------------------------
    remediation_max_retries: int = Field(default=3)  # patch self-correction budget

    # --- Verification ------------------------------------------------------
    halmos_timeout_s: int = Field(default=120)  # symbolic proof budget; timeout != refutation

    # --- Paths -------------------------------------------------------------
    work_root: Path = Field(default=Path(".redforge_work"))
    benchmarks_root: Path = Field(default=Path("benchmarks"))
    reports_root: Path = Field(default=Path("reports"))

    # --- Observability -----------------------------------------------------
    langfuse_public_key: str = Field(default="")
    langfuse_secret_key: str = Field(default="")
    langfuse_host: str = Field(default="https://cloud.langfuse.com")

    def ensure_dirs(self) -> None:
        for p in (self.work_root, self.reports_root):
            p.mkdir(parents=True, exist_ok=True)


settings = Settings()
