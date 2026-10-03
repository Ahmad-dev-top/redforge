"""LLM access, injected into agents so tests can stub it.

Agents never import the Anthropic SDK directly — they receive an `LLMClient`.
In production that's `AnthropicLLM`; in tests it's `StubLLM` with a canned
reply. Every call returns an `LLMResult` carrying the USD cost so the graph can
accumulate `state.token_cost_usd`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from redforge.config import settings
from redforge.logging_conf import get_logger

log = get_logger("llm")

# List price per 1M tokens (input, output). Verified against
# docs.claude.com/en/docs/about-claude/pricing (Oct 2026): Opus 4.8 $5/$25,
# Sonnet 4.6 $3/$15, Haiku 4.5 $1/$5. Keyed by substring of the model id.
# These only affect the cost *estimate*, not logic — refresh when prices change.
_PRICING: dict[str, tuple[float, float]] = {
    "opus": (5.0, 25.0),
    "sonnet": (3.0, 15.0),
    "haiku": (1.0, 5.0),
}


def _price_for(model: str) -> tuple[float, float]:
    for key, price in _PRICING.items():
        if key in model:
            return price
    return _PRICING["haiku"]


def estimate_cost(model: str, input_tokens: int, output_tokens: int) -> float:
    pin, pout = _price_for(model)
    return input_tokens / 1e6 * pin + output_tokens / 1e6 * pout


@dataclass
class LLMResult:
    text: str
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0


class LLMClient(Protocol):
    def complete(
        self, *, system: str, prompt: str, model: str, max_tokens: int | None = None
    ) -> LLMResult: ...


class AnthropicLLM:
    """Real client. Imports the SDK lazily so the package imports without it."""

    def __init__(self, api_key: str | None = None) -> None:
        self._api_key = api_key or settings.anthropic_api_key
        self._client = None

    def _ensure(self):
        if self._client is None:
            import anthropic  # lazy

            if not self._api_key:
                raise RuntimeError(
                    "No Anthropic API key. Set REDFORGE_ANTHROPIC_API_KEY in .env"
                )
            self._client = anthropic.Anthropic(api_key=self._api_key)
        return self._client

    def complete(
        self, *, system: str, prompt: str, model: str, max_tokens: int | None = None
    ) -> LLMResult:
        client = self._ensure()
        resp = client.messages.create(
            model=model,
            max_tokens=max_tokens or settings.max_tokens,
            system=system,
            messages=[{"role": "user", "content": prompt}],
        )
        text = "".join(
            block.text for block in resp.content if getattr(block, "type", "") == "text"
        )
        itok = resp.usage.input_tokens
        otok = resp.usage.output_tokens
        return LLMResult(
            text=text,
            input_tokens=itok,
            output_tokens=otok,
            cost_usd=estimate_cost(model, itok, otok),
        )


class StubLLM:
    """Test double. Returns queued replies (or a single fixed one), records
    every call, and reports a flat cost so cost-accumulation is exercised."""

    def __init__(self, replies: list[str] | str, cost_usd: float = 0.001) -> None:
        self._queue = [replies] if isinstance(replies, str) else list(replies)
        self._cost = cost_usd
        self.calls: list[dict[str, str]] = []

    def complete(
        self, *, system: str, prompt: str, model: str, max_tokens: int | None = None
    ) -> LLMResult:
        self.calls.append({"system": system, "prompt": prompt, "model": model})
        text = self._queue.pop(0) if self._queue else "{}"
        return LLMResult(text=text, input_tokens=100, output_tokens=100, cost_usd=self._cost)
