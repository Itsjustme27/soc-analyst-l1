"""
LLM backend factory.

    LLM_PROVIDER=anthropic|openai|google|mock|freellmapi   (env, default: anthropic)

  - anthropic  : Anthropic Claude (original default)
  - openai     : any OpenAI-compatible /chat/completions endpoint
                 (OpenAI, OpenRouter, Ollama, vLLM, LM Studio, DeepSeek, ...)
                 via OPENAI_BASE_URL
  - google     : Google Gemini (REST API)
  - mock       : deterministic offline provider - no API key, for dev/CI/demos
  - freellmapi : unified-key gateway to dozens of free LLM providers
                 (FREELLMAPI_API_KEY + FREELLMAPI_BASE_URL, model defaults to
                 'auto' so the gateway routes per request)

To add another provider: implement llm/base.LLMProvider, drop the file in
this package, and register it in _PROVIDERS below. Nothing else changes.
"""

from __future__ import annotations

from config import cfg
from llm.anthropic_provider import AnthropicProvider
from llm.base import LLMProvider, LLMResponse, ToolCall
from llm.freellmapi_provider import FreeLLMAPIProvider
from llm.google_provider import GoogleProvider
from llm.mock_provider import MockProvider
from llm.openai_compat_provider import OpenAICompatProvider

_PROVIDERS: dict[str, type[LLMProvider]] = {
    "anthropic": AnthropicProvider,
    "openai": OpenAICompatProvider,
    "google": GoogleProvider,
    "mock": MockProvider,
    "freellmapi": FreeLLMAPIProvider,
}


def get_provider(name: str | None = None) -> LLMProvider:
    """Return an LLMProvider. `name` overrides the LLM_PROVIDER env var."""
    key = (name or cfg.LLM_PROVIDER).strip().lower()
    try:
        cls = _PROVIDERS[key]
    except KeyError:
        raise ValueError(
            f"Unknown LLM_PROVIDER '{key}'. Available providers: "
            f"{', '.join(sorted(_PROVIDERS))} (set LLM_PROVIDER in .env)"
        ) from None
    return cls()


__all__ = ["get_provider", "LLMProvider", "LLMResponse", "ToolCall"]
