"""
FreeLLMAPI provider - one unified API key for many free LLM providers.

FreeLLMAPI (https://freellmapi.co / github.com/tashfeenahmed/freellmapi)
aggregates dozens of free LLM provider tiers behind a single OpenAI-compatible
endpoint. You paste your provider keys into its dashboard once, grab the
unified `freellmapi-...` key, and point this provider at it:

    FREELLMAPI_API_KEY=freellmapi-your-unified-key
    FREELLMAPI_BASE_URL=http://localhost:3001/v1   # self-hosted default
    FREELLMAPI_MODEL=auto                          # router picks the best model

Because the gateway speaks the OpenAI `/chat/completions` protocol, this
provider is a thin subclass of OpenAICompatProvider that reuses the exact
wire logic (tool calling included) and logs which upstream provider actually
served each call via the `X-Routed-Via` response header.

Rate-limit handling: when the gateway exhausts the free-tier quota of the
routed provider it answers 429. After the bounded retries in the base
transport fail, this provider makes ONE extra attempt with an explicit
alternate model (a different provider family than the last one that routed
successfully, pulled from the gateway's own /v1/models list). The fallback is
gated by FREELLMAPI_FALLBACK_ENABLED, cached, and only fires *on failure* -
the happy path performs identical request volume to before.
"""

from __future__ import annotations

import time

import requests

from config import cfg
from llm.base import LLMRateLimitedError, LLMResponse, trace_llm
from llm.openai_compat_provider import OpenAICompatProvider

DEFAULT_BASE_URL = "http://localhost:3001/v1"  # FreeLLMAPI self-hosted gateway
DEFAULT_MODEL = "auto"  # let the router pick; or auto:fast / auto:smart / profile / model id

# Router-only pseudo-models - never worth picking as an explicit fallback.
_NON_FALLBACK_MODELS = {"auto", "fusion", "auto:fast", "auto:smart"}


class FreeLLMAPIProvider(OpenAICompatProvider):
    name = "freellmapi"

    def __init__(self):
        self._api_key = cfg.FREELLMAPI_API_KEY
        self._base_url = (cfg.FREELLMAPI_BASE_URL or DEFAULT_BASE_URL).rstrip("/")
        self.last_routed_via: str | None = None
        self._models_cache: tuple[float, list[str]] | None = None  # (fetched_ts, ids)
        # Provider families that failed as fallback candidates (404/429).
        # Fallback is best-effort; learning which families the key doesn't
        # cover keeps repeated rate-limited chats from retrying the same dead
        # model - they converge on the first model that actually routes.
        self._bad_families: dict[str, float] = {}

    def _model(self) -> str:
        return cfg.FREELLMAPI_MODEL or DEFAULT_MODEL

    @staticmethod
    def _family(provider_or_model: str | None) -> str | None:
        """First path segment of 'x-routed-via' or a model id -> provider family.

        'aion/aion-labs/aion-3.0' -> 'aion'; 'claude-opus-4-5' -> 'claude-opus-4-5'.
        """
        if not provider_or_model:
            return None
        first = provider_or_model.split("/", 1)[0].strip().lower()
        return first or None

    def _available_models(self) -> list[str]:
        """Gateway's model list, cached for FREELLMAPI_FALLBACK_MODELS_TTL s.

        Never cached on failure (so a transient gateway blip doesn't poison
        fallback selection) and never logged (it goes out with the API key).
        """
        now = time.time()
        cached = self._models_cache
        if cached and now - cached[0] < cfg.FREELLMAPI_FALLBACK_MODELS_TTL:
            return cached[1]
        try:
            resp = requests.get(f"{self._base_url}/models", headers=self._headers(), timeout=10)
            resp.raise_for_status()
            data = resp.json().get("data") or []
            models = [m.get("id") for m in data if isinstance(m, dict) and m.get("id")]
        except Exception:  # noqa: BLE001 - fallback is best-effort
            return []
        self._models_cache = (now, models)
        return models

    def _select_fallback_model(self) -> str | None:
        """Pick an explicit model from a different family than the last route.

        Returns None when fallback is disabled, the model list is unavailable,
        or every candidate shares the last-routed provider family (or is a
        family that previously failed as a fallback candidate).
        """
        if not cfg.FREELLMAPI_FALLBACK_ENABLED:
            return None
        exclude_family = self._family(self.last_routed_via)
        now = time.time()
        ttl = cfg.FREELLMAPI_FALLBACK_MODELS_TTL
        bad = {f for f, ts in self._bad_families.items() if now - ts < ttl}
        for mid in self._available_models():
            if mid in _NON_FALLBACK_MODELS:
                continue
            family = self._family(mid)
            if exclude_family and family == exclude_family:
                continue
            if family in bad:
                continue
            return mid
        return None

    def _remember_fallback_failure(self, model: str) -> None:
        family = self._family(model)
        if family:
            self._bad_families[family] = time.time()

    def chat(self, *, system, messages, tools, max_tokens) -> LLMResponse:
        request_id = uuid_hex()
        model = self._model()
        try:
            resp = self._build_and_post(
                system=system,
                messages=messages,
                tools=tools,
                max_tokens=max_tokens,
                model=model,
                request_id=request_id,
            )
        except LLMRateLimitedError as primary:
            fallback_model = self._select_fallback_model()
            if not fallback_model:
                raise
            trace_llm(
                event="llm.fallback",
                request_id=request_id,
                from_model=model,
                to_model=fallback_model,
            )
            try:
                resp = self._build_and_post(
                    system=system,
                    messages=messages,
                    tools=tools,
                    max_tokens=max_tokens,
                    model=fallback_model,
                    request_id=f"{request_id}-fb",
                )
            except LLMRateLimitedError as fb:
                self._remember_fallback_failure(fallback_model)
                trace_llm(
                    event="llm.fallback_failed",
                    request_id=request_id,
                    to_model=fallback_model,
                    error=str(fb)[:120],
                )
                raise primary from fb
            except Exception as other:  # noqa: BLE001 - surface the primary 429
                self._remember_fallback_failure(fallback_model)
                trace_llm(
                    event="llm.fallback_failed",
                    request_id=request_id,
                    to_model=fallback_model,
                    error=str(other)[:120],
                )
                raise primary from other

        routed = resp.headers.get("x-routed-via")
        if routed:
            self.last_routed_via = routed
            trace_llm(event="llm.routed", request_id=request_id, provider=routed)

        out = self._parse_response(resp)
        out.request_id = request_id
        trace_llm(
            event="llm.done",
            request_id=request_id,
            model=resp.json().get("model"),
            status=resp.status_code,
            usage=out.usage or None,
            provider=routed,
        )
        return out


def uuid_hex() -> str:
    """Tiny seam so tests can pin request ids if ever needed."""
    import uuid

    return uuid.uuid4().hex[:12]
