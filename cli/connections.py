"""
Connections from the terminal - /providers, /connect, /disconnect, /test,
/model. Reuses siem_providers.py (the same store the dashboard uses) and
llm.get_provider, so nothing here is a parallel implementation.

Secrets are read with getpass (never echoed, never printed back): listings
always go through siem_providers.redact_provider. /model changes the LLM
backend for THIS CLI process only - .env is not edited.
"""

from __future__ import annotations

import getpass
from collections.abc import Callable
from typing import Any

import siem_providers as store
from config import cfg

_MODEL_ATTRS = {
    "anthropic": "ANTHROPIC_MODEL",
    "openai": "OPENAI_MODEL",
    "google": "GOOGLE_MODEL",
    "freellmapi": "FREELLMAPI_MODEL",
}


def platforms() -> dict[str, Any]:
    from connectors.siem import PLATFORM_FIELDS

    return PLATFORM_FIELDS


def list_providers() -> list[dict[str, Any]]:
    return [store.redact_provider(p) for p in store.load_providers()]


def _coerce(field: dict[str, Any], raw: str) -> Any:
    if field.get("type") == "boolean":
        return raw.strip().lower() in ("1", "true", "yes", "y", "on")
    return raw


def connect(
    platform: str,
    *,
    name: str | None = None,
    ask: Callable[[str], str] = input,
    ask_secret: Callable[[str], str] = getpass.getpass,
) -> dict[str, Any]:
    """Prompt for each platform field and save the connection. Returns the
    REDACTED provider record."""
    spec = platforms().get(platform)
    if not spec:
        raise ValueError(
            f"Unknown platform '{platform}'. Choose from: {', '.join(sorted(platforms()))}"
        )
    name = (
        name
        or ask(f"Connection name [{spec.get('label', platform)}]: ").strip()
        or spec.get("label", platform)
    )
    config: dict[str, Any] = {}
    for f in spec.get("fields", []):
        label = f.get("label", f["key"])
        hint = f" ({f['placeholder']})" if f.get("placeholder") else ""
        default = f.get("default")
        suffix = f" [{default}]" if default is not None else ""
        prompt = f"  {label}{hint}{suffix}{' *' if f.get('required') else ''}: "
        raw = (ask_secret if f.get("secret") else ask)(prompt).strip()
        if not raw:
            if default is not None:
                config[f["key"]] = default
                continue
            if f.get("required"):
                raise ValueError(f"'{label}' is required.")
            continue
        config[f["key"]] = _coerce(f, raw)
    provider = store.add_provider({"name": name, "platform": platform, "config": config})
    return store.redact_provider(provider)


def remove(provider_id: str) -> bool:
    return store.remove_provider(provider_id)


def test(provider_id: str) -> dict[str, Any]:
    p = store.get_provider(provider_id)
    if not p:
        return {"ok": False, "error": f"No provider '{provider_id}'."}
    try:
        return {"ok": True, **(store.connector_for(p).test_connection() or {})}
    except Exception as e:  # noqa: BLE001 - surface, don't crash the REPL
        return {"ok": False, "error": str(e)}


def llm_backends() -> list[str]:
    import llm

    return sorted(getattr(llm, "_PROVIDERS", {}) or [])


def current_model() -> dict[str, str]:
    backend = (cfg.LLM_PROVIDER or "").lower()
    attr = _MODEL_ATTRS.get(backend)
    model = (getattr(cfg, attr, "") if attr else "") or getattr(cfg, "AGENT_MODEL", "")
    return {"backend": backend, "model": model}


def set_model(backend: str, model: str | None = None) -> dict[str, str]:
    """Switch backend (and optionally model) for this process. Validates by
    constructing the provider; on failure nothing is changed."""
    from llm import get_provider

    backend = backend.strip().lower()
    attr = _MODEL_ATTRS.get(backend)
    old = {
        "LLM_PROVIDER": cfg.LLM_PROVIDER,
        (attr or "AGENT_MODEL"): getattr(cfg, attr or "AGENT_MODEL", ""),
    }
    try:
        cfg.LLM_PROVIDER = backend
        if model:
            setattr(cfg, attr or "AGENT_MODEL", model)
        get_provider(backend)  # raises on unknown backend / missing credentials
    except Exception:
        for k, v in old.items():
            setattr(cfg, k, v)
        raise
    return current_model()
