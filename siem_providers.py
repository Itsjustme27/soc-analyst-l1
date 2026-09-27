"""
Persistent store of SIEM provider connections.

Two sources are merged into one "active connection" list:

1. **Env-seeded providers** - one per platform whose credentials are set in
   `.env` (SPLUNK_HOST, QRADAR_HOST, ...), plus a mock provider. These always
   exist and cannot be deleted (edit `.env` to change them).
2. **Stored providers** - connections added at runtime through the dashboard.
   Persisted as a JSON list at SIEM_PROVIDERS_PATH (default
   data/siem_providers.json).

Each provider dict: {id, name, platform, source, enabled, config}.

`config` holds the per-connection overrides (host, token, search, ...); each
connector merges them over the matching `cfg.<PLATFORM>_*` env values, so a
provider can point at any host/tenant without touching `.env`.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from config import cfg
from connectors.siem import SIEM_PLATFORMS, SIEMConnector, get_siem_connector


@dataclass
class ProviderError(ValueError):
    message: str = ""

    def __str__(self) -> str:
        return self.message


def default_providers_path() -> Path:
    return Path(cfg.SIEM_PROVIDERS_PATH)


# --------------------------------------------------------------------------- #
def env_seeded_providers() -> list[dict[str, Any]]:
    """One provider per platform whose .env creds are configured (+ mock)."""
    providers = []

    def add(platform: str, name: str, required: tuple[str, ...]):
        if all(getattr(cfg, key) for key in required):
            providers.append(
                {
                    "id": f"env-{platform}",
                    "name": name,
                    "platform": platform,
                    "source": "env",
                    "enabled": True,
                    "config": {},
                }
            )

    add("splunk", "Splunk (env)", ("SPLUNK_HOST",))
    add("qradar", "IBM QRadar (env)", ("QRADAR_HOST",))
    add("elastic", "Elastic Security (env)", ("ELASTIC_HOST",))
    add(
        "sentinel",
        "Microsoft Sentinel (env)",
        ("SENTINEL_TENANT_ID", "SENTINEL_CLIENT_ID", "SENTINEL_WORKSPACE_ID"),
    )
    add("wazuh", "Wazuh (env)", ("WAZUH_HOST",))

    # The mock platform always works - zero credentials, useful for demos/tests.
    providers.append(
        {
            "id": "env-mock",
            "name": "Mock SIEM",
            "platform": "mock",
            "source": "env",
            "enabled": True,
            "config": {"alerts_file": cfg.MOCK_SIEM_ALERTS_FILE},
        }
    )
    return providers


def _load_stored(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return []
    return [p for p in data if isinstance(p, dict)]


def load_providers(path: Path | None = None) -> list[dict[str, Any]]:
    """Merged list: stored providers first, then env-seeded defaults."""
    path = path or default_providers_path()
    stored = _load_stored(path)
    env_ids = {p["id"] for p in env_seeded_providers()}
    # Don't duplicate a stored provider whose id collides with an env one.
    stored = [p for p in stored if p.get("id") not in env_ids]
    return stored + env_seeded_providers()


def save_providers(providers: list[dict[str, Any]], path: Path | None = None) -> None:
    path = path or default_providers_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    # Only persist dashboard-added (non-env) providers - env ones are derived.
    stored = [p for p in providers if p.get("source") != "env"]
    path.write_text(json.dumps(stored, indent=2))


def get_provider(provider_id: str, path: Path | None = None) -> dict[str, Any] | None:
    for p in load_providers(path):
        if p.get("id") == provider_id:
            return p
    return None


def redact_provider(provider: dict[str, Any]) -> dict[str, Any]:
    """Mask fields PLATFORM_FIELDS marks `secret: True` before a provider
    dict leaves the process (API responses, logs, etc). `load_providers()`/
    `get_provider()` still return the real values - `connector_for()` needs
    them to actually authenticate - so callers must redact explicitly at
    the point they hand a provider to something outside the process."""
    from connectors.siem import PLATFORM_FIELDS

    fields = (PLATFORM_FIELDS.get(provider.get("platform") or "") or {}).get("fields", [])
    secret_keys = {f["key"] for f in fields if f.get("secret")}
    if not secret_keys:
        return provider
    config = dict(provider.get("config") or {})
    for key in secret_keys:
        if config.get(key):
            config[key] = "••••••••"
    return {**provider, "config": config}


# --------------------------------------------------------------------------- #
def _validate(payload: dict[str, Any]) -> dict[str, Any]:
    name = str(payload.get("name") or "").strip()
    platform = str(payload.get("platform") or "").strip().lower()
    config = payload.get("config") or {}

    if not name:
        raise ProviderError("Name is required.")
    if platform not in SIEM_PLATFORMS:
        raise ProviderError(
            f"Unknown platform '{platform}'. Available: {', '.join(sorted(SIEM_PLATFORMS))}"
        )

    cleaned: dict[str, Any] = {}
    for item in config.items():
        key, val = item
        if isinstance(val, str):
            val = val.strip()
        if val not in (None, ""):
            cleaned[key] = val
    return {"name": name, "platform": platform, "config": cleaned}


def add_provider(payload: dict[str, Any], path: Path | None = None) -> dict[str, Any]:
    """Validate + append a new connection. Raises ProviderError on bad input."""
    path = path or default_providers_path()
    valid = _validate(payload)
    provider = {
        "id": f"siem-{uuid.uuid4().hex[:10]}",
        "source": "dashboard",
        "enabled": True,
        **valid,
    }
    providers = load_providers(path)
    providers.append(provider)
    save_providers(providers, path)
    return provider


def remove_provider(provider_id: str, path: Path | None = None) -> bool:
    """Delete a stored provider. Returns False if it wasn't found / is env-seeded."""
    path = path or default_providers_path()
    providers = load_providers(path)
    target = next((p for p in providers if p.get("id") == provider_id), None)
    if target is None or target.get("source") == "env":
        return False  # env-seeded providers are derived from .env - edit that instead
    kept = [p for p in providers if p.get("id") != provider_id]
    save_providers(kept, path)
    return True


# --------------------------------------------------------------------------- #
def connector_for(provider: dict[str, Any]) -> SIEMConnector:
    """Instantiate the live connector for a provider dict."""
    return get_siem_connector(
        platform=provider.get("platform"),
        name=provider.get("name", "default"),
        config=provider.get("config") or {},
    )


def resolve_connector(selector: str | None = None, path: Path | None = None) -> SIEMConnector:
    """Resolve a connector from a provider id / platform name / default.

    Used by main.py --siem so you can triage from any configured connection:
        python main.py live --siem env-qradar      (provider id)
        python main.py live --siem qradar          (any platform, env creds)
        python main.py live                        (SIEM_PROVIDER from .env)
    """
    if not selector:
        selector = cfg.SIEM_PROVIDER
    selector = selector.strip().lower()

    provider = get_provider(selector, path)
    if provider:
        return connector_for(provider)

    if selector in SIEM_PLATFORMS:
        return get_siem_connector(selector)

    available = sorted({p["id"] for p in load_providers(path)} | set(SIEM_PLATFORMS))
    raise ValueError(
        f"Unknown SIEM '{selector}'. Available connections/platforms: {', '.join(available)}"
    )
