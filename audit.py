"""
Audit logging for the AI SOC engineer.

Every tool invocation - read, proposed, or executed - is appended to
data/audit_log.jsonl (AUDIT_LOG_PATH) with the fields the spec requires:

    timestamp, user, agent, requested action (tool), params, result,
    permission level, approval status, execution status, error.

This is append-only and never gated on the tool having succeeded: failures
are logged with their error so triage of the *agent* is possible. Writers
never rotate this file - log_rotation.py handles that for the other JSONL
logs; add AUDIT_LOG_PATH to the rotation list if it grows.
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any

from config import cfg

DEFAULT_AUDIT_PATH = "data/audit_log.jsonl"

REDACTED = "••••••••"

# Keys whose values are masked wholesale (case-insensitive - 'Authorization',
# 'client_secret', 'api_key', ...). Deliberately does NOT match bare
# "token"/"tokens" so numeric telemetry like tokens_used/max_tokens survives.
_SECRET_KEY_RE = re.compile(
    r"(password|passwd|pwd|api[_-]?key|apikey|client[_-]?secret|authorization|"
    r"auth[_-]?token|bearer[_-]?token|private[_-]?key|access[_-]?key|credential|secret)",
    re.IGNORECASE,
)

# Secret-shaped strings inside free text: "Bearer <token>", "?token=xyz",
# "?key=...", "password=...". The captured prefix stays, only the value is
# masked, so the surrounding sentence is still readable.
_SECRET_STRING_RES = (
    re.compile(r"(Authorization:\s*Bearer\s+)\S+", re.IGNORECASE),
    re.compile(r"(Bearer\s+)[A-Za-z0-9._~+/=\-]{8,}", re.IGNORECASE),
    re.compile(r"([?&]token=)[^&\s\"'<>]+"),
    re.compile(r"([?&](?:password|passwd|secret|api[_-]?key|key)=)[^&\s\"'<>]+", re.IGNORECASE),
)


def redact_secrets(value: Any) -> Any:
    """Recursively mask secrets in params/results before they hit the audit
    trail. Never mutates the input: returns a new structure."""
    if isinstance(value, dict):
        return {
            k: (REDACTED if _SECRET_KEY_RE.search(k) else redact_secrets(v))
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [redact_secrets(v) for v in value]
    if isinstance(value, str):
        out = value
        for rx in _SECRET_STRING_RES:
            out = rx.sub(lambda m: m.group(1) + REDACTED, out)
        return out
    return value


def audit_log(
    *,
    tool: str,
    params: dict[str, Any],
    result: Any = None,
    permission: str = "read",
    approval_status: str = "not_required",
    execution_status: str = "success",
    user: str | None = None,
    agent: str = "soc_engineer",
    error: str | None = None,
    action: str | None = None,
    path: str | Path | None = None,
) -> None:
    """Append one audit record. Never raises - auditing must not crash the
    operation being audited."""
    record = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "user": user or getattr(cfg, "ENGINE_USER", "analyst"),
        "agent": agent,
        "action": action or tool,
        "tool": tool,
        "params": _safe(redact_secrets(params)),
        "result": _safe(redact_secrets(result)),
        "permission": permission,
        "approval_status": approval_status,
        "execution_status": execution_status,
        "error": error,
    }
    try:
        p = Path(path or getattr(cfg, "AUDIT_LOG_PATH", DEFAULT_AUDIT_PATH))
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "a") as f:
            f.write(json.dumps(record, default=str) + "\n")
    except Exception:  # noqa: BLE001 - audit must never break the caller
        pass


def _safe(obj: Any) -> Any:
    """Serialize anything into a JSON-safe, size-capped form. Oversized values
    become {"truncated": True, ...} wrapping the cap prefix (still valid
    JSON). Secrets are already redacted before _safe is called."""
    try:
        text = json.dumps(obj, default=str)
    except TypeError:
        return {"unserializable": str(obj)[:200]}
    if len(text) > 4000:
        cap = text[:4000]
        try:
            partial = json.loads(cap)
        except json.JSONDecodeError:
            partial = None
        if partial is not None:
            return {"truncated": True, "data": partial}
        return {"truncated": True, "repr": cap}
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {"repr": text}


def read_audit_log(path: str | Path | None = None, limit: int = 100) -> list[dict[str, Any]]:
    """Newest-first audit records, for the dashboard's read-only Audit panel."""
    p = Path(path or getattr(cfg, "AUDIT_LOG_PATH", DEFAULT_AUDIT_PATH))
    if not p.exists():
        return []
    rows = []
    for line in p.read_text().splitlines():
        if not line.strip():
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows[-limit:][::-1]
