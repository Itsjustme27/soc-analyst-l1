"""
Lookup tables - read/write threat-intel stores for the SOC agent and dashboard.

A lookup table is a small named JSON store the analyst (or the chat agent)
keeps around for correlation and enrichment:

    {
      "name": "known_bad_ips",
      "description": "Threat-intel IPs to auto-block",
      "entries": {"185.220.101.7": {"reason": "MASS scanner", "source": "chat", "ts": "..."}},
      "updated": "2026-09-23T..."
    }

Operations are all R/W (create / list / read / upsert / delete / rename) and
persisted atomically to a single JSON file (LOOKUP_TABLES_PATH) so a crash
mid-write can't corrupt the store. Thread-unsafe by nature of Python GIL but
the dashboard writes from one process; the file replace is atomic regardless.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from config import cfg

DEFAULT_PATH = Path("data/lookup_tables.json")


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S")


def _load(file: Path) -> dict[str, dict[str, Any]]:
    if not file.exists():
        return {}
    try:
        data = json.loads(file.read_text())
    except (json.JSONDecodeError, OSError):
        return {}
    return data if isinstance(data, dict) else {}


def _save(file: Path, tables: dict[str, dict[str, Any]]) -> None:
    file.parent.mkdir(parents=True, exist_ok=True)
    tmp = file.with_suffix(".tmp")
    tmp.write_text(json.dumps(tables, indent=2, default=str))
    tmp.replace(file)


def _current_path(path: str | Path | None) -> Path:
    return Path(path) if path else Path(cfg.LOOKUP_TABLES_PATH or DEFAULT_PATH)


# ------------------------------------------------ read ------------------ #
def list_lookup_tables(path: str | Path | None = None) -> list[dict[str, Any]]:
    """Summaries (name, description, entry count, updated) - for dashboards."""
    file = _current_path(path)
    tables = _load(file)
    out = []
    for name, table in tables.items():
        entries = table.get("entries") or {}
        out.append(
            {
                "name": name,
                "description": table.get("description", ""),
                "entry_count": len(entries),
                "updated": table.get("updated", ""),
            }
        )
    return sorted(out, key=lambda t: t["name"])


def read_lookup_table(name: str, path: str | Path | None = None) -> dict[str, Any] | None:
    tables = _load(_current_path(path))
    return tables.get(name)


def lookup_entry(name: str, key: str, path: str | Path | None = None) -> dict[str, Any] | None:
    table = read_lookup_table(name, path=path)
    if not table:
        return None
    return (table.get("entries") or {}).get(key)


def search_lookup(name: str, needle: str, path: str | Path | None = None) -> list[dict[str, Any]]:
    """Substring search across keys + values (case-insensitive)."""
    table = read_lookup_table(name, path=path)
    if not table:
        return []
    needle = needle.lower()
    hits = []
    for key, value in (table.get("entries") or {}).items():
        blob = f"{key} {json.dumps(value, default=str)}".lower()
        if needle in blob:
            hits.append({"key": key, "value": value})
    return hits


# ------------------------------------------------ write ----------------- #
def create_lookup_table(
    name: str, description: str = "", path: str | Path | None = None
) -> dict[str, Any]:
    file = _current_path(path)
    tables = _load(file)
    if name in tables:
        raise KeyError(f"Lookup table '{name}' already exists.")
    tables[name] = {"description": description, "entries": {}, "updated": now_iso()}
    _save(file, tables)
    return tables[name]


def upsert_lookup_entry(
    name: str, key: str, value: Any, path: str | Path | None = None
) -> dict[str, Any]:
    """Create the table if missing, then set/merge one key. R/W friendly."""
    file = _current_path(path)
    tables = _load(file)
    table = tables.setdefault(name, {"description": "", "entries": {}, "updated": now_iso()})
    entries = table.setdefault("entries", {})
    entries[key] = value
    table["updated"] = now_iso()
    _save(file, tables)
    return table


def delete_lookup_entry(name: str, key: str, path: str | Path | None = None) -> bool:
    file = _current_path(path)
    tables = _load(file)
    table = tables.get(name)
    if not table or key not in (table.get("entries") or {}):
        return False
    del table["entries"][key]
    table["updated"] = now_iso()
    _save(file, tables)
    return True


def delete_lookup_table(name: str, path: str | Path | None = None) -> bool:
    file = _current_path(path)
    tables = _load(file)
    if name not in tables:
        return False
    del tables[name]
    _save(file, tables)
    return True
