"""
Rotation/archiving for the JSONL logs this project writes forever otherwise:
data/triage_log.jsonl, data/chat_log.jsonl, data/notifications.jsonl,
data/feedback_log.jsonl. None of the writers (main.py, run.py, dashboard.py,
notify.py, agent/memory.py) rotate on their own - they just append - so left
alone these grow without bound. This module is the rotation step you run
periodically (cron, or by hand), not something wired into every write.

Two trigger conditions, either rotates a log:
  - size:  the file exceeds ROTATE_MAX_BYTES
  - age:   the oldest line in the file is older than ROTATE_MAX_AGE_DAYS

Rotating a log means: move it to <name>.<timestamp>.jsonl.gz (gzip-compressed,
so archives stay small) and start a fresh empty file at the original path.
Nothing is ever deleted by rotate_log() itself - see prune_archives() for
that, which is separate and opt-in (a retention policy is a decision, not a
default).
"""

from __future__ import annotations

import gzip
import json
import shutil
import time
from pathlib import Path
from typing import Any

DEFAULT_MAX_BYTES = 100 * 1024 * 1024  # 100 MB
DEFAULT_MAX_AGE_DAYS = 30


def _archive_dir(log_path: Path) -> Path:
    return log_path.parent / "archive"


def _oldest_entry_ts(log_path: Path) -> float | None:
    """Best-effort: look at the first line's "ts" or "timestamp" field, if
    present. Not every writer includes one (see metrics.py's own notes on
    this same inconsistency) - falls back to the file's mtime when absent,
    which is still a reasonable proxy for "how long has this been sitting
    here unrotated"."""
    try:
        with log_path.open() as f:
            first_line = f.readline()
    except OSError:
        return None
    if first_line.strip():
        try:
            entry = json.loads(first_line)
            ts = entry.get("ts") or entry.get("timestamp")
            if isinstance(ts, str):
                return time.mktime(time.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S"))
            if isinstance(ts, (int, float)):
                return float(ts)
        except (json.JSONDecodeError, ValueError):
            pass
    try:
        return log_path.stat().st_mtime
    except OSError:
        return None


def needs_rotation(
    log_path: str | Path,
    *,
    max_bytes: int = DEFAULT_MAX_BYTES,
    max_age_days: float = DEFAULT_MAX_AGE_DAYS,
) -> dict[str, Any]:
    """Check whether a log should be rotated, without rotating it. Returns
    {"path", "exists", "should_rotate", "reason", "size_bytes", "age_days"}."""
    path = Path(log_path)
    if not path.exists():
        return {"path": str(path), "exists": False, "should_rotate": False, "reason": None}

    size = path.stat().st_size
    oldest = _oldest_entry_ts(path)
    age_days = (time.time() - oldest) / 86400 if oldest else None

    reason = None
    if max_bytes and size > max_bytes:
        reason = f"size {size} bytes exceeds max_bytes {max_bytes}"
    elif max_age_days and age_days is not None and age_days > max_age_days:
        reason = f"oldest entry is {age_days:.1f} days old, exceeds max_age_days {max_age_days}"

    return {
        "path": str(path),
        "exists": True,
        "should_rotate": reason is not None,
        "reason": reason,
        "size_bytes": size,
        "age_days": age_days,
    }


def rotate_log(log_path: str | Path, *, archive_dir: str | Path | None = None) -> dict[str, Any]:
    """Unconditionally rotate a log (use needs_rotation() first to decide
    whether to). Moves it to <archive_dir>/<name>.<timestamp>.jsonl.gz and
    replaces the original with a fresh empty file. Safe to call on a
    missing or empty file (no-op). Returns {"rotated": bool, "archive_path": str|None}."""
    path = Path(log_path)
    if not path.exists() or path.stat().st_size == 0:
        return {"rotated": False, "archive_path": None}

    out_dir = Path(archive_dir) if archive_dir else _archive_dir(path)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    archive_path = out_dir / f"{path.stem}.{stamp}.jsonl.gz"

    with path.open("rb") as f_in, gzip.open(archive_path, "wb") as f_out:
        shutil.copyfileobj(f_in, f_out)
    path.write_text("")  # truncate to empty, not delete - writers assume the file exists

    return {"rotated": True, "archive_path": str(archive_path)}


def rotate_if_needed(
    log_path: str | Path,
    *,
    max_bytes: int = DEFAULT_MAX_BYTES,
    max_age_days: float = DEFAULT_MAX_AGE_DAYS,
    archive_dir: str | Path | None = None,
) -> dict[str, Any]:
    """Convenience: check + rotate in one call. Returns needs_rotation()'s
    result merged with rotate_log()'s (when it ran)."""
    check = needs_rotation(log_path, max_bytes=max_bytes, max_age_days=max_age_days)
    if not check["should_rotate"]:
        return {**check, "rotated": False, "archive_path": None}
    result = rotate_log(log_path, archive_dir=archive_dir)
    return {**check, **result}


def prune_archives(archive_dir: str | Path, *, keep_days: float = 365) -> list[str]:
    """Delete archived (already-rotated, .jsonl.gz) files older than
    keep_days. Opt-in, separate from rotation itself - a retention policy is
    a decision the operator makes, not something rotate_log() assumes.
    Returns the list of deleted paths."""
    out_dir = Path(archive_dir)
    if not out_dir.exists():
        return []
    cutoff = time.time() - keep_days * 86400
    deleted = []
    for f in out_dir.glob("*.jsonl.gz"):
        try:
            if f.stat().st_mtime < cutoff:
                f.unlink()
                deleted.append(str(f))
        except OSError:
            continue
    return deleted


LOG_PATHS_TO_MANAGE = (
    "TRIAGE_LOG_PATH",
    "CHAT_LOG_PATH",
    "ENGINEER_LOG_PATH",
    "NOTIFICATIONS_LOG_PATH",
    "FEEDBACK_LOG_PATH",
    "AUDIT_LOG_PATH",
)


def rotate_all(
    *,
    max_bytes: int = DEFAULT_MAX_BYTES,
    max_age_days: float = DEFAULT_MAX_AGE_DAYS,
) -> dict[str, dict[str, Any]]:
    """Rotate every log this project manages, by its cfg.*_PATH setting.
    Used by the `python log_rotation.py` CLI and available for a scheduled
    task to call directly."""
    from config import cfg

    results = {}
    for attr in LOG_PATHS_TO_MANAGE:
        path = getattr(cfg, attr, None)
        if not path:
            continue
        results[attr] = rotate_if_needed(path, max_bytes=max_bytes, max_age_days=max_age_days)
    return results


if __name__ == "__main__":  # pragma: no cover - thin CLI wrapper
    import argparse

    parser = argparse.ArgumentParser(
        description="Rotate this project's JSONL logs (triage/chat/notifications/feedback)."
    )
    parser.add_argument(
        "--max-bytes",
        type=int,
        default=DEFAULT_MAX_BYTES,
        help=f"Rotate if a log exceeds this size (default {DEFAULT_MAX_BYTES}).",
    )
    parser.add_argument(
        "--max-age-days",
        type=float,
        default=DEFAULT_MAX_AGE_DAYS,
        help=f"Rotate if a log's oldest entry is older than this (default {DEFAULT_MAX_AGE_DAYS}).",
    )
    parser.add_argument(
        "--prune-archives-older-than-days",
        type=float,
        default=None,
        help="Also delete rotated archives older than N days (opt-in - omit to keep everything).",
    )
    args = parser.parse_args()

    results = rotate_all(max_bytes=args.max_bytes, max_age_days=args.max_age_days)
    for name, r in results.items():
        if not r["exists"]:
            print(f"  {name}: no file yet - nothing to do")
        elif r["rotated"]:
            print(f"  {name}: rotated ({r['reason']}) -> {r['archive_path']}")
        else:
            print(f"  {name}: OK, no rotation needed ({r['size_bytes']} bytes)")

    if args.prune_archives_older_than_days is not None:
        from config import cfg

        seen_dirs = {
            Path(getattr(cfg, attr)).parent / "archive"
            for attr in LOG_PATHS_TO_MANAGE
            if getattr(cfg, attr, None)
        }
        for d in seen_dirs:
            deleted = prune_archives(d, keep_days=args.prune_archives_older_than_days)
            for path in deleted:
                print(f"  pruned: {path}")
