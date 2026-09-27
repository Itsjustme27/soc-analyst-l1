"""
Offline tests for log_rotation.py. No network, MOCK_MODE only.

Run: python -m unittest tests.test_log_rotation -v
"""

from __future__ import annotations

import gzip
import json
import os
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault("MOCK_MODE", "true")
os.environ.setdefault("LLM_PROVIDER", "mock")


class TestNeedsRotation(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="rotation-test-")
        self.log_path = Path(self.tmp_dir) / "test.jsonl"

    def tearDown(self):
        import shutil

        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_missing_file_does_not_need_rotation(self):
        import log_rotation

        r = log_rotation.needs_rotation(self.log_path)
        self.assertFalse(r["exists"])
        self.assertFalse(r["should_rotate"])

    def test_small_recent_file_does_not_need_rotation(self):
        import log_rotation

        self.log_path.write_text(json.dumps({"ts": time.strftime("%Y-%m-%dT%H:%M:%S")}) + "\n")
        r = log_rotation.needs_rotation(self.log_path, max_bytes=10_000_000, max_age_days=30)
        self.assertFalse(r["should_rotate"])

    def test_oversized_file_needs_rotation(self):
        import log_rotation

        self.log_path.write_text(json.dumps({"x": "y"}) + "\n")
        r = log_rotation.needs_rotation(self.log_path, max_bytes=5, max_age_days=9999)
        self.assertTrue(r["should_rotate"])
        self.assertIn("size", r["reason"])

    def test_old_entry_needs_rotation(self):
        import log_rotation

        old_ts = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(time.time() - 100 * 86400))
        self.log_path.write_text(json.dumps({"ts": old_ts}) + "\n")
        r = log_rotation.needs_rotation(self.log_path, max_bytes=10_000_000, max_age_days=30)
        self.assertTrue(r["should_rotate"])
        self.assertIn("days old", r["reason"])

    def test_malformed_first_line_falls_back_to_mtime(self):
        import log_rotation

        self.log_path.write_text("not json at all\n")
        r = log_rotation.needs_rotation(self.log_path, max_bytes=10_000_000, max_age_days=30)
        self.assertIsNotNone(r["age_days"])  # fell back to mtime, didn't crash
        self.assertFalse(r["should_rotate"])  # file was just written, so it's recent


class TestRotateLog(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="rotation-test-")
        self.log_path = Path(self.tmp_dir) / "test.jsonl"

    def tearDown(self):
        import shutil

        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_missing_file_is_a_noop(self):
        import log_rotation

        r = log_rotation.rotate_log(self.log_path)
        self.assertFalse(r["rotated"])

    def test_empty_file_is_a_noop(self):
        import log_rotation

        self.log_path.write_text("")
        r = log_rotation.rotate_log(self.log_path)
        self.assertFalse(r["rotated"])

    def test_rotates_and_compresses_content(self):
        import log_rotation

        entries = [{"alert_id": f"A{i}"} for i in range(5)]
        self.log_path.write_text("".join(json.dumps(e) + "\n" for e in entries))

        r = log_rotation.rotate_log(self.log_path)
        self.assertTrue(r["rotated"])
        archive_path = Path(r["archive_path"])
        self.assertTrue(archive_path.exists())
        self.assertTrue(archive_path.name.endswith(".jsonl.gz"))

        # original file still exists but is now empty - writers assume it exists
        self.assertTrue(self.log_path.exists())
        self.assertEqual(self.log_path.read_text(), "")

        # archived content is intact and readable
        with gzip.open(archive_path, "rt") as f:
            restored = [json.loads(l) for l in f if l.strip()]
        self.assertEqual(restored, entries)

    def test_rotate_if_needed_only_rotates_when_over_threshold(self):
        import log_rotation

        self.log_path.write_text(json.dumps({"x": 1}) + "\n")

        r1 = log_rotation.rotate_if_needed(self.log_path, max_bytes=10_000_000, max_age_days=9999)
        self.assertFalse(r1["rotated"])
        self.assertTrue(self.log_path.exists())
        self.assertGreater(self.log_path.stat().st_size, 0)

        r2 = log_rotation.rotate_if_needed(self.log_path, max_bytes=1, max_age_days=9999)
        self.assertTrue(r2["rotated"])
        self.assertEqual(self.log_path.read_text(), "")


class TestPruneArchives(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="rotation-test-")
        self.archive_dir = Path(self.tmp_dir) / "archive"
        self.archive_dir.mkdir()

    def tearDown(self):
        import shutil

        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def _make_archive(self, name: str, age_days: float) -> Path:
        p = self.archive_dir / name
        with gzip.open(p, "wt") as f:
            f.write("{}\n")
        old_time = time.time() - age_days * 86400
        os.utime(p, (old_time, old_time))
        return p

    def test_missing_archive_dir_returns_empty(self):
        import log_rotation

        self.assertEqual(log_rotation.prune_archives(self.archive_dir / "nope", keep_days=30), [])

    def test_prunes_only_old_archives(self):
        import log_rotation

        old = self._make_archive("old.jsonl.gz", age_days=400)
        recent = self._make_archive("recent.jsonl.gz", age_days=1)
        deleted = log_rotation.prune_archives(self.archive_dir, keep_days=365)
        self.assertEqual(deleted, [str(old)])
        self.assertFalse(old.exists())
        self.assertTrue(recent.exists())

    def test_keep_days_zero_prunes_everything(self):
        import log_rotation

        self._make_archive("a.jsonl.gz", age_days=1)
        self._make_archive("b.jsonl.gz", age_days=1)
        deleted = log_rotation.prune_archives(self.archive_dir, keep_days=0)
        self.assertEqual(len(deleted), 2)


class TestRotateAll(unittest.TestCase):
    def test_rotate_all_uses_configured_paths(self):
        import log_rotation
        from config import cfg

        tmp_dir = tempfile.mkdtemp(prefix="rotation-test-")
        try:
            orig = {attr: getattr(cfg, attr) for attr in log_rotation.LOG_PATHS_TO_MANAGE}
            for attr in log_rotation.LOG_PATHS_TO_MANAGE:
                setattr(cfg, attr, str(Path(tmp_dir) / f"{attr.lower()}.jsonl"))
            # only seed one of the four logs
            Path(cfg.TRIAGE_LOG_PATH).write_text(json.dumps({"x": 1}) + "\n")

            results = log_rotation.rotate_all(max_bytes=1, max_age_days=9999)
            self.assertTrue(results["TRIAGE_LOG_PATH"]["exists"])
            self.assertTrue(results["TRIAGE_LOG_PATH"]["rotated"])
            self.assertFalse(results["CHAT_LOG_PATH"]["exists"])
        finally:
            for attr, val in orig.items():
                setattr(cfg, attr, val)
            import shutil

            shutil.rmtree(tmp_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
