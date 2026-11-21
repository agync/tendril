#!/usr/bin/env python3
"""Unit tests for scripts/prune_caches.py."""

import unittest
from datetime import datetime, timezone

from prune_caches import family, to_delete


class PruneCachesTests(unittest.TestCase):
    def test_family_groups_rust_and_hashed_keys(self):
        self.assertEqual(
            family("v0-rust-core-Linux-x64-abc12345"),
            "v0-rust-core-Linux-x64",
        )
        self.assertEqual(
            family("pre-commit-Linux-0123456789abcdef"),
            "pre-commit-Linux",
        )

    def test_to_delete_keeps_newest_and_respects_grace_and_branches(self):
        now = datetime(2026, 11, 21, 15, 0, tzinfo=timezone.utc)
        rows = [
            ("10", "refs/heads/main", "v0-rust-core-Linux-x64-11111111", "2026-11-21T10:00:00Z", "2026-11-21T10:05:00Z"),
            ("11", "refs/heads/main", "v0-rust-core-Linux-x64-22222222", "2026-11-21T12:00:00Z", "2026-11-21T12:05:00Z"),
            ("12", "refs/heads/main", "pre-commit-Linux-11111111", "2026-11-21T10:00:00Z", "2026-11-21T14:30:00Z"),
            ("13", "refs/heads/main", "pre-commit-Linux-22222222", "2026-11-21T12:00:00Z", "2026-11-21T12:05:00Z"),
            ("14", "refs/pull/5/merge", "v0-rust-core-Linux-x64-11111111", "2026-11-21T09:00:00Z", "2026-11-21T09:05:00Z"),
        ]
        victims = to_delete(rows, now)
        self.assertEqual(victims, [("10", "v0-rust-core-Linux-x64-11111111")])


if __name__ == "__main__":
    unittest.main()
