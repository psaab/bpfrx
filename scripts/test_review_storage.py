#!/usr/bin/env python3
"""Hermetic regression tests for review deduplication across storage layouts.

Run directly or through make selftest. Fixtures replace filesystem reads and
discovery, so no existing temporary reports, Git checkout metadata, or network
access are needed. Publication and watcher behavior are not exercised here.
"""

import importlib.util
import io
import json
from pathlib import Path
import unittest
from unittest.mock import call, patch


_SPEC = importlib.util.spec_from_file_location(
    "review_dedup", Path(__file__).with_name("review-dedup-check.py")
)
dedup = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(dedup)

NEW_REPORT = "/var/tmp/deep-review-reports/gpt-5.6-sol-review-storage-001.md"
OLD_REPORT = "/tmp/muse-spark-review-009.md"
NEW_INDEX = "/var/tmp/deep-review-work/review-index.json"
OLD_INDEX = "/tmp/review-index.json"
NEW_ISSUES = "/var/tmp/deep-review-work/issue-pr-index.json"
OLD_ISSUES = "/tmp/issue-pr-index.json"


class ReviewStorageTests(unittest.TestCase):
    def setUp(self):
        self.files = {}
        self.discovered = {
            "/var/tmp/deep-review-reports/*-review*.md": [NEW_REPORT],
            "/tmp/*-review*.md": [OLD_REPORT],
        }
        reads = patch.object(dedup, "open", side_effect=self.read, create=True)
        reads.start()
        self.addCleanup(reads.stop)
        discovery = patch.object(
            dedup.glob, "glob", side_effect=self.discovered.__getitem__
        )
        self.glob = discovery.start()
        self.addCleanup(discovery.stop)

    def read(self, path, *args, **kwargs):
        if str(path) not in self.files:
            raise FileNotFoundError(path)
        return io.StringIO(self.files[str(path)])

    def test_both_report_roots_without_indexes(self):
        self.files = {
            NEW_REPORT: "Title: Current finding\n",
            OLD_REPORT: "Title: Legacy finding\n",
        }
        self.assertEqual(dedup.load_review_titles(), [
            (Path(NEW_REPORT).name, "Current finding"),
            (Path(OLD_REPORT).name, "Legacy finding"),
        ])
        self.assertEqual(self.glob.call_args_list, [
            call("/var/tmp/deep-review-reports/*-review*.md"),
            call("/tmp/*-review*.md"),
        ])

    def test_legacy_cached_index_cannot_hide_new_reports(self):
        self.files = {
            OLD_INDEX: json.dumps([
                {"filename": "cached.md", "titles": ["Cached finding"]},
            ]),
            NEW_REPORT: "Title: Newly published finding\n",
            OLD_REPORT: "Title: Legacy finding\n",
        }
        self.assertEqual(set(dedup.load_review_titles()), {
            ("cached.md", "Cached finding"),
            (Path(NEW_REPORT).name, "Newly published finding"),
            (Path(OLD_REPORT).name, "Legacy finding"),
        })

    def test_merge_indexes_and_scans_without_duplicate_rows(self):
        entry = {"filename": Path(NEW_REPORT).name, "titles": ["Current finding"]}
        self.files = {
            NEW_INDEX: json.dumps([entry]),
            OLD_INDEX: json.dumps([
                entry, {"filename": "cached.md", "titles": ["Cached finding"]},
            ]),
            NEW_REPORT: "Title: Current finding\n",
        }
        self.assertEqual(dedup.load_review_titles(), [
            (Path(NEW_REPORT).name, "Current finding"),
            ("cached.md", "Cached finding"),
        ])

    def test_corrupt_index_cannot_hide_reports(self):
        for index in (NEW_INDEX, OLD_INDEX):
            with self.subTest(index=index):
                self.files = {
                    index: "{invalid-json",
                    NEW_REPORT: "Title: Current finding\n",
                }
                self.assertEqual(dedup.load_review_titles(), [
                    (Path(NEW_REPORT).name, "Current finding"),
                ])

    def test_disappeared_report_does_not_hide_readable_report(self):
        # Both names were discovered, but the current report is no longer readable.
        self.files = {OLD_REPORT: "Title: Legacy finding\n"}
        self.assertEqual(dedup.load_review_titles(), [
            (Path(OLD_REPORT).name, "Legacy finding"),
        ])

    def test_empty_roots_need_no_preexisting_state(self):
        for paths in self.discovered.values():
            paths.clear()
        self.assertEqual(dedup.load_review_titles(), [])
        self.assertEqual(dedup.load_issue_titles(), [])

    def test_merge_issue_indexes_without_duplicate_rows(self):
        self.files = {
            NEW_ISSUES: json.dumps({"issues": [
                {"number": 1, "title": "A"}, {"number": 3, "title": "C"},
            ]}),
            OLD_ISSUES: json.dumps({"issues": [
                {"number": 1, "title": "A"}, {"number": 2, "title": "B"},
            ]}),
        }
        self.assertEqual(dedup.load_issue_titles(), [
            ("ISSUE #1", "A"), ("ISSUE #3", "C"), ("ISSUE #2", "B"),
        ])

    def test_legacy_issue_index_survives_absent_empty_or_bad_current_index(self):
        for current in (None, '{"issues": []}', "{invalid-json"):
            with self.subTest(current=current):
                self.files = {
                    OLD_ISSUES: json.dumps({"issues": [{"number": 2, "title": "B"}]}),
                }
                if current is not None:
                    self.files[NEW_ISSUES] = current
                self.assertEqual(dedup.load_issue_titles(), [("ISSUE #2", "B")])

    def test_matching_uses_fresh_reports_despite_legacy_cache(self):
        title = "Review storage layout changed"
        self.files = {
            OLD_INDEX: json.dumps([
                {"filename": "cached.md", "titles": ["Unrelated cached finding"]},
            ]),
            NEW_REPORT: "Title: " + title + "\n",
        }
        matches = dedup.check_finding(title)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0][:3], (Path(NEW_REPORT).name, title, 1.0))


if __name__ == "__main__":
    unittest.main(verbosity=2)
