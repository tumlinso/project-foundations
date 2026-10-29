import hashlib
import json
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from project_source import CppContextCompilerProvider, Repository
import project_source.index as source_index


class CppExportCacheTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / "repo"
        self.root.mkdir()
        self.source_path = self.root / "a.cpp"
        self.source = b"int a();\nint b();\n"
        self.source_path.write_bytes(self.source)
        self.export = self.base / "export.json"
        self._write_export("a.cpp", self.source, "a", "a-id")
        self.repository = Repository(self.root, "fixture", self.base / "state")
        self.provider = CppContextCompilerProvider(self.export)

    def _write_export(self, path, source, name, symbol_id, *, integrity=True, root=None):
        records = [
            {"record": "file", "path": path, "hash": hashlib.sha256(source).hexdigest()},
            {"record": "symbol", "file": path, "id": symbol_id, "name": name,
             "line": 1, "end_line": 1, "definition": True},
            {"record": "edge", "file": path, "type": "call", "from": "caller",
             "to": symbol_id, "start": 4, "end": 5, "metadata": {"nested": [1]}},
        ]
        self.export.write_text(json.dumps({"format": "CTXPP-EXPORT/1",
            "root": str(root or self.root), "index_integrity": integrity,
            "index_meta": {"semantic": True}, "records": records}), encoding="utf-8")

    def _extract(self, path="a.cpp", source=None, repository=None):
        return self.provider.extract(repository or self.repository, path, self.source if source is None else source)

    def test_one_parse_reuses_index_for_different_files_and_defensively_copies_edges(self):
        second = self.root / "b.cpp"
        second.write_bytes(self.source)
        data = json.loads(self.export.read_text())
        data["records"].extend([
            {"record": "file", "path": "b.cpp", "hash": hashlib.sha256(self.source).hexdigest()},
            {"record": "symbol", "file": "b.cpp", "id": "b-id", "name": "b", "line": 1},
        ])
        self.export.write_text(json.dumps(data))
        original_read = Path.read_bytes
        with patch.object(Path, "read_bytes", autospec=True, side_effect=original_read) as read_bytes, \
                patch.object(source_index.json, "loads", wraps=source_index.json.loads) as parse:
            first = self._extract()
            other = self._extract("b.cpp")
        self.assertEqual(read_bytes.call_count, 1)
        self.assertEqual(parse.call_count, 1)
        self.assertEqual([unit.name for unit in first.units], ["a", "call"])
        self.assertEqual([unit.name for unit in other.units], ["b"])
        edge_unit = first.units[1]
        edge_unit.metadata["edge"]["metadata"]["nested"].append(99)
        repeated = self._extract()
        self.assertEqual(repeated.units[1].metadata["edge"]["metadata"]["nested"], [1])

    def test_atomic_replacement_reloads_even_with_same_size_and_timestamps(self):
        before = self._extract()
        old_stat = self.export.stat()
        replacement = self.base / "replacement.json"
        updated = json.loads(self.export.read_text())
        updated["records"][1]["name"] = "z"
        replacement.write_text(json.dumps(updated))
        # Keep file length and timestamps identical; inode remains part of generation identity.
        self.assertEqual(replacement.stat().st_size, old_stat.st_size)
        os.utime(replacement, ns=(old_stat.st_atime_ns, old_stat.st_mtime_ns))
        os.replace(replacement, self.export)
        after = self._extract()
        self.assertEqual(before.units[0].name, "a")
        self.assertEqual([unit.name for unit in after.units], ["z", "call"])

    def test_malformed_and_missing_replacement_fail_closed(self):
        self.assertEqual(self._extract().coverage, "partial")
        self.export.write_text("{")
        malformed = self._extract()
        self.assertEqual(malformed.coverage, "unavailable")
        self.assertEqual(malformed.units, ())
        self.assertIn("cannot read C++ export", malformed.diagnostics[0])
        self.export.unlink()
        missing = self._extract()
        self.assertEqual(missing.coverage, "unavailable")
        self.assertEqual(missing.units, ())

    def test_legacy_export_symlink_remains_supported(self):
        link = self.base / "legacy-export-link.json"
        link.symlink_to(self.export)
        provider = CppContextCompilerProvider(link)
        result = provider.extract(self.repository, "a.cpp", self.source)
        self.assertEqual(result.coverage, "partial")
        self.assertEqual([unit.name for unit in result.units], ["a", "call"])

    def test_source_edit_still_reports_stale(self):
        self.assertEqual(self._extract().coverage, "partial")
        edited = b"int a();\nint b();\n// changed\n"
        self.source_path.write_bytes(edited)
        result = self._extract(source=edited)
        self.assertEqual(result.coverage, "stale")
        self.assertEqual(result.units, ())

    def test_policy_root_integrity_and_degraded_guards_remain_active_on_cache_hits(self):
        self.assertEqual(self._extract().coverage, "partial")
        denied = Repository(self.root, "fixture", self.base / "denied", deny_patterns=("a.cpp",))
        self.assertEqual(self._extract(repository=denied).coverage, "unavailable")
        wrong_root = Repository(self.base, "other", self.base / "other-state")
        self.assertEqual(self._extract(repository=wrong_root).coverage, "mismatch")
        self._write_export("a.cpp", self.source, "a", "a-id", integrity=False)
        self.assertEqual(self._extract().coverage, "corrupt")
        self._write_export("a.cpp", self.source, "a", "a-id")
        data = json.loads(self.export.read_text())
        data["records"][1]["degraded"] = True
        self.export.write_text(json.dumps(data))
        result = self._extract()
        self.assertEqual([unit.name for unit in result.units], ["call"])
        self.assertEqual(result.coverage, "partial")

    def test_coverage_only_matches_full_validation_without_constructing_units(self):
        def assert_matches(repository, path="a.cpp", source=None):
            source = self.source if source is None else source
            expected = self.provider.extract(repository, path, source)
            with patch.object(source_index, "StructuralUnit", side_effect=AssertionError("coverage must not build units")):
                actual = self.provider._coverage(repository, path, source)
            self.assertEqual(actual.units, ())
            self.assertEqual((actual.path, actual.sha256, actual.coverage, actual.diagnostics, actual.provider),
                             (expected.path, expected.sha256, expected.coverage, expected.diagnostics, expected.provider))

        assert_matches(self.repository)
        edited = b"int a();\nint b();\n// changed\n"
        assert_matches(self.repository, source=edited)
        denied = Repository(self.root, "fixture", self.base / "denied", deny_patterns=("a.cpp",))
        assert_matches(denied)
        wrong_root = Repository(self.base, "other", self.base / "wrong-root")
        assert_matches(wrong_root)
        self._write_export("a.cpp", self.source, "a", "a-id", integrity=False)
        assert_matches(self.repository)
        self._write_export("a.cpp", self.source, "a", "a-id")
        data = json.loads(self.export.read_text())
        data["records"][1]["degraded"] = True
        self.export.write_text(json.dumps(data))
        assert_matches(self.repository)
        data["index_meta"]["semantic"] = False
        self.export.write_text(json.dumps(data))
        assert_matches(self.repository)
        self.export.unlink()
        assert_matches(self.repository)

    def test_concurrent_first_load_reads_export_once(self):
        original_read = Path.read_bytes
        with patch.object(Path, "read_bytes", autospec=True, side_effect=original_read) as read_bytes:
            with ThreadPoolExecutor(max_workers=8) as pool:
                results = list(pool.map(lambda _: self._extract(), range(16)))
        self.assertEqual(read_bytes.call_count, 1)
        self.assertTrue(all([unit.name for unit in result.units] == ["a", "call"] for result in results))

    def test_edge_line_fallback_matches_offsets_and_is_lazy(self):
        data = json.loads(self.export.read_text())
        data["records"][2].pop("line", None)
        data["records"][2].pop("end_line", None)
        data["records"][2]["start"] = 10
        data["records"][2]["end"] = 15
        self.export.write_text(json.dumps(data))
        result = self._extract()
        edge = result.units[1]
        self.assertEqual((edge.line, edge.end_line), (2, 2))

    def test_edge_line_fallback_preserves_negative_and_oversized_slice_offsets(self):
        data = json.loads(self.export.read_text())
        edge = data["records"][2]
        edge.pop("line", None)
        edge.pop("end_line", None)
        edge["start"] = -1
        edge["end"] = len(self.source) + 100
        self.export.write_text(json.dumps(data))
        result = self._extract()
        self.assertEqual((result.units[1].line, result.units[1].end_line), (2, 3))

    def test_explicit_none_line_values_keep_previous_conversion_error(self):
        data = json.loads(self.export.read_text())
        data["records"][2]["line"] = None
        self.export.write_text(json.dumps(data))
        with self.assertRaises(TypeError):
            self._extract()
        data["records"][2].pop("line")
        data["records"][2]["end_line"] = None
        self.export.write_text(json.dumps(data))
        with self.assertRaises(TypeError):
            self._extract()


if __name__ == "__main__":
    unittest.main()
