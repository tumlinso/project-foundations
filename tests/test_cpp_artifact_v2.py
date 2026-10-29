from __future__ import annotations

from contextlib import closing
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest import mock
import zlib

from project_source import CppContextCompilerProvider, Repository, SourceIndex
from project_source.cpp_artifact_v2 import CtxppArtifactError, open_generation, read_edges, read_file, read_symbols
import project_source.cpp_artifact_v2 as v2


class CtxppV2Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / "repo"
        (self.root / "src").mkdir(parents=True)
        self.source = b"int freeze();\nvoid caller() { freeze(); }\n"
        (self.root / "src/a.cpp").write_bytes(self.source)
        (self.root / "src/b.cpp").write_text("void test_freeze() {}\n", encoding="utf-8")
        self.state = self.base / "state"
        self.state.mkdir()
        self.database_path = self.state / "index.sqlite"
        self.generation = "fixture-generation-1"
        self._write_database(self.database_path, self.generation)
        self.descriptor = self.state / "export.json"
        self._write_descriptor(self.generation)
        self.repository = Repository(self.root, "fixture", self.base / "source-index-state")
        self.provider = CppContextCompilerProvider(self.descriptor)

    def _pack(self, record):
        return zlib.compress(json.dumps(record, sort_keys=True, separators=(",", ":")).encode(), 6)

    def _write_database(self, path, generation):
        db = sqlite3.connect(path)
        db.executescript("""
            PRAGMA user_version=2;
            CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);
            CREATE TABLE strings(id INTEGER PRIMARY KEY,value TEXT UNIQUE NOT NULL);
            CREATE TABLE files(path TEXT PRIMARY KEY,file_order INTEGER NOT NULL,data BLOB NOT NULL);
            CREATE TABLE symbols(id TEXT NOT NULL,name TEXT,qualified_name TEXT,kind TEXT,file TEXT,line INTEGER,end_line INTEGER,
             start_byte INTEGER,end_byte INTEGER,definition INTEGER,is_test INTEGER,search_text TEXT,
             symbol_order INTEGER PRIMARY KEY,has_occurrences INTEGER NOT NULL,data BLOB NOT NULL);
            CREATE TABLE occurrences(symbol_row_id INTEGER,occurrence_order INTEGER,translation_unit TEXT,data BLOB,
             PRIMARY KEY(symbol_row_id,occurrence_order));
            CREATE TABLE edges(edge_order INTEGER PRIMARY KEY,from_id INTEGER,to_id INTEGER,file_id INTEGER,tu_id INTEGER,
             type_id INTEGER,kind_id INTEGER,config_id INTEGER,via_id INTEGER,start INTEGER,end INTEGER,line INTEGER,
             column INTEGER,end_line INTEGER,end_column INTEGER,fields INTEGER NOT NULL,data BLOB);
        """)
        a_hash = hashlib.sha256(self.source).hexdigest()
        b_source = (self.root / "src/b.cpp").read_bytes()
        b_hash = hashlib.sha256(b_source).hexdigest()
        metadata = {
            "schema": 2,
            "generation": generation,
            "source_root": str(self.root.resolve()),
            "index_meta": {"semantic": True, "incomplete": False},
            "manifest": {"generation": generation},
            "freshness": {"generation": generation, "files": {
                "src/a.cpp": {"hash": a_hash}, "src/b.cpp": {"hash": b_hash}}},
        }
        db.executemany("INSERT INTO metadata VALUES(?,?)", [
            (key, json.dumps(value, separators=(",", ":"))) for key, value in metadata.items()])
        db.executemany("INSERT INTO files VALUES(?,?,?)", [
            ("src/a.cpp", 0, self._pack({"record": "file", "path": "src/a.cpp", "hash": a_hash, "parse_status": "ok"})),
            ("src/b.cpp", 1, self._pack({"record": "file", "path": "src/b.cpp", "hash": b_hash, "parse_status": "ok"})),
        ])
        # The same semantic symbol ID may legitimately have declaration and
        # definition rows. Storage identity is the independent symbol_order.
        symbols = [
            ("usr:freeze", "freeze", "demo::freeze", "function", "src/a.cpp", 1, 1, 4, 10, 1, 0, "demo::freeze", 0, 1,
             {"record": "symbol", "id": "usr:freeze", "name": "freeze", "qualified_name": "demo::freeze", "kind": "function", "file": "src/a.cpp", "line": 1, "end_line": 1, "start": 4, "end": 10, "definition": True}),
            ("usr:freeze", "freeze", "demo::freeze", "function", "src/b.cpp", 1, 1, 5, 11, 0, 1, "demo::freeze", 1, 1,
             {"record": "symbol", "id": "usr:freeze", "name": "freeze", "qualified_name": "demo::freeze", "kind": "function", "file": "src/b.cpp", "line": 1, "end_line": 1, "start": 5, "end": 11, "definition": False}),
        ]
        db.executemany("INSERT INTO symbols VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", [
            (*record[:14], self._pack(record[14])) for record in symbols])
        db.executemany("INSERT INTO occurrences VALUES(?,?,?,?)", [
            (0, 0, "src/a.cpp", self._pack({"translation_unit": "src/a.cpp", "configuration": "debug"})),
            (1, 0, "src/b.cpp", self._pack({"translation_unit": "src/b.cpp", "configuration": "debug"})),
        ])
        strings = [(1, "call"), (2, "caller"), (3, "usr:freeze"), (4, "src/a.cpp")]
        db.executemany("INSERT INTO strings VALUES(?,?)", strings)
        # type/from/to/file/translation_unit/start/end fields are present.
        mask = sum(1 << bit for bit in (0, 1, 2, 3, 4, 8, 9))
        db.execute("INSERT INTO edges VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (
            0, 2, 3, 4, 4, 1, None, None, None, 28, 34, None, None, None, None, mask,
            self._pack({"semantic": True})))
        db.commit()
        db.close()

    def _write_descriptor(self, generation):
        self.descriptor.write_text(json.dumps({
            "format": "CTXPP-EXPORT/2", "root": str(self.root.resolve()),
            "source_root": str(self.root.resolve()), "state_dir": str(self.state.resolve()),
            "database": "index.sqlite", "schema": "CTXPP-INDEX/2",
            "generation": generation, "artifact_id": generation,
        }), encoding="utf-8")

    def test_file_extraction_is_bounded_and_preserves_duplicate_symbol_rows_and_edges(self):
        decode = v2._decode_record
        with mock.patch.object(v2, "_decode_record", wraps=decode) as records:
            result = self.provider.extract(self.repository, "src/a.cpp", self.source)
        # One file row, its symbol and occurrence, and its sourced edge. The
        # second file's symbol is not decoded while extracting this file.
        self.assertEqual(records.call_count, 4)
        self.assertEqual(result.coverage, "complete")
        self.assertEqual([unit.name for unit in result.units], ["freeze", "call"])
        self.assertEqual(result.units[0].target, "usr:freeze")
        self.assertEqual(result.units[1].line, 2)
        self.assertEqual(result.units[1].metadata["edge"]["translation_unit"], "src/a.cpp")
        with closing(sqlite3.connect(self.database_path)) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM symbols WHERE id='usr:freeze'").fetchone()[0], 2)
        exported = json.loads(self.descriptor.read_text(encoding="utf-8"))
        self.assertEqual(exported["generation"], self.generation)

    def test_indexed_symbol_and_relationship_queries_touch_only_matching_paths(self):
        index = SourceIndex(self.repository, [self.provider])
        selected = index._cpp_candidate_paths(
            ["src/a.cpp", "src/b.cpp"], index._cpp_query(), symbol="usr:freeze")
        self.assertEqual(selected, ["src/a.cpp", "src/b.cpp"])
        callers = index._cpp_candidate_paths(
            ["src/a.cpp", "src/b.cpp"], index._cpp_query(), incoming={"usr:freeze"}, predicates=("call",))
        self.assertEqual(callers, ["src/a.cpp"])

    def test_v2_provider_matches_v1_structure_for_same_source_records(self):
        digest = hashlib.sha256(self.source).hexdigest()
        old_export = self.base / "legacy.json"
        old_export.write_text(json.dumps({
            "format": "CTXPP-EXPORT/1", "root": str(self.root.resolve()),
            "index_integrity": True, "index_meta": {"semantic": True, "incomplete": False},
            "freshness": {"status": "fresh"},
            "records": [
                {"record": "file", "path": "src/a.cpp", "hash": digest, "parse_status": "ok"},
                {"record": "symbol", "id": "usr:freeze", "name": "freeze", "qualified_name": "demo::freeze",
                 "kind": "function", "file": "src/a.cpp", "line": 1, "end_line": 1, "definition": True},
                {"record": "edge", "type": "call", "from": "caller", "to": "usr:freeze", "file": "src/a.cpp",
                 "translation_unit": "src/a.cpp", "start": 28, "end": 34, "semantic": True},
            ]}), encoding="utf-8")
        legacy = CppContextCompilerProvider(old_export).extract(self.repository, "src/a.cpp", self.source)
        current = self.provider.extract(self.repository, "src/a.cpp", self.source)
        self.assertEqual(asdict(current), asdict(legacy))

    def test_readonly_database_rejects_wrong_root_generation_schema_and_corruption(self):
        descriptor, _, _, _ = self.provider._load_export()
        self.assertEqual(descriptor["format"], "CTXPP-EXPORT/2")
        db, metadata = open_generation(descriptor)
        self.assertEqual(metadata["generation"], self.generation)
        self.assertEqual(read_file(db, "src/a.cpp")["hash"], hashlib.sha256(self.source).hexdigest())
        self.assertEqual(len(read_symbols(db, "src/a.cpp")), 1)
        self.assertEqual(read_edges(db, "src/a.cpp")[0]["type"], "call")
        db.close()

        wrong = self.base / "wrong-root"
        wrong.mkdir()
        self._write_descriptor("other-generation")
        mismatch = self.provider.extract(self.repository, "src/a.cpp", self.source)
        self.assertEqual(mismatch.coverage, "unavailable")
        self.assertTrue(any("generation" in item for item in mismatch.diagnostics))

        self._write_descriptor(self.generation)
        wrong_root = Repository(self.base / "wrong-root", "other", self.base / "other-state")
        mismatch = self.provider.extract(wrong_root, "src/a.cpp", self.source)
        self.assertEqual(mismatch.coverage, "mismatch")

        (self.root / "src/a.cpp").write_bytes(b"int changed();\n")
        stale = self.provider.extract(self.repository, "src/a.cpp", b"int changed();\n")
        self.assertEqual(stale.coverage, "stale")

    def test_v2_descriptor_symlink_is_rejected(self):
        link = self.base / "descriptor-link.json"
        link.symlink_to(self.descriptor)
        provider = CppContextCompilerProvider(link)
        result = provider.extract(self.repository, "src/a.cpp", self.source)
        self.assertEqual(result.coverage, "unavailable")
        self.assertEqual(result.units, ())


if __name__ == "__main__":
    unittest.main()
