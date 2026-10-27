import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from project_evidence import Assessment, EvidenceReader, EvidenceStore, LegacyReader, Observation, Relation


class EvidenceTests(unittest.TestCase):
    def test_artifacts_records_and_append_only_assessments(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = EvidenceStore(root / "evidence.sqlite", root / "blobs")
            artifact = store.put_artifact(b"result", "text/plain")
            observation = store.record_observation(Observation("obs-1", "lab", "measurement", "run-1",
                artifact_refs=(artifact,), payload={"value": 3}))
            assessment = store.record_assessment(Assessment("ass-1", observation.observation_id,
                "reviewer", "reproduction", "supported"))
            store.record_relation(Relation("rel-1", "run-1", "measured", "result-1", "observed"))
            self.assertEqual(store.get_artifact(artifact), b"result")
            self.assertEqual(store.get_observation("obs-1")["payload"], {"value": 3})
            self.assertEqual(store.list_assessments("obs-1")[0]["assessment_id"], assessment.assessment_id)
            with self.assertRaises(sqlite3.IntegrityError):
                with store._connect() as db: db.execute("DELETE FROM observations WHERE observation_id='obs-1'")

    def test_legacy_reader_is_readonly_and_notes_are_advisory(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "legacy.sqlite"
            db = sqlite3.connect(path)
            db.executescript("CREATE TABLE bodies(hash TEXT PRIMARY KEY,payload TEXT NOT NULL);"
                "CREATE TABLE packets(id TEXT PRIMARY KEY,alias TEXT,metadata TEXT,hash TEXT,expired INTEGER);"
                "CREATE TABLE knowledge_notes(note_id TEXT,project TEXT,metadata TEXT,access_scope TEXT,created REAL,updated REAL);")
            db.execute("INSERT INTO bodies VALUES('abc','packet body')")
            db.execute("INSERT INTO packets VALUES('p1','alias','{}','abc',0)")
            db.execute("INSERT INTO knowledge_notes VALUES('n1','repo',?, '{}',1,1)",
                       (json.dumps({"claim":"maybe true","provenance":"model","authoritative":True}),))
            db.commit(); db.close()
            before = path.read_bytes()
            reader = LegacyReader(path)
            self.assertEqual(reader.packets()[0].payload, "packet body")
            note = reader.notes()[0]
            self.assertTrue(note.advisory)
            self.assertFalse(note.independent_evidence)
            self.assertEqual(path.read_bytes(), before)

    def test_evidence_reader_does_not_initialize_or_write(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            missing=root/"missing"/"authority.sqlite"
            reader=EvidenceReader(missing)
            self.assertFalse(reader.available)
            self.assertFalse(missing.parent.exists())
            with self.assertRaises(FileNotFoundError): reader.list_observations()
            store=EvidenceStore(root/"authority.sqlite",root/"blobs")
            store.record_observation(Observation("obs", "lab", "result", "run"))
            before=store.path.read_bytes()
            readonly=EvidenceReader(store.path)
            self.assertTrue(readonly.available)
            self.assertEqual(readonly.list_observations(),store.list_observations())
            with self.assertRaises(sqlite3.OperationalError):
                with readonly._connect() as db: db.execute("CREATE TABLE accidental(value TEXT)")
            self.assertEqual(store.path.read_bytes(),before)


if __name__ == "__main__": unittest.main()
