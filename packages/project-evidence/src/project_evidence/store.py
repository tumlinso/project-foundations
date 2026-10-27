"""SQLite-backed append-only evidence records and content-addressed blobs."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import uuid
from contextlib import contextmanager
from typing import Any, Mapping


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _dump(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


@dataclass(frozen=True)
class SourceRef:
    repository_id: str
    path: str
    sha256: str
    revision: str | None = None
    worktree_id: str | None = None
    start_line: int | None = None
    end_line: int | None = None

    def __post_init__(self) -> None:
        if (not self.repository_id or not self.path or len(self.sha256) != 64 or
                any(c not in "0123456789abcdef" for c in self.sha256)):
            raise ValueError("source reference needs repository, path and SHA-256")
        if (self.start_line is None) != (self.end_line is None):
            raise ValueError("source line range needs both endpoints")
        if self.start_line is not None and (self.start_line < 1 or self.end_line < self.start_line):
            raise ValueError("invalid inclusive source line range")


@dataclass(frozen=True)
class ArtifactRef:
    artifact_id: str
    sha256: str
    byte_length: int
    media_type: str

    def __post_init__(self) -> None:
        if (len(self.sha256) != 64 or any(c not in "0123456789abcdef" for c in self.sha256)
                or self.byte_length < 0 or not self.media_type):
            raise ValueError("invalid artifact reference")


@dataclass(frozen=True)
class Observation:
    observation_id: str
    owner: str
    kind: str
    subject: str
    source_refs: tuple[SourceRef, ...] = ()
    artifact_refs: tuple[ArtifactRef, ...] = ()
    observed_at: str = ""
    payload: Mapping[str, Any] | None = None


@dataclass(frozen=True)
class Assessment:
    assessment_id: str
    observation_id: str
    assessor: str
    rubric: str
    outcome: str
    created_at: str = ""
    payload: Mapping[str, Any] | None = None


@dataclass(frozen=True)
class Relation:
    relation_id: str
    subject: str
    predicate: str
    object: str
    basis: str
    source_refs: tuple[SourceRef, ...] = ()
    asserted_by: str = ""
    created_at: str = ""

    def __post_init__(self) -> None:
        if self.basis not in {"observed", "declared", "guidance", "mention", "assessment"}:
            raise ValueError("unsupported relationship basis")


class EvidenceStore:
    """Explicit-path store. Records are insert-only; blob files are SHA-256 named."""

    def __init__(self, path: str | Path, artifact_dir: str | Path):
        self.path = Path(path).expanduser().resolve()
        self.artifact_dir = Path(artifact_dir).expanduser().resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.artifact_dir.mkdir(parents=True, exist_ok=True)
        self._initialize()

    @contextmanager
    def _connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        try:
            with db:
                yield db
        finally:
            db.close()

    def _initialize(self) -> None:
        with self._connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS artifacts(
                    artifact_id TEXT PRIMARY KEY, sha256 TEXT NOT NULL, byte_length INTEGER NOT NULL,
                    media_type TEXT NOT NULL, created_at TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS observations(
                    observation_id TEXT PRIMARY KEY, owner TEXT NOT NULL, kind TEXT NOT NULL,
                    subject TEXT NOT NULL, record TEXT NOT NULL, created_at TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS assessments(
                    assessment_id TEXT PRIMARY KEY, observation_id TEXT NOT NULL,
                    assessor TEXT NOT NULL, record TEXT NOT NULL, created_at TEXT NOT NULL,
                    FOREIGN KEY(observation_id) REFERENCES observations(observation_id));
                CREATE TABLE IF NOT EXISTS relations(
                    relation_id TEXT PRIMARY KEY, subject TEXT NOT NULL, predicate TEXT NOT NULL,
                    object TEXT NOT NULL, basis TEXT NOT NULL, record TEXT NOT NULL, created_at TEXT NOT NULL);
                CREATE TRIGGER IF NOT EXISTS observations_no_update BEFORE UPDATE ON observations BEGIN SELECT RAISE(ABORT,'append-only'); END;
                CREATE TRIGGER IF NOT EXISTS observations_no_delete BEFORE DELETE ON observations BEGIN SELECT RAISE(ABORT,'append-only'); END;
                CREATE TRIGGER IF NOT EXISTS assessments_no_update BEFORE UPDATE ON assessments BEGIN SELECT RAISE(ABORT,'append-only'); END;
                CREATE TRIGGER IF NOT EXISTS assessments_no_delete BEFORE DELETE ON assessments BEGIN SELECT RAISE(ABORT,'append-only'); END;
                CREATE TRIGGER IF NOT EXISTS relations_no_update BEFORE UPDATE ON relations BEGIN SELECT RAISE(ABORT,'append-only'); END;
                CREATE TRIGGER IF NOT EXISTS relations_no_delete BEFORE DELETE ON relations BEGIN SELECT RAISE(ABORT,'append-only'); END;
            """)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    def put_artifact(self, data: bytes, media_type: str = "application/octet-stream") -> ArtifactRef:
        if not isinstance(data, bytes):
            raise TypeError("artifact data must be bytes")
        digest = hashlib.sha256(data).hexdigest()
        destination = self.artifact_dir / digest[:2] / digest[2:]
        destination.parent.mkdir(parents=True, exist_ok=True)
        if not destination.exists():
            tmp = destination.with_name(destination.name + "." + uuid.uuid4().hex + ".tmp")
            tmp.write_bytes(data)
            try:
                os.chmod(tmp, 0o600)
            except OSError:
                pass
            try:
                os.replace(tmp, destination)
            finally:
                tmp.unlink(missing_ok=True)
        artifact_id = "sha256:" + digest
        ref = ArtifactRef(artifact_id, digest, len(data), media_type)
        with self._connect() as db:
            db.execute("INSERT OR IGNORE INTO artifacts VALUES(?,?,?,?,?)",
                       (artifact_id, digest, len(data), media_type, _now()))
        return ref

    def get_artifact(self, ref: ArtifactRef | str) -> bytes:
        digest = ref.sha256 if isinstance(ref, ArtifactRef) else ref.removeprefix("sha256:")
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise ValueError("invalid artifact digest")
        data = (self.artifact_dir / digest[:2] / digest[2:]).read_bytes()
        if hashlib.sha256(data).hexdigest() != digest:
            raise IOError("artifact content does not match its identity")
        return data

    def record_observation(self, record: Observation) -> Observation:
        now = record.observed_at or _now()
        record = Observation(record.observation_id or uuid.uuid4().hex, record.owner, record.kind,
                             record.subject, tuple(record.source_refs), tuple(record.artifact_refs), now,
                             dict(record.payload or {}))
        value = asdict(record)
        with self._connect() as db:
            db.execute("INSERT INTO observations VALUES(?,?,?,?,?,?)",
                       (record.observation_id, record.owner, record.kind, record.subject, _dump(value), now))
        return record

    def record_assessment(self, record: Assessment) -> Assessment:
        record = Assessment(record.assessment_id or uuid.uuid4().hex, record.observation_id,
                            record.assessor, record.rubric, record.outcome,
                            record.created_at or _now(), dict(record.payload or {}))
        with self._connect() as db:
            db.execute("INSERT INTO assessments VALUES(?,?,?,?,?)", (record.assessment_id,
                       record.observation_id, record.assessor, _dump(asdict(record)), record.created_at))
        return record

    def record_relation(self, record: Relation) -> Relation:
        record = Relation(record.relation_id or uuid.uuid4().hex, record.subject, record.predicate,
                          record.object, record.basis, tuple(record.source_refs), record.asserted_by,
                          record.created_at or _now())
        with self._connect() as db:
            db.execute("INSERT INTO relations VALUES(?,?,?,?,?,?,?)", (record.relation_id,
                       record.subject, record.predicate, record.object, record.basis,
                       _dump(asdict(record)), record.created_at))
        return record

    def get_observation(self, observation_id: str) -> dict[str, Any] | None:
        with self._connect() as db:
            row = db.execute("SELECT record FROM observations WHERE observation_id=?", (observation_id,)).fetchone()
        return json.loads(row[0]) if row else None

    def list_observations(self, *, owner: str | None = None, subject: str | None = None,
                          limit: int = 100) -> list[dict[str, Any]]:
        if not 1 <= limit <= 1000:
            raise ValueError("limit must be 1..1000")
        sql, params = "SELECT record FROM observations", []
        clauses = []
        if owner is not None: clauses.append("owner=?"); params.append(owner)
        if subject is not None: clauses.append("subject=?"); params.append(subject)
        if clauses: sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY created_at, observation_id LIMIT ?"; params.append(limit)
        with self._connect() as db:
            return [json.loads(row[0]) for row in db.execute(sql, params)]

    def list_assessments(self, observation_id: str, limit: int = 100) -> list[dict[str, Any]]:
        with self._connect() as db:
            return [json.loads(row[0]) for row in db.execute(
                "SELECT record FROM assessments WHERE observation_id=? ORDER BY created_at LIMIT ?",
                (observation_id, limit))]

    def list_relations(self, *, subject: str | None = None, basis: str | None = None,
                       limit: int = 100) -> list[dict[str, Any]]:
        sql, params, clauses = "SELECT record FROM relations", [], []
        if subject is not None: clauses.append("subject=?"); params.append(subject)
        if basis is not None: clauses.append("basis=?"); params.append(basis)
        if clauses: sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY created_at, relation_id LIMIT ?"; params.append(limit)
        with self._connect() as db:
            return [json.loads(row[0]) for row in db.execute(sql, params)]


class EvidenceReader:
    """Read-only view of a configured evidence authority.

    Construction never creates directories, opens a writable connection, or
    initializes a schema. A missing authority reports ``available=False``;
    reads against it raise ``FileNotFoundError``.
    """
    def __init__(self, path: str | Path, artifact_dir: str | Path | None = None):
        self.path = Path(path).expanduser().resolve()
        self.artifact_dir = Path(artifact_dir).expanduser().resolve() if artifact_dir is not None else None

    @property
    def available(self) -> bool:
        return self.path.is_file()

    @contextmanager
    def _connect(self):
        if not self.available: raise FileNotFoundError(self.path)
        db=sqlite3.connect(self.path.as_uri()+"?mode=ro",uri=True)
        db.row_factory=sqlite3.Row
        db.execute("PRAGMA query_only=ON")
        try:
            with db: yield db
        finally: db.close()

    def _require_schema(self, db: sqlite3.Connection, table: str) -> None:
        found=db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(table,)).fetchone()
        if not found: raise ValueError(f"not a Project Evidence database: missing {table} table")

    def get_observation(self, observation_id: str) -> dict[str, Any] | None:
        with self._connect() as db:
            self._require_schema(db,"observations")
            row=db.execute("SELECT record FROM observations WHERE observation_id=?",(observation_id,)).fetchone()
        return json.loads(row[0]) if row else None

    def list_observations(self, *, owner: str | None = None, subject: str | None = None,
                          limit: int = 100) -> list[dict[str, Any]]:
        if not 1<=limit<=1000: raise ValueError("limit must be 1..1000")
        with self._connect() as db:
            self._require_schema(db,"observations")
            sql,params,clauses="SELECT record FROM observations",[],[]
            if owner is not None: clauses.append("owner=?"); params.append(owner)
            if subject is not None: clauses.append("subject=?"); params.append(subject)
            if clauses: sql+=" WHERE "+" AND ".join(clauses)
            sql+=" ORDER BY created_at,observation_id LIMIT ?"; params.append(limit)
            return [json.loads(row[0]) for row in db.execute(sql,params)]

    def list_assessments(self, observation_id: str, limit: int = 100) -> list[dict[str, Any]]:
        if not 1<=limit<=1000: raise ValueError("limit must be 1..1000")
        with self._connect() as db:
            self._require_schema(db,"assessments")
            return [json.loads(row[0]) for row in db.execute(
                "SELECT record FROM assessments WHERE observation_id=? ORDER BY created_at,assessment_id LIMIT ?",
                (observation_id,limit))]

    def list_relations(self, *, subject: str | None = None, basis: str | None = None,
                       limit: int = 100) -> list[dict[str, Any]]:
        if not 1<=limit<=1000: raise ValueError("limit must be 1..1000")
        with self._connect() as db:
            self._require_schema(db,"relations")
            sql,params,clauses="SELECT record FROM relations",[],[]
            if subject is not None: clauses.append("subject=?"); params.append(subject)
            if basis is not None: clauses.append("basis=?"); params.append(basis)
            if clauses: sql+=" WHERE "+" AND ".join(clauses)
            sql+=" ORDER BY created_at,relation_id LIMIT ?"; params.append(limit)
            return [json.loads(row[0]) for row in db.execute(sql,params)]

    def get_artifact(self, ref: ArtifactRef | str) -> bytes:
        if self.artifact_dir is None: raise ValueError("artifact_dir is required to read artifact bytes")
        digest=ref.sha256 if isinstance(ref,ArtifactRef) else ref.removeprefix("sha256:")
        if len(digest)!=64 or any(c not in "0123456789abcdef" for c in digest): raise ValueError("invalid artifact digest")
        data=(self.artifact_dir/digest[:2]/digest[2:]).read_bytes()
        if hashlib.sha256(data).hexdigest()!=digest: raise IOError("artifact content does not match its identity")
        return data


@dataclass(frozen=True)
class LegacyPacket:
    packet_id: str
    alias: str
    metadata: Mapping[str, Any]
    payload: str | None
    expired: bool
    provenance: str = "legacy_project_control_packet"


@dataclass(frozen=True)
class LegacyNote:
    note_id: str
    project: str
    metadata: Mapping[str, Any]
    advisory: bool = True
    independent_evidence: bool = False
    provenance: str = "legacy_project_control_note"


class LegacyReader:
    """Read-only adapter for copied Project Control packet/note SQLite stores."""
    def __init__(self, path: str | Path):
        self.path = Path(path).expanduser().resolve()
        if not self.path.is_file():
            raise FileNotFoundError(self.path)

    @contextmanager
    def _connect(self):
        uri = self.path.as_uri() + "?mode=ro"
        db = sqlite3.connect(uri, uri=True)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA query_only=ON")
        try:
            yield db
        finally:
            db.close()

    def packets(self, limit: int = 100) -> list[LegacyPacket]:
        with self._connect() as db:
            tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if not {"packets", "bodies"}.issubset(tables): return []
            rows = db.execute("SELECT p.id,p.alias,p.metadata,p.hash,p.expired,b.payload FROM packets p "
                              "LEFT JOIN bodies b ON b.hash=p.hash ORDER BY p.id LIMIT ?", (limit,))
            return [LegacyPacket(r["id"], r["alias"], json.loads(r["metadata"]), r["payload"],
                                 bool(r["expired"])) for r in rows]

    def notes(self, limit: int = 100) -> list[LegacyNote]:
        with self._connect() as db:
            tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if "knowledge_notes" not in tables: return []
            rows = db.execute("SELECT note_id,project,metadata FROM knowledge_notes "
                              "ORDER BY created,note_id LIMIT ?", (limit,))
            return [LegacyNote(r["note_id"], r["project"], json.loads(r["metadata"])) for r in rows]
