"""Read-only access to the versioned ctxpp SQLite artifact format.

The descriptor is intentionally small.  Graph records stay in the SQLite
database and consumers decode only rows for the requested source file.
"""
from __future__ import annotations

import json
from pathlib import Path, PurePosixPath
import sqlite3
import zlib
from typing import Any


FORMAT = "CTXPP-EXPORT/2"
INDEX_FORMAT = "CTXPP-INDEX/2"
_EDGE_FIELDS = (
    "type", "from", "to", "file", "translation_unit", "kind",
    "configuration_hash", "via", "start", "end", "line", "column",
    "end_line", "end_column",
)
class CtxppArtifactError(ValueError):
    """A v2 ctxpp descriptor or database is unavailable or inconsistent."""


def _decode_json(value: Any) -> Any:
    if isinstance(value, bytes):
        value = value.decode("utf-8")
    if not isinstance(value, str):
        return value
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return value


def _decode_record(value: bytes | str | None) -> dict[str, Any]:
    if value is None:
        return {}
    try:
        if isinstance(value, str):
            raw = value.encode("utf-8")
        else:
            raw = value
        decoded = json.loads(zlib.decompress(raw))
    except (zlib.error, UnicodeDecodeError, json.JSONDecodeError, TypeError) as exc:
        raise CtxppArtifactError(f"invalid compressed ctxpp record: {exc}") from exc
    if not isinstance(decoded, dict):
        raise CtxppArtifactError("ctxpp record payload must be an object")
    return decoded


def load_descriptor(path: Path, expected_root: Path | None = None) -> dict[str, Any]:
    """Read and validate the small v2 descriptor without opening project source."""
    if path.is_symlink() or not path.is_file():
        raise CtxppArtifactError("ctxpp descriptor is missing or is not a regular file")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CtxppArtifactError(f"cannot read ctxpp descriptor: {exc}") from exc
    if not isinstance(payload, dict) or payload.get("format") != FORMAT:
        raise CtxppArtifactError("unsupported ctxpp export format")
    if payload.get("schema") != INDEX_FORMAT:
        raise CtxppArtifactError("unsupported ctxpp index schema")
    try:
        source_root = Path(payload["source_root"]).resolve(strict=True)
        state_dir = Path(payload["state_dir"]).resolve(strict=True)
    except (KeyError, TypeError, OSError) as exc:
        raise CtxppArtifactError("ctxpp source root or state directory is unavailable") from exc
    if expected_root is not None and source_root != expected_root.resolve():
        raise CtxppArtifactError("export repository root does not match source repository")
    database = payload.get("database")
    if not isinstance(database, str):
        raise CtxppArtifactError("ctxpp database path is missing")
    relative = PurePosixPath(database)
    if relative.is_absolute() or ".." in relative.parts or not relative.parts:
        raise CtxppArtifactError("ctxpp database path must be relative to its state directory")
    candidate = state_dir.joinpath(*relative.parts)
    if candidate.is_symlink() or not candidate.is_file():
        raise CtxppArtifactError("ctxpp database is missing or is not a regular file")
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(state_dir)
    except (OSError, ValueError) as exc:
        raise CtxppArtifactError("ctxpp database path escapes its state directory") from exc
    generation = payload.get("generation")
    if not isinstance(generation, (str, int)) or str(generation) == "":
        raise CtxppArtifactError("ctxpp generation is missing")
    if str(payload.get("artifact_id", "")) != str(generation):
        raise CtxppArtifactError("ctxpp artifact identity does not match its generation")
    return {**payload, "source_root": str(source_root), "state_dir": str(state_dir),
            "database_path": resolved}


def open_generation(descriptor: dict[str, Any]) -> tuple[sqlite3.Connection, dict[str, Any]]:
    """Open a read-only SQLite snapshot and validate it inside one transaction."""
    path = descriptor["database_path"]
    try:
        database = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=2.0)
        database.row_factory = sqlite3.Row
        database.execute("PRAGMA query_only=ON")
        database.execute("BEGIN")
        if database.execute("PRAGMA user_version").fetchone()[0] != 2:
            raise CtxppArtifactError("ctxpp SQLite user_version is not 2")
        rows = database.execute("SELECT key,value FROM metadata").fetchall()
        metadata = {row["key"]: _decode_json(row["value"]) for row in rows}
        if str(metadata.get("schema")) != "2":
            raise CtxppArtifactError("ctxpp database metadata schema is not 2")
        if str(metadata.get("generation")) != str(descriptor["generation"]):
            raise CtxppArtifactError("ctxpp database generation differs from descriptor")
        if str(metadata.get("source_root", "")) != str(descriptor["source_root"]):
            raise CtxppArtifactError("ctxpp database source root differs from descriptor")
        files = database.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='files'"
        ).fetchone()
        if files is None:
            raise CtxppArtifactError("ctxpp database is missing the files table")
        return database, metadata
    except CtxppArtifactError:
        try:
            database.close()
        except UnboundLocalError:
            pass
        raise
    except (sqlite3.Error, OSError, ValueError) as exc:
        try:
            database.close()
        except UnboundLocalError:
            pass
        raise CtxppArtifactError(f"cannot open ctxpp database: {exc}") from exc


def read_file(database: sqlite3.Connection, path: str) -> dict[str, Any] | None:
    row = database.execute("SELECT data FROM files WHERE path=?", (path,)).fetchone()
    if row is None:
        return None
    record = _decode_record(row["data"])
    if record.get("record") != "file" or record.get("path") != path:
        raise CtxppArtifactError("ctxpp file row does not match its key")
    return record


def read_symbols(database: sqlite3.Connection, path: str) -> list[dict[str, Any]]:
    rows = database.execute(
        "SELECT id,symbol_order,data,has_occurrences FROM symbols WHERE file=? ORDER BY symbol_order", (path,)
    ).fetchall()
    result = []
    for row in rows:
        record = _decode_record(row["data"])
        if record.get("record") != "symbol" or record.get("file") != path or str(record.get("id")) != row["id"]:
            raise CtxppArtifactError("ctxpp symbol row does not match its key")
        if row["has_occurrences"]:
            occurrences = database.execute(
                "SELECT data FROM occurrences WHERE symbol_row_id=? ORDER BY occurrence_order",
                (row["symbol_order"],)
            ).fetchall()
            record["occurrences"] = [_decode_record(item["data"]) for item in occurrences]
        result.append(record)
    return result


def read_edges(database: sqlite3.Connection, path: str) -> list[dict[str, Any]]:
    """Read edges sourced in one file; preserve exact v1 edge records."""
    try:
        rows = database.execute(
            "SELECT e.*, f.value AS edge_file, t.value AS edge_type, "
            "s.value AS edge_from, d.value AS edge_to, k.value AS edge_kind, "
            "c.value AS edge_config, v.value AS edge_via, u.value AS edge_tu "
            "FROM edges e JOIN strings f ON f.id=e.file_id "
            "LEFT JOIN strings t ON t.id=e.type_id LEFT JOIN strings s ON s.id=e.from_id "
            "LEFT JOIN strings d ON d.id=e.to_id LEFT JOIN strings k ON k.id=e.kind_id "
            "LEFT JOIN strings c ON c.id=e.config_id LEFT JOIN strings v ON v.id=e.via_id "
            "LEFT JOIN strings u ON u.id=e.tu_id "
            "WHERE f.value=? ORDER BY e.edge_order", (path,)
        ).fetchall()
    except sqlite3.Error as exc:
        raise CtxppArtifactError(f"cannot query ctxpp edges: {exc}") from exc
    output = []
    for row in rows:
        record = {"record": "edge", **_decode_record(row["data"])}
        values = {
            "type": row["edge_type"], "from": row["edge_from"], "to": row["edge_to"],
            "file": row["edge_file"], "translation_unit": row["edge_tu"],
            "kind": row["edge_kind"], "configuration_hash": row["edge_config"], "via": row["edge_via"],
            "start": row["start"], "end": row["end"], "line": row["line"], "column": row["column"],
            "end_line": row["end_line"], "end_column": row["end_column"],
        }
        mask = int(row["fields"])
        for bit, field in enumerate(_EDGE_FIELDS):
            if mask & (1 << bit):
                record[field] = values[field]
        output.append(record)
    return output
