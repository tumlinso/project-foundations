"""Bounded, provenance-carrying local source retrieval."""
from __future__ import annotations

import ast
import base64
from dataclasses import asdict, dataclass, field, replace
import fnmatch
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import sqlite3
import subprocess
from contextlib import contextmanager
from typing import Any, Iterable, Mapping, Protocol

from project_evidence import SourceRef


@dataclass(frozen=True)
class Repository:
    root: str | Path
    repository_id: str
    state_dir: str | Path
    revision: str | None = None
    worktree_id: str | None = None
    exclude: tuple[str, ...] = (".git", ".ctxpp", "__pycache__", ".venv", "venv", "node_modules")
    deny_patterns: tuple[str, ...] = ()

    def __post_init__(self):
        root = Path(self.root).expanduser().resolve()
        state = Path(self.state_dir).expanduser().resolve()
        if not root.is_dir(): raise NotADirectoryError(root)
        if not self.repository_id: raise ValueError("repository_id is required")
        object.__setattr__(self, "root", root)
        object.__setattr__(self, "state_dir", state)

    @property
    def identity(self) -> str:
        revision = self.revision or "working-tree"
        return f"{self.repository_id}@{revision}:{self.worktree_id or _worktree_id(self.root)}"

    def includes(self, path: str) -> bool:
        """Return whether a repository-relative path is visible under this view."""
        normalized = PurePosixPath(path).as_posix()
        parts = PurePosixPath(normalized).parts
        if any(part in self.exclude for part in parts): return False
        if normalized.startswith("./"): normalized = normalized[2:]
        return not any(PurePosixPath(normalized).match(pattern) or fnmatch.fnmatchcase(normalized, pattern)
                       for pattern in self.deny_patterns)


@dataclass(frozen=True)
class SourceResult:
    path: str
    content: str | None
    sha256: str
    source: SourceRef
    complete: bool = True
    omissions: tuple[str, ...] = ()
    cursor: str | None = None


@dataclass(frozen=True)
class RetrievalTarget:
    """Typed source target suitable for composing one retrieval request."""
    kind: str
    target: str = ""
    path: str | None = None
    symbol: str | None = None
    repository_id: str | None = None
    revision: str | None = None
    line_start: int | None = None
    line_end: int | None = None

    def __post_init__(self):
        if self.kind not in {"path","file","symbol","entity"}:
            raise ValueError("target kind must be path, file, symbol or entity")
        if not (self.target or self.path or self.symbol): raise ValueError("target needs path, symbol or target")
        if self.line_start is not None and self.line_start<1:
            raise ValueError("target line_start must be positive")
        if self.line_end is not None and self.line_end<1:
            raise ValueError("target line_end must be positive")
        if self.line_start is not None and self.line_end is not None and self.line_end<self.line_start:
            raise ValueError("invalid target line range")


@dataclass(frozen=True)
class StructuralUnit:
    name: str
    kind: str
    path: str
    line: int
    end_line: int
    qualified_name: str | None = None
    target: str | None = None
    resolution: str = "resolved"
    basis: str = "observed"
    provider: str = "python-ast"
    source_sha256: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class StructuralResult:
    path: str
    sha256: str
    units: tuple[StructuralUnit, ...]
    coverage: str = "complete"
    diagnostics: tuple[str, ...] = ()
    provider: str = "python-ast"


class StructuralProvider(Protocol):
    name: str
    def extract(self, repository: Repository, path: str, source_bytes: bytes) -> StructuralResult: ...


class CppContextCompilerProvider:
    """Read-only adapter for a previously exported CTXPP index.

    The caller supplies an export file. This adapter never invokes ctxpp, scans
    source, initializes state, or refreshes stale records.
    """
    name = "cpp-context-compiler"

    def __init__(self, export_path: str | Path):
        self.export_path = Path(export_path).expanduser().resolve()

    def extract(self, repository: Repository, path: str, source_bytes: bytes) -> StructuralResult:
        if not repository.includes(path):
            return StructuralResult(path, hashlib.sha256(source_bytes).hexdigest(), (),
                "unavailable", ("source path is excluded by repository policy",), self.name)
        try:
            envelope = json.loads(self.export_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return StructuralResult(path, hashlib.sha256(source_bytes).hexdigest(), (),
                "unavailable", (f"cannot read C++ export: {exc}",), self.name)
        if envelope.get("format") != "CTXPP-EXPORT/1":
            return StructuralResult(path, hashlib.sha256(source_bytes).hexdigest(), (),
                "unsupported", ("unsupported cpp-context-compiler export format",), self.name)
        if envelope.get("index_integrity") is False:
            return StructuralResult(path, hashlib.sha256(source_bytes).hexdigest(), (),
                "corrupt", ("producer reported an index integrity failure",), self.name)
        export_root = Path(envelope.get("root", "")).resolve()
        if export_root != Path(repository.root):
            return StructuralResult(path, hashlib.sha256(source_bytes).hexdigest(), (),
                "mismatch", ("export repository root does not match source repository",), self.name)
        digest = hashlib.sha256(source_bytes).hexdigest()
        records = envelope.get("records", [])
        indexed = next((r for r in records if r.get("record") == "file" and
                        r.get("path", r.get("file")) == path), None)
        if indexed is None:
            return StructuralResult(path, digest, (), "unavailable",
                ("file is absent from the exported C++ index",), self.name)
        if indexed and indexed.get("hash") not in {None, digest}:
            return StructuralResult(path, digest, (), "stale",
                ("exported C++ file hash differs from current source",), self.name)
        symbols = [r for r in records if r.get("record") == "symbol" and r.get("file") == path]
        units: list[StructuralUnit] = []
        for record in symbols:
            record_path = str(record.get("file", ""))
            if not repository.includes(record_path):
                continue
            line = int(record.get("line", 1)); end_line = int(record.get("end_line", line))
            units.append(StructuralUnit(str(record.get("name", "")),
                "definition" if record.get("definition") else "declaration", path, line, end_line,
                record.get("qualified_name"), target=record.get("id"),
                resolution="resolved", basis="observed", provider=self.name,
                source_sha256=digest, metadata={"semantic_origin": record.get("semantic_origin"),
                    "degraded": bool(record.get("degraded")), "representation_kind": record.get("representation_kind"),
                    "symbol_id": record.get("id")}))
        edges = [r for r in records if r.get("record") == "edge" and r.get("file") == path]
        for edge in edges:
            record_path = str(edge.get("file", ""))
            if not repository.includes(record_path):
                continue
            start_offset=int(edge.get("start",0)); end_offset=int(edge.get("end",start_offset))
            units.append(StructuralUnit(str(edge.get("type", "reference")), str(edge.get("type", "reference")),
                path, int(edge.get("line",source_bytes[:start_offset].count(b"\n")+1)),
                int(edge.get("end_line",source_bytes[:end_offset].count(b"\n")+1)),
                target=edge.get("to"), resolution="resolved" if edge.get("to") else "unresolved",
                basis="observed", provider=self.name, source_sha256=digest,
                metadata={"from": edge.get("from"), "type": edge.get("type"),
                          "semantic": edge.get("semantic", True), "edge": edge}))
        freshness = envelope.get("freshness", {})
        status = freshness.get("status", freshness.get("freshness", "unknown")) if isinstance(freshness, dict) else "unknown"
        if status == "unknown" and envelope.get("freshness_scope") == "as-recorded-at-index-time" and indexed.get("hash") == digest:
            status = "fresh-for-selected-source"
        meta = envelope.get("index_meta", {})
        diagnostics = [] if status in {"fresh", "current", "ok", "fresh-for-selected-source"} else [f"producer freshness status: {status}"]
        if meta.get("semantic") is False:
            diagnostics.append("producer index is lexical/degraded, not fully semantic")
        if indexed.get("parse_status") in {"error", "unobserved"}:
            diagnostics.append(f"file parse status: {indexed['parse_status']}")
        if meta.get("incomplete"):
            diagnostics.append("producer index reports incomplete overall coverage")
        coverage = "complete" if not diagnostics else "partial"
        return StructuralResult(path, digest, tuple(units), coverage, tuple(diagnostics), self.name)


@dataclass(frozen=True)
class ContextPacket:
    sections: dict[str, tuple[Any, ...]]
    budget_bytes: int
    used_bytes: int
    complete: bool
    omissions: tuple[Any, ...] = ()
    cursor: str | None = None
    continuations: tuple[dict[str, Any], ...] = ()
    associations: tuple[dict[str, Any], ...] = ()


def _git(root: Path, *args: str) -> str | None:
    try:
        result = subprocess.run(["git", "-C", str(root), *args], capture_output=True,
                                text=True, timeout=3, check=True)
        return result.stdout.strip() or None
    except (OSError, subprocess.SubprocessError):
        return None


def _worktree_id(root: Path) -> str:
    return "wt-" + hashlib.sha256(str(root).encode()).hexdigest()[:12]


def _cursor(offset: int, scope: str) -> str:
    payload=json.dumps({"offset":offset,"scope":scope},sort_keys=True,separators=(",",":"))
    return base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=")


def _offset(cursor: str | None, scope: str) -> int:
    if not cursor: return 0
    try:
        payload=json.loads(base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)))
        if payload.get("scope")!=scope: raise ValueError("cursor does not match this query or source generation")
        return max(0,int(payload["offset"]))
    except ValueError: raise
    except Exception as exc: raise ValueError("invalid continuation cursor") from exc


class SourceIndex:
    """Content-hash index with caller-selected state and bounded read methods."""
    def __init__(self, repository: Repository, providers: Iterable[StructuralProvider] = ()):
        self.repository = repository
        self.providers = {p.name: p for p in providers}
        self.repository.state_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = Path(self.repository.state_dir) / (hashlib.sha256(
            self.repository.repository_id.encode()).hexdigest()[:16] + ".sqlite3")
        with self._connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS files(path TEXT PRIMARY KEY, sha256 TEXT NOT NULL,
                  size INTEGER NOT NULL, mtime_ns INTEGER NOT NULL, ctime_ns INTEGER NOT NULL DEFAULT 0, text TEXT);
                CREATE TABLE IF NOT EXISTS units(path TEXT NOT NULL, sha256 TEXT NOT NULL,
                  record TEXT NOT NULL, PRIMARY KEY(path,sha256,record));
            """)
            columns={r[1] for r in db.execute("PRAGMA table_info(files)")}
            if "ctime_ns" not in columns: db.execute("ALTER TABLE files ADD COLUMN ctime_ns INTEGER NOT NULL DEFAULT 0")

    @contextmanager
    def _connect(self):
        db = sqlite3.connect(self.db_path, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def _path(self, value: str | Path) -> tuple[Path, str]:
        raw = Path(value)
        full = (self.repository.root / raw).resolve() if not raw.is_absolute() else raw.resolve()
        try: rel = full.relative_to(self.repository.root).as_posix()
        except ValueError as exc: raise ValueError("source path escapes repository root") from exc
        if any(part in {"..", ".git"} for part in PurePosixPath(rel).parts):
            raise ValueError("source path is outside the readable project tree")
        return full, rel

    def _included(self, rel: str) -> bool:
        return self.repository.includes(rel)

    def _normalize_target(self, value: Any) -> dict[str, Any]:
        if isinstance(value, str):
            try:
                _,rel=self._path(value)
                is_path=(self.repository.root/rel).is_file() or bool(self.repository.revision)
            except ValueError:
                is_path=False
            return asdict(RetrievalTarget("path" if is_path else "symbol",target=value,path=value if is_path else None,
                symbol=None if is_path else value))
        if isinstance(value, RetrievalTarget): record=asdict(value)
        elif isinstance(value, Mapping): record=dict(value)
        elif hasattr(value,"model_dump"): record=value.model_dump()
        elif hasattr(value,"dict"): record=value.dict()
        else: raise TypeError("targets must be strings, RetrievalTarget records or mappings")
        kind=str(record.get("kind","entity"))
        path=record.get("path"); symbol=record.get("symbol")
        target=record.get("target") or symbol or path
        normalized=asdict(RetrievalTarget(kind=kind,target=str(target or ""),path=str(path) if path is not None else None,
            symbol=str(symbol) if symbol is not None else None,
            repository_id=record.get("repository_id"),revision=record.get("revision"),
            line_start=record.get("line_start"),line_end=record.get("line_end")))
        if normalized["repository_id"] not in {None,self.repository.repository_id}:
            raise ValueError(f"target belongs to repository {normalized['repository_id']!r}, not {self.repository.repository_id!r}")
        return normalized

    def read(self, path: str, start_line: int | None = None, end_line: int | None = None,
             max_bytes: int = 64_000, cursor: str | None = None) -> SourceResult:
        if max_bytes < 1: raise ValueError("max_bytes must be positive")
        full, rel = self._path(path)
        if not self._included(rel): raise FileNotFoundError(rel)
        revision = self.repository.revision
        if revision:
            try:
                proc = subprocess.run(["git", "-C", str(self.repository.root), "show", f"{revision}:{rel}"],
                    capture_output=True, timeout=5, check=True)
                data = proc.stdout
            except (OSError, subprocess.SubprocessError):
                raise FileNotFoundError(f"{rel} at revision {revision}")
        else:
            if not full.is_file(): raise FileNotFoundError(rel)
            data = full.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        text = data.decode("utf-8", errors="replace")
        line_start = line_end = None
        if start_line is not None or end_line is not None:
            lines = text.splitlines(keepends=True)
            start = start_line or 1; end = end_line or len(lines)
            if start < 1 or end < start: raise ValueError("invalid inclusive line range")
            line_start,line_end=start,end
            text = "".join(lines[start - 1:end])
        raw = text.encode("utf-8")
        scope=f"read:{rel}:{digest}:{line_start}:{line_end}"
        offset=_offset(cursor,scope)
        if offset>len(raw): raise ValueError("read cursor is past the end of the selected source")
        page=raw[offset:offset+max_bytes]
        next_offset=offset+len(page)
        complete=next_offset>=len(raw)
        text=page.decode("utf-8",errors="replace")
        source = SourceRef(self.repository.repository_id, rel, digest,
                           revision,
                           self.repository.worktree_id or _worktree_id(self.repository.root),
                           line_start, line_end)
        return SourceResult(rel, text, digest, source, complete,
                            () if complete else (f"content truncated at {max_bytes} bytes",),
                            None if complete else _cursor(next_offset,scope))

    def tree(self, path: str | None = None, limit: int = 200, cursor: str | None = None) -> dict[str, Any]:
        if not 1 <= limit <= 2000: raise ValueError("limit must be 1..2000")
        base, base_rel = self._path(path or ".")
        if base_rel != "." and not self._included(base_rel): raise FileNotFoundError(base_rel)
        if self.repository.revision:
            output = _git(self.repository.root, "ls-tree", "-r", "--name-only", self.repository.revision)
            if output is None: raise ValueError(f"cannot list revision {self.repository.revision}")
            items = [name for name in output.splitlines() if (base_rel == "." or name == base_rel or name.startswith(base_rel.rstrip("/") + "/")) and self._included(name)]
        elif not base.exists(): raise FileNotFoundError(base_rel)
        elif base.is_file(): items = [base_rel]
        else:
            listed=_git(self.repository.root,"ls-files","--cached","--others","--exclude-standard","-z")
            if listed is not None:
                all_paths=[p for p in listed.split("\0") if p and self._included(p)]
                items=[p for p in all_paths if base_rel=="." or p==base_rel or p.startswith(base_rel.rstrip("/")+"/")]
            else:
                items = []
                for root, dirs, files in os.walk(base):
                    dirs[:] = sorted(d for d in dirs if d not in self.repository.exclude)
                    for name in sorted(files):
                        full = Path(root) / name
                        rel = full.relative_to(self.repository.root).as_posix()
                        if self._included(rel): items.append(rel)
        items.sort(); scope="tree:"+base_rel+":"+hashlib.sha256("\n".join(items).encode()).hexdigest()
        start = _offset(cursor,scope); page = items[start:start + limit]
        return {"paths": page, "complete": start + len(page) >= len(items),
                "total": len(items), "cursor": _cursor(start + limit,scope) if start + limit < len(items) else None}

    def _all_tree_paths(self) -> list[str]:
        result=[]; cursor=None
        while True:
            page=self.tree(limit=2000,cursor=cursor)
            result.extend(page["paths"])
            cursor=page["cursor"]
            if cursor is None: return result

    def update(self, paths: Iterable[str] | None = None) -> dict[str, int]:
        changed = removed = unchanged = 0
        full_scan = paths is None
        if self.repository.revision:
            if paths is None:
                candidates = self._all_tree_paths()
            else: candidates = list(paths)
            changed = unchanged = 0
            removed = 0
            with self._connect() as db:
                seen = set()
                for value in candidates:
                    _, rel = self._path(value)
                    if not self._included(rel): continue
                    try: data = subprocess.run(["git","-C",str(self.repository.root),"show",f"{self.repository.revision}:{rel}"],capture_output=True,timeout=5,check=True).stdout
                    except (OSError,subprocess.SubprocessError): continue
                    seen.add(rel)
                    digest=hashlib.sha256(data).hexdigest()
                    row=db.execute("SELECT sha256 FROM files WHERE path=?",(rel,)).fetchone()
                    if row and row["sha256"]==digest: unchanged+=1; continue
                    db.execute("INSERT OR REPLACE INTO files(path,sha256,size,mtime_ns,ctime_ns,text) VALUES(?,?,?,?,?,?)",
                        (rel,digest,len(data),0,0,data.decode("utf-8",errors="replace")))
                    db.execute("DELETE FROM units WHERE path=?",(rel,))
                    for unit in self._parse_python(rel,data): db.execute("INSERT OR IGNORE INTO units VALUES(?,?,?)",(rel,digest,json.dumps(asdict(unit),sort_keys=True)))
                    changed+=1
                if paths is None:
                    for stale in {r[0] for r in db.execute("SELECT path FROM files")} - seen:
                        db.execute("DELETE FROM files WHERE path=?",(stale,)); db.execute("DELETE FROM units WHERE path=?",(stale,)); removed+=1
            return {"changed":changed,"unchanged":unchanged,"removed":removed}
        if paths is None:
            candidates = self._all_tree_paths()
        else: candidates = list(paths)
        with self._connect() as db:
            seen = set()
            for value in candidates:
                full, rel = self._path(value)
                if not self._included(rel) or not full.is_file(): continue
                seen.add(rel); stat = full.stat()
                row = db.execute("SELECT sha256,mtime_ns,ctime_ns,size FROM files WHERE path=?", (rel,)).fetchone()
                if row and (row["mtime_ns"],row["ctime_ns"],row["size"]) == (stat.st_mtime_ns,stat.st_ctime_ns,stat.st_size):
                    unchanged += 1; continue
                data = full.read_bytes(); digest = hashlib.sha256(data).hexdigest()
                if row and row["sha256"] == digest:
                    db.execute("UPDATE files SET mtime_ns=?,ctime_ns=?,size=? WHERE path=?", (stat.st_mtime_ns,stat.st_ctime_ns,len(data),rel))
                    unchanged += 1; continue
                text = data.decode("utf-8", errors="replace")
                db.execute("INSERT OR REPLACE INTO files(path,sha256,size,mtime_ns,ctime_ns,text) VALUES(?,?,?,?,?,?)",
                    (rel,digest,len(data),stat.st_mtime_ns,stat.st_ctime_ns,text))
                db.execute("DELETE FROM units WHERE path=?", (rel,))
                for unit in self._parse_python(rel, data):
                    db.execute("INSERT OR IGNORE INTO units VALUES(?,?,?)", (rel,digest,json.dumps(asdict(unit),sort_keys=True)))
                changed += 1
            if full_scan:
                known = {row[0] for row in db.execute("SELECT path FROM files")}
                for stale in known - seen:
                    db.execute("DELETE FROM files WHERE path=?", (stale,))
                    db.execute("DELETE FROM units WHERE path=?", (stale,))
                    removed += 1
            db.commit()
        return {"changed": changed, "unchanged": unchanged, "removed": removed}

    def _parse_python(self, path: str, data: bytes) -> list[StructuralUnit]:
        if not path.endswith(".py"): return []
        try: tree = ast.parse(data, filename=path)
        except (SyntaxError, UnicodeDecodeError): return []
        units: list[StructuralUnit] = []
        symbols: dict[str, list[str]] = {}
        def walk(node: ast.AST, parents: tuple[str, ...] = ()):
            for child in ast.iter_child_nodes(node):
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    qname = ".".join((*parents, child.name))
                    kind = "class" if isinstance(child, ast.ClassDef) else "definition"
                    units.append(StructuralUnit(child.name, kind, path, child.lineno,
                        getattr(child,"end_lineno",child.lineno), qname, provider="python-ast"))
                    symbols.setdefault(child.name, []).append(qname)
                    walk(child, (*parents, child.name))
                elif isinstance(child, ast.Import):
                    for alias in child.names: units.append(StructuralUnit(alias.name,"import",path,child.lineno,child.lineno,target=alias.name,basis="declared"))
                elif isinstance(child, ast.ImportFrom):
                    target = "." * child.level + (child.module or "")
                    for alias in child.names: units.append(StructuralUnit(alias.name,"import",path,child.lineno,child.lineno,target=target+":"+alias.name,basis="declared"))
                else: walk(child, parents)
        walk(tree)
        calls = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                target = node.func.id if isinstance(node.func, ast.Name) else node.func.attr if isinstance(node.func, ast.Attribute) else None
                attribute_receiver=isinstance(node.func,ast.Attribute)
                if target: calls.append((target, node.lineno, attribute_receiver))
        for target, line, attribute_receiver in calls:
            matches = symbols.get(target, [])
            units.append(StructuralUnit(target,"call",path,line,line,target=matches[0] if len(matches)==1 else target,
                resolution="unresolved" if attribute_receiver else "resolved" if len(matches)==1 else "ambiguous" if len(matches)>1 else "unresolved",
                provider="python-ast",metadata={"candidates":matches,"attribute_receiver":attribute_receiver,
                    "resolution_reason":"receiver type is dynamic or unavailable" if attribute_receiver else None}))
        return units

    def search(self, query: str, limit: int = 30, cursor: str | None = None) -> dict[str, Any]:
        if not query.strip(): raise ValueError("query must not be empty")
        if not 1 <= limit <= 500: raise ValueError("limit must be 1..500")
        self.update()
        with self._connect() as db:
            rows = db.execute("SELECT path,sha256,text FROM files ORDER BY path").fetchall()
        matches=[]; needle=query.casefold()
        for row in rows:
            if not self._included(row["path"]): continue
            for number,line in enumerate((row["text"] or "").splitlines(),1):
                if needle in line.casefold():
                    matches.append({"path":row["path"],"line":number,"text":line[:1000],"sha256":row["sha256"],
                        "kind":"lexical_match","basis":"mention",
                        "source":asdict(SourceRef(self.repository.repository_id,row["path"],row["sha256"],self.repository.revision,
                            self.repository.worktree_id or _worktree_id(self.repository.root),number,number))})
        generation=hashlib.sha256("\n".join(r["path"]+":"+r["sha256"] for r in rows).encode()).hexdigest()
        scope=f"search:{query.casefold()}:{generation}"
        start=_offset(cursor,scope); page=matches[start:start+limit]
        return {"matches":page,"complete":start+len(page)>=len(matches),"total":len(matches),
                "cursor":_cursor(start+limit,scope) if start+limit<len(matches) else None}

    def resolve(self, query: str, kinds: Iterable[str] = ("definition","class","import"),
                limit: int = 100) -> dict[str, Any]:
        """Resolve an exact indexed name; multiple matching declarations stay ambiguous."""
        if not query.strip() or not 1<=limit<=1000: raise ValueError("query and a limit in 1..1000 are required")
        self.update()
        wanted=set(kinds)
        with self._connect() as db:
            rows=db.execute("SELECT units.record,files.sha256 FROM units JOIN files USING(path) ORDER BY units.path").fetchall()
        matches=[]
        for row in rows:
            unit=json.loads(row["record"])
            if not self._included(unit.get("path", "")): continue
            if unit.get("kind") not in wanted or query not in {unit.get("name"),unit.get("qualified_name"),unit.get("target")}:
                continue
            unit["source"]=asdict(SourceRef(self.repository.repository_id,unit["path"],row["sha256"],
                self.repository.revision,self.repository.worktree_id or _worktree_id(self.repository.root),
                unit.get("line"),unit.get("end_line")))
            matches.append(unit)
        if any(p.name=="cpp-context-compiler" for p in self.providers.values()):
            for path in self._all_tree_paths():
                if Path(path).suffix.lower() not in {".cc",".cpp",".cxx",".c",".hh",".hpp",".hxx",".h"}: continue
                try: result=self.structure(path)
                except (OSError,ValueError): continue
                for item in result.units:
                    if item.kind not in wanted or query not in {item.name,item.qualified_name,item.target,item.metadata.get("symbol_id")}:
                        continue
                    matches.append({**asdict(item),"source":asdict(SourceRef(self.repository.repository_id,path,
                        result.sha256,self.repository.revision,self.repository.worktree_id or _worktree_id(self.repository.root),
                        item.line,item.end_line))})
        resolution="unresolved" if not matches else "resolved" if len(matches)==1 else "ambiguous"
        return {"query":query,"resolution":resolution,"matches":matches[:limit],
                "complete":len(matches)<=limit,"total":len(matches)}

    def structure(self, path: str, language: str | None = None) -> StructuralResult:
        _, rel = self._path(path)
        if not self._included(rel): raise FileNotFoundError(rel)
        if not self.repository.revision:
            self.update([rel])
        if self.repository.revision:
            try:
                data = subprocess.run(["git", "-C", str(self.repository.root), "show", f"{self.repository.revision}:{rel}"],
                    capture_output=True, timeout=5, check=True).stdout
            except (OSError, subprocess.SubprocessError): raise FileNotFoundError(f"{rel} at revision {self.repository.revision}")
        else:
            data = (self.repository.root / rel).read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        extension=Path(rel).suffix.lower()
        if extension==".py" and language in {None,"python"}:
            units = self._parse_python(rel,data)
            with self._connect() as db:
                definitions = [json.loads(row[0]) for row in db.execute("SELECT record FROM units")]
            definitions = [item for item in definitions if self._included(item.get("path", ""))]
            by_name: dict[str, set[tuple[str,str,int]]] = {}
            for item in definitions:
                if item.get("kind") == "definition":
                    by_name.setdefault(item["name"],set()).add((item.get("path", ""),
                        item.get("qualified_name") or item["name"],int(item.get("line",0))))
            resolved=[]
            for unit in units:
                if unit.kind != "call" or unit.metadata.get("attribute_receiver"):
                    resolved.append(unit); continue
                candidate_records=sorted(by_name.get(unit.name, set()))
                candidates=[f"{path}:{qualified}:{line}" for path,qualified,line in candidate_records]
                if len(candidates)==1:
                    resolved.append(replace(unit,target=candidate_records[0][1],resolution="resolved",
                        metadata={**unit.metadata,"candidates":candidates,"candidate_set":"indexed-files"}))
                elif len(candidates)>1:
                    resolved.append(replace(unit,target=unit.name,resolution="ambiguous",
                        metadata={**unit.metadata,"candidates":candidates,"candidate_set":"indexed-files"}))
                else:
                    resolved.append(replace(unit,metadata={**unit.metadata,"candidate_set":"indexed-files"}))
            return StructuralResult(rel,digest,tuple(resolved))
        providers = list(self.providers.values())
        if extension in {".cc", ".cpp", ".cxx", ".c", ".hh", ".hpp", ".hxx", ".h"}:
            providers.sort(key=lambda p: 0 if p.name == "cpp-context-compiler" else 1)
        for provider in providers:
            if extension not in {".cc", ".cpp", ".cxx", ".c", ".hh", ".hpp", ".hxx", ".h"} and provider.name == "cpp-context-compiler":
                continue
            result=provider.extract(self.repository,rel,data)
            if result.sha256 != digest: raise ValueError(f"provider {provider.name} returned stale source hash")
            return result
        return StructuralResult(rel,digest,(),"lexical-only",("no structural provider for this language",),"none")

    def history(self, path: str | None = None, limit: int = 30, cursor: str | None = None) -> dict[str, Any]:
        if not 1 <= limit <= 500: raise ValueError("limit must be 1..500")
        args=["log","--date=iso-strict","--format=%H%x09%aI%x09%s"]
        if self.repository.revision: args += [self.repository.revision]
        if path:
            _, rel = self._path(path)
            if not self._included(rel): raise FileNotFoundError(rel)
            args += ["--",rel]
        output=_git(self.repository.root,*args)
        rows=[]
        if output:
            for line in output.splitlines():
                bits=line.split("\t",2)
                if len(bits)==3: rows.append({"revision":bits[0],"committed_at":bits[1],"subject":bits[2]})
        scope=f"history:{path or '.'}:{self.repository.revision or _git(self.repository.root,'rev-parse','HEAD')}:{hashlib.sha256(json.dumps(rows,sort_keys=True).encode()).hexdigest()}"
        start=_offset(cursor,scope); page=rows[start:start+limit]
        return {"commits":page,"complete":start+len(page)>=len(rows),"total":len(rows),
                "cursor":_cursor(start+limit,scope) if start+limit<len(rows) else None}

    def relationships(self, target: str | None = None, limit: int = 200) -> dict[str, Any]:
        """Read explicit project-context declarations; never infer them from mentions."""
        config=self.repository.root/".project-context.json"
        if not self._included(".project-context.json"):
            return {"relationships": [], "complete": False, "declarations": "excluded_by_policy"}
        if not config.is_file(): return {"relationships":[],"complete":True,"declarations":"not-configured"}
        try: payload=json.loads(config.read_text(encoding="utf-8"))
        except (OSError,json.JSONDecodeError) as exc:
            return {"relationships":[],"complete":False,"declarations":"invalid","diagnostics":[str(exc)]}
        rows=[]
        for field_name,basis in (("dependencies","declared"),("guidance","guidance"),("references","declared")):
            values=payload.get(field_name,[])
            if not isinstance(values,list): continue
            for item in values:
                if isinstance(item,str): item={"target":item}
                if not isinstance(item,dict): continue
                name=str(item.get("target",item.get("repository",item.get("path",item.get("name","")))))
                if target and target not in {name,item.get("name"),item.get("repository"),item.get("path")}: continue
                rows.append({"subject":self.repository.repository_id,"predicate":field_name,
                    "object":name,"basis":basis,"source":".project-context.json",
                    "detail":item})
        rows.sort(key=lambda r:(r["basis"],r["predicate"],r["object"]))
        return {"relationships":rows[:limit],"complete":len(rows)<=limit,"declarations":"explicit"}

    def trace(self, targets: Iterable[str], predicates: Iterable[str] = (), direction: str = "out",
              max_hops: int = 1, limit: int = 100) -> dict[str, Any]:
        if direction not in {"out","in","both"}: raise ValueError("direction must be out, in, or both")
        if not 0 <= max_hops <= 8 or not 1 <= limit <= 1000: raise ValueError("invalid traversal bound")
        starts=list(targets); self.update()
        edges=[]; coverage="complete"
        with self._connect() as db:
            rows=db.execute("SELECT units.record,files.sha256 FROM units JOIN files USING(path)").fetchall()
        for row in rows:
            unit=json.loads(row["record"])
            if not self._included(unit.get("path", "")): continue
            if unit.get("kind")=="call":
                edges.append({"source":unit["path"],"target":unit.get("target"),"predicate":"call",
                    "resolution":unit.get("resolution","unresolved"),"basis":"observed","line":unit.get("line"),
                    "provider":"python-ast","sha256":row["sha256"]})
            elif unit.get("kind")=="import":
                edges.append({"source":unit["path"],"target":unit.get("target"),"predicate":"import",
                    "resolution":"declared","basis":"declared","line":unit.get("line"),
                    "provider":"python-ast","sha256":row["sha256"]})
        symbol_nodes={}
        if any(p.name=="cpp-context-compiler" for p in self.providers.values()):
            extensions={".cc",".cpp",".cxx",".c",".hh",".hpp",".hxx",".h"}
            for path in self._all_tree_paths():
                if Path(path).suffix.lower() not in extensions: continue
                try: result=self.structure(path)
                except (OSError,ValueError): coverage="partial"; continue
                if result.coverage!="complete": coverage="partial"
                for unit in result.units:
                    if unit.kind in {"definition","declaration","class"}:
                        for name in (unit.name,unit.qualified_name,unit.metadata.get("symbol_id")):
                            if name: symbol_nodes.setdefault(name,set()).add(unit.metadata.get("symbol_id"))
                    edge=unit.metadata.get("edge",{})
                    if unit.kind in {"call","reference","type_use","member_access","include","test_relationship"}:
                        edges.append({"source":edge.get("from",path),"target":edge.get("to"),
                            "predicate":unit.kind,"resolution":unit.resolution,"basis":"observed",
                            "line":unit.line,"provider":unit.provider,"sha256":result.sha256,
                            "source_path":path,"metadata":unit.metadata})
        if predicates: edges=[e for e in edges if e["predicate"] in set(predicates)]
        # Paths and exact symbol names/IDs are both accepted starts. Resolve names
        # to provider IDs where available, while retaining the caller's spelling.
        start_nodes=set()
        for target in starts:
            try:
                _,path=self._path(target)
                if not self._included(path): raise FileNotFoundError(path)
                if (self.repository.root/path).exists():
                    start_nodes.add(path)
                    start_nodes.update(edge.get("source") for edge in edges if edge.get("source_path")==path)
                else: start_nodes.add(target)
            except ValueError: start_nodes.add(target)
            start_nodes.update(node for node in symbol_nodes.get(target, set()) if node)
        selected=[]; frontier=set(start_nodes); seen_nodes=set(frontier)
        for _ in range(max_hops):
            next_nodes=set()
            for edge in edges:
                forward=edge.get("source") in frontier and direction in {"out","both"}
                backward=edge.get("target") in frontier and direction in {"in","both"}
                if forward or backward:
                    selected.append(edge)
                    node=edge.get("target") if forward else edge.get("source")
                    if node is not None and node not in seen_nodes: next_nodes.add(node)
            seen_nodes.update(next_nodes); frontier=next_nodes
            if not frontier: break
        return {"edges":selected[:limit],"complete":len(selected)<=limit and coverage=="complete",
                "coverage":coverage,"visited":sorted(str(x) for x in seen_nodes),
                "omissions":[] if coverage=="complete" else ["one or more structural providers were stale or unavailable"]}

    def context(self, targets: Iterable[str | RetrievalTarget | Mapping[str, Any]], include: Iterable[str] = ("implementation",),
                budget_bytes: int = 32_000, cursor: str | None = None) -> ContextPacket:
        if not 1 <= budget_bytes <= 1_000_000: raise ValueError("budget must be 1..1000000")
        sections: dict[str,tuple[Any,...]]={}; remaining=budget_bytes; omissions=[]
        continuations=[]; associations=[]
        original=[self._normalize_target(target) for target in targets]; requested=tuple(include)
        denied_targets: dict[int, str] = {}
        for index, record in enumerate(original):
            candidate = record.get("path") or record.get("target")
            if not candidate: continue
            try:
                _, rel = self._path(candidate)
                is_path = bool(record.get("path")) or record.get("kind") in {"path", "file"} or \
                    (record.get("kind") != "symbol" and
                     ((self.repository.root / rel).is_file() or bool(self.repository.revision)))
                if is_path and not self._included(rel): denied_targets[index] = rel
            except ValueError:
                continue
        revisions={record["revision"] for record in original if record.get("revision") is not None}
        if len(revisions)>1: raise ValueError("one context request can cover only one pinned revision; group targets by repository and revision")
        requested_revision=next(iter(revisions),self.repository.revision)
        if requested_revision!=self.repository.revision:
            pinned=Repository(self.repository.root,self.repository.repository_id,self.repository.state_dir,
                requested_revision,self.repository.worktree_id,self.repository.exclude,self.repository.deny_patterns)
            return SourceIndex(pinned,self.providers.values()).context(original,requested,budget_bytes,cursor)
        for record in original:
            if record.get("repository_id") not in {None,self.repository.repository_id}:
                raise ValueError(f"target belongs to repository {record['repository_id']!r}, not {self.repository.repository_id!r}")
        wants_index=any(section in requested for section in ("callers","references","tests"))
        has_symbol=any(record["kind"]=="symbol" or not (self.repository.root/str(record.get("path") or record["target"])).is_file()
                       for record in original)
        if wants_index or has_symbol:
            self.update()
            with self._connect() as db:
                generation_rows=db.execute("SELECT path,sha256 FROM files ORDER BY path").fetchall()
            generation="index:"+hashlib.sha256("\n".join(r["path"]+":"+r["sha256"] for r in generation_rows).encode()).hexdigest()
        else:
            fingerprints=[]
            for record in original:
                target=record.get("path") or record.get("target")
                try:
                    _,rel=self._path(target)
                    if not self._included(rel):
                        fingerprints.append(rel + ":denied")
                    else:
                        data=(self.repository.root/rel).read_bytes()
                        fingerprints.append(rel+":"+hashlib.sha256(data).hexdigest())
                except (ValueError,OSError): fingerprints.append(str(target)+":missing")
            generation="targets:"+hashlib.sha256("\n".join(fingerprints).encode()).hexdigest()
        scope=f"context:{self.repository.identity}:{json.dumps(original)}:{json.dumps(requested)}:{budget_bytes}:{generation}"
        start=_offset(cursor,scope); selected=original[start:]
        completed_targets=0
        indexed_units=None
        for selected_offset, target_record in enumerate(selected):
            target_index = start + selected_offset
            if target_index in denied_targets:
                omissions.append({"reason": "path_denied", "target": target_record.get("target"),
                    "path": denied_targets[target_index]})
                completed_targets += 1
                continue
            if remaining <= 0: omissions.append("budget exhausted before remaining targets"); break
            target=target_record.get("symbol") or target_record.get("path") or target_record["target"]
            path_candidate=None; symbol_definition=None; provider_partial=False
            try:
                _, rel=self._path(target_record.get("path") or target)
                if target_record.get("kind")!="symbol" and (target_record.get("kind") in {"path","file"} or
                        target_record.get("path") or (self.repository.root/rel).is_file() or self.repository.revision):
                    path_candidate=rel
            except ValueError: pass
            target_name=str(target).rsplit(".",1)[0]
            if path_candidate is None:
                with self._connect() as db:
                    matches=[json.loads(r[0]) for r in db.execute("SELECT record FROM units")]
                matches=[unit for unit in matches if self._included(unit.get("path", ""))]
                definitions=[u for u in matches if u.get("kind") in {"definition","class"} and
                    target in {u.get("name"),u.get("qualified_name")} and
                    (target_record.get("path") is None or u.get("path")==target_record.get("path"))]
                if any(p.name=="cpp-context-compiler" for p in self.providers.values()):
                    for candidate_path in self._all_tree_paths():
                        if Path(candidate_path).suffix.lower() not in {".cc",".cpp",".cxx",".c",".hh",".hpp",".hxx",".h"}: continue
                        if target_record.get("path") and candidate_path!=target_record["path"]: continue
                        try: result=self.structure(candidate_path)
                        except (OSError,ValueError): continue
                        if result.coverage!="complete": provider_partial=True
                        for unit in result.units:
                            if unit.kind in {"definition","declaration","class"} and target in {
                                    unit.name,unit.qualified_name,unit.target,unit.metadata.get("symbol_id")}:
                                definitions.append({"name":unit.name,"kind":unit.kind,"path":candidate_path,
                                    "line":unit.line,"end_line":unit.end_line,"qualified_name":unit.qualified_name,
                                    "provider":unit.provider,"metadata":unit.metadata,"source_sha256":result.sha256})
                if len(definitions)==1:
                    symbol_definition=definitions[0]; path_candidate=symbol_definition["path"]
                elif len(definitions)>1: omissions.append(f"{target}: ambiguous symbol target"); continue
                else: omissions.append(f"{target}: target not found as a path or indexed symbol"); continue
            if target_record.get("line_start") is not None or target_record.get("line_end") is not None:
                source=self.read(path_candidate,target_record.get("line_start"),target_record.get("line_end"),remaining)
            elif symbol_definition:
                source=self.read(path_candidate,symbol_definition["line"],symbol_definition["end_line"],remaining)
            else:
                source=self.read(path_candidate,max_bytes=remaining)
            if source.cursor:
                continuations.append({"target":target,"section":"implementation","path":path_candidate,
                    "source":asdict(source.source),"cursor":source.cursor})
            implementation=(source,)
            got_by_section={"implementation":implementation}
            remaining-=len((source.content or "").encode())
            if not source.complete: omissions.extend(source.omissions)
            if any(name in requested for name in ("callers","references","tests")):
                if indexed_units is None:
                    with self._connect() as db:
                        indexed_units=[unit for r in db.execute("SELECT record FROM units")
                            if self._included((unit:=json.loads(r[0])).get("path", ""))]
                units=indexed_units
            else: units=[]
            target_names={target,target_name}
            if symbol_definition:
                target_names.update({symbol_definition.get("name"),symbol_definition.get("qualified_name")})
            else:
                target_names.update(u.get("name") for u in units if u.get("path")==path_candidate and u.get("kind") in {"definition","class"})
                target_names.update(u.get("qualified_name") for u in units if u.get("path")==path_candidate and u.get("kind") in {"definition","class"})
            matching=[u for u in units if u.get("kind")=="call" and
                (u.get("name") in target_names or u.get("target") in target_names) and
                "test" not in u.get("path","").lower() and not u.get("metadata",{}).get("attribute_receiver")]
            cpp_matches=[]
            cpp_target=(symbol_definition or {}).get("metadata",{}).get("symbol_id")
            cpp_extensions={".cc",".cpp",".cxx",".c",".hh",".hpp",".hxx",".h"}
            if any(p.name=="cpp-context-compiler" for p in self.providers.values()) and (
                    cpp_target or Path(path_candidate).suffix.lower() in cpp_extensions):
                target_ids={cpp_target} if cpp_target else {u.metadata.get("symbol_id") for u in self.structure(path_candidate).units
                    if u.kind in {"definition","declaration","class"}}
                for candidate_path in self._all_tree_paths():
                    if Path(candidate_path).suffix.lower() not in cpp_extensions: continue
                    try: result=self.structure(candidate_path)
                    except (OSError,ValueError): continue
                    if result.coverage!="complete": provider_partial=True
                    for unit in result.units:
                        edge=unit.metadata.get("edge",{})
                        if unit.kind in {"call","reference","type_use","member_access","test_relationship"} and edge.get("to") in target_ids:
                            cpp_matches.append((candidate_path,unit))
            callers=[]; references=[]; cpp_tests=[]
            for unit in matching:
                associations.append({"target":target,"relation":"call","resolution":unit.get("resolution","candidate"),
                    "candidates":unit.get("metadata",{}).get("candidates",[]),"path":unit["path"],
                    "line":unit["line"],"basis":"observed"})
                if remaining<=0: omissions.append("callers: budget exhausted"); break
                result=self.read(unit["path"],unit["line"],unit["end_line"],remaining)
                callers.append(result); remaining-=len((result.content or "").encode())
                if result.cursor: continuations.append({"target":target,"section":"callers","path":unit["path"],"source":asdict(result.source),"cursor":result.cursor})
            for cpp_path,unit in cpp_matches:
                associations.append({"target":target,"relation":unit.kind,"resolution":unit.resolution,
                    "path":cpp_path,"line":unit.line,"basis":"observed","provider":unit.provider,
                    "symbol_id":cpp_target})
                if remaining<=0: omissions.append("C++ relationships: budget exhausted"); break
                result=self.read(cpp_path,unit.line,unit.end_line,remaining)
                destination=callers if unit.kind=="call" else cpp_tests if unit.kind=="test_relationship" else references
                destination.append(result); remaining-=len((result.content or "").encode())
            got_by_section["callers"]=tuple(callers)
            got_by_section["references"]=tuple(references)
            if "tests" in requested:
                test_files=sorted({u["path"] for u in units if "test" in u["path"].lower() and
                                   (u.get("name") in target_names or u.get("target") in target_names) and u["path"]!=path_candidate})
                tests=[]
                for test_file in test_files:
                    if remaining<=0: omissions.append("tests: budget exhausted"); break
                    result=self.read(test_file,max_bytes=remaining); tests.append(result)
                    associations.append({"target":target,"relation":"test_candidate","resolution":"lexical_candidate",
                        "path":test_file,"line":None,"basis":"mention"})
                    remaining-=len((result.content or "").encode())
                    if result.cursor: continuations.append({"target":target,"section":"tests","path":test_file,"source":asdict(result.source),"cursor":result.cursor})
                got_by_section["tests"]=tuple((*tests,*cpp_tests))
            elif cpp_tests:
                got_by_section["tests"]=tuple(cpp_tests)
            got_by_section["references"]=tuple(references)
            if "guidance" in requested:
                got_by_section["guidance"]=tuple(r for r in self.relationships().get("relationships",[]) if r.get("basis")=="guidance")
            if "dependencies" in requested:
                got_by_section["dependencies"]=tuple(r for r in self.relationships(target).get("relationships",[])
                    if r.get("basis")=="declared")
            if "evidence" in requested:
                omissions.append(f"{target}: evidence must be joined by the consuming application")
            for section in requested:
                if section in got_by_section:
                    sections[section]=sections.get(section,())+tuple(got_by_section[section])
                elif section != "changes":
                    omissions.append(f"unsupported context section: {section}")
            if "changes" in requested:
                sections["changes"]=sections.get("changes",())+tuple(self.history(path_candidate,limit=5)["commits"])
            if provider_partial:
                omissions.append(f"{target}: structural provider reports partial coverage; related results may be missing")
            completed_targets+=1
        used=budget_bytes-remaining
        complete=not omissions and start+completed_targets>=len(original)
        next_cursor=_cursor(start+completed_targets,scope) if completed_targets<len(selected) else None
        return ContextPacket(sections,budget_bytes,used,complete,tuple(omissions),next_cursor,
                             tuple(continuations),tuple(associations))

    def batch_context(self, requests: Iterable[dict[str, Any]]) -> tuple[ContextPacket,...]:
        # One index object and its content cache are shared across all request sections.
        return tuple(self.context(req.get("targets",()), req.get("include",("implementation",)),
                                 req.get("budget_bytes",32_000), req.get("cursor")) for req in requests)
