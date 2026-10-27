# Project Foundations API contract

This is the initial consumer contract for Project Control and Project-Lab.
Both packages are pure Python packages; neither imports either application,
Todo, or an inference runtime. Filesystem and database locations are explicit.

## `project_evidence` 0.1

Stable public records are frozen dataclasses:

- `SourceRef(repository_id, path, sha256, revision=None, worktree_id=None,
  start_line=None, end_line=None)` identifies exact source bytes and an optional
  inclusive line range.
- `ArtifactRef(artifact_id, sha256, byte_length, media_type)` identifies
  content-addressed bytes. Retention and expiry are storage policy, not
  semantic evidence identity.
- `Observation(observation_id, owner, kind, subject, source_refs, artifact_refs,
  observed_at, payload)` records an immutable attributed observation.
- `Assessment(assessment_id, observation_id, assessor, rubric, outcome,
  created_at, payload)` appends an attributed assessment without changing the
  observation.
- `Relation(relation_id, subject, predicate, object, basis, source_refs,
  asserted_by, created_at)` records a typed relationship. `basis` is one of
  `observed`, `declared`, `guidance`, `mention`, or `assessment`.

`EvidenceStore(path, artifact_dir)` provides `put_artifact(bytes, media_type)`,
`get_artifact(ref)`, `record_observation(record)`, `record_assessment(record)`,
`record_relation(record)`, and filtered list/get methods. Record IDs are
caller-supplied or generated once and immutable; writes are append-only.
`LegacyReader(path)` opens copied Project Control packet/note SQLite databases
read-only and returns legacy records with original IDs and provenance. Legacy
notes remain attributed advisory material and are never converted to
assessments or proof.

## `project_source` 0.1

`Repository(root, repository_id, state_dir, revision=None, worktree_id=None)`
is an explicit local source view. `SourceIndex(repository).update(paths=None)`
indexes changed file content by digest in its private state directory.

Core operations are `read(path, start_line=None, end_line=None, max_bytes=...,
cursor=None)`,
`tree(path=None, limit=..., cursor=None)`, `search(query, limit=..., cursor=None)`,
`history(path=None, limit=..., cursor=None)`, `structure(path, language=None)`,
`trace(targets, predicates, direction=..., max_hops=..., limit=...)`,
`relationships(target=None, limit=...)`, and `context(targets, include=(...),
budget_bytes=..., cursor=None)`. Targets may be strings or
`RetrievalTarget(kind, target, path=None, symbol=None, repository_id=None,
revision=None, line_start=None, line_end=None)` records. Repository identity
is checked; one explicit revision selects a pinned read view. Requests spanning
multiple repositories or revisions should be grouped into separate calls.
Results carry source locators and byte hashes. Bounded results include explicit omissions and
opaque continuation cursors; truncation never means complete coverage.
Pass a read result's cursor back to `read()` to continue the same exact source
range. Cursors are bound to their query and source generation; changed results
must be requested from the beginning.

Structural records distinguish definitions, imports, references, calls,
declared dependencies, guidance references, and incidental mentions. A
relationship that cannot resolve uniquely is returned as ambiguous/unresolved,
not emitted as a verified edge. Python uses the standard-library AST parser.
Other languages use lexical discovery unless a structural producer is
registered. C++ producers implement `StructuralProvider.extract(repository,
path, source_bytes) -> StructuralResult`; provider/version and source hash are
retained with each result. The cpp-context-compiler adapter is read-only and
must not initialize, rebuild, or mutate its producer state.

`relationships()` reads explicit `.project-context.json` dependency, guidance
and reference declarations. Lexical `search()` hits remain mentions and are
not upgraded to declarations.

`SourceIndex.batch_context(requests)` shares reads/index lookups within a call.
Dependency and guidance declarations remain distinct from incidental text
mentions. `ContextPacket.cursor` continues across selected targets; each
oversized source excerpt includes its own `SourceResult.cursor` and a matching
entry in `ContextPacket.continuations`. Pass that source cursor to `read()` to
continue the exact hash and range. Context assembly returns caller excerpts,
lexical test candidates, declared guidance and recent changes when requested;
`ContextPacket.associations` preserves each relationship's basis, resolution
and ambiguity candidates alongside the excerpts.
an evidence section must be joined by the consuming application and is
reported as an omission. Graph primitives are package-local; no separate graph
service is required.

The API is intentionally small and versioned at package level. This contract
may gain optional fields before 1.0, but names and semantic distinctions above
are the integration baseline.
