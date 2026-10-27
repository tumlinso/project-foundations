# project-evidence

Store durable observations, attributed assessments, typed relations and
content-addressed artifact bytes. Database and artifact paths are explicit.

```python
from project_evidence import EvidenceStore, Observation
store = EvidenceStore("/state/evidence.sqlite", "/state/blobs")
blob = store.put_artifact(b"hello", "text/plain")
store.record_observation(Observation("obs-1", "my-app", "output", "job-1",
                                     artifact_refs=(blob,)))
```

Observations, assessments and relations are append-only through the API.
Assessments identify their author and rubric. Legacy Project Control notes
remain attributed advisory material when read through `LegacyReader`.

For a registered external authority, use `EvidenceReader(path)`. It opens an
existing database read-only and never initializes a missing one; check
`reader.available` before requesting records.
