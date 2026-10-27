# Project Foundations

Project Foundations provides two small Python libraries for applications that
need to inspect source or keep durable evidence. Project Control and
Project-Lab can both use them without depending on one another.

## Install the source tools

Install evidence first, then source:

```sh
python -m pip install ./packages/project-evidence
python -m pip install ./packages/project-source
```

Point each repository at a private state directory. Index state is disposable
and can be rebuilt from the source tree; source files are never changed by
retrieval.

```python
from project_source import Repository, SourceIndex

repo = Repository("/work/my-project", "my-project", "/tmp/my-project-index")
source = SourceIndex(repo)
print(source.tree(limit=50)["paths"])
print(source.read("src/main.py", start_line=1, end_line=40).content)
print(source.structure("src/main.py").units)
```

For durable records, use an explicit evidence database and artifact directory:

```python
from project_evidence import EvidenceStore, Observation

store = EvidenceStore("/state/evidence.sqlite", "/state/evidence-blobs")
artifact = store.put_artifact(b"captured output", "text/plain")
store.record_observation(Observation(
    "run-1-output", "project-lab", "command-output", "run-1",
    artifact_refs=(artifact,), payload={"exit_code": 0},
))
```

Read [the API contract](docs/API.md) for bounds, provenance, relationships,
legacy data access and structural provider behavior.

## Package boundaries

- `project-evidence` records what was observed, by whom, where it came from,
  and which artifact bytes were retained.
- `project-source` lists, reads, searches and relates project source. It uses
  Python's built-in AST parser and accepts optional structural providers such
  as the C++ Context Compiler.

Neither library runs model inference or owns an application's workflow state.
Source observations and indexed packets are not proof that a claim is true.
