# project-source

Inspect one project using an explicit root and private index directory. Reads
carry content hashes and source locations; tree and search results can be
continued with their returned cursors.

```python
from project_source import Repository, SourceIndex
repo = Repository("/work/my-project", "my-project", "/tmp/my-project-index")
index = SourceIndex(repo)
index.update()                       # incremental; repeat after source edits
packet = index.context(["src/main.py"], budget_bytes=12000)
print(packet.sections, packet.complete, packet.cursor)
```

Python definitions, imports and locally resolvable calls are structural
observations. Unresolved or ambiguous calls remain labeled as such. Other
languages have file and lexical search unless a structural provider is added.
See [the shared API contract](../../docs/API.md).
