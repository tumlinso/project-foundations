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

Consumers may pass `deny_patterns=(".env", "private/**")` on `Repository` to
apply their existing path policy uniformly to discovery, indexing, direct and
historical reads, structural providers, graph traversal, and context assembly.
The patterns use the same path matching rules as Project Control. Cached rows
from an older or less restrictive consumer remain filtered at query time.
In a context bundle, excluded targets are reported as `path_denied` omissions;
other requested targets still return their available context.

Python definitions, imports and locally resolvable calls are structural
observations. Unresolved or ambiguous calls remain labeled as such. Other
languages have file and lexical search unless a structural provider is added.
See [the shared API contract](../../docs/API.md).
