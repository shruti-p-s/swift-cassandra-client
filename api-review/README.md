# API review

Working files for the package's 1.0 API review.

`CassandraClient-public-api.txt` is the whole public surface of the `CassandraClient`
module: every public declaration with its availability, conformances, and doc comment,
grouped by owning type. It exists so the API can be read and commented on line by line.

**This directory is not meant to merge.** It lives on a review branch on a fork, not on
`apple/swift-cassandra-client` main. The file is a derived artifact, and the package does
not otherwise commit generated output.

## Regenerating

The file goes stale as soon as the public surface changes — it did once already mid-review,
when `setPagingSize` became public. Regenerate rather than edit:

```
swift build --target CassandraClient \
  -Xswiftc -emit-symbol-graph -Xswiftc -emit-symbol-graph-dir -Xswiftc /tmp/symgraph

api-review/render-public-api.py /tmp/symgraph/CassandraClient.symbols.json > /tmp/api.txt
mv /tmp/api.txt api-review/CassandraClient-public-api.txt
```

The header records the hash of `Sources/CassandraClient` rather than a commit, so two rounds
can be compared without mistaking unrelated drift for API change. A tree hash rather than a
commit because it doesn't move when only `api-review/` changes: the renderer and the file it
produces can land in one commit and stay verifiable, where a recorded HEAD would name the
parent and so predate the renderer.

Render with `Sources/` committed. The renderer warns on stderr otherwise, because a hash
marked `(plus uncommitted changes)` describes a state that isn't in history. Write to a
temporary file and move it into place — redirecting straight onto the output truncates it
first, which is harmless for the hash but loses the previous version if the render fails.

Rendering is toolchain-sensitive, so regenerating on a different Swift version will produce
incidental differences.

One limitation is worth knowing when reading the file: the symbol graph emits no `==` at
all, and no synthesized `encode(to:)`, though it emits `!=` and `init(from:)`. Those
declarations are reconstructed and marked `[reconstructed]`, so the API is complete on the
page and every member has a line to comment on. Both are protocol requirements, so their
signatures come from the protocol rather than the conforming type.

`render-public-api.py` documents the judgement calls it makes — how inherited protocol
members are attributed and why compiler-synthesized ones are listed apart from them, why
availability and deprecations are rendered, why noncopyability is read from the source
rather than the graph, and why conformance targets are resolved through the symbol table.
