#!/usr/bin/env python3
"""Render the CassandraClient public interface from a Swift symbol graph.

Usage, from the package root, on a clean tree:
    swift build --target CassandraClient \
        -Xswiftc -emit-symbol-graph -Xswiftc -emit-symbol-graph-dir -Xswiftc /tmp/symgraph
    api-review/render-public-api.py /tmp/symgraph/CassandraClient.symbols.json > /tmp/api.txt
    mv /tmp/api.txt api-review/CassandraClient-public-api.txt

Render via a temporary file: redirecting onto the output truncates it first, which dirties
the tree before the provenance check runs.

Choices worth knowing:
  - Inherited protocol members (Sequence, AsyncSequence, RawRepresentable, Equatable) are
    listed but their standard-library documentation is not. The declarations matter — a
    `Rows: Sequence` conformance hands adopters every buffering algorithm — but Swift's
    prose for them does not. Discriminator: an inherited symbol carries no `location`.
  - Inherited members are attributed to the protocol that declared them, read off the
    symbol's own USR: a synthesized member's identifier is `<origin>::SYNTHESIZED::<type>`,
    and the origin prefix matches the USR of a `conformsTo` target. That resolves 100 of 107
    without a hand-written table. The `requirementOf` and `defaultImplementationOf` edges do
    not help here — all 30 cover this module's own protocols, none of the standard library's.
  - The remaining 7 are not inherited at all: five `init(rawValue:)` and two `init(from:)`
    that the compiler synthesizes for the type itself. They are listed separately, because
    calling them inherited would be wrong.
  - The graph omits some synthesized members: it emits no `==` at all (while emitting 20
    `!=`), and no synthesized `encode(to:)` (while emitting `init(from:)`). Adding
    `-Xswiftc -emit-extension-block-symbols` does not recover them. Rather than let a reader
    take absence for absence, the declaration is reconstructed and marked, so there is a line
    to comment on. Both are protocol requirements, so their signatures come from the protocol
    rather than the conforming type. Which types are affected is read from the graph.
  - Availability is rendered, on inherited members too, because the package declares no
    `platforms:` and these annotations are the only statement of minimum versions. That
    also catches members Swift itself has deprecated.
  - Noncopyability is read from the source, not the graph: 38 of 42 public types lack a
    `Copyable` conformance edge while only one is actually `~Copyable`, so absence of that
    edge is not a usable signal.
  - A conformance to a protocol declared in this module carries no `targetFallback`, only a
    precise identifier, so targets are resolved through the symbol table rather than read
    off the edge.
"""

import collections
import json
import pathlib
import re
import subprocess
import sys

TYPE_KINDS = {"swift.struct", "swift.class", "swift.enum", "swift.protocol"}

# Members a conformance guarantees that the symbol graph does not emit when synthesized.
# Keyed by protocol, as (member name, declaration). The declaration is a protocol
# requirement, so its signature is fixed by the protocol rather than by the conforming type
# — the same text the graph produces for a hand-written one. Emitted only when no symbol of
# that name is present, and marked, so a reviewer has a line to comment on.
UNEMITTED = {
    "Equatable": ("==(_:_:)", "static func == (lhs: Self, rhs: Self) -> Bool"),
    "Hashable": ("==(_:_:)", "static func == (lhs: Self, rhs: Self) -> Bool"),
    "Encodable": ("encode(to:)", "func encode(to encoder: Encoder) throws"),
}

# Universal, or implied by another conformance the type already lists. Not shown at all.
IMPLIED = {"SendableMetatype", "Copyable", "Escapable", "BitwiseCopyable"}


def noncopyable_types(sources: pathlib.Path) -> set[str]:
    """Public types declared `~Copyable`, read from the source.

    Matched on the unqualified type name, so two same-named nested types would both be
    annotated. There is one such type today; revisit if that changes.
    """
    pattern = re.compile(
        r"public\s+(?:final\s+)?(?:struct|class|enum)\s+(\w+)\s*(?:<[^>]*>)?\s*:[^{]*~Copyable"
    )
    found: collections.Counter = collections.Counter()
    for path in sorted(sources.glob("*.swift")):
        found.update(pattern.findall(path.read_text()))
    for name, count in found.items():
        if count > 1:
            print(f"warning: '{name}' declared ~Copyable {count} times", file=sys.stderr)
    return set(found)


def availability(symbol) -> list[str]:
    """Rendered `@available` lines: version gates first, then deprecations.

    Deprecations are kept because whether they survive the 1.0 boundary is an open
    question for the reviewer.
    """
    gates, notices = [], []
    for entry in symbol.get("availability", []):
        domain = entry.get("domain")
        if introduced := entry.get("introduced"):
            if not domain:
                continue
            version = f"{introduced['major']}"
            if introduced.get("minor") is not None:
                version += f".{introduced['minor']}"
            gates.append(f"{domain} {version}")
        elif entry.get("isUnconditionallyDeprecated"):
            text = "@available(*, deprecated"
            if message := entry.get("message"):
                text += f', message: "{message}"'
            notices.append(text + ")")
        elif deprecated := entry.get("deprecated"):
            version = f"{deprecated['major']}"
            if deprecated.get("minor") is not None:
                version += f".{deprecated['minor']}"
            text = f"@available({domain}, deprecated: {version}"
            if renamed := entry.get("renamed"):
                text += f', renamed: "{renamed}"'
            notices.append(text + ")")
    lines = []
    if gates:
        lines.append("@available(" + ", ".join(gates) + ", *)")
    return lines + notices


def source_state(sources: pathlib.Path) -> tuple[str, str]:
    """The hash of the source tree this describes, and the toolchain that rendered it.

    The tree hash rather than the commit, so that renderer and output can land in one commit
    and still be verifiable: `Sources/` does not move when only `api-review/` changes, where
    HEAD would name the parent commit and so predate the renderer that produced the file.
    """

    def run(*args):
        return subprocess.run(args, capture_output=True, text=True).stdout

    tree = run("git", "rev-parse", "--short", f"HEAD:{sources}").strip() or "unknown"
    if run("git", "status", "--porcelain", str(sources)).strip():
        tree += " (plus uncommitted changes)"
        print(
            f"warning: {sources} has uncommitted changes, so the recorded tree hash describes "
            "a state that is not in history. Commit first if this output is to be shared.",
            file=sys.stderr,
        )
    version = run("swift", "--version").splitlines()
    return tree, version[0].strip() if version else "unknown"


def render(graph_path: pathlib.Path, sources: pathlib.Path) -> str:
    graph = json.loads(graph_path.read_text())
    symbols = [s for s in graph["symbols"] if s.get("accessLevel") == "public"]
    names = {s["identifier"]["precise"]: s["pathComponents"][-1] for s in graph["symbols"]}

    conformances = collections.defaultdict(set)
    protocol_by_usr: dict[str, str] = {}
    for rel in graph["relationships"]:
        if rel["kind"] != "conformsTo":
            continue
        if name := (rel.get("targetFallback", "").split(".")[-1] or names.get(rel["target"])):
            protocol_by_usr[rel["target"]] = name
        # In-module protocols carry no targetFallback, so fall back to the symbol table.
        target = rel.get("targetFallback", "").split(".")[-1] or names.get(rel["target"])
        if target and target not in IMPLIED:
            conformances[rel["source"]].add(target)
    # Hashable implies Equatable, so showing both on a declaration is noise. Attribution needs
    # the undeduped set: `!=` is Equatable's default, not Hashable's.
    displayed = {
        identifier: (entry - {"Equatable"}) if "Hashable" in entry else entry
        for identifier, entry in conformances.items()
    }

    def declaring_protocol(symbol) -> str | None:
        """The protocol a synthesized member came from, or None if the compiler made it."""
        precise = symbol["identifier"]["precise"]
        if "::SYNTHESIZED::" not in precise:
            return None
        origin = precise.split("::SYNTHESIZED::")[0]
        matches = [usr for usr in protocol_by_usr if origin.startswith(usr)]
        return protocol_by_usr[max(matches, key=len)] if matches else None

    noncopyable = noncopyable_types(sources)

    def declaration(symbol) -> str:
        text = "".join(f["spelling"] for f in symbol.get("declarationFragments", []))
        if symbol["kind"]["identifier"] not in TYPE_KINDS:
            return text
        suffix = []
        if symbol["pathComponents"][-1] in noncopyable:
            suffix.append("~Copyable")
        suffix += sorted(displayed.get(symbol["identifier"]["precise"], []))
        if suffix and " : " not in text:
            text += " : " + ", ".join(suffix)
        return text

    def owner(symbol) -> str:
        path = symbol["pathComponents"]
        return ".".join(path[:-1]) if len(path) > 1 else "(module scope)"

    groups = collections.defaultdict(list)
    for symbol in symbols:
        groups[owner(symbol)].append(symbol)

    # A type is a member of its parent's group, so reaching it from its own section needs
    # a path lookup.
    type_by_path = {
        ".".join(s["pathComponents"]): s for s in symbols if s["kind"]["identifier"] in TYPE_KINDS
    }

    tree, toolchain = source_state(sources)
    unlocated = [s for s in symbols if not s.get("location")]
    synthesized_total = sum(1 for s in unlocated if "::SYNTHESIZED::" not in s["identifier"]["precise"])
    inherited_total = len(unlocated) - synthesized_total

    out = [
        f"// CassandraClient public interface — {len(symbols)} public symbols",
        f"// Sources tree: {tree}",
        f"// Toolchain:    {toolchain}",
        "// Renderer:     api-review/render-public-api.py, alongside this file",
        "//",
        "// Derived, not maintained by hand — regenerate rather than edit.",
        "// Declarations carry their availability, conformances, and doc comments.",
        f"// {inherited_total} members reached through protocol conformances are listed without",
        "// their standard-library documentation, grouped under the protocol that declared each.",
        f"// {synthesized_total} more are compiler-synthesized for the type itself.",
        "",
    ]

    for group in sorted(groups):
        members = sorted(groups[group], key=lambda s: (s["pathComponents"][-1], declaration(s)))
        own = [s for s in members if s.get("location")]
        inherited = [s for s in members if not s.get("location")]

        out += ["", f"// ===== {group} ({len(members)}) ====="]
        for symbol in own:
            doc = symbol.get("docComment")
            if doc:
                for line in doc["lines"]:
                    text = line["text"]
                    out.append(f'  ///{" " + text if text else ""}'.rstrip())
            for gate in availability(symbol):
                out.append(f"  {gate}")
            out.append(f"  {declaration(symbol)}")
            if doc:
                out.append("")

        by_protocol: dict[str | None, list] = collections.defaultdict(list)
        for symbol in inherited:
            by_protocol[declaring_protocol(symbol)].append(symbol)

        def emit(label, members):
            out.append(f"  // {label}:")
            for symbol in members:
                for gate in availability(symbol):
                    out.append(f"  {gate}")
                out.append(f"  {declaration(symbol)}")

        # A conformance guarantees members the graph may not have emitted; say so rather
        # than let a reader read absence as absence.
        holder = type_by_path.get(group)
        present = {s["pathComponents"][-1] for s in members}
        missing = sorted(
            {
                UNEMITTED[name]
                for name in conformances.get(holder["identifier"]["precise"], ())
                if name in UNEMITTED and UNEMITTED[name][0] not in present
            }
        ) if holder else []

        first = not own
        for protocol in sorted(k for k in by_protocol if k):
            members = by_protocol[protocol]
            if not first:
                out.append("")
            first = False
            plural = "member" if len(members) == 1 else "members"
            emit(f"[inherited from {protocol}] {len(members)} {plural}", members)
        if synthesized := by_protocol.get(None):
            if not first:
                out.append("")
            first = False
            plural = "member" if len(synthesized) == 1 else "members"
            emit(f"[compiler-synthesized] {len(synthesized)} {plural}", synthesized)
        if missing:
            if not first:
                out.append("")
            plural = "member" if len(missing) == 1 else "members"
            out.append(
                f"  // [reconstructed] {len(missing)} {plural} guaranteed by a conformance above "
                "that the symbol graph does not emit:"
            )
            for _, text in missing:
                out.append(f"  {text}")

    return "\n".join(out) + "\n"


if __name__ == "__main__":
    graph = pathlib.Path(sys.argv[1])
    sources = pathlib.Path(sys.argv[2] if len(sys.argv) > 2 else "Sources/CassandraClient")
    sys.stdout.write(render(graph, sources))
