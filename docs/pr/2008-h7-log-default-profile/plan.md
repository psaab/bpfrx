# #2008 H7 — `security log profile` / `default-profile` (vSRX parity)

Status: DRAFT v1 — pending hostile Claude reviews (2 independent + SMR).

## Issue framing (H7, #2008 umbrella)

The #2008 parity audit lists **H7** as `security log profile`
(stream-name / category / default-profile) — "whole stanza absent."
The Tier-3 `/research` (branch `research/2008-tier3`,
`docs/research/2008-tier3/plan.md`) corrected that: xpf's
`security log stream <name>` machinery already implements the *substance*
of Junos per-stream profile routing end-to-end (typed `SyslogStream`,
full `compileLog`, per-stream `SyslogClient` build in
`daemon_system.go`, per-client filtered RT_FLOW broadcast in
`ringbuf.go`). What is genuinely **absent** is the literal
`security log profile <name> { ... }` stanza and its `default-profile`
flag: there is no schema child, no typed field, and no compiler case, so
a config such as the one shipped in `vsrx-ha.conf` (lines 751-763):

```
security log {
    profile default-syslog {
        stream-name syslog-container;
        category { session { field-extra-name hostname; ... } }
        default-profile;
    }
}
```

**parses but is silently discarded** (`schema_walk.go` returns nil for an
unknown leaf under a known parent; `compileLog` has no `profile` case).
This is the audit's silent-drop failure class: commit succeeds, operator
intent is lost, and commit-time validation + `?` completion are absent.

## Scope (H7 ONLY)

Implement `security log profile <name>` as a validated, compiled config
object with `default-profile` semantics, restoring commit-time
validation in place of the silent-drop. **No runtime/dataplane change** —
xpf's per-stream routing is already a Junos superset (every matching
stream receives the event), so a `profile`'s `stream-name` maps onto the
existing per-stream routing. This is the Tier-3 research's recommended
**FEASIBLE-INCREMENT (small)**, sharpened from "validated alias leaf" to
the real grammar found in the imported config (`profile <name>` object
with a `stream-name` routing target + `default-profile` flag).

Strictly out of scope (deferred, documented below): any change to
`ringbuf.go` dispatch semantics ("catch-all only when no stream
matched"), per-category `field-extra-name` structured-data emission, and
H12 (dns-proxy).

## Honest scope/value framing

The win is **truth-in-commit**: a silently-dropped stanza that real
imported vSRX configs use (`vsrx-ha.conf`) becomes parsed, validated,
and cross-referenced. A `profile` naming a non-existent stream is
rejected at commit (strict) / warned on tolerant load (mirrors the
sibling cross-ref gates). The runtime routing is unchanged because it is
already a Junos superset. No perf dimension. If reviewers conclude the
parity value is too small to justify the surface, PLAN-KILL is an
acceptable verdict — but the silent-drop of a real imported stanza is
the project's explicitly-flagged operationally-dangerous class.

## What's already shipped / composes-with

- H1 `inactive:` (#2042, merged): the `inactive: profile default-syslog`
  marker in `vsrx-ha.conf` is stripped before compile by the centralized
  inactive-subtree prune. The new `profile` schema/compiler must behave
  correctly for an **active** `profile` (the inactive one never reaches
  `compileLog`). Tests cover the active case.
- H8 / M2 / M3 Tier-1.5 schema-hardening (merged): `stream`'s
  `transport` child + IKE/IPsec proposal leaves + dest-NAT match are
  already typed. The new `profile` child sits beside `stream` under the
  same `log` node.
- The cross-ref + lenient-downgrade pattern
  (`validateIPsecPolicyProposalReferencesStrict`,
  `validateIPsecGatewayReferencesStrict`,
  `validatePolicyMatchAddressesStrict`) is the exact template for the
  `profile.stream-name` cross-reference.

## Concrete design

### Types (`pkg/config/types_security.go`)

```go
// LogProfile is a Junos `security log profile <name>` object: a named
// log routing profile that targets a configured stream and may be the
// default profile. xpf's per-stream routing is a Junos superset (every
// matching stream receives the event), so a profile's StreamName names
// the stream that carries its events; no dispatch change is required.
type LogProfile struct {
    Name           string
    StreamName     string // references LogConfig.Streams[StreamName]
    DefaultProfile bool   // `default-profile;` — marks this the default
}
```

Add to `LogConfig`:

```go
Profiles map[string]*LogProfile
```

### Schema (`pkg/config/schema_security.go`, under the `log` node)

Add a `profile` child beside `stream`:

```go
"profile": {desc: "Security log profile (routing object)", args: 1,
    placeholder: "<profile-name>", children: map[string]*schemaNode{
    "stream-name":     {desc: "Stream this profile routes to", args: 1,
        valueHint: ValueHintStreamName, placeholder: "<stream-name>", children: nil},
    "default-profile": {desc: "Mark this profile as the default", children: nil},
    "category": {desc: "Per-category field configuration", children: map[string]*schemaNode{
        "session": {desc: "Session category fields", children: map[string]*schemaNode{
            "field-extra-name": {desc: "Extra field to include", args: 1,
                placeholder: "<field>", children: nil},
        }},
    }},
}},
```

`category { session { field-extra-name ...; } }` is declared so it
parses + completes; xpf already emits per-stream structured data, so the
field list is accepted/validated but not (in this increment) used to
alter the emitted structured-data set — noted in the docs.

### Compiler (`pkg/config/compiler_security.go`, in `compileLog`)

After the stream loop, extract profiles (mirror the stream loop's
`namedInstances` + flag handling for `default-profile`):

```go
for _, inst := range namedInstances(node.FindChildren("profile")) {
    p := &LogProfile{Name: inst.name}
    for _, prop := range inst.node.Children {
        switch prop.Name() {
        case "stream-name":
            p.StreamName = nodeVal(prop)
        case "default-profile":
            p.DefaultProfile = true
        case "category":
            // accepted for parity; per-category field emission is
            // out of scope for this increment.
        }
    }
    if sec.Log.Profiles == nil {
        sec.Log.Profiles = make(map[string]*LogProfile)
    }
    sec.Log.Profiles[p.Name] = p
}
```

### Cross-reference validator (`pkg/config/compiler.go`)

New `validateLogProfileStreamReferencesStrict(cfg)` mirroring
`validateIPsecPolicyProposalReferencesStrict`: a `profile` whose
`stream-name` is set but does not resolve to a configured
`LogConfig.Streams[name]` is rejected (sorted keys → deterministic
first-error). A profile with no `stream-name` is accepted (Junos allows
a profile that inherits global routing). Call site mirrors the ipsec
gateway-ref block: strict on commit / commit-check, downgraded to a
warning on the tolerant load + peer-sync paths via a new
`lenientLogProfileStreamRef` opt (set true in the two lenient option
constructors).

Rationale for compiler-side cross-ref (not a schema validator): the
`schema_walk` per-leaf validators cannot see sibling `stream` nodes;
`compileLog` (and the post-compile `*Config`) has the full stream map in
scope. Same reason the ipsec proposal/gateway refs live in the compiler.

## Public API preservation

Pure additive. `LogConfig` gains one field (`Profiles`); a new exported
type `LogProfile`; one new unexported validator + opt. No existing
signature changes. `applySecurityLogging` / `ringbuf.go` untouched
(runtime already correct).

## Hidden invariants preserved

- **Silent-drop → validated**: `profile`/`default-profile` were dropped;
  now compiled + cross-referenced. No previously-accepted *valid* config
  becomes rejected — only a `profile` naming a non-existent stream (a
  typo / dangling ref) is newly rejected, and only on the strict path.
- **Tolerant-path boot**: an already-persisted config with a dangling
  `profile.stream-name` still boots (warning), per the #1960
  fail-closed-on-load doctrine and every sibling cross-ref gate.
- **Inactive interaction (#2042)**: an `inactive: profile` is pruned
  before `compileLog`, so it never reaches the new code — verified by a
  test that an inactive profile naming a missing stream does NOT error.
- **Dual-AST**: `compileLog` reads via `namedInstances` + `nodeVal`,
  which already handle both hierarchical and flat-set shapes (same as the
  stream loop).

## Risk assessment

| Class | Level | Note |
|---|---|---|
| Behavioral regression | LOW | Additive; no runtime path touched; only new commit-time reject for a dangling ref (strict only, warned on load) |
| Lifetime / borrow | N/A | Go, no borrow concerns |
| Performance | NONE | Compile-time only; no dataplane/hot-path change |
| Architectural mismatch | LOW | Reuses the established cross-ref + lenient-downgrade pattern verbatim; does not introduce a parallel `profile` dispatch model (Option B, rejected by research as a regression risk to the working broadcast model) |

## Test plan (control-plane — NO dataplane smoke)

Per parent scope: cover with `pkg/config` compile/validate unit tests,
dual-AST flat-set via `ParseSetCommand` + `SetPath` (NOT `NewParser`),
non-tautological (each reject test FAILS pre-fix).

1. Flat-set: `set security log profile P stream-name S` +
   `set ... default-profile` → compiles to `Profiles["P"]` with
   `StreamName=="S"`, `DefaultProfile==true` (FAILS today — silently
   dropped, map empty).
2. Hierarchical round-trip: the `vsrx-ha.conf` profile shape (active,
   not inactive) compiles to the same typed struct.
3. Cross-ref reject (strict): `profile P stream-name nope` with no
   stream `nope` → `CompileConfig`/`SchemaValidate` errors referencing
   the profile + missing stream (FAILS today — accepted).
4. Cross-ref accept: `profile P stream-name S` with stream `S` defined →
   no error.
5. Tolerant path: dangling ref on the lenient compile path → warning,
   not error (config still compiles).
6. Inactive interaction (#2042): `inactive: profile P stream-name nope`
   → no error (pruned before compile).
7. Schema completion/validation: `default-profile` + `stream-name`
   accepted under `profile`; a bad child rejected by `SchemaValidate`.

Gates: `go build ./...`, `go vet ./pkg/config/`,
`go test ./pkg/config/...` (full package), `go test ./...` (full Go
suite). No Rust / no cluster smoke — H7 is control-plane only.

## Out of scope (explicitly deferred)

- `ringbuf.go` "default-profile catches only unmatched events" dispatch
  semantics (research Option B — rejected; xpf's broadcast model is a
  Junos superset and changing it risks regressing working routing).
- Per-category `field-extra-name` structured-data field selection
  (accepted/validated, not yet used to alter emitted SD).
- H12 dns-proxy (separate Tier-3 row, research disposition = DEFER).

## Open questions for hostile review

1. Is `stream-name` the correct cross-ref target, or does Junos
   `default-profile` ALSO need a global "which profile is default"
   uniqueness check (reject two `default-profile` profiles)? Proposed:
   accept multiple but the cross-ref is per-profile; is a
   single-default invariant worth enforcing?
2. Should a dangling `profile.stream-name` be a hard commit ERROR or
   only a WARNING even on the strict path? (Sibling ipsec refs are hard
   errors on commit; this plan matches them. Counter: a log misroute is
   less dangerous than a dropped crypto proposal.)
3. Is declaring the `category { session { field-extra-name } }` subtree
   (parsed-but-unused) better than omitting it (so it silently drops
   again)? Plan says declare-and-accept; argue the other way.
4. Does adding `profile` as a `log` child collide with any existing
   flat-set token grouping or completion path (e.g. the feeds `profile`
   node elsewhere in the schema)?
5. Is the lenient-downgrade opt necessary, or does a log-profile
   cross-ref never appear on a peer-sync/load path that must boot
   through it? (Plan adds it for symmetry with the #1960 doctrine.)
6. Is there any consumer that would now read `LogConfig.Profiles` and
   change behavior unexpectedly (HA config-equality, display-set
   round-trip, `show configuration`)?
