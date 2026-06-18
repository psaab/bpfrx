# Claude SMR — #1977 NUM_WIDTH plan review, round 1

**Posture:** hostile domain SMR (serialization / Go-Rust interop). Not a self-rubber-stamp.

**Verdict: PLAN-NEEDS-MINOR** — design is sound and the load-bearing assumption
verified; three folds before `/engineer`.

## Verified directly

- **Chokepoint (Q5) — CONFIRMED.** `buildFlowSnapshot` (flow.go:5) and
  `buildFlowExportSnapshot` (flow.go:24) are called ONLY from `buildSnapshot`
  (builder.go:45,59), which is the sole `ConfigSnapshot` constructor that feeds
  `m.lastSnapshot` (the published snapshot). `FlowExportSnapshot{}` is
  constructed only inside `buildFlowExportSnapshot` (flow.go:53). So Layer A at
  these two functions covers **every** config-derived snapshot regardless of how
  the config arrived (CLI, gRPC, file). Layer A's "covers all input paths" claim
  is true, not aspirational. This is the strongest part of the design.
- **Mechanism** matches #1961: the whole `ControlRequest` decodes in one
  `serde_json::from_str` (server/handlers/mod.rs), so one out-of-range numeric
  aborts the entire `apply_snapshot`. The fields are Go `int`
  (types_security.go:68-72,110; types_system.go:501-502,515-516) → emitted as
  signed JSON numbers; Rust expects unsigned. Sound.

## Required minor folds (into v2)

1. **Re-confirm the field set (Q4) at implementation start, not just trust the
   audit.** The Q5 audit predates the #1976 merge; #1976 didn't touch these
   structs, but the implementer must diff current `protocol.go`
   FlowSnapshot/FlowExportSnapshot int fields against the Rust
   `snapshot.rs`/`security.rs` unsigned fields and confirm exactly these 9 (and
   no int→unsigned field in any OTHER snapshot struct slipped past the audit's
   would_fail_decode filter). Cheap; closes the "is the audit complete" gap.
2. **Frame Layer A as the must-have, Layer B as optional.** Layer A (build-
   boundary coercion) is the *guarantee* — it alone makes the decode abort
   impossible on every path. Layer B (commit-time `ValidateInteger`) is operator
   UX (a clear `commit check` error vs silent coercion). If reviewers push back
   on scope (Codex's #1961 "don't over-scope" instinct), ship Layer A and file
   Layer B separately — do NOT ship Layer B without Layer A (Layer B alone
   leaves the gRPC/file paths exposed).
3. **Ranges = the Rust wire-type bounds suffice for THIS fix.** The goal is
   preventing the decode abort, so u16 fields validate/coerce to `[0,65535]`,
   u32/u64 to `[0,typeMax]`. A tighter Junos-correct bound (MSS MTU-derived,
   port `[1,65535]`, sane timeout caps) is a *config-correctness* improvement,
   not required to stop the abort — call it out as optional so the PR doesn't
   balloon into MSS-semantics debates. (Exception: CollectorPort should use
   `[1,65535]` since port 0 is already the skip sentinel.)

## Non-blocking notes

- Coercion semantics (Q1): MSS→0 (=disabled), port→skip-export, timeout→0/clamp
  are each the safe degradation. With Layer B present, the CLI rejects so the
  operator sees the error; Layer A's silent coercion only fires on non-CLI
  paths, where coerce+`slog.Warn` beats a dead dataplane. Good.
- A class-level guard (Q5 of the plan): a Go test asserting every numeric
  snapshot field placed by the builders is within its Rust type's range would
  catch a future int→unsigned field — worth it but lighter-weight than #1961's
  reflection guard (cross-language range isn't reflectable, so it'd be a
  hand-maintained table). Optional; reviewers decide.
