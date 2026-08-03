# Plan: gate conflicting inline-term `icmp-type` / `icmp-code` repeats (#6766)

## Goal

A single-valued `icmp-type` or `icmp-code` leaf repeated with a DIFFERENT value
inside one inline application `term` is currently last-writer-wins with no
commit error: `parseApplicationTerms` assigns each repeat straight into the
`icmpType` / `icmpCode` pointer, the term subtree is opaque to SchemaValidate
(`schema_security.go` `term` is `args:1, children:nil`), and the strict
structure gate only sees leaves recorded on `Application.DuplicateTermLeaves` —
which the inline parser never populates for ICMP. A referenced DENY application
therefore enforces only the last type/code (a silent narrowing of the deny
match). The direct-body path (#5574) and the port/timeout/ALG inline leaves
(#3366) already track first-value/set and record conflicting repeats; ICMP was
omitted from the #3366 framework.

## Approach

Mirror the existing #3366 value-aware duplicate tracking for the two ICMP
leaves, in the same function, with the same semantics:

1. `pkg/config/compiler_applications.go` `parseApplicationTerms`:
   - add `icmpTypeSet` / `icmpCodeSet` bools plus first parsed values
     (`uint8`), exactly like the direct body's `itypeSet`/`icodeSet`;
   - on a repeat whose parsed value differs from the first, append
     `"icmp-type"` / `"icmp-code"` to `dupTermLeaves`;
   - an idempotent same-value repeat stays accepted (no record);
   - a malformed token keeps its current path (`badICMP` → `UnknownICMP` →
     strict specs gate) — duplicate tracking only applies to values that parse,
     so a `icmp-type 8 icmp-type foo` sequence is still caught by the malformed
     arm, not the duplicate arm;
   - update the #3366 comment block to name the ICMP leaves.
2. `pkg/config/compiler_validate_strict_application.go`:
   - extend the `DuplicateTermLeaves` error text to enumerate
     `icmp-type / icmp-code` alongside the existing leaves;
   - update the `validateApplicationStructureStrict` doc comment (#3366 bullet)
     to name the ICMP leaves.

No dataplane or Rust change: `capabilities.go` and `policy.rs` consume the
final compiled constraint; the fix makes the compiler reject a config that
previously compiled to a silently narrowed constraint.

## Alternatives rejected

- **Schema-typing the term subtree**: the inline term is a single packed
  statement in both AST shapes; making the schema walk it would be a much
  larger grammar change and is not how #3352/#3366 solved the same opacity.
- **Value-blind rejection (any repeat)**: would break the accepted idempotent
  same-value restate (apply-groups merges can legitimately restate a value);
  inconsistent with the #3366/#5574 semantics.

## Files touched

- `pkg/config/compiler_applications.go` (parseApplicationTerms + comment)
- `pkg/config/compiler_validate_strict_application.go` (error text + doc comment)
- `pkg/config/compiler_application_term_icmp_dup_6766_test.go` (new tests)
- `pkg/config/README.md` (#3366 section: extend the tracked leaf list)
- `docs/pr/6766-inline-icmp-dup/plan.md` (this file)
- `_Log.md` (work log entry)

## Test strategy

New fail-on-revert table + guards in
`pkg/config/compiler_application_term_icmp_dup_6766_test.go`:

- **packed flat-set** (the `flatTreeFromSets` shape, one `set` line carrying
  the repeat): `icmp-type 8 icmp-type 0` and `icmp-code 1 icmp-code 2` reject,
  error names the leaf;
- **hierarchical** (`hierTree` brace block with sibling repeats): both leaves
  reject;
- **apply-groups**: a group restates the term with a conflicting value; the
  merged config rejects;
- **deny-policy**: a referenced deny app with a conflicting inline `icmp-type`
  rejects at strict compile; on the lenient path the compiled term demonstrably
  enforces ONLY the last type (characterizes the silent narrowing the strict
  gate prevents);
- **same-value idempotent**: `icmp-type 8 icmp-type 8` and
  `icmp-code 0 icmp-code 0` commit cleanly;
- **lenient downgrade**: conflicting repeat downgrades to a warning, no brick.

RED-first: the rejection tests fail against the pre-fix compiler (nothing
records the duplicate, strict compile succeeds).
