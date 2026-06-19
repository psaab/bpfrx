# Claude SMR — #1979 Layer B plan review, round 1

**Verdict: PLAN-NEEDS-MINOR** (design is sound and experimentally grounded; two
real gaps to fold + several decisions to lock before /engineer).

Reviewed hostilely, not as synthesizer. I ran the experiments myself (in-place
schema mutation tests, deleted after) before writing this — the Tier-3 trap and
the Tier-1/2 cleanliness are reproduced facts, not assertions.

## What the plan gets right (verified, not taken on faith)

1. **The three-tier decomposition is real and load-bearing.** I reproduced:
   - Tier 1 (`flow-active/inactive-timeout`): adding `valueType+validator` to the
     existing `args:1, children:nil` leaf validates good/bad correctly and keeps
     round-trip byte-stable. Zero risk. Confirmed.
   - Tier 2 (`flow-server port`, `input rate`, session timeouts): both flat AND
     hierarchical shapes validate, out-of-range rejected, two bare flow-servers
     still append. Confirmed.
   - Tier 3 (`tcp-mss gre-in`): the dual-value-location trap is **real**. Typed-leaf
     model false-rejects `gre-in { mss 1360 }` with "missing value"; container model
     silently ignores flat `gre-in 70000`. Both forms are valid configs
     (TestTCPMSSHierarchical + parser_security_test.go). This is the single most
     important finding and it is correct.
2. **Bounds = Layer-A caps.** Cross-checked the §3 table against
   flow.go on master: u16 [0,65535], u64 [0,MaxDurationSeconds] (the
   from_seconds*1e9 unchecked-overflow reasoning is right and matches the existing
   `hold-down` leaf), u32 [0,u32max]. No drift. Good.
3. **Q1 completeness — I independently confirmed** `parseMSSValue` is called ONLY
   from compiler_security.go (the flow path); there is no interface-level tcp-mss
   feeding these flow fields. The 8-leaf / 11-field set is complete. The plan's
   Q1 bracketed note ("interface-level family inet tcp-mss") is a red herring it
   should resolve to "out of scope / does not reach flow fields" — see Gap A.

## Gaps to fold (the MINOR findings)

### Gap A — Q1 interface-tcp-mss note is unresolved noise; resolve it.
The plan's Q1 leaves a bracketed open question about interface-level
`family inet tcp-mss`. I checked: `parseMSSValue` has exactly four callers, all in
compiler_security.go:629-641 (the `security flow tcp-mss` switch). There is no
per-unit MSS leaf feeding FlowSnapshot. **Fold the resolution into the plan** so a
reviewer doesn't re-chase it: the enumeration is complete; interface MSS (if any)
is a separate field out of scope.

### Gap B — T3-A(ii) hook point is under-specified, and that is exactly where
this plan could go wrong at /engineer time.
`SchemaValidate`/`walkSchemaNode` today ONLY runs declarative typed-leaf
validators (validator/treeValidator on a node with valueType != ValueAny). A
`validateTCPMSS` dual-read helper is NOT that shape — it must be invoked somehow.
The plan offers two sub-mechanisms but doesn't commit:
  - (i) a new `schemaNode` field (`selfValueValidator`) the container branch runs
    against Keys[1] — additive, but it touches the schemaNode type + the golden +
    docs/config-schema.md, and it is a NEW walker concept (must handle the
    flat-value-on-container case the container branch deliberately ignores today,
    walkSchemaNode:270-284).
  - (ii) a standalone AST pre-pass invoked from SchemaValidate (or from a
    security-specific validate step) that walks `tcp-mss` and range-checks both
    positions.
**This is the crux of the whole plan and must be decided before /engineer, not
during.** My read: (ii) is cleaner ONLY IF there is a clean place to call it.
SchemaValidate's entry (schema_walk.go:70-82) is generic; bolting a tcp-mss-specific
pre-pass there is a layering smell. The honest options:
  - (ii-a) call `validateTCPMSS` from within `walkSchemaNode` when the resolved
    container is the `tcp-mss` node (keyed by a marker, e.g. a node-level
    `customValidator func([]*Node) error` field invoked on the container's
    children) — this generalizes (i) and is the least surprising;
  - (ii-b) a separate top-level validation function the configstore calls
    alongside SchemaValidate (like the existing validateVRRPTrackInterfaceAST,
    compiler_interfaces.go:746 — a precedent the plan should CITE: xpf already has
    AST-walk validators OUTSIDE the schema walker for exactly this "the schema
    walker can't express it" case).
**Fold:** pick a concrete mechanism. I recommend (ii-b) — `validateTCPMSS` as a
standalone AST validator modeled on `validateVRRPTrackInterfaceAST`, wired where
that one is wired. It needs zero schemaNode/golden churn, it mirrors an existing
project pattern, and it keeps Tier 3 fully decoupled from the SSOT grouping
machinery. The plan currently leans (ii) "focused helper" but doesn't name the
VRRP precedent or the wiring site — name them.

## Decisions to lock (the plan correctly raises these as Q3/Q4/Q5/Q7; pick now)

- **Q3 (sampling rate bound):** `[1, u32max]`. Reject 0 at commit (Junos rejects
  it; Layer A normalizes 0→1 only as a defense). Clear-error UX is the whole point.
- **Q4 (tcp-session 4 timeouts):** type all four. Once `tcp-session` is a
  container you must declare its children anyway (completion), and the three
  non-wire timeouts share the `[0,MaxDurationSeconds]` bound — typing them is
  free and consistent. AGREE with the plan.
- **Q5 (version-ipfix pair):** type them too. Same one-line change, UX parity,
  and it future-proofs if IPFIX is ever wired. AGREE.
- **Q7 (worth it / PLAN-KILL):** NOT a kill. But be honest in the issue comment:
  this is UX-only; Layer A is the safety fix. The recommended scope (Tier 1+2 +
  T3-A) is justified because the issue's HEADLINE example (`tcp-mss-gre-in
  70000`) is precisely the Tier-3 flat path — shipping Tier 1+2 and deferring
  Tier 3 (T3-C) would leave the marquee case un-validated, which would read as a
  half-fix. So either do T3-A properly or be explicit that T3-C is a partial.

## Hostile probes that did NOT find a problem (recorded so reviewers don't redo)

- Does expanding `tcp-session` (args:0) to a container break the `i >= len(path)`
  REPLACE branch? No — that branch requires `args > 0` (ast_edit.go:196); args:0
  nodes were never replace-leaves. Confirmed by round-trip test.
- Does the `flow-server` APPEND flip duplicate-explode a single-collector config?
  No — a real config sets `flow-server <addr> port <n>` (one node, descended);
  the APPEND only matters for the (valid) multi-collector case. Confirmed.
- Do the hierarchical Tier-2 shapes (`udp-session { timeout 60; }`) validate?
  Yes — value lands in the sub-leaf Keys[1] regardless of shape. Confirmed.

## Bottom line

Design is right, the hard case is correctly identified and is the reason this was
deferred from #1977. Fold Gap A (resolve Q1) and Gap B (commit to a concrete
T3 mechanism + cite the validateVRRPTrackInterfaceAST precedent and wiring site),
lock Q3/Q4/Q5, and this is PLAN-READY. Re-review after the fold.
