# #1814 — vrrp-group track-interface nested priority-cost block

Status: DRAFT v1 — pending adversarial plan review

## Issue framing

Junos models VRRP interface tracking as a container:
`track-interface ge-0/0/1 { priority-cost 20; }` (and the flat-set
equivalent `set ... vrrp-group 1 track-interface ge-0/0/1 priority-cost 20`).
xpf's setSchema (schema.go:433-434) models `track-interface` and
`track-priority-cost` as flat SIBLING leaves, so the nested form is ignored
by BOTH AST shapes — consistent-empty, invisible to the U5a differential
harness (which only catches shape divergence). Found by AGY on PR #1813;
follow-up to #1796.

## Current state (verified, master f96290a98)

- schema.go:433-434: `track-interface {args:1}`, `track-priority-cost
  {args:1}` — both leaf, no children.
- compiler_interfaces.go:399-409 (Keys-packed flat walk) + :448-452
  (child-node walk): both read the two flat spellings into
  `vg.TrackInterface string` + `vg.TrackPriorityDelta int`.
- vrrpGroupPropertyKeywords (compiler_interfaces.go:20-21) lists both — the
  U5b greedy-consume logic treats them as value-bearing keywords.
- pkg/vrrp/vrrp.go:23-24,47-48: consumes single TrackInterface +
  TrackPriorityCost. Runtime tracking logic exists for ONE interface.

## Design options

**Option 1 (recommended): model the nested block, keep single-track
runtime.**
- schema.go: `track-interface` becomes `{args:1, placeholder:"<interface>",
  children: {"priority-cost": {args:1}}}`. Keep `track-priority-cost` flat
  sibling for back-compat (existing configs).
- Compiler: in the child-node walk, `track-interface` node may carry
  Keys[1]=iface plus either (a) a child `priority-cost` node (hierarchical
  or flat-set replay) or (b) nothing (legacy spelling). Read both. In the
  Keys-packed walk, after consuming `track-interface <iface>`, peek for
  `priority-cost <n>` continuation (flat-set
  `... track-interface ge-0/0/1 priority-cost 20` packs into the same
  node's Keys — verify with ParseSetCommand, the U5b lesson; add
  "priority-cost" to the property-keyword handling so greedy consume
  doesn't swallow it as a virtual-address).
- Multiple `track-interface` blocks: detect and surface a commit-check
  WARNING "only one tracked interface supported; using <first|last>"
  (pick FIRST + warn — deterministic), rather than silent last-wins.
- Junos compat note: real Junos syntax is
  `track { interface <name> { priority-cost <n>; } }` under vrrp-group;
  vSRX also accepts the flatter `track-interface` form xpf already chose.
  This plan extends xpf's EXISTING spelling; adding the full `track {}`
  container is listed as out of scope (separate issue if wanted).

**Option 2: full multi-track list.** `[]VRRPTrackInterface{Iface,
PriorityCost}` through config types, compiler, pkg/vrrp runtime (priority
recomputation summing costs of down tracked links), HA event wiring.
Substantially larger blast radius (vrrp state machine), not justified by
the filed defect. Documented as future work.

## Honest scope/value framing

Option 1 is a config-surface completeness fix: the nested form currently
parses to NOTHING (track silently disabled — a real operational footgun:
operator believes tracking is armed). Small compiler + schema change, one
harness fixture. PLAN-KILL acceptable if reviewers conclude the nested
spelling shouldn't be accepted at all (reject-at-commit instead) — but
silent-ignore is the one indefensible state.

## Public API preservation

Config struct unchanged (Option 1 reuses TrackInterface/
TrackPriorityDelta). setSchema additions are additive (existing spellings
still valid). No wire/protocol changes.

## Hidden invariants

- Dual-AST: hierarchical `track-interface ge-0/0/1 { priority-cost 20; }`
  → Node{Keys:["track-interface","ge-0/0/1"], Children:[{Keys:["priority-cost","20"]}]};
  flat-set replay may pack `Keys:["track-interface","ge-0/0/1","priority-cost","20"]`
  OR nest a child — compiler must read BOTH (test with
  ParseSetCommand+SetPath, never NewParser, per CLAUDE.md).
- U5b greedy virtual-address consume (vrrpGroupPropertyKeywords): adding
  `priority-cost` as a recognized continuation must not break
  virtual-address multi-value parsing — fixture both orders.
- SchemaValidate (typed-leaf walk) runs on both strict and lenient paths —
  schema change must not reject existing flat spellings (additive children
  only).
- Harness (U5a dual_ast_differential_test.go): add fixtures for nested
  form; expect IDENTICAL compile both shapes (this closes the
  consistent-empty blind spot for this leaf).

## Risk assessment

| Class | Level |
|---|---|
| Behavioral regression | LOW (additive parse; existing spellings covered by U5b tests) |
| Performance | NONE (commit path) |
| Architectural mismatch | LOW |

## Test plan

- pkg/config unit tests: hierarchical nested block, flat-set nested
  (ParseSetCommand+SetPath), legacy flat sibling spellings, multiple
  track-interface warning, priority-cost-without-track-interface case.
- Differential harness fixture(s).
- Schema completion test (CompleteSetPathWithValues offers priority-cost
  under track-interface) if the schema test file has precedent.
- go build + go test ./pkg/config/ ./pkg/vrrp/ ./pkg/cli/.
- Smoke: config-apply on cluster (vrrp config touched in cos fixture?
  verify a track-interface config commits + `show vrrp` reflects it);
  failover gate (VRRP-adjacent — cheap insurance, the cluster smoke
  includes it anyway per campaign convention).

## Out of scope

- Option 2 multi-track runtime.
- Full Junos `track { interface ... }` container spelling (file follow-up
  if reviewers want it).
- vrrp.go runtime changes (none needed for Option 1).

## Open questions for adversarial review

1. First-wins+warn vs last-wins+warn vs reject for multiple
   track-interface blocks?
2. Should the legacy `track-priority-cost` sibling leaf be deprecated
   (warn) once the nested form exists, or kept silently forever?
3. Flat-set packing: does `set ... track-interface ge-0/0/1 priority-cost
   20` actually pack Keys as assumed? Reviewer should verify with the
   parser (ParseSetCommand) before approving the compiler design.
4. Is commit-check WARNING the right surface for multi-track (vs
   SchemaValidate error)? SchemaValidate runs on lenient/boot path — must
   NOT hard-fail there (U7 lesson).
5. Does pkg/cli `show configuration` re-rendering (FormatSet) round-trip
   the nested form correctly once schema knows the child?
