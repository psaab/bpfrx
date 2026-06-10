# #1814 — VRRP track-interface: nested priority-cost block + make tracking actually work

Status: DRAFT v2 — REFRAMED after round-1 (Codex PLAN-KILL on v1's false
premise; AGY design review constructive). Pending round-2 confirm.

## Round-1 verdicts and the reframe

Codex KILLED v1 on a decisive fact: `TrackInterface`/`TrackPriorityCost`
are parsed and copied into pkg/vrrp's InstanceConfig (vrrp.go:23-24,
:47-48) **but the runtime never uses them** — `UpdateInstances` ignores
them in its change comparison (manager.go:194) and advertised priority is
always static `cfg.Priority` (instance.go:248-252 getPriority,
instance.go:391). v1's "single-track runtime unchanged" invariant was
false in the worst way: parsing MORE config would still do NOTHING.

Per the project's Junos-parity rule (don't drop Junos-compat features —
fix the implementation to match Junos semantics), v2 implements the
minimal single-track runtime AND the nested config form. Both reviewers'
parser findings are folded: flat-set `set ... track-interface ge-0/0/1
priority-cost 20` produces a `track-interface` node with a CHILD
`priority-cost` node (SetPath descends on schema match, ast_edit.go:270;
confirmed independently by both reviewers) — there is no Keys-packed
spelling to handle once the schema knows the child.

## Issue framing (v2)

Two defects, one feature surface:
1. The nested `track-interface <if> { priority-cost <n>; }` block — the
   standard Junos shape — silently loses `priority-cost` in both AST
   shapes (the child walk reads the interface via nodeVal,
   compiler_interfaces.go:448, and drops the child).
2. Even the values that DO parse are dead: VRRP tracking is a no-op
   end-to-end. An operator who configures tracking believes a link
   failure will demote the VRRP master; it will not.

## Concrete design

### A. Runtime: single-interface tracking (pkg/vrrp)

- `vrrpInstance` gains `trackDown bool` (guarded by the existing vi.mu).
- `getPriority()` returns the **effective** priority:
  `p := vi.cfg.Priority; if vi.trackDown && vi.cfg.TrackInterface != "" {
  p -= vi.cfg.TrackPriorityCost }`, clamped to [1, 254] (0 is the
  release/shutdown sentinel and must never result from tracking; 255 is
  owner). Default cost when the nested/flat form omits it: Junos default
  is priority-cost required? Junos allows 1-254, no default — if the
  operator gives track-interface without priority-cost, treat cost as 0
  and surface a commit WARNING ("track-interface without priority-cost
  has no effect") so the no-op is visible, not silent.
- Link-state source: the Manager runs ONE `netlink.LinkSubscribe`
  goroutine (the package already imports vishvananda/netlink for VIP
  management, instance.go:19) started lazily when ≥1 instance has a
  TrackInterface; it maintains ifname → operstate and calls
  `vi.setTrackDown(down)` on transitions for instances tracking that
  ifname. Initial state seeded by `netlink.LinkByName` at instance
  start/update. Subscribe-failure fallback: log + 1s poll ticker
  (bounded; only while tracked instances exist).
- `setTrackDown` recomputes effective priority; if it CHANGED: log
  (slog.Info, transition-only), and let the existing state machine act —
  master with lowered priority keeps advertising the lower value and a
  higher-priority backup preempts per protocol (no forced abdication
  needed; preempt=true peers take over; document that with preempt=false
  peers, takeover waits for masterDown like real VRRP). The
  advert-on-next-tick is sufficient (30ms-1s intervals).
- `UpdateInstances` comparison (manager.go:194) includes TrackInterface +
  TrackPriorityCost so config changes propagate (track-field-only changes
  update cfg in place rather than full instance restart if the existing
  compare/update structure distinguishes; otherwise restart-on-change is
  acceptable and simpler — implementer follows the existing pattern).
- HA note: RETH VRRP instances are suppressed under PrivateRGElection
  (daemon_ha_vip.go) — tracking applies to standalone VRRP instances;
  no chassis-cluster interaction. State it in docs.

### B. Config: nested block parse (pkg/config)

- schema.go vrrp-group subtree: `track-interface` gets
  `children: {"priority-cost": {args:1, placeholder:"<1..254>"}}`
  (args stays 1 for the interface name). `track-priority-cost` flat
  sibling stays (back-compat) — when BOTH are present, nested wins +
  warning.
- compiler_interfaces.go child walk: `track-interface` node →
  `vg.TrackInterface = prop.Keys[1]` (guard len), then child
  `priority-cost` → `vg.TrackPriorityDelta`. The legacy Keys-packed
  flat-sibling walk (:399-409) unchanged.
- Multiple `track-interface` nodes: **first-wins + warning** via
  `cfg.Warnings` (AGY: compileInterfaces takes only InterfacesConfig and
  cannot append warnings — so the warning is collected by an AST-level
  pre-walk in compileExpanded (compiler.go) where Config IS in scope,
  same place U7 put tree-level checks; Codex preferred strict-reject —
  v2 chooses warning-first because a strict reject needs the
  strict/lenient split plumbed into a section compiler and the
  operational risk of first-wins-with-visible-warning is low; round-2
  may overrule).
- `priority-cost` without `track-interface`, and track-interface without
  cost: warnings (see A).
- FormatSet: with the schema child added, `FormatSet` renders the nested
  child recursively (ast_format.go:192 per Codex) — round-trip covered
  by harness fixture.

### C. Tests

- pkg/config: hierarchical nested block; flat-set nested via
  ParseSetCommand+SetPath (asserting the CHILD shape lands and compiles);
  legacy flat sibling spellings; both-present precedence; multiple
  track-interface first-wins + warning; missing-cost warning.
- U5a differential harness fixture for the nested form (closes the
  consistent-empty blind spot).
- pkg/vrrp unit tests: getPriority clamp matrix (cost>priority → 1;
  normal subtract; no-track unchanged); setTrackDown transition triggers
  effective-priority change; UpdateInstances reacts to track-field
  change. Link-subscribe goroutine tested via the poll fallback seam or
  an injectable link-state source (follow existing pkg/vrrp test
  patterns — it has instance tests).
- Live gate (cluster): commit a track-interface config on fw0
  (standalone-style VRRP instance if the cluster config allows, else the
  local regression VM), `show vrrp` reflects effective priority; flap
  the tracked link (`ip link set down` on a non-critical iface) →
  priority drops in adverts; restore → recovers.
- make test-failover (VRRP-adjacent change — mandatory per CLAUDE.md).

## Honest scope/value framing

This grew from a parse fix to a small feature completion (~150 lines
runtime + ~100 config + tests) because shipping the parse fix alone would
deepen the silent-no-op trap. If round-2 reviewers judge the runtime
half too large for this issue, the fallback is NOT parse-only — it is
parse + **commit-check warning "interface tracking is not implemented"**
until a runtime issue ships; silent no-op is the one indefensible state.
PLAN-KILL acceptable only with a better alternative for the silence.

## Public API preservation

Config struct unchanged (TrackInterface/TrackPriorityDelta reused).
pkg/vrrp adds internal state only; InstanceConfig unchanged. setSchema
additive. No wire changes.

## Hidden invariants

- SchemaValidate must keep accepting all spellings on lenient paths (the
  new warnings come from the compiler pre-walk, NEVER SchemaValidate —
  store.go:337 calls it on Load/SyncApply; U7 lesson).
- getPriority is called from the advert path and masterDownInterval
  computation (instance.go:287) — keep it lock-cheap (RLock as today).
- Priority 0 reserved (release); 255 owner semantics — clamp [1,254].
- VIP add/remove on master transitions unchanged.

## Risk assessment

| Class | Level | Notes |
|---|---|---|
| Behavioral regression | MED | getPriority is load-bearing in the state machine; clamp + no-track fast path keep default behavior identical |
| Lifetime/borrow | N/A (Go) | |
| Performance | LOW | one subscribe goroutine; per-advert int math |
| Architectural mismatch | LOW | matches kernel-state-watch patterns elsewhere in the daemon |

## Out of scope

- Multi-track list (Option 2) — follow-up issue if wanted.
- Full Junos `track { interface <n> { ... } }` container spelling and
  route-tracking — follow-up.
- RETH/chassis-cluster tracking interplay (suppressed instances).

## Open questions for adversarial review (round 2)

1. Warning-first vs strict-reject for multiple track-interface — v2
   chooses warning+first-wins; overrule with a concrete plumbing
   proposal if reject is required.
2. Is letting protocol preemption handle the demotion sufficient, or
   must a master that loses effective-priority superiority abdicate
   immediately (send priority-0)? Real VRRP: it keeps advertising at the
   lower priority; higher-priority preempt-enabled backup takes over.
   Confirm against pkg/vrrp's receive path (does a backup with higher
   priority + preempt=true preempt on hearing a LOWER-priority advert?).
3. LinkSubscribe vs poll: any precedent in the daemon for netlink
   subscriptions that this should reuse instead of a pkg/vrrp-local one?
4. getPriority clamp interaction with masterDownInterval skew math
   (instance.go:287) — any issue advertising a changed priority
   mid-master-tenure?
