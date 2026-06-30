# Stable-identity scheme for zone IDs (#3075) and policy IDs (#3395)

## 1. Status

`DRAFT v1 — pending adversarial plan review (Claude SMR + AGY; Codex infra-blocked, 2-of-3)`

Research worktree: `.claude/worktrees/3075-3395-research` (branch
`research/3075-3395-stable-id`), based on `origin/master` HEAD `49765c603`
(includes the #3322 fix `ef72285df`). Docs-only — no production source touched.

## 2. Issue framing

Both issues are instances of the same *symptom* — "a positional id assigned in
config order renumbers when an earlier-sorting/earlier-positioned element is
added or removed, so an established session's frozen numeric id now resolves to
the wrong thing after a config edit." But they are NOT the same *mechanism*, and
that distinction is the central finding of this research (see §5).

- **#3075 (zone IDs).** `pkg/dataplane/compiler.go:183-194` sorts zone names and
  assigns `1..N`. The in-code comment already admits the breakage: *"existing
  sessions store zone IDs, so changing them breaks session→policy lookups."*
  Adding/renaming a zone that sorts before an existing zone shifts every later
  id by one. A live session's stored numeric `IngressZone`/`EgressZone` (u16 in
  the BPF conntrack value) then reverse-resolves under the wrong name via
  `manager_ha.go:zoneNameByID` — wrong zone in `show security flow session`,
  wrong name pushed to the HA peer (the send side does
  `req.IngressZone = m.zoneNameByID(val.IngressZone)`), and the duplicate
  positional map in `daemon_ha_userspace.go:buildZoneIDs` mis-installs on the
  receive side.

- **#3395 (policy IDs).** `pkg/dataplane/userspace/policies.go:194-196`:
  `policyID = PolicySetID*MaxRulesPerPolicy + RuleIndex`, span-accumulated in
  config order by `walkPolicyRuleSlots`. Stamped frozen onto the session at
  install (`poll_descriptor/mod.rs:2190,2438`) and carried as a `u32` on four
  surfaces (live session rows, RT_FLOW SESSION_CREATE `[44:48]`, SESSION_CLOSE
  `[136:140]`, HA delta). A live mid-list policy insert/delete renumbers every
  later rule, so an established session's frozen `policy_id` now resolves to a
  different policy's *name* — wrong attribution on session rows, close logs, and
  the post-failover peer view. This is the *display/forensic* sibling of #3322
  (the hit-counter-attribution instance), which is already FIXED.

The deliverable this research must decide: **one unified allocator for both, or
two separate schemes; the identity primitive (persistent allocator vs
name-hash vs flush-on-remap); wire compatibility; migration; risk; tests.**

## 3. Honest scope/value framing

This is **forensic/observability correctness**, not a forwarding or security
correctness fix. No packet is mis-forwarded and no policy decision is wrong: a
freshly-evaluated flow is always attributed correctly because the number→name
map is rebuilt from the same current config that admitted it. The defect is
strictly that an **already-established** session, after a **live** config edit
that perturbs ordering, displays/logs a **stale** numeric id (and therefore a
wrong name). The operationally severe instance of the class — the hit-counter
misattribution — was already closed by **#3322** with a Rust-internal name-keyed
`Arc` handle (no wire change).

Absolute scale of the remaining win:
- #3075 zone remap requires adding/renaming a zone whose name sorts before an
  existing zone *while sessions are live*. On the typical 3-8 zone box this is a
  rare, operator-initiated event; the mis-attribution self-heals as sessions
  age out.
- #3395 policy remap requires a live mid-list policy insert/delete *while
  long-lived sessions exist* AND an operator cross-referencing a closed-session
  log's `policy_id` afterward. Narrow forensic edge.

**If reviewers conclude the forensic-correctness win is too small to justify the
churn — particularly for the policy half — PLAN-KILL (or PLAN-DEFER of the
policy half) is an acceptable verdict.** This line is load-bearing: the policy
half's full ("rule-id-on-wire") fix is three two-sided wire growths plus a wire
version bump, and the present plan deliberately does NOT recommend it (§5, §10).

## 4. What's already shipped / prior art the plan must compose with

- **#1873 `pkg/config/tunnelid.go` — the blessed precedent.** Fixed the
  identical "positional id renumbers a sibling and breaks HA session metadata"
  defect for tunnel endpoints. `StableTunnelEndpointID(name)` = FNV-1a/64
  xor-folded to u16, mapped into `[1, 0xFFFF]` — *a pure function of the name
  alone, never of the set or allocation history, so both HA nodes agree by
  construction with zero synced/persisted state.* Collisions are caught by a
  commit-time gate (`validateTunnelEndpointIDCollisionAST`: strict reject on
  commit, lenient warning on load/peer-sync) plus a fail-closed dataplane belt
  that drops the later-sorting collider. Tests in `pkg/config/tunnelid_test.go`.
  This is the project's chosen answer to this defect class.

- **#3322 `ef72285df` — the policy hit-counter half, already fixed.** Binds the
  admitting rule's shared `Arc<PolicyRuleCounter>` (name-keyed
  `PolicyCounterStore`, keyed by stable `rule_id` string) onto the session at
  install and prefers that bound handle on the established fast path. Local
  derived state, NOT serialized. The commit message states verbatim:
  *"policy_id (#3056) is itself positional (#3395), so it cannot serve as the
  stable handle"* and *"fully fixing the peer side needs a rule-id-on-wire
  identity change and is left for future work."* It also documents and ACCEPTS
  the residual: a reorder AFTER a session was synced still mis-attributes that
  session on the peer.

- **#3063 cross-reference contract.** `RuntimePolicyIDs` /
  `RuntimePolicyIndex` (`policies.go:198-227,1201-1215`) document that the
  RT_FLOW/event `policy_id` MUST equal the `show security policies` **Index**
  column — *the same span-accumulated positional namespace, by design.* Both are
  computed by the one SSOT walker `walkPolicyRuleSlots`. This is a self-imposed
  xpf contract (Junos does not expose a stable numeric policy Index), but it is
  live and tested.

- **#2391 zone-count cap.** `MaxUsableZoneID = 255` /
  `validateZoneCountStrict` (`compiler_validate_strict.go:3313-3358`) exists
  *because* the event-stream wire carries the zone id in a **u8** field. A stable
  scheme for zones that widens that field supersedes this cap.

- **Verified wire-width inventory (this research).** Zone id is **u16
  everywhere** — Rust `SessionMetadata.{ingress,egress}_zone`
  (`session/entry.rs:25-26`), BPF conntrack value
  (`bpf_map/mod.rs:153-154,200-201`), Go `SessionValue`
  (`types.go:30-31`), `SessionDeltaInfo`/`SessionSyncRequest`
  (`protocol.go:2608-2609,2679-2680`), and the **cross-node HA wire**
  (`sync_protocol.go:116/118/211/213/356/358/470/472`, `PutUint16`) — **EXCEPT**
  two same-host same-version IPC chokepoints that narrow to **u8**:
  `event_stream/codec.rs:338-360,467-473` (`[27]/[28]`, with a
  `debug_assert!(< 256)`) read by `eventstream.go:932-933,1056-1059`, and the
  forwarding-snapshot builder `forwarding_build/zones.rs:40` (`id > u8::MAX`
  skip). Reserved sentinels: `JUNOS_GLOBAL_ZONE_ID = u16::MAX`,
  `ZONE_ID_RESERVED_MIN = u16::MAX-1` (`policy.rs:608-609`).
  Policy id is **u32 on every surface** — BPF conntrack
  (`bpf_map/mod.rs:152,199`), RT_FLOW create `[44:48]` / close `[136:140]`
  (`codec.rs:774,685`), HA delta (`protocol/security.rs:374-375` +
  `sync_protocol.go:114/209/354/468`, `PutUint32`), Rust
  `SessionMetadata.policy_id` (`session/entry.rs:58`). **Policy id has no width
  problem; its blocker is purely the #3063 semantic contract.**

  Crucially, the cross-node HA session path is **name-keyed, not number-keyed**:
  the send side reverse-maps the local numeric id to a name
  (`zoneNameByID`) and the receive side re-resolves the name to the *local*
  numeric id (`daemon_ha_userspace.go:207-211 zoneIDs[delta.IngressZone]`). So
  the HA wire is already stable-by-name for NEW deltas; the bug enters the HA
  path only because the send-side reverse lookup of a *stale local numeric id*
  returns the wrong name. Making the local numeric id stable fixes the HA path
  too, for free.

## 5. Concrete design — the converged recommendation

### 5.0 Decision: TWO schemes sharing ONE pattern — NOT a unified allocator

The #3395 prior verdict's headline ("resolve both under one commit-time
persistent stable-id allocator") is **rejected**, on three source-verified
grounds:

1. **Zones and policies have different binding constraints.** The zone bug is
   driven by wire **WIDTH**: the u8 event-stream field forces ids to be packed
   into `[1,255]`, and the only way to pack stably into 255 slots is a positional
   sort (which renumbers) or a synced allocator (state). The policy bug is driven
   by a **SEMANTIC CONTRACT**: `policy_id` is already a u32 with ample room for a
   content-stable value, but #3063 pins it to the live positional **Index** and
   the `MaxRulesPerPolicy` span-contiguity model. These are different problems;
   one mechanism cannot be optimal for both.

2. **A unified persistent allocator saddles zones with state they provably do
   not need.** #1873 already demonstrated that a pure name-hash (zero synced,
   zero persisted, zero rollback/cold-boot state) is the correct fix for this
   exact class — *for an id that is free to be any value in a wide space.* Once
   the zone wire is widened to u16, zone ids ARE free to be any value, so the
   name-hash applies verbatim. Forcing zones through an allocator to "unify" with
   policies reintroduces precisely the authoritative-name→id state (synced,
   persisted, rollback-aware, cold-boot-rebuilt-or-diverge) that #1873
   deliberately rejected — and that, if it diverges between nodes, IS the very
   session-mis-mapping bug, now durable and sneakier.

3. **A unified allocator still does not let `policy_id` itself become the stable
   wire number without breaking #3063.** Even with an allocator, making the
   `policy_id` scalar content-stable either (a) breaks the Index↔RT_FLOW
   equality, or (b) forces the *entire* Index namespace (operator-facing column,
   policy-deny cross-ref, the SSOT walker, the span/spill guard) to adopt the
   allocator id — a large blast radius that turns the operator's sequential row
   number into an opaque allocator value and discards the `MaxRulesPerPolicy`
   span semantics that much code assumes. The allocator buys nothing here that
   the proportionate local fix (§5.2) does not.

**What IS unified is the PATTERN, not the allocator:** stable-name-derived
identity + commit-time collision gate + positional namespace retained as the
old-peer/fallback. A small shared helper (§5.3) can DRY the hash+gate mechanism
across `tunnelid.go`, the new zone id, and (if P2 is ever taken) a policy
rule-uid — without unifying the id *namespaces* or their wire treatments.

### 5.1 Zone IDs (#3075) — Option C: stable name-hash + u16 widen (PLAN-READY)

Adopt the #1873 pattern, now viable because the only u8 chokepoints are
same-host same-version IPC and can be widened with no cross-version interop.

1. **New SSOT** in `pkg/config` (mirror `tunnelid.go`):
   ```go
   // StableZoneID maps a zone name to a stable nonzero u16 in
   // [1, ZONE_ID_RESERVED_MIN-1]. Pure function of the name — never of
   // the zone set or allocation history — so adding/removing a zone can
   // never renumber another, and both HA nodes agree by construction.
   func StableZoneID(name string) uint16 {
       h := fnv.New64a(); _, _ = h.Write([]byte(name)); s := h.Sum64()
       folded := uint16(s) ^ uint16(s>>16) ^ uint16(s>>32) ^ uint16(s>>48)
       // fold into [1, ZONE_ID_RESERVED_MIN-1] (avoid 0 and the
       // u16::MAX / u16::MAX-1 reserved sentinels)
       return folded % (ZoneIDReservedMin - 1) + 1
   }
   ```
   `ZoneIDReservedMin` is the Go mirror of Rust `ZONE_ID_RESERVED_MIN`
   (`u16::MAX-1 = 65534`); usable range `[1, 65533]`.

2. **Collapse the three duplicated positional mappings onto it:**
   - `compiler.go:183-194` — replace the sorted `1..N` loop with
     `result.ZoneIDs[name] = StableZoneID(name)`.
   - `daemon_ha_userspace.go:24 buildZoneIDs` — same (it must stay
     byte-identical to the compiler mapping; an HA-symmetry test enforces this).
   - `manager_ha.go:zoneNameByID` is unchanged (it reverse-maps the *current*
     `ZoneIDs`); it simply never mis-resolves a surviving session now, because
     the id never moved.

3. **Commit-time collision gate** `validateZoneIDCollisionAST` mirroring
   `validateTunnelEndpointIDCollisionAST`: strict reject on commit/commit-check,
   lenient warning on load/peer-sync; message "rename one zone (#3075)". Must use
   the same node0/node1 expansion-view discipline if zones can be group-scoped
   (`groups node0 ... security zones ...`) so the accept/reject verdict is
   identical on both HA nodes (a collision in a `${node}`-scoped zone must fail
   commit on both, or config-sync splits). Fail-closed dataplane belt: the
   forwarding builder already rejects ids `>= ZONE_ID_RESERVED_MIN`; the gate's
   strict-reject is the primary guard.

4. **Widen the two u8 chokepoints to u16** (same-host same-version IPC; see
   §6/§7 for why this needs no cross-version handling):
   - `event_stream/codec.rs:338-360,467-473` — write `[27]/[28]` (open) and the
     close-delta zone bytes as **u16 LE** (+1 byte each); drop the
     `debug_assert!(< 256)`. Bump the event-stream record version.
   - `eventstream.go:932-933,1056-1059` — read u16 LE at the widened offsets;
     extend the existing trailing-length tolerance (`eventstream.go:1022` already
     accepts both length variants).
   - `forwarding_build/zones.rs:40` — drop the `id > u8::MAX` skip; keep only the
     `>= ZONE_ID_RESERVED_MIN` reserved-range reject.

5. **Retire #2391:** raise/rename `MaxUsableZoneID` to `ZoneIDReservedMin-1`
   (65533); keep `validateZoneCountStrict` as the reserved-range guard; update
   `pkg/config/zone_count_cap_test.go`, `userspace-dp/src/FEATURES.md`, and the
   zone-id contract note. Cross-link/close #2391.

Result: the zone id is a pure function of the name; the local numeric id never
moves on a config edit, so display, logs, and the name-keyed HA path are all
correct by construction with **zero synced/persisted state**.

### 5.2 Policy IDs (#3395) — P1: bound-local re-resolution (the #3322 analog), NO wire change (PLAN-READY); P2 (rule-id-on-wire) DEFERRED

`policy_id` cannot become content-stable cheaply (§5.0 ground 3). The
proportionate fix is the exact analog of #3322's already-merged approach: bind a
stable identity locally and re-resolve the **current** positional id at the
local publish surfaces — preserving the #3063 contract and the span model, with
no wire change.

1. **Carry a stable rule identity on the session, locally only.** Either reuse
   #3322's bound `Arc<PolicyRuleCounter>` (already keyed by the stable
   `rule_id`) or add `SessionMetadata.stable_rule_id` (a cheap handle into the
   `PolicyCounterStore`'s `rule_id` registry). Local derived state, NOT
   serialized — identical discipline to `policy_counter` (which #3322 already
   excludes from `SessionMetadata` `PartialEq`/serde).

2. **Re-resolve the current `policy_id` at the LOCAL publish surfaces:**
   - **Live session rows.** Instead of stamping the frozen `metadata.policy_id`
     into the BPF conntrack value at install, re-resolve it from the bound stable
     rule id against the current `PolicyState` at the ~1s
     `refresh_bpf_conntrack_last_seen` hook (`bpf_map/mod.rs:344-355`), stamping
     the current positional id. Go then resolves the correct name AND the #3063
     Index with **no Go change**. `PolicyState` gains
     `current_policy_id_for_rule_id(&rule_id) -> Option<u32>` (derived from the
     current snapshot's `walkPolicyRuleSlots` equivalent).
   - **RT_FLOW SESSION_CLOSE.** Re-resolve at close time. This is the one new
     plumbing item: #3322 notes the close-delta path does NOT currently hold
     `PolicyState`. The plan threads a read-only `PolicyState` reference (or a
     pre-resolved current id) into the close-emit path so the close log carries
     the current positional id. (SESSION_CREATE is emitted at install when the
     positional id is already correct — no change needed there.)

3. **Keep `policy_id` positional for the Index / #3063.** The Index column,
   `RuntimePolicyIDs`, the SSOT walker, and the `MaxRulesPerPolicy` span/spill
   guard are untouched. A freshly-evaluated flow still logs the current Index;
   an established flow now ALSO logs the current Index of its true admitting
   rule (re-resolved), so the #3063 equality holds for both.

4. **DEFER P2 (rule-id-on-wire) explicitly** (§10). The remaining residual after
   P1 is identical to the one #3322 already documented and accepted: a session
   SYNCED to the HA peer, followed by a reorder, still shows a stale id **on the
   peer** (the peer froze the scalar it received and holds no local bound
   handle). Fixing that requires carrying a stable rule-uid on all three wire
   surfaces (conntrack v4+v6, RT_FLOW create+close, HA delta+SyncRequest) plus a
   wire version bump — three two-sided changes for a Medium forensic edge whose
   severe sibling is already fixed. **Recommend NOT shipping P2 this cycle.**

If reviewers judge even P1's close-path plumbing too much for the forensic win,
the fallback is **P0: P1's live-session-row half only** (re-resolve on the ~1s
refresh, leave the close log as-is) — the smallest possible improvement, fixing
the most-viewed surface (`show security flow session`) with no close-path change.

### 5.3 Shared mechanism (optional DRY, not a unified namespace)

Extract `pkg/config/stableid.go`: `foldFNV(name) uint16/u32` + a generic
`detectFoldCollisions(names, fold, lenient) ([]warnings, error)` helper that
`tunnelid.go`, the new zone gate, and (if P2 is ever taken) a policy rule-uid
gate all call. This unifies the *mechanism* without unifying the id namespaces,
wire widths, or persistence model. Strictly optional; can be a follow-up.

## 6. Public API preservation

- **Go signatures preserved:** `CompileConfig*`, `Manager.zoneNameByID`,
  `buildZoneIDs`, `RuntimePolicyIDs`, `RuntimePolicyIndex`,
  `StablePolicyRuleID`, `ReadPolicyCounters` (callers keep passing the raw
  ordinal handle), `validateZoneCountStrict`. `CompileResult.ZoneIDs` stays
  `map[string]uint16` (values change from `1..N` to hashed; type unchanged).
- **Wire structs:** `SessionValue.{Ingress,Egress}Zone` stays `uint16`;
  `SessionDeltaInfo`/`SessionSyncRequest` zone fields unchanged (already u16 +
  name). `policy_id` stays `u32` on every surface (P1 changes the VALUE stamped,
  not the type or layout). The only struct-layout change is the **u8→u16 widen
  of the event-stream zone field**, gated by the event-stream record version.
- **Rust:** `SessionMetadata.{ingress,egress}_zone` already u16 (no change);
  `SessionMetadata.policy_id` already u32 (no change); P1 adds at most one local
  `stable_rule_id` field excluded from serde/`PartialEq` (same pattern as
  `policy_counter`).

## 7. Hidden invariants the change must preserve

- **HA symmetry by construction.** `StableZoneID` must be a pure function of the
  name so `buildZoneIDs(cfg)` (daemon) `==` compiler `ZoneIDs` for the same cfg
  on both node0 and node1 expansions. The collision gate's verdict must be
  identical on both nodes (node0/node1 expansion-view discipline, mirror #1873
  Views 2/3).
- **Reserved-id avoidance.** The fold must never produce `0`,
  `ZONE_ID_RESERVED_MIN`, or `JUNOS_GLOBAL_ZONE_ID` (`u16::MAX`). Range
  `[1, ZONE_ID_RESERVED_MIN-1]`.
- **Fail-closed belts retained.** Forwarding builder still rejects reserved-range
  zone ids and unknown-zone interfaces (`SnapshotIntegrityError`); the policy
  span/spill `MaxRulesPerPolicy` guard is untouched.
- **#3063 equality.** P1 must keep `policy_id` logged == current Index for BOTH
  freshly-evaluated and re-resolved-established flows.
- **#3322 non-regression.** The hit-counter bound `Arc` path and its
  `resolve_session_hit_counter` fallback must be unaffected; if P1 reuses the
  same bound handle, the counter resolution must not change.
- **Event-stream framing.** The widened zone field must bump the record version
  and keep `eventstream.go`'s dual-length tolerance working; a drain after
  restart re-syncs (no in-flight mixed-width frames across a daemon/helper
  replace).
- **Stale-handle hazard.** P1's bound `stable_rule_id` must resolve to `None`
  (fall back to the frozen positional id, today's behavior) when the rule was
  deleted — never to a wrong rule.
- **Cold-boot / rollback / ISSU.** Because both schemes are pure functions of
  the config (no persisted id state), a cold-booting node, a `rollback`, and a
  mixed-version ISSU peer all recompute identical ids — the property a persistent
  allocator would have to engineer and could get wrong.

## 8. Risk assessment

| Class | Zone (Option C) | Policy (P1) |
|---|---|---|
| **Behavioral regression** | LOW — pure-function id; the only behavior change is which u16 a name maps to; fail-closed belts retained. Existing sessions across the cutover: see §migration. | LOW-MED — re-resolution changes the VALUE published for established sessions; must prove fresh flows are byte-identical and deleted-rule sessions fall back safely. |
| **HA mixed-version** | LOW — cross-node wire already u16 and **name-keyed**; the widened field is same-host IPC only. A mixed-version cluster (old peer hashing differently? no — both compute the same hash from the same config) agrees by construction. The only mixed-version concern is the event-stream record version within ONE host across a daemon/helper replace — atomic per #1917, drained on restart. | LOW — P1 is local-only, no wire change, so a mixed-version peer is unaffected (it keeps its pre-existing positional behavior). The HA-peer-after-reorder residual is pre-existing (#3322) and explicitly out of scope (P2). |
| **Wire compatibility** | MED — event-stream zone field grows u8→u16 (record-version bump) + forwarding-snapshot accepts u16. Both same-host same-version (the #1917 STOP→FLIP→START .deb cut replaces daemon+helper atomically; the event stream is drained fresh). No cross-version interop to manage. zones.rs/codec.rs/eventstream.go must land in lock-step. | NONE — P1 changes no wire layout or width. (P2, deferred, would be HIGH: three two-sided growths + version bump.) |
| **Performance** | LOW — one FNV hash per zone per compile (compile-time, not per-packet); no hot-path change. | LOW-MED — re-resolution adds a `rule_id → current policy_id` lookup at the ~1s refresh and at close-emit. Must NOT add per-packet cost; the established fast path keeps reading the (now re-resolved-at-refresh) stamped value. Bound the lookup; verify no control-socket/throughput regression. |
| **Architectural mismatch** | LOW — verbatim reuse of the reviewed #1873 pattern; supersedes #2391. | MED — P1 reuses the reviewed #3322 pattern, but the close-path `PolicyState` plumbing is genuinely new (#3322 flagged its absence). Risk that close-path re-resolution is more invasive than estimated → fallback P0 (live-rows only) bounds it. |

**PLAN-KILL is an acceptable verdict if reviewers conclude the
forensic-correctness win does not justify the churn — most plausibly for the
policy half (P1's close-path plumbing) and/or the deferred P2.** The zone half
(Option C) is the higher-value, lower-risk change and could ship alone.

## 9. Test plan (RED-on-revert)

**Zone (#3075):**
- *Stability (pure function):* `StableZoneID("untrust")` is identical whether or
  not `"alpha"` exists in the config. RED if reverted to the sorted `1..N` loop.
- *The issue's exact scenario:* compile zones `[trust,untrust]`, capture
  `id(untrust)`; build `SessionValue{IngressZone:id(untrust)}`; add zone `alpha`
  (sorts first) and recompile; assert `id(untrust)` is UNCHANGED so
  `zoneNameByID(stored_id)` still returns `"untrust"` — the session can never be
  logged/synced under the wrong zone. RED on revert.
- *Collision gate:* a config whose two zone names fold to the same id is
  hard-rejected on commit, warned on lenient load (mirror
  `tunnelid_test.go`). Include a node0/node1-scoped collision case.
- *HA symmetry:* `buildZoneIDs(cfg) == compiler.ZoneIDs` for the same cfg on
  both node0 and node1 expansions.
- *Wire widen:* Rust codec round-trips a zone id in `256..=1000`; `zones.rs`
  accepts a u16 zone id `> 255` and still rejects `>= ZONE_ID_RESERVED_MIN`;
  `eventstream.go` parses the widened field. Run `go test ./pkg/config/...
  ./pkg/dataplane/...`, `go test ./pkg/logging/` (event/screen contract), and
  the userspace-dp Rust suite.
- *#2391:* update `zone_count_cap_test.go` for the raised cap.

**Policy (#3395, P1):**
- *Re-resolution survives reorder:* admit a session under rule B; insert rule A
  above B (live, same `PolicyState`); assert the session's published
  `policy_id` now equals B's NEW current Index (not the frozen old one) on both
  the live-row refresh and the close log. Reverting to the frozen stamp reads
  the stale id → RED.
- *Fresh-flow identity unchanged:* a flow created AFTER the reorder logs the
  current Index byte-identically to today (no #3063 drift).
- *Deleted-rule fallback:* delete the admitting rule; assert the session falls
  back to the frozen positional id (today's behavior), never a wrong rule.
- *#3322 non-regression:* the bound hit-counter test still passes.
- *HA residual is unchanged:* document (not "fix") that a synced session on the
  peer still shows the pre-existing residual — assert P1 introduced no new HA
  wire field.

**Cluster (mandatory for both):** `make test-failover` on the loss userspace
cluster — both halves touch session-sync metadata resolution. Smoke v4+v6.

## 10. Out of scope (explicitly deferred)

- **P2 — rule-id-on-wire for `policy_id`.** Carrying a stable rule-uid on all
  three wire surfaces (conntrack v4+v6, RT_FLOW create+close, HA delta +
  SyncRequest) + wire version bump, to fix the HA-peer-after-reorder display.
  Deferred as disproportionate churn for a Medium forensic edge; this is exactly
  the "future work" #3322 named. Reconsider only if operators report concrete
  pain.
- **Making `policy_id` / the Index column content-stable** (allocator or hash for
  the Index namespace). Rejected (§5.0); would break #3063 and the span model.
- **A persistent/synced stable-id allocator for either id** (the #3395 verdict's
  headline). Rejected (§5.0).
- **Renaming a zone with live sessions** is a delete+add at config level → new
  name → new id; orphaned sessions in the renamed-away zone should be flushed by
  the existing zone-delete path, independent of this renumber fix. Note in the
  engineer step; not a renumber concern.
- **Zone-id flush-on-remap (#3075 Option B / D)** as the primary fix. Retained
  only as a documented no-wire fallback if reviewers veto the widen, at the cost
  of session churn on any ordering-perturbing zone edit.

## 11. Migration: in-flight sessions / persisted state across the cutover

- **No persisted id state exists** for either id (both are recomputed from config
  every compile), so there is nothing to migrate at rest. `active.json` /
  configstore hold config, not ids.
- **Zone cutover (one host).** On the deploy that flips to `StableZoneID`,
  sessions established under the OLD `1..N` ids have stale numeric
  `IngressZone`/`EgressZone` in the live conntrack — under the NEW map those
  numbers resolve to the wrong name (or to nothing). This is a one-time
  transient, bounded by session lifetime, and is exactly the symptom being
  fixed for all FUTURE edits. Options to handle the one-time cutover: (a) accept
  the transient (sessions age out; no security impact); (b) flush sessions once
  on the version-bump apply if the previous applied `ZoneIDs` used the legacy
  scheme (detect via a scheme marker on `LastApplyResult`). Recommend (a) unless
  reviewers want (b); a `make test-deploy` already restarts the helper and the
  event stream drains fresh. The #1917 atomic cut means daemon+helper share the
  new scheme immediately.
- **HA cutover.** Because the cross-node session path is name-keyed, a
  rolling-upgraded cluster where one node is on the new scheme and one on the old
  still syncs correctly (names cross the wire; each side resolves to its own
  local id). The transient is per-node and self-heals; no split.
- **Policy P1 cutover.** No wire/layout change → no migration; established
  sessions simply begin re-resolving correctly at the next refresh after the
  helper carries the bound handle. Sessions synced before the upgrade lack the
  bound handle and fall back to the frozen id (today's behavior) until they age
  out.

---

## Appendix: source citations (verified against `49765c603`)

- Zone positional SSOT: `pkg/dataplane/compiler.go:183-194` (sorted `1..N`),
  duplicated `pkg/daemon/daemon_ha_userspace.go:24-30 buildZoneIDs`, reverse
  `pkg/dataplane/userspace/manager_ha.go:1157-1169 zoneNameByID`, receive
  `daemon_ha_userspace.go:207-211 zoneIDs[delta.IngressZone]`.
- Zone wire widths: u16 — `session/entry.rs:25-26`, `bpf_map/mod.rs:153-154,
  200-201`, `types.go:30-31`, `protocol.go:2608-2609,2679-2680`,
  `sync_protocol.go:116/118/211/213/356/358/470/472`; u8 chokepoints —
  `event_stream/codec.rs:338-360,467-473`, `eventstream.go:932-933,1056-1059`,
  `forwarding_build/zones.rs:27,40`. Sentinels `policy.rs:608-609`.
- #2391 cap: `compiler_validate_strict.go:3313-3358`.
- Policy positional SSOT: `policies.go:194-196` (`policyID`),
  `policies.go:243-302 walkPolicyRuleSlots`, `compiler.go:806,852,941,982`
  (`RuleID`/`PolicyNames`), `dataplane/types.go:418 MaxRulesPerPolicy=256`,
  `:438 DefaultPolicySentinelID=0xFFFFFFFF`.
- #3063 contract: `policies.go:198-227 RuntimePolicyIDs`,
  `:1201-1215 RuntimePolicyIndex`, `:1190-1199 StablePolicyRuleID`.
- Policy wire widths (u32): `poll_descriptor/mod.rs:2190,2438`,
  `bpf_map/publish_conntrack.rs:168,273`, `bpf_map/mod.rs:152,199`,
  `codec.rs:774 (create [44:48]),685 (close [136:140])`,
  `ringbuf.go:242,609 resolvePolicyName`, `protocol/security.rs:374-375`,
  `sync_protocol.go:114/209/354/468`, `session/entry.rs:58`.
- #3322 precedent: commit `ef72285df` (bound `Arc` handle; "rule-id-on-wire …
  left for future work").
- #1873 precedent: `pkg/config/tunnelid.go` (`StableTunnelEndpointID`,
  `validateTunnelEndpointIDCollisionAST`), `pkg/config/tunnelid_test.go`.
