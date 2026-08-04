# #6746 — zero-RG → first-RG clustered live apply: LocalDelivery fail-open window (falsification + residual hardening)

**Status: DRAFT v2 — round 1 complete (AGY PLAN-READY 1 MINOR + 1 NIT;
SMR DEMAND-REVISION 1 MAJOR + 3 MINOR + 1 NIT; Codex infra-blocked,
usage-capped until Aug 10, two documented retries); v2 folds all r1
findings; under round-2 review**

- Issue: #6746 (opus-review-001 root R02, severity Medium, confidence High)
- Research base: `ad9591177` (origin/master at worktree creation)
- Research branch: `research/6746-zero-rg-window` (plan docs only — no
  production code in this branch)
- v1 @ `cc6860d5d` (r1: AGY PLAN-READY; SMR DEMAND-REVISION — folds below);
  v2 folds SMR MAJOR-1 (owner_rg>0 premise evidenced), MINOR-1 (deferred
  path traced), MINOR-2 (empty-sender audit), MINOR-3 (operator-arm
  interleaving), NIT-1/AGY-MINOR (M2 pin + no-empty-update assertion in
  §9)

## 1. Status

v1 DRAFT. This plan's primary content is a **falsification of the issue's
framed window** with three independent, test-backed closing mechanisms found
during the code walk, plus a residual latent-hazard analysis and three path
options (kill / harden / both). Awaiting round-1 hostile review from Codex,
AGY, and Claude SMR — the reviewers' job is to break the falsification, not
to confirm it.

## 2. Issue framing

The issue (opus-review-001 R02, narrowed) claims:

> A zero-RG (standalone-inventory) cluster node that receives its FIRST
> redundancy-group config via a live commit can expose `LocalDelivery`
> before the HA inventory publication lands. The helper is "already armed"
> and "its HA map remains empty because `syncHAStateLocked` sends nothing
> for an empty inventory"; the day-2 commit publishes the new forwarding
> snapshot and applies helper status *before* the HA inventory publication,
> so during that interval an RG-owned interface-NAT `LocalDelivery` hits the
> explicit `ha_state.is_empty()` permit in
> `userspace-dp/src/afxdp/forwarding/ha.rs` and bypasses owner-RG
> enforcement on the inactive node.

Cited mechanism chain:

1. Zero-RG cluster: `syncHAStateLocked` early-returns on
   `len(m.haGroups) == 0` (`manager_ha.go:37`) → helper `ha_state` stays
   empty.
2. Topology preflight (`cluster_topology_preflight.go:84`) rejects only
   standalone↔cluster flips; a zero-RG → first-RG edit within cluster mode
   passes.
3. `manager_compile.go:369` applies helper status before `:383-388`
   refreshes/publishes HA state; daemon step 2
   (`daemon_apply_dataplane.go:137`) applies the dataplane before step 19
   (`daemon_apply_tail.go:221`) updates the cluster state machine.
4. Rust: `enforce_ha_resolution_snapshot` returns early (permits) on
   `LocalDelivery && ha_state.is_empty()` (`forwarding/ha.rs:80`).
5. `rgTransitionInFlight` (`maps_sync.go:391`) fences only explicit
   activation callbacks, not config-apply ordering.

Proposed fix direction in the issue: represent HA as
`Standalone | ClusterUninitialized | Ready(map)`, fail closed in the middle
state, fence `userspace_ctrl` whenever an accepted snapshot changes HA
ownership inventory, publish+ack matching HA state before re-enable, and
add a zero-RG → first-RG live-apply regression.

## 3. Falsification of the framed window (the core finding)

The framed window requires TWO conjuncts to hold simultaneously on the
zero-RG node at the moment the first-RG snapshot is published:

- **(C1) the helper is armed and processing packets** (ctrl=1, workers
  receiving), and
- **(C2) the helper's `ha_state` map is empty** (so the
  `forwarding/ha.rs:80` `is_empty()` LocalDelivery permit fires).

Independent code walk at `ad9591177` shows **both conjuncts fail** on a
zero-RG cluster node, for three independent reasons. Each is individually
sufficient to close the window.

### 3.1 Closing mechanism 1 — the #1928 phantom-group fabrication keeps the helper `ha_state` non-empty on every clustered node (kills C2)

- `rg_active` is a fixed-size BPF **ARRAY** (`arrayMapSpec("rg_active",
  sizeOf[uint8](), MaxRedundancyGroups=16)`,
  `pkg/dataplane/loader_userspace_shim.go:670`,
  `pkg/dataplane/types.go:1005`). BPF arrays are always fully populated:
  iteration yields all 16 slots, zero-valued when unwritten.
- `refreshHAStateFromMapsLocked` (`manager_ha.go:257`) calls
  `mergeHAStateFromMaps` (`manager_ha.go:325`), which inserts **every**
  array slot into the merged map. On a clustered node with zero configured
  RGs this fabricates 16 *inactive* phantom groups. This is the exact
  behavior pinned by
  `TestMergeHAStateFromMapsFabricatesGroupsFromArrayMap`
  (`manager_ha_test.go:544`, passes at this SHA — run during this
  research), whose doc comment states the array "is ALWAYS fully populated
  with keys 0-15 regardless of whether any redundancy group is configured".
- That refresh runs on **every clustered apply**
  (`manager_compile.go:383-384`, under the `if m.clusterHA` guard that
  #1928 added — commit `e5e751448`, long before the audited SHA) and on
  **every 1s status poll** (`process_status.go:211-212`).
- Therefore `m.haGroups` on a clustered node is **never empty after the
  first apply/poll**, and the `len(m.haGroups) == 0` early-return in
  `syncHAStateLocked` (`manager_ha.go:37`) — the issue's "sends nothing
  when the inventory is empty" anchor — is **unreachable on clustered
  nodes**. The boot apply publishes `{0..15, all inactive}` to the helper
  via `update_ha_state`; the Rust handler (`afxdp/ha/state.rs:4`) inserts
  every supplied group (active or not) into the worker-visible map, so the
  helper's `ha_state` is **non-empty from the first boot apply onward**.
- Consequence: on the first-RG commit, during the interval between
  `apply_snapshot` and `update_ha_state`, the helper holds
  `{0..15 inactive}` (RG1 present as a phantom **inactive** entry). An
  RG1-owned interface-NAT `LocalDelivery` resolution takes
  `owner_rg_id = 1` → `ha_state.get(&1)` → entry exists →
  `is_forwarding_active(now_secs)` false → `HAInactive` → **drop**.
  Fail-closed, precisely because the phantom entry occupies the key.
- **The `owner_rg = 1` premise, evidenced (SMR r1 MAJOR-1 fold).** The
  phantom-entry argument depends on the framed "RG-owned interface-NAT
  local address" resolving with `owner_rg > 0`. The chain has three links,
  each verified at base: (i) `interface_nat_local_resolution`
  (`forwarding/nat.rs:137-160`) resolves the destination address to the
  OWNING interface's ifindex — the map is populated per-interface at
  `forwarding_build/interfaces.rs:157` (`state.interface_nat_v4.insert(
  v4.addr(), iface.ifindex)`) for addresses in the NAT-exclusion set;
  (ii) `owner_rg_for_resolution` → `owner_rg_for_flow` reads the egress
  row for that ifindex; (iii) the egress row's `redundancy_group` is
  populated from the snapshot interface at
  `forwarding_build/interfaces.rs:334` (`redundancy_group:
  iface.redundancy_group`) — for a reth in RG1 that value is 1. (The
  `ha.rs:83-85` comment about a historical "RETH RG propagation fix" is
  why §9 adds a Rust test arm asserting `owner_rg == 1` for an RG1 reth
  interface-NAT resolution, guarding future propagation regressions.)
- **Design-permit boundary (stated for blast-radius honesty).** For
  `LocalDelivery` with `owner_rg_id <= 0`, the gate returns the resolution
  UNCHANGED (`forwarding/ha.rs:86-94`) even when `ha_state` is non-empty:
  node-local addresses on non-RG interfaces (management, loopback, plain
  interfaces) are deliberately not owner-gated — there is no RG to own
  them. This permit is out of the issue's frame (its trace is explicitly
  an "RG-owned interface-NAT local address"), but it bounds what
  "RG-owned" means: only addresses whose owning interface carries
  `redundancy_group > 0` in the egress row are owner-gated at all.
- **Empty-sender audit (SMR r1 MINOR-2 fold).** C2 additionally rests on
  "no path publishes an EMPTY HA set while clustered". The only empty
  `update_ha_state` sender is `clearHelperHAStateLocked`, and every call
  site is `!m.clusterHA`-gated: the non-cluster else-branch at
  `manager_compile.go:391`, the `pendingXSKStartup` `!m.clusterHA` branch
  at `manager_compile.go:296`, and `retryPendingHAStateClearLocked`
  (`manager_ha.go:145`: `if !m.pendingHAStateClear || m.clusterHA {
  return }`). No empty publish is reachable on a clustered node; the
  helper-side rebuild (`afxdp/ha/state.rs:4`) inserts every supplied group
  unconditionally, and nothing else mutates `rg_runtime`
  (`apply_snapshot` never touches it — constructed once at
  `coordinator/ha_state.rs:39`, stored only from `ha/state.rs`).

### 3.2 Closing mechanism 2 — a zero-RG cluster node's desired forwarding state is DISARMED (kills C1)

- `desiredForwardingArmedLocked` (`manager_ha.go:363`): standalone → true;
  clustered with a configured data RG in the last applied snapshot
  (`configHasDataRGLocked`, `manager_ha.go:523`) → true; clustered with an
  Active group in `m.haGroups` → true; **otherwise false**.
- A zero-RG cluster node (no `redundancy-group` stanza at all, per the
  issue's own validation reference `TestChassisRedundancyGroupInRangeCommits`)
  has no data RG in config and no active group: the cluster manager creates
  groups only from `cfg.RedundancyGroups` (`pkg/cluster/group_state.go:13-36`;
  there is no implicit RG0 creation anywhere in `pkg/cluster`), so no
  cluster events fire and `UpdateRGActive` is never called. Phantom groups
  are all `Active=false`.
- Therefore `desired == false`, the helper boots and stays **disarmed**
  (`forwarding_armed=false`), `status.Enabled` computes false
  (`server/helpers/status.rs` enabled expression), and
  `applyHelperStatusLocked` keeps `ctrl.Enabled = 0`
  (`maps_sync.go:391-486`). With ctrl=0 the shim passes only proven
  local/control traffic to the kernel and drops transit; **the userspace
  workers see no packets at all**, so no `LocalDelivery` resolution can
  occur in the helper regardless of map contents.
  `TestDesiredForwardingArmedRequiresDataRGOrActiveLocalOnlyGroup`
  (`manager_ha_test.go:786`, passes at this SHA) pins exactly this:
  "no data RG and no active local-only RG → desired false".
- The issue's premise "the helper is already armed" does not hold for the
  framed zero-RG starting state.

### 3.3 Closing mechanism 3 — on the first-RG commit itself, the HA publication lands and is ACKed strictly BEFORE the arm

- The first-RG apply's arm transition happens inside
  `syncHAStateLocked` (`manager_ha.go:26-67`): it sends
  `update_ha_state` (publishing the seeded `{0,1}` inventory overlaid on
  the re-fabricated phantoms — all inactive, including RG1), applies the
  returned status, and **only then** calls
  `syncDesiredForwardingStateLocked` (`manager_ha.go:66`), which is where
  `desired` first becomes true (`configHasDataRGLocked` flips true against
  the new `m.lastSnapshot`, set at `manager_compile.go:354` before the HA
  block) and `set_forwarding_state{Armed: true}` is sent.
- All of this runs under `m.mu` in one apply; the ctrl=1 gate additionally
  requires a later status poll with readiness checks plus the 15s
  cluster-HA delay (`maps_sync.go:420-424`).
- So even if C1/C2 somehow held before the commit, the apply itself never
  creates an armed-and-unpublished instant: the sequence observed by the
  helper is `apply_snapshot` (still disarmed, ctrl=0) → `update_ha_state`
  (RG1 inactive) → `set_forwarding_state{Armed:true}` → (polls) ctrl=1.
- The daemon-side ordering the issue cites (step 2 dataplane apply at
  `daemon_apply_dataplane.go:137` before step 19 `cluster.UpdateConfig` at
  `daemon_apply_tail.go:221`) is **load-bearing but harmless**: the
  dataplane-side publication is self-contained and publishes RG1 as
  *inactive* (fail-closed) until cluster events later drive
  `UpdateRGActive(1, true)` through `watchClusterEvents`
  (`daemon_ha.go:248+`). Moving step 19 earlier would change nothing
  packet-visible.

### 3.4 Adjacent paths checked and also closed

- **Deferred first-RG commit during XSK startup (SMR r1 MINOR-1 fold).**
  If the first-RG apply takes the `pendingXSKStartup` early return
  (`manager_compile.go:269-309` — second-or-later apply while XSK liveness
  is unproven), the HA block is skipped and the publish resumes later via
  the poll's `syncSnapshotLocked` (`process_status.go:10`), which sends no
  HA state at all. The window still does not open: the helper already
  holds `{0..15 inactive}` from the boot apply's full path (the first
  apply has `publishedSnapshot == 0`, so `pendingXSKStartup` is false and
  the boot apply always runs the HA block), nothing clears that map
  (§3.1's empty-sender audit), and the same poll re-fabricates phantoms
  (`process_status.go:211-212`) before its tail
  `syncDesiredForwardingStateLocked` (`process_status.go:243`) arms. The
  watchdog-sync skip (`newActiveSig == ""` when all groups are inactive)
  is irrelevant: no publish is needed because the map was never emptied.
- **Helper restart** (crash/unhealthy): `ensureProcessLocked`
  (`process.go:18`) only respawns inside the locked apply path, which
  republishes snapshot → HA → arm in the same order. The helper's
  packet-path `rg_runtime` starts empty at process construction and is
  repopulated by the apply's `update_ha_state` before any arm.
- **RG0-only cluster** (control group configured, no data RGs): the
  RG0-primary node IS armed (RG0 active), but its helper `ha_state` is
  `{0:active, 1..15 inactive phantoms}` — non-empty, and the first-data-RG
  commit resolves RG1 `LocalDelivery` to `HAInactive` via the phantom
  entry. The flow-cache path is covered too: `cached_flow_decision_valid`
  re-runs `enforce_ha_resolution_snapshot` and invalidates on any
  `HAInactive` transition. Fail-closed.
- **Standby with data RGs**: armed by design
  ("keep the helper armed on standby HA nodes", `manager_ha.go:376-381`),
  helper `ha_state` non-empty (phantoms + real RGs inactive), RG-owned
  `LocalDelivery` → `HAInactive`. Fail-closed.
- **Operator-arm interleaving (SMR r1 MINOR-3 fold).** `request chassis
  ... forwarding arm` (`cli_request_chassis.go:151-158`) and the gRPC
  diag action (`server_diag_system_action.go:395-415`) let an operator arm
  forwarding directly, defeating M2 by definition on a zero-RG node. The
  window still does not open: M1 leaves the helper `ha_state` non-empty
  (phantoms), and the ctrl gate independently withholds packet delivery —
  `ctrl.Enabled=1` requires `status.Enabled` plus binding/neighbor
  readiness plus the 15s `clusterHA` prewarm delay
  (`maps_sync.go:420-424`), so even an operator-armed helper sees no
  packets until long after the boot apply's phantom publish. Fail-closed.
- **cluster→standalone**: `clearHelperHAStateWithDebtEnsureRetryLocked`
  sends an *empty* `update_ha_state`, but only on the non-cluster branch
  where the exemption is the intended standalone posture, and the topology
  preflight rejects the live mode flip anyway.

### 3.5 What the opus verification actually established vs. assumed

The R02 verification (`/tmp/opus-review-001.md` §R02) ran two Go tests:
`TestClusterTopologyDay2TransitionRejected` (proves only cross-mode flips
are rejected) and `TestChassisRedundancyGroupInRangeCommits` (proves a
zero-RG cluster config is accepted). Those establish **config-path
reachability** — the commit is accepted. They do not establish the
packet-path preconditions C1/C2. The "already-armed helper" and "HA map
remains empty" assertions are not backed by a runtime trace or test in the
verification; both are contradicted by §3.1/§3.2 above, each of which is
pinned by an existing, passing unit test at the audited SHA.

## 4. Residual latent hazard (the honest remainder)

The falsification closes the *framed* window, but the walk surfaced a real
design wart that the issue's fix direction correctly identifies in
principle:

- The worker hot path distinguishes **standalone** from **clustered**
  solely by `ha_state.is_empty()` (`forwarding/ha.rs:80`). "Empty map" is
  doing double duty: "standalone node" (permit LocalDelivery, skip
  owner-RG enforcement) vs. "clustered node whose inventory publication
  hasn't landed" (should fail closed).
- Today the second state is unreachable *by accident*: the #1928
  phantom-group fabrication (an artifact of ARRAY iteration, retained to
  fix the standalone transit-drop bug) guarantees the clustered map is
  never empty. No comment, type, or test declares "clustered ⇒ non-empty
  `ha_state` while armed" as an **invariant**. A future cleanup of the
  phantom fabrication (it is already documented as a wart for standalone),
  or any new publish path that arms before publishing, silently re-opens
  the fail-open with no compile-time or test tripwire.
- This is a **latent semantic-collapse hazard**, not a live defect: no
  current path reaches armed+empty on a clustered node (§3).

## 5. Multiple Path Options

### Path A — PLAN-KILL the framed window; land the fail-closed regression pin (recommended)

- Close #6746 as **not reproducible** at `ad9591177` with the §3
  counter-evidence (three independent closing mechanisms, two pinned by
  existing tests).
- Land the one artifact the issue's fix direction asks for that has value
  independent of the (nonexistent) window: a **zero-RG → first-RG
  live-apply regression test** that pins the fail-closed posture —
  i.e., asserts (a) a clustered apply publishes a non-empty HA inventory
  before any arm, and (b) `enforce_ha_resolution_snapshot` with an
  RG-owned `LocalDelivery` and an inactive-phantom HA map yields
  `HAInactive`, plus (c) `desiredForwardingArmedLocked` is false for a
  zero-RG cluster config. Most of (b)/(c) exists
  (`TestMergeHAStateFromMapsFabricatesGroupsFromArrayMap`,
  `TestDesiredForwardingArmedRequiresDataRGOrActiveLocalOnlyGroup`); the
  new work is an ordering assertion (HA-publish-before-arm) and a Rust
  unit test for the phantom-inactive `LocalDelivery` → `HAInactive` arm.
- Optionally: a one-line comment at `forwarding/ha.rs:80` documenting that
  the `is_empty()` exemption's correctness depends on the Go-side
  never-empty-while-clustered invariant, so a future refactor sees the
  tripwire.
- Cost: test-only, zero packet-path or protocol risk. Effort: small.
- Benefit: converts accidental correctness into pinned correctness; closes
  the issue honestly without shipping a fence that adds dataplane flaps
  (the issue's "fence userspace control whenever an accepted snapshot
  changes HA ownership inventory" would disable `ctrl` on **every**
  routine RG-inventory-touching commit on live clusters — a real
  availability cost to close a window that does not exist).

### Path B — Re-scope to the latent hazard: tri-state HA readiness representation

- Implement the issue's fix direction as **defense-in-depth**, not as a
  window fix: represent HA readiness in the helper as
  `Standalone | ClusterUninitialized | Ready(map)`; the LocalDelivery
  exemption applies only in `Standalone`; `ClusterUninitialized` fails
  closed (HAInactive). The cluster/standalone bit must travel atomically
  with the forwarding state (snapshot field) or the HA update so a reader
  can never pair a cluster snapshot with a standalone bit across
  generations (the #6592 lesson).
- Go side: set the bit from `m.clusterHA` at snapshot build; helper side:
  store it beside `rg_runtime` in the coordinator HA state; worker side:
  extend `enforce_ha_resolution_snapshot`.
- Cost: touches the control protocol (snapshot schema → protocol-version
  bump), the coordinator, and the per-packet HA gate; requires care to
  keep the standalone `clearHelperHAStateLocked` semantics and the #1928
  phantom behavior consistent. Effort: medium.
- Benefit: kills the semantic collapse structurally; the invariant becomes
  a type, not an accident.
- Risk: any change to `enforce_ha_resolution_snapshot` is on the packet
  path for every HA flow; a botched tri-state transitions the *entire*
  clustered fleet's LocalDelivery posture. Given §3 shows no live defect,
  this is hardening spend against a hypothetical refactor.

### Path C — A + B sequenced

- Do Path A now (kill + pin), file Path B as a separate
  hardening issue (not a bug) so it can be scheduled against real
  refactors (e.g., any future removal of the phantom fabrication must be
  paired with the tri-state).

### Recommendation

**Path A**, with Path B filed as a follow-up hardening issue (i.e., Path C
in execution, but #6746 itself closes as falsified). The framed window
does not exist at the audited SHA; the three closing mechanisms are
independent and two are already test-pinned. The residual value is the
regression pin and the documented invariant, not a packet-path change.

## 6. Public API preservation

- Path A: no API, protocol, CLI, or config-grammar change. New tests only,
  plus optionally a doc comment.
- Path B (follow-up): changes the internal Go↔helper control protocol
  (snapshot schema / HA update payload) → requires a
  `ConfigSnapshotProtocolVersion` bump and the usual same-deb
  helper/daemon rollout story. No Junos config-grammar change; no gRPC
  surface change.

## 7. Hidden invariants any change must preserve

1. **#1928**: a standalone node must never receive phantom HA groups (the
   16-inactive publish re-arms the `HAInactive` transit-drop gate → total
   transit outage on non-cluster nodes). The `m.clusterHA` guards at
   `manager_compile.go:383` and `process_status.go:211` are the load-bearing
   lines.
2. **#5487/#5873**: the standalone `clearHelperHAState` retry debt must
   keep its only consumer (the status loop) reachable on every path that
   records it.
3. **#279/#284/#457**: `rgTransitionInFlight` suppresses ctrl only during
   *activation*; demotion must not globally disable ctrl.
4. **#6165/#6163/#5648**: the desired-state arm path must keep honoring
   the required-snapshot-protocol gate; a disarm must never be blocked.
5. **#6592**: worker-visible validation+forwarding pairing — any new
   readiness bit must be paired atomically with the forwarding state it
   qualifies (no cross-generation pairing).
6. **Fail-closed posture of `HAInactive` for unknown/inactive owner RGs**
   (`forwarding/ha.rs:96-110`): any tri-state must map
   `ClusterUninitialized` to the same `HAInactive` outcome, not to a new
   disposition.
7. The **#1928 phantom fabrication itself** currently *is* the
   never-empty invariant's enforcement mechanism. Any cleanup of it
   (e.g., filtering zero-valued array slots) must be paired with a
   replacement guarantee or the Path B tri-state BEFORE it lands.

## 8. Risk assessment

- Path A: ~zero runtime risk (tests + comment). Risk is *process*: closing
  an audit-filed issue as falsified requires the counter-evidence to
  survive hostile review — that is what rounds 1..N are for. The evidence
  is deliberately stated as independently checkable claims (file:line +
  runnable tests).
- Path B: packet-path and protocol risk as noted; only worth it as
  scheduled hardening.
- Doing nothing at all (no Path A pin): the accidental invariant stays
  unpinned; the next well-meaning cleanup of the phantom fabrication (it
  *looks* like dead/wrong code — `syncHAStateLocked`'s `len==0` branch
  reads as reachable) can re-open a real fail-open. This is the strongest
  argument for Path A's regression pin even though the window is
  falsified.

## 9. Test plan (Path A)

1. **Go ordering test** (`pkg/dataplane/userspace`): scripted fake control
   server; run a Compile/ApplyConfig for a zero-RG cluster config followed
   by a first-RG config; record the control-request sequence; assert
   `update_ha_state` (non-empty) precedes any `set_forwarding_state
   {Armed:true}`, and assert the published HA set contains the new RG as
   inactive. Assert `desiredForwardingArmedLocked()==false` after the
   zero-RG apply and `true` after the first-RG apply (the M2 pin — AGY r1
   MINOR / SMR r1 NIT-1 fold: assert the false value BOTH before and after
   the zero-RG apply, matching
   `manager_ha_test.go:786-802`). Add the no-empty-publish assertion
   (SMR r1 NIT-1): across the whole scripted session, no
   `update_ha_state` request with an empty group set is sent while
   `m.clusterHA` is true — this pins §3.1's empty-sender audit against
   future refactors. Add a deferred-path variant (SMR r1 MINOR-1): force
   `pendingXSKStartup` on the first-RG apply (pre-set
   `publishedSnapshot != 0`, `xskLivenessProven=false`) and assert the
   poll-driven resume still never sends `set_forwarding_state{Armed:true}`
   before the helper holds a non-empty HA set.
2. **Rust unit test** (`userspace-dp/src/afxdp/forwarding/ha.rs` tests):
   build a `ForwardingState` with an interface-NAT local address on an
   RG1-owned interface and an `ha_state` of `{1: inactive}` (the phantom
   shape); assert `enforce_ha_resolution_snapshot` maps the `LocalDelivery`
   resolution to `HAInactive`; controls: empty map → permit (standalone);
   `{1: active-lease}` → permit. Include the SMR r1 MAJOR-1 guard arm:
   assert `owner_rg_for_resolution` for that interface-NAT resolution
   returns 1 (i.e., the egress row's `redundancy_group` propagation is
   exercised by the test, so a future RG-propagation regression fails
   loudly instead of silently re-permitting).
3. **Existing pins re-run**: `TestMergeHAStateFromMapsFabricatesGroupsFrom
   ArrayMap`, `TestDesiredForwardingArmedRequiresDataRGOrActiveLocalOnly
   Group`, `TestClusterTopologyDay2TransitionRejected`,
   `TestChassisRedundancyGroupInRangeCommits` (all pass at base; re-run in
   CI).
4. Validation lanes: `make build`, `make test-go`, `make test-rust`
   (CARGO_TARGET_DIR isolation per research env). No cluster smoke needed
   for Path A (no behavior change); if Path B is later engineered, the
   full `make test-failover` + zero-RG→first-RG live-apply scenario on the
   loss userspace cluster is mandatory.

## 10. Out of scope (explicitly)

- The #6749 (R06) armed-state convergence plan — it owns the binding-slot
  arm/registered convergence layer (`planning.rs` slot state,
  `syncDesiredForwardingStateLocked` early-return semantics for *slots*),
  a different layer from the HA-inventory/LocalDelivery gate. Cited, not
  duplicated: its ownership model does NOT cover or close anything in this
  issue's frame, and vice versa.
- #6187 (standalone/cluster supervisor boundary) and #6707 (rejected
  policy snapshots) — adjacent, distinct per the issue's own dedup note.
- Any change to the phantom fabrication itself beyond documenting the
  invariant (a real cleanup belongs with Path B).
- `userspace_ctrl` fencing on HA-inventory-changing snapshots (the issue's
  fix direction) — rejected as framed: it adds ctrl flaps on routine
  clustered commits to close a falsified window; superseded by Path A's
  pin + Path B's structural hardening.

## 11. Open questions for adversarial review

1. Is there ANY reachable path at `ad9591177` that leaves a clustered
   node's helper **armed with an empty `ha_state`**? The falsification
   claims no (§3.1-§3.4). Reviewers: try to find one — candidates to
   attack: overlay sub-apply paths (`manager_overlay.go:236`,
   `manager_worker_arm_5134.go:76`), the `publishedPlanChangedDuring
   Startup` helper-restart branch (`manager_compile.go:255-266`), event-
   stream-driven applies, `UpdateRGActive` interleavings, state-file
   restore on helper respawn.
2. Is the phantom fabrication guaranteed on *every* clustered boot —
   i.e., can `refreshHAStateFromMapsLocked` error (map missing) on a
   healthy node in a way that leaves the apply successful but the HA
   publish skipped? (Its error fails the apply — verify.)
3. Does any helper-side path other than `update_ha_state` mutate
   `rg_runtime` (e.g., snapshot apply clearing it)? If a full
   `apply_snapshot` RESET the helper's `ha_state` to empty, the framed
   window would re-open *inside* every clustered apply. (The walk found no
   such reset — verify independently.)
4. Is `desiredForwardingArmedLocked`'s false-for-zero-RG behavior itself
   the intended posture (zero-RG cluster = control-only, no userspace
   forwarding), or an accidental behavior the project would want changed
   on other grounds? (If the project ever arms zero-RG nodes deliberately,
   C1 could become reachable — does that change the Path A/B calculus?)
5. Path B scope check: is a snapshot-carried cluster/standalone bit
   sufficient, or must the bit also gate the `owner_rg_id <= 0 &&
   !ha_state.is_empty()` transit-drop arm (`forwarding/ha.rs:90`) to keep
   standalone and cluster-uninitialized transit postures distinct?
