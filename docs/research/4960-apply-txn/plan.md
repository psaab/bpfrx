# Plan: Fence-first fail-closed config-apply for the userspace dataplane (#4960 + #4959)

**Status:** DRAFT v2 — MAJOR REDESIGN after r1. r1 verdicts: Codex = PLAN-NEEDS-MAJOR,
Claude SMR = PLAN-NEEDS-MAJOR, AGY = infra-blocked (3 documented retries). v2
abandons the v1 rollback/journal model for a **fence-first / staged-commit** model
per both reviewers. See §12 revision log for the point-by-point r1 response.

Research branch: `research/4960-apply-txn`. This is a `/research` deliverable — it
STOPS at PLAN-READY. No production code changes here; implementation happens later
under `/engineer 4960`.

---

## 1. Issue framing

Two open High-severity issues are two facets of the same structural gap: **the
userspace config-apply path mutates host state and BPF classifier maps while
`userspace_ctrl.enabled=1`, publishes the helper snapshot LAST, and on a late
failure leaves partial/candidate mutation live with ctrl still enabled and
nothing fenced.**

### #4960 — destructive host netlink mutation before later compile phases fail

`Manager.Compile` (`manager_compile.go:185`) → `CompileUserspaceShim`
(`loader.go:173`) → `CompileConfig` (`compiler.go:216`). Phase 2 `compileZones`
(`compiler_iface.go:249`) performs destructive host netlink mutation while the
old dataplane is live and ctrl is enabled:

- `ensureVLANSubInterface` (`compiler_iface.go:105`) — `LinkAdd` + **`LinkSetUp`
  (brings the new child UP before the shim is attached to it)** + `accept_ra` write.
- `reconcileInterfaceAddresses` (`:187`) — `AddrDel` (stale) + `AddrAdd` (missing).
- `LinkSetMTU`, `applyEthtool`/speed-duplex, `ensureRxVlanOff`, txqueuelen/rings/
  RPS/RFS/XPS/RSS tuning (`compiler.go:1387-1653`), `LinkSetUp`/`LinkSetDown`.
- Unmanaged-interface strip (`compiler_iface.go:1150-1166`): `AddrDel` + `LinkSetDown`.
- `LinkDel` of stale bond devices (`:1135`); `BumpFIBGeneration` (`compiler.go:298`).

These run before Phases 3-11 (`compiler.go:222-296`). A later-phase error returns
with no undo; `CompileUserspaceShim` returns before `attachUserspaceShimXDP`
(`loader.go:197`); the store already committed the new config
(`daemon_apply.go:369`); the Rust helper keeps enforcing the previous snapshot.
Result: host topology moved to the new config, forwarding pinned to the old,
transit cut on the mutated interfaces — while ctrl stays enabled.

### #4959 — address-only commit mutates classifier maps in place, then fails open

`snapshotBindingPlanKey` (`maps_sync.go:1596`) omits local/interface-NAT addresses,
so an address-only commit hits `samePlanRefresh` (`manager_compile.go:235`) →
`syncUserspaceClassifierMapsFailClosedLocked` (`maps_sync.go:266`) mutates the
ingress/local/interface-NAT BPF maps **in place** (populate-before-clear across
THREE maps, not an atomic swap) and installs nftables RST-suppression rules
(`maps_sync.go:1188-1213` → `pkg/nftables/rst_suppress.go`). ctrl stays enabled
throughout the helper round trip (up to a 67s deadline, `process_control.go:42-56`).
It disables ctrl only if a map op itself errors. Control then falls through to
`apply_snapshot` (`manager_compile.go:332`).

On helper rejection: maps are on the NEW plan, ctrl is still 1, nft rules on the
NEW set, and `publishedSnapshot`/`lastSnapshot`/`lastSnapshotHash` are not advanced.
No restore. The enabled shim classifies kernel-pass vs XSK-redirect and local/NAT
ownership on the NEW maps while Rust enforces the OLD snapshot →
security-availability mismatch.

### The unified root cause

Map mutation, host mutation, attachment changes, nft state, and helper-snapshot
publication are **not one fail-closed transaction**, and **ctrl stays enabled**
throughout — so on any unproven outcome the dataplane is left in a mixed
generation instead of fenced.

---

## 2. Honest scope / value framing

Correctness + security-availability, not performance. The win is blast-radius
reduction: one class of failed commit (config clears configstore but trips a
runtime dataplane phase, OR the helper rejects a snapshot) today produces a live
host/forwarding mismatch on a production firewall, and on HA the committed config
also syncs to the peer (`daemon_apply.go:428`) → both nodes can diverge.

**The central design tension v1 got wrong (r1):** true atomicity at the
packet-observable boundary is *impossible* here — you cannot make immediate
netlink writes invisible to packets, and you cannot atomically swap three BPF
classifier maps across a multi-ms/multi-s helper round trip while ctrl is enabled.
So the honest model is not "mutate then roll back" but **"fence, then mutate under
the fence, then unfence only after a verified-coherent commit."** The cost is a
brief transit-fenced window on a mutating apply; the benefit is that no failure
mode leaves a mismatch — every unproven outcome stays fenced (fail-closed).

*If reviewers conclude the fenced-window cost is unacceptable and there is no
tractable hitless-and-safe design (there is not, per r1), PLAN-KILL — or a
narrower "fence-on-reject only, accept the transient success-window inconsistency"
scope — is an acceptable outcome. This plan argues the fence model is both
tractable and the correct fail-closed contract.*

---

## 3. What's already shipped / partially batched (must compose with)

- **#5680 hybrid-ACK guard** (`manager_overlay.go:140-235`): a **refuse-BEFORE-publish
  + do-not-advance-identity** precedent. r1 correction: it does NOT disable ctrl —
  it is an identity-retention guard, **not** a ctrl-fence precedent. Do not conflate
  the two.
- **#2138 / #1960 required-protocol-gate abort** (`manager_compile.go:20-69`;
  `daemon_apply.go:439-455`): a helper-too-old rejection DISARMS the helper
  (`ForwardingArmed=false`) and `applyErrSkipsPeerSync` suppresses the peer sync.
  Distinct from a ctrl fence (a fence writes `userspace_ctrl.enabled=0`, not the
  helper Armed flag) — see §4.5.
- **#4952 post-teardown fail-closed** (merged `64c3c9acc`, Rust): the helper
  reports the dataplane DOWN when a worker spawn fails after teardown
  (`server/handlers/snapshot.rs:183-223`). Critically (r1 7.1): **an
  `apply_snapshot` NACK does not prove the old dataplane is still live** — it can
  be a post-teardown "down" outcome. The Go publish-outcome model must distinguish
  pre-teardown-reject (old live) from post-teardown-down.
- **#3789 pre-teardown fail-close** (Rust snapshot monotonicity gate,
  `server/handlers/snapshot.rs:83-105`): rejects a snapshot with an older/equal
  generation. r1 3.1 consequence: a helper-first ordering that fails on host and
  wants to "republish the old snapshot" is REJECTED by this gate — you cannot
  compensate with an old-generation snapshot.
- **#3924 non-authoritative-enumeration guard** (`maps_sync.go:998-1013`): the
  local-address sync skips the destructive prune when the netlink dump is
  incomplete and returns nil. r1 5.1: this makes an "old-snapshot re-sync = exact
  rollback" claim false — a partial dump leaves candidate keys and still returns
  success.
- **populate-before-clear** map discipline (`maps_sync.go:955-971`, etc.): NOT an
  atomic 3-map swap (r1 1.1).
- **#2514 snapshot-build fail-closed** (`manager_compile.go:199-202`): a
  config-shaped snapshot-build error already retains the previous snapshot — but
  it runs AFTER host mutation today.

## 4. Concrete design — fence-first staged commit

### 4.1 The invariant (corrected r1)

> Every mutating apply runs **inside a ctrl fence**. The fence
> (`userspace_ctrl.enabled=0`: shim passes only proven local/control to the
> kernel, drops transit) is established BEFORE the first packet-observable
> mutation and lifted (`enabled=1`) ONLY after a verified-coherent commit
> (host + attachments + all classifier maps + nft + published Rust snapshot all
> proven consistent). On ANY unproven, ambiguous, or failed outcome the fence is
> RETAINED — the node forwards nothing it cannot prove the enforced snapshot
> matches. No path leaves classifier maps, host topology, or attachments on a
> generation the applied Rust snapshot does not match with ctrl enabled.

This replaces v1's "atomic transaction with rollback." It is achievable because
the fence, not rollback, is what closes the mismatch window.

### 4.2 The apply state machine (single ordered pipeline)

Phases, with the commit point explicit:

```
  P0  config-only validation (PURE — no host/map/helper mutation)
        resolve every ref (zones, interfaces, screen profiles, addresses parse),
        run Phases 3-11 that are host-netlink-pure (address-book/apps/policy/NAT/
        filters/flow — verified host-pure, §4.4), reject config-shaped errors here.
        On error: return, ZERO observable mutation.
  ----- FENCE (write userspace_ctrl.enabled=0) if this apply will mutate host,
        bindings, or (optionally) classifier maps — see §4.6 hitless scoping -----
  P1  host + attachment actuation (STAGED)
        new links created DOWN or attached to the ctrl-disabled shim BEFORE going
        up; obsolete XDP/TC hooks RETAINED (not detached) until commit; run the
        existing zone host pass (VLAN/addr/MTU/admin/ethtool/unmanaged/bond).
        Attachments (XDP/TC add) staged; DETACH of obsolete hooks deferred to P6.
  P2  build the FINAL snapshot from POST-actuation LIVE state
        buildInterfaceSnapshots reads live child ifindex/MTU/MAC/addrs; connected
        routes derive from live addresses (routes.go). This build is fallible
        (RuleList, etc.) — an error here keeps the fence.
  P3  program candidate classifier maps + nft RST-suppression
  P4  publish: apply_snapshot with TYPED OUTCOME (§4.3)
  P5  verify: reconcile helper status/generation; prove the published snapshot
        generation == the programmed maps + actuated host; prove workers live.
  ----- COMMIT POINT: only past here may ctrl be re-enabled -----
  P6  commit-gated removal of obsolete XDP/TC hooks; advance published/last
        snapshot identity + hash; post-commit fallible work (HA/status/desired-
        forwarding sync) is POST-COMMIT — its errors do NOT re-fence/rollback
        (they carry their own retry/debt owners).
  P7  UNFENCE (userspace_ctrl.enabled=1) — verified-coherent only.
```

On any failure at P1-P5: **stay fenced**, do not advance identity, do not remove
obsolete hooks, return a typed apply error to the daemon (§4.5).

### 4.3 Typed publication outcomes (r1 7.1)

`requestLocked`/`apply_snapshot` today flattens dial/write/read/decode/timeout/
`OK:false` into one `error` and discards the response on `OK:false`
(`process_control.go:103-143`; Rust attaches status even on failure,
`server/handlers/mod.rs:257-264`). The publish must return a typed outcome:

1. **Accepted** — helper ACK, new snapshot live.
2. **Pre-teardown reject (old live)** — helper NACK with status proving the
   previous snapshot is still enforced (Rust monotonicity/integrity reject before
   teardown). → stay fenced; old dataplane is coherent; safe to unfence back to
   old ONLY if maps/host also reconcile to old (usually simplest to stay fenced
   and let the operator re-commit, or re-run to old).
3. **Post-teardown down (#4952)** — NACK/DOWN: workers gone, dataplane not
   forwarding. → stay fenced; recovery needs a full re-apply.
4. **Ambiguous / ACK-lost** — write succeeded, response lost/timed out after the
   helper may have applied live (`process_control.go:47-50`). → stay fenced;
   reconcile generation on the next status pass before any unfence.
5. **Accepted-with-post-commit-error** — ACK, but P6 tail work failed. →
   post-commit; do NOT re-fence; the tail work's existing debt/retry owner handles
   it.

The publish path must parse and preserve the Rust status on NACK (stop discarding
it) so outcomes 2 vs 3 are distinguishable.

### 4.4 Host-netlink purity of the middle phases (verified r1 N1)

Destructive host mutation is concentrated in exactly two phases — Phase 2
`compileZones` (first) and Phase 11 `compilePortMirroring` (last, `compiler.go:1704`,
netlink at `:1758/:1811`). The fallible MIDDLE phases (`compileAddressBook`,
`compileApplications`, `compilePolicies`, `compileNAT`/StaticNAT/NAT64/NPTv6,
`compileFirewallFilters`, `compileScreenProfiles`, `compileFlowConfig`) are
host-netlink-pure (grep: 0 netlink/`os.WriteFile` refs in `compiler_nat.go`,
`compiler_filter.go`; the refs in `compiler.go` are all in the tuning helpers used
by `compileZones`/port-mirroring). This is what makes the P0 config-validation
pass tractable: run the pure phases + all cross-reference checks BEFORE the fence
so most "config passed configstore but trips a runtime phase" failures never reach
P1. **But P0 is not sufficient alone** (r1 1.2/7.7): the FINAL snapshot build (P2)
and the P1 netlink/attach/map/socket ops remain fallible after P0 — hence the
fence, not pure-validation, is the protection.

### 4.5 Daemon dispositions — the daemon CANNOT stay unchanged (r1 4.2/7.4)

r1 falsified v1's "daemon surface unchanged." Two INDEPENDENT dispositions are
needed, and the current `compileErrorMustAbortApply`/`applyErrSkipsPeerSync`
coupling cannot express them:

- **Local tail disposition**: may the daemon continue the new-config tail
  (RETH MAC/VIP, route-leak, session-clear, `daemon_apply.go:1220-1469`)? A fenced
  or unknown-outcome apply must STOP the tail; a verified restored-and-armed
  outcome may continue.
- **Peer-sync disposition**: push the committed config to the standby? A
  **verified restored-and-armed** outcome pushes (#4034, avoid divergence); a
  **fenced/down/unknown** outcome suppresses (#2138, don't propagate a
  deterministic outage). These are orthogonal, so `applyErrSkipsPeerSync` must
  key on the typed outcome, not the error class.

Also (r1 7.4): **`Manager.Compile` is NOT the sole host orchestrator.** The daemon
reconciles VRF/xfrmi/bond/tunnel/fabric-IPVLAN BEFORE `d.dp.ApplyConfig`
(`daemon_apply.go:916-959`) and RETH MAC/VIP AFTER. The fence must be a
DAEMON-level concept spanning the whole apply, or those daemon-owned host mutations
sit outside it. Simplest: the daemon establishes the fence before its host
reconcile and lifts it after the Manager reports a verified commit.

And (r1 7.6): **a ctrl fence is invisible to `takeoverReadyLocked`**
(`manager_ha.go:401-447`) — it inspects helper status/mode/liveness/session-mirror/
event-stream but NOT the ctrl map. A fenced node can be reported HA-ready. The
fence must either flip a readiness-visible flag or `takeoverReadyLocked` must
consult `ctrlWasEnabled`/the ctrl map.

### 4.6 Hitless scoping — do we fence EVERY apply? (the key tradeoff)

Today an address-only commit is hitless (samePlanRefresh in-place). Fencing every
apply regresses that to a brief outage. Options (reviewer decision, §11 OQ-A):

- **(i) Fence-always**: every mutating apply fences. Simplest, uniformly safe,
  regresses hitless address-only commits to a ~fence-window outage.
- **(ii) Fence-on-mutation-class**: fence only when host/binding actuation is
  required (already disruptive, so ~free); for a pure classifier-map-only change,
  keep the in-place path hitless on SUCCESS and **fence only on a non-Accepted
  publish outcome** (§4.3 outcomes 2-4). This preserves hitless address-only
  commits and still guarantees fail-closed on reject. The residual is a transient
  new-maps/old-helper window on the SUCCESS path during the round trip — bounded,
  self-healing on ACK, and no worse than today's steady state for a few ms.
- Recommended: **(ii)**. It keeps the hitless benefit that `samePlanRefresh`
  exists to provide while closing the persistent mismatch (#4959) via fence-on-
  non-accept. It also covers the async `pendingXSKStartup` leg (§4.7).

### 4.7 The three affected publish/mutate sites (r1 7.2, audited)

- `manager_compile.go:301` (samePlanRefresh) — in-place maps then publish →
  **fence-on-non-accept** (§4.6 ii).
- `manager_compile.go:264` (pendingXSKStartup) — syncs candidate maps, advances
  `m.lastSnapshot`, DEFERS publish (returns success at `:298`). The status loop
  later calls `applyHelperStatusLocked` (which may re-enable ctrl from the new
  `lastSnapshot`) THEN `syncSnapshotLocked`, whose `apply_snapshot` error has NO
  fence (`process_status.go:143-165`; `maps_sync.go:779-797`). This is a genuine
  second #4959. Fix needs **persistent transaction/debt state shared with
  `syncSnapshotLocked`** so the deferred publish stays fenced until Accepted.
- `programBootstrapMapsLocked:194` (!samePlanRefresh) — already fail-closed
  (ctrl pre-disabled + bindings cleared before publish, r1 F1) — leave as-is
  except add outcome-typed recovery.

The overlay (`manager_overlay.go`) and worker-arm (`manager_worker_arm_5134.go`)
sites do NOT pre-mutate classifier maps and are already safe — **must not be
touched.**

### 4.8 What v2 explicitly drops from v1

- The **bounded host rollback journal** and **B1 map re-reconcile** — both unsound
  (r1 1.1/1.2/5.1/5.2/7.1). A journal cannot make netlink writes invisible; the
  re-sync synthesizes an `old-config ∪ current-kernel` state and can leave nft on
  the candidate set. Replaced by fence + stage.
- The **`planZones`/`actuateZoneHostState` "build snapshot before actuation"**
  split (r1 6.1): the snapshot MUST be built from POST-actuation live state
  (buildInterfaceSnapshots reads live child ifindex/MTU/MAC/addrs; the binding plan
  key includes the live ifindex). P0 stays a pure *validation* pass that builds NO
  wire snapshot; the wire snapshot is built at P2 after actuation.

## 5. Public API preservation (corrected r1 7.7)

- `Manager.Compile`, `Manager.ApplyConfig`, `LegacyDataPlaneAdapter.*`,
  `CompileUserspaceShim` — signatures preserved.
- **NOT preserved / must change** (r1 was wrong to claim otherwise): the daemon
  apply-error classification (`applyErrSkipsPeerSync`/`compileErrorMustAbortApply`)
  gains the typed-outcome dimensions (§4.5); `takeoverReadyLocked` gains a
  fence check (§4.5); the publish path gains typed outcomes (§4.3); `m.mu`/apply
  serialization scope changes if host actuation moves under the lock (§6).
- Tolerated behavior: `compileZones` currently WARN-skips missing interfaces /
  malformed addresses (`compiler_iface.go:197-203,342-357`). P0 validation
  changing these to hard-fail is a **compatibility decision** that must be made
  explicitly (r1 6.3) — recommend: keep warn-skip for non-critical, hard-fail only
  the refs that would otherwise trip a later phase.

## 6. Hidden invariants the change must preserve

- **Locking (r1 7.7):** host compile + `syncInterfaceAttachments` currently run
  BEFORE `m.mu` (`manager_compile.go:185-213`); direct `userspace.Manager.ApplyConfig`
  has NO `applySem` (`manager.go:318`). Moving actuation under the fence + lock is a
  NEW design needing explicit lock/liveness analysis — not a preserved invariant.
- **Side-effect ordering** within P1 (tx_ports before XDP attach; ring/ethtool
  before attach — NIC reset; `KeepConfiguration=static` on RETH; DHCP/RETH/fabric
  SKIP addr reconcile; #1922 protected set never stripped; #1956 device-map
  leave-alone). The staged actuation must preserve all of these.
- **#3924 enumComplete** on any local-address sync.
- **HA state**: `m.clusterHA`/`m.haGroups` set from the candidate before publish
  (`manager_compile.go:226-227`) — must be part of the fenced transaction's
  "unproven until commit" set, and the status loop branches on `m.clusterHA`
  (`process_status.go:180-217`).
- **nft RST-suppression** (`maps_sync.go:1188-1213`): part of the resource set;
  its install failure is currently warning-only and must become a fence trigger
  (or be proven coherent before unfence).
- **Rust monotonicity gate** (`snapshot.rs:83-105`): no old-generation
  compensating publish.
- **ConfigSnapshot wire shape** unchanged (no new wire fields; typed outcomes are
  derived from the existing status response).

## 7. Risk assessment

| Risk class | Level | Notes |
|---|---|---|
| Behavioral regression | **HIGH** | Touches the largest function in the tree AND the daemon apply pipeline AND the publish/status loop AND HA readiness. Mitigation: land incrementally — (a) fence + typed outcomes for the map path (#4959) first with the async-leg debt; (b) fence-before-host-mutation for #4960 second; each behind tests. |
| Hitless regression | **MED** | Fence-on-mutation (§4.6 ii) preserves hitless address-only commits; fence-always (i) regresses them. Reviewer decision OQ-A. |
| Lock / liveness | **MED** | Extending the fence + `m.mu` over host actuation and coordinating with the daemon-level fence needs explicit deadlock analysis (status loop also takes `m.mu`). |
| Performance | **LOW** | Control-plane only; the fence window is a brief transit outage on a mutating apply, not a per-packet cost. |
| Architectural mismatch | **MED→LOW** | The fence model is the reviewer-endorsed shape (Codex OQ-7); it composes with #2138/#4952/#3789 rather than fighting them. The v1 journal (the #961 dead-end risk) is dropped. |

## 8. Recommendation

**Ship the fence-first staged-commit model, in two lands:**

1. **#4959 (map path) — land 1:** fence-on-non-accept for the `samePlanRefresh`
   in-place site (§4.6 ii), typed publish outcomes (§4.3), and shared
   transaction/debt state so the async `pendingXSKStartup` deferred publish
   (§4.7) also stays fenced until Accepted. Include nft RST-suppression in the
   proven-coherent set. Leave the already-safe overlay/worker-arm/bootstrap sites
   untouched.
2. **#4960 (host path) — land 2:** P0 pure-validation pass → fence-before-host-
   mutation → staged P1 actuation (new links down/shim-first, obsolete hooks
   retained) → P2 post-actuation snapshot build → publish → verify → P6 commit-
   gated hook removal → P7 unfence. Daemon-level fence spanning the daemon's own
   host reconcile (§4.5); daemon typed dispositions; HA-readiness fence check.

**No host rollback journal** (dropped, r1). The fence is the fail-closed contract:
a partial host topology under a fenced dataplane forwards no transit, so it cannot
mis-steer — degraded-safe availability, never a security mismatch. The only
PLAN-KILL-able scope question is OQ-A (fence-always vs fence-on-mutation) and
whether the fenced-window outage is acceptable at all.

## 9. Test plan (r1 item 5 — the controlling distinctions)

- `go build ./...`; `go vet ./pkg/dataplane/... ./pkg/daemon/...`.
- **New Go tests (each a distinct outcome the current suite does not cover):**
  1. samePlanRefresh + publish **Accepted** → maps advanced, ctrl re-enabled, hitless.
  2. samePlanRefresh + publish **pre-teardown reject** → fenced, identity not
     advanced, maps NOT declared "rolled back" (fence, not restore).
  3. samePlanRefresh + **ACK-lost/ambiguous** → fenced, generation reconciled on
     next status pass before any unfence (r1 7.1).
  4. samePlanRefresh + **post-teardown down (#4952)** → fenced, recovery = full
     re-apply.
  5. **pendingXSKStartup deferred reject** → fenced via shared debt; ctrl not
     re-enabled by the interleaved `applyHelperStatusLocked` (r1 7.2).
  6. #4960: late compile phase (missing screen profile) fails in P0 → ZERO host
     mutation (needs an injected actuator seam / netns, r1 7.7).
  7. #4960: P1 host-actuation failure → fenced, obsolete hooks retained, new links
     not left up (r1 1.2/7.3).
  8. #4960: `attachUserspaceShimXDP`/generic-attach failure after host actuation →
     fenced (r1 7.3).
  9. #4960: new-VLAN live materialization — snapshot built at P2 carries the
     RESOLVED child ifindex/MTU (proves P2-after-actuation, r1 6.1).
  10. #3924 incomplete enumeration during the fenced apply does not prune live
      VIP/local keys.
  11. nft RST-suppression install failure → fence (not warning-only, r1 5.2).
  12. daemon: fenced outcome suppresses peer sync + stops tail; restored-and-armed
      outcome pushes + continues (r1 4.2).
  13. HA: `takeoverReadyLocked` reports NOT-ready for a ctrl-fenced node (r1 7.6).
- Tests need an **injected actuator/netlink seam** (r1 7.7) — no byte-identical
  golden test (unsorted map iteration has no stable baseline); use per-interface
  partial-order assertions.
- **Rust cargo suite** (`make test-rust`): the typed-outcome parsing may need the
  helper to attach status on NACK — verify no wire regression.
- **Smoke (loss userspace cluster, `/engineer` time):** v4+v6, push+reverse,
  CoS-off+on; inject a runtime-phase-failing commit and confirm the DUT stays on
  previous-good forwarding (fenced, not half-migrated). Sustained iperf3 through
  the DUT (`feedback_verify_forwarding_with_sustained_iperf`).
- **Failover** (`make test-failover`): required — touches ctrl/HA/RETH state.

## 10. Out of scope (explicitly)

- Config-store-commit-vs-dataplane-apply 2PC (`store.Commit` promotes before
  `applyConfigLocked`). This makes the DATAPLANE apply fenced/fail-closed; it does
  not make store+dataplane one distributed transaction. Divergence cost is
  documented (§4.5), not eliminated.
- Rust helper transactionality (#4952/#3789 merged) — no helper wire/handler change
  beyond attaching status on NACK for outcome typing (§4.3).
- Expanding `snapshotBindingPlanKey` to include local/interface-NAT addresses —
  rejected (would force a helper restart on address-only changes; the fix keeps the
  hitless in-place path and makes it fail-closed).
- The **reused-process bootstrap teardown** (r1 F2): an iface-binding-only plan-key
  change reuses the running helper yet `programBootstrapMaps` tears down its live
  ctrl+bindings — fail-closed but availability-destructive. Separate follow-up (it
  is already fail-closed).
- The already-safe overlay/worker-arm publish sites — must not be touched.
- ISSU / rolling-upgrade apply paths.

## 11. Open questions for adversarial review (each invitable to PLAN-KILL)

A. **Fence-always vs fence-on-mutation (§4.6).** Is regressing hitless
   address-only commits to a fenced-window outage acceptable (i), or must the
   hitless path be preserved with fence-only-on-non-accept (ii)? If neither the
   fenced window NOR the transient success-window inconsistency of (ii) is
   acceptable, is there a third design — or is this PLAN-KILL?
B. **Is the fenced window's transit outage acceptable at all** for #4960's host
   path, given host mutation (address/VLAN reconcile) is already disruptive today?
   Quantify: what is the realistic fence-window duration (P1 host actuation + P2
   build + P4 round trip)?
C. **Daemon-level vs Manager-level fence (§4.5/7.4).** Must the fence be owned by
   the daemon to span its VRF/xfrmi/RETH host reconcile, or is a Manager-level
   fence + a documented "daemon host reconcile is outside the fence" residual
   acceptable for land 2?
D. **Typed-outcome sufficiency (§4.3).** Are the 5 outcomes the right partition?
   Specifically, can Go reliably distinguish pre-teardown-reject (old live) from
   post-teardown-down using the Rust status on NACK, or is the only safe rule
   "any non-Accept ⇒ stay fenced and reconcile generation next status pass"
   (collapsing outcomes 2-4)?
E. **Peer-sync/divergence (§4.5).** Is the "sync only verified-restored-and-armed,
   suppress fenced/unknown" rule correct, and who owns the reconvergence
   (reverse-sync-on-reconnect vs a retry debt)? Is the resulting store/peer
   divergence window acceptable?
F. **Async leg debt (§4.7).** Is persistent transaction/debt state shared with
   `syncSnapshotLocked` the right mechanism for the `pendingXSKStartup` deferred
   publish, or should the deferred-publish path be removed in favor of always
   fencing until the first Accepted publish?
G. **Incremental landing.** Is land-1 (#4959 map fence) shippable independently of
   land-2 (#4960 host fence), or do they share enough fence machinery that they
   must land together?

## 12. Revision log

### v2 (this revision) — response to r1

**Claude SMR r1 (PLAN-NEEDS-MAJOR):**
- F1 (OQ-2 restart path fail-closed, not fail-open) → §4.7, OQ-2 deleted as a
  question; confirmed restart path is fail-closed.
- F2 (reused-process teardown) → §10 out-of-scope follow-up.
- F3 (three call sites) → §4.7 audited all sites; async leg gets shared debt.
- F4/OQ-6 (rollback = re-reconcile, not exact) → dropped the re-reconcile entirely
  (§4.8); fence instead.
- F5 (firm up recommendation) → §8 concrete two-land scope.
- F6 (attach failure) → P1/P6 staging + test 8.
- N1 (middle phases host-pure) → §4.4 verified.
- N3 (peer-sync default) → §4.5 typed dispositions.

**Codex r1 (PLAN-NEEDS-MAJOR):**
- 1.1/1.2 (rollback recreates skew; journal incomplete) → dropped journal + B1;
  fence-first model (§4.1/4.2).
- OQ-1 (fence before first mutation; stage new links; retain old hooks) → §4.2 P1/P6.
- 2.1 (restart path fail-closed; delete false restart claims) → §4.7; §1 corrected.
- 3.1/OQ-3 (publish-last behind a fence; no old-gen compensating publish) → §4.2,
  §3 #3789 note.
- 4.1/4.2/OQ-4 (two daemon dispositions; daemon cannot stay unchanged) → §4.5, §5.
- 5.1/5.2/OQ-6 (re-sync synthesizes never-existed state; nft omitted) → §4.8 drop
  re-sync; §4.1/§6 include nft in resource set.
- 6.1/6.2/6.3 (snapshot must be built after actuation; host.err doesn't exist;
  smaller two-pass) → §4.2 P2-after-actuation; §5 critical-vs-best-effort + warn-
  skip compatibility decision; §4.8 drop the pre-actuation split.
- 7.1 (typed outcomes; ACK-loss ≠ reject) → §4.3.
- 7.2 (pendingXSKStartup uncovered) → §4.7 shared debt.
- 7.3 (attachment state in the transaction) → §4.2 P1/P6, resource set §6.
- 7.4 (Manager not sole host orchestrator; HA fields) → §4.5, §6.
- 7.5 (post-commit fallible work) → §4.2 P6 (post-commit, no re-fence).
- 7.6 (fence invisible to HA readiness) → §4.5, test 13.
- 7.7 (locking/zero-mutation/test claims wrong) → §5/§6 corrected; §9 injected seam,
  no golden test.
- 7.8 (#5680 not a fence precedent) → §3 corrected.
