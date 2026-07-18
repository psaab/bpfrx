# Plan: Fail-closed transactional config-apply for the userspace dataplane (#4960 + #4959)

**Status:** DRAFT v1 — pending adversarial plan review (Codex + AGY + Claude SMR)

Research branch: `research/4960-apply-txn`. This is a `/research` deliverable —
it STOPS at PLAN-READY. No production code changes here; implementation happens
later under `/engineer 4960`.

---

## 1. Issue framing

Two open High-severity issues are two facets of the same structural gap: **the
userspace config-apply path mutates host state and BPF classifier maps BEFORE
the helper snapshot is published, and on a late failure leaves that partial
mutation live with `userspace_ctrl.enabled=1` and no rollback.**

### #4960 — destructive host netlink mutation before later compile phases fail

`pkg/dataplane/userspace/manager_compile.go:185` `Manager.Compile` calls
`m.bpfShim.CompileUserspaceShim(cfg)` (`pkg/dataplane/loader.go:173`), which runs
`CompileConfig` (`pkg/dataplane/compiler.go:216`). Phase 2 `compileZones`
(`compiler_iface.go:249`) performs **destructive host netlink mutation**:

- `ensureVLANSubInterface` (`compiler_iface.go:105`) — `LinkAdd` + `LinkSetUp` +
  writes `/proc/sys/.../accept_ra`.
- `reconcileInterfaceAddresses` (`compiler_iface.go:187`) — `AddrDel` (stale) +
  `AddrAdd` (missing) on physical and VLAN sub-interfaces.
- `LinkSetMTU`, `applyEthtool`, `ensureRxVlanOff`, ring-buffer tuning,
  `LinkSetUp`/`LinkSetDown` (admin state).
- Unmanaged-interface strip (`compiler_iface.go:1150-1166`): `AddrDel` + `LinkSetDown`.
- `LinkDel` of stale bond devices (`compiler_iface.go:1135`).

These run in Phase 2, **before** Phases 3-11 (address book, applications,
policies, NAT, static NAT, NAT64, NPTv6, screen, default policy, flow timeouts,
firewall filters, flow config, port mirroring — `compiler.go:222-296`). Any
later phase returns on the first error with **no undo**. `CompileUserspaceShim`
then returns the error before `attachUserspaceShimXDP` (`loader.go:197`), so the
old XDP shim/Rust snapshot stays published while partial host state (created
VLANs, reconciled addresses, brought-down interfaces, deleted bonds) is live.
The `BumpFIBGeneration` error path is not the concern (it is discarded and only
runs on `isRecompile`, `compiler.go:302`), but the destructive-before-fallible
ordering is.

**Failure trace:** a config that passed `configstore` compile (`pkg/config`) but
fails a runtime dataplane phase after `compileZones` — e.g. a screen-profile
name a zone references that is missing (`compiler_iface.go:301`,
`buildScreenConfig` path), a NAT counter-key error, or a filter-expansion
rejection — leaves VLANs created and addresses reconciled while `Compile`
returns an error, the store has already committed the new config
(`daemon_apply.go:369` promotes before `applyConfigLocked`), and the Rust helper
keeps enforcing the previous snapshot. Result: host topology moved to the new
config, forwarding state pinned to the old — traffic cut on the mutated
interfaces.

### #4959 — address-only commit mutates classifier maps in place, then fails open

`pkg/dataplane/userspace/maps_sync.go:1596` `snapshotBindingPlanKey` hashes
worker/ring/interface-binding + fabric fields but **omits local and
interface-NAT addresses**. So an address-only commit produces the same plan key
→ `samePlanRefresh` is true (`manager_compile.go:235-238`) → the apply takes the
in-place branch (`manager_compile.go:300-303`) calling
`syncUserspaceClassifierMapsFailClosedLocked` (`maps_sync.go:266`).

That function mutates the ingress/local/interface-NAT BPF maps **in place**
(`syncUserspaceClassifierMapsLocked` → `syncIngressIfaceMapLocked` /
`syncLocalAddressMapsLocked` / `syncInterfaceNATAddressMapsLocked`,
`maps_sync.go:247-254`) using populate-before-clear. It only disables ctrl **if a
map op itself errors** (`failClosedUserspaceCtrlLocked`, `maps_sync.go:230`).
Control then falls through to `apply_snapshot` (`manager_compile.go:332`).

**On helper rejection** (`apply_snapshot` returns an error at
`manager_compile.go:333`): the maps are already on the NEW plan, `ctrl.enabled`
is still 1, and `publishedSnapshot` / `lastSnapshot` / `lastSnapshotHash` are
**not advanced** (they are only set at `manager_compile.go:336,343,349`, after a
successful publish). No restore runs. The enabled XDP shim reads these maps to
decide kernel-pass vs XSK-redirect and local/interface-NAT ownership while Rust
still enforces the previous-good snapshot → wrong kernel delivery / wrong XSK
steering / wrong NAT ownership — a **security-availability mismatch**, the
opposite of the intended "retain previous-good."

### The unified root cause

Map mutation, host mutation, and helper-snapshot publication are **not one
fail-closed transaction**. On helper rejection or a late compile-phase error,
partial mutation is left live with ctrl enabled and nothing is rolled back or
fenced.

---

## 2. Honest scope / value framing

This is a **correctness + security-availability** fix, not a performance change.
The win is measured in blast-radius reduction, not cycles or MB:

- Today, one class of failed commit (config passes configstore but fails a
  runtime dataplane phase, OR the helper rejects an address-only snapshot)
  produces a **live host/forwarding mismatch** on a production firewall:
  interfaces moved to the new config while the enforced policy/NAT/steering is
  the old one. On an HA cluster the committed config also syncs to the peer
  (`applyAndSyncCommitted`, `daemon_apply.go:428`) unless the apply error is a
  required-protocol-gate error, so both nodes can diverge.
- Frequency: low (requires a config that clears the parser/compiler but trips a
  runtime phase, or a helper protocol/integrity rejection), but the impact when
  it fires is a partial traffic outage that persists until the next successful
  commit — exactly the fail-open class the #1960 / #2138 / #5680 fail-closed
  doctrine exists to prevent.

*If reviewers conclude the transactionality win is too small to justify the
churn — or that a simpler fail-closed floor (Path C) is the correct ceiling for
this issue and full rollback (Path A/B) is over-engineering — PLAN-KILL (or
downscope to Path C) is an acceptable verdict.*

---

## 3. What's already shipped / partially batched (must compose with)

- **#5680 hybrid-ACK fail-closed guard** (`manager_overlay.go:140-235`,
  `routeOnlyPublishHybrid`): the route-only overlay publish already REFUSES to
  advance the applied identity when `cfg` carries an unpublished policy delta.
  This is the canonical "do not ACK a hybrid; retain previous-good; reconverge on
  next full apply" precedent. Our transaction must extend the same discipline to
  the full-apply and samePlanRefresh paths.
- **#2138 / #1960 required-protocol-gate abort** (`manager_compile.go:20-69`,
  `requiredProtocolGateSentinels`, `IsRequiredProtocolGateError`,
  `daemon_apply.go:439-455` `applyErrSkipsPeerSync`): a helper-too-old rejection
  DISARMS the helper (fail-closed) and the daemon suppresses the peer sync. This
  is the existing model for "surface a failed commit rather than report success
  against a disarmed dataplane." A helper *content* rejection (integrity
  preflight) is a sibling class our transaction must also fail closed on.
- **#4952 post-teardown fail-closed** (merged `64c3c9acc`, Rust side —
  `userspace-dp/src/afxdp/coordinator/reconcile/bringup.rs`,
  `server/handlers/snapshot.rs`): the helper now fails closed when a worker spawn
  fails AFTER the old workers were torn down during a reconcile. This is the
  in-helper analogue of what we need on the Go side: a reconcile that can't
  complete must not leave the dataplane half-migrated and forwarding.
- **#3789 pre-teardown fail-close** (Rust snapshot apply): the helper validates a
  snapshot BEFORE tearing down the previous good state; an invalid snapshot is
  rejected with the previous state intact. **This is exactly the `apply_snapshot`
  rejection our Go path mishandles** — the helper correctly kept previous-good,
  but Go had already advanced the maps and left ctrl enabled.
- **#3924 non-authoritative-enumeration guard** (`maps_sync.go:998-1013`): the
  local-address sync already SKIPS the destructive prune when the netlink dump is
  incomplete (adds are safe, prunes against a partial set are not). Our map
  rollback must preserve this — a rollback re-sync against the old snapshot must
  not itself prune against a partial enumeration.
- **#2514 snapshot-build fail-closed** (`manager_compile.go:199-202`): a
  config-shaped input that fails `buildSnapshot*` already returns an error and
  `m.lastSnapshot` is NOT advanced. But this runs AFTER
  `CompileUserspaceShim` (host mutation) at line 185 — so the host is already
  mutated when the snapshot build fails. Reordering matters here.
- **populate-before-clear** is already the map-write discipline
  (`syncIngressIfaceMapLocked:955-971`, `syncLocalAddressMapsLocked`,
  `compileZones` `DeleteStaleIfaceZone`/`DeleteStaleVlanIface:1169-1170`): new
  entries written first, stale pruned after. This is what makes a **content-driven
  re-sync against the old snapshot a valid map rollback**.

---

## 4. Concrete design

### 4.1 The transaction invariant (both facets)

> An apply is atomic at the observable boundary: nothing the dataplane enforces
> or steers on (host interface topology + addresses, BPF classifier maps, the
> published Rust snapshot) advances unless **all three** succeed. On any failure,
> the apply fails closed — it either restores the previous-good state or leaves
> the dataplane fenced (`ctrl.enabled=0`, transit dropped, only proven
> local/control to kernel) — and never leaves classifier maps or host topology on
> a newer generation than the applied Rust snapshot with ctrl enabled.

The two issues live in different layers (host netlink in `pkg/dataplane`
`compileZones`; classifier maps + helper publish in `pkg/dataplane/userspace`
`manager_compile`), so the plan proposes **one shared invariant enforced by two
coordinated mechanisms**, sequenced by a single apply orchestrator in
`Manager.Compile`.

### 4.2 Facet B (#4959) — transactional classifier-map + helper publish

Root-cause clarification the reviewers must weigh: **`samePlanRefresh` (in-place
map update, no helper restart) is the DESIRED path for an address-only change.**
Expanding `snapshotBindingPlanKey` to include local/interface-NAT addresses
would force address-only commits onto the `!samePlanRefresh` → `programBootstrapMaps`
→ helper-restart path, which drops all transit for the restart window. That is a
regression, not a fix. **The defect is not the path selection; it is that the
in-place path fails OPEN on `apply_snapshot` rejection.** So the fix
transactionalizes the in-place path; it does not avoid it.

Design (`manager_compile.go:300-334`, `maps_sync.go`):

1. **Capture a rollback anchor before the in-place map mutation.** On the
   `samePlanRefresh` branch, the previous-good classifier state is exactly
   `m.lastSnapshot` (still the old snapshot at this point) plus the map-tracking
   fields (`m.lastIngressIfaces`). Snapshot these before calling
   `syncUserspaceClassifierMapsLocked(snap)`.

2. **Publish-gated map commit.** Reorder so the observable map state is not
   "ahead" of the helper on rejection. Two sub-options (reviewer choice):
   - **B1 (rollback):** keep the current maps-first order, but wrap the
     `samePlanRefresh` leg + `apply_snapshot` in a transaction: if
     `apply_snapshot` is rejected, re-run `syncUserspaceClassifierMapsLocked`
     against the OLD snapshot (`rollbackSnap`) to restore the maps
     (populate-before-clear makes this a valid content-driven restore), reset
     `m.lastIngressIfaces` to the old set, and leave ctrl at its prior value.
     The old Rust snapshot and old maps are then coherent again — true
     previous-good retention. If the restore itself fails, escalate to B2.
   - **B2 (fence):** on `apply_snapshot` rejection in the `samePlanRefresh` leg,
     call `failClosedUserspaceCtrlLocked` (disable `ctrl.enabled`) so the shim
     stops XSK-redirecting and only passes proven local/control to the kernel.
     Simpler, but drops transit until the next successful apply — a heavier
     fail-closed floor.
   Recommended: **B1 with B2 as the escalation fallback** (matches the existing
   two-tier `failClosedUserspaceCtrlLocked` → `blindFailClosedUserspaceCtrlLocked`
   structure at `maps_sync.go:266-335`).

3. **Do not advance `publishedSnapshot`/`lastSnapshot`/`lastSnapshotHash`/
   `publishedPlanKey`/`markAppliedSnapshotLocked` on the reject path** (already
   true — they are only set after the successful publish). The new work is
   the map restore/fence, not the identity guard (which #5680 already models).

4. **`snapshotBindingPlanKey` stays as-is for path selection** but gains a
   documented contract comment that its omission of local/interface-NAT is
   INTENTIONAL (address-only changes must stay on the no-restart in-place path)
   and that the in-place path's transactionality (this fix) is what makes the
   omission safe. This closes the "is the key wrong?" reviewer question
   explicitly.

Signatures (illustrative):

```go
// transactional wrapper around the samePlanRefresh in-place map update.
// rollbackSnap is m.lastSnapshot captured BEFORE the mutation.
func (m *Manager) applyClassifierMapsTxLocked(newSnap, rollbackSnap *ConfigSnapshot,
    publish func() error) error {
    prevIngress := append([]uint32(nil), m.lastIngressIfaces...)
    if err := m.syncUserspaceClassifierMapsFailClosedLocked(newSnap); err != nil {
        return err // map op failed -> already ctrl-disabled by failClosed path
    }
    if err := publish(); err != nil {
        // helper rejected the snapshot: restore maps to previous-good.
        if rbErr := m.rollbackClassifierMapsLocked(rollbackSnap, prevIngress); rbErr != nil {
            // restore failed -> escalate to fence (disable ctrl).
            return errors.Join(err, m.fenceCtrlLocked(newSnap, rbErr))
        }
        return err // maps restored, ctrl unchanged, snapshot identity not advanced
    }
    return nil
}
```

### 4.3 Facet A (#4960) — host netlink actuation ordering + bounded rollback

The cleanest structural fix is **validate-before-first-destructive-op**: move the
destructive host netlink actuation so it only begins after all fallible
side-effect-free work has succeeded. The natural cut points:

1. **Pre-validate in a pure planning pass.** Before any `LinkAdd`/`AddrDel`,
   walk the config and verify: every VLAN parent resolves (`LinkByName`), every
   configured address parses, every referenced screen profile exists, every
   zone/interface ref resolves. Most of the "config passed configstore but trips a
   runtime phase" failures (e.g. the missing-screen-profile error at
   `compiler_iface.go:301`) can be surfaced here, side-effect-free, so
   `compileZones` never starts mutating on a config that a later phase will
   reject.

2. **Order host actuation after the pure compile phases.** The fallible Phases
   3-11 (address book, apps, policy, NAT, filters, flow) and the wire-snapshot
   build (`buildSnapshotWithSchedulerState…`, `manager_compile.go:199`) are
   **pure with respect to host netlink** (they write BPF maps and build structs,
   no `AddrDel`/`LinkAdd`). Reorder `Manager.Compile` so the host-mutating portion
   of `compileZones` runs LAST — after Phases 3-11 and the snapshot build have all
   succeeded. This requires splitting `compileZones` into:
   - `planZones` (pure): resolve ifindexes, build the desired host-op set +
     the zone/vlan BPF-map plan + `result.pendingXDP/pendingTC/ManagedInterfaces`.
     No netlink writes.
   - `actuateZoneHostState` (impure): execute the VLAN creates, address
     reconciles, MTU/admin/ethtool, unmanaged strip — run once everything
     fallible has passed.

   Data-dependency note: `ensureVLANSubInterface` yields a sub-ifindex that feeds
   the `vlan_iface` map and zone map. The split must plan the VLAN op, then in the
   actuate step create it and write the dependent map entries together — i.e.
   the BPF map writes that depend on a created ifindex move into the actuate step
   alongside the netlink op that produces the ifindex. (Alternatively, resolve
   already-existing sub-interfaces in the plan pass and only defer the *create*.)

3. **Bounded rollback journal for the reversible host ops.** For the actuate
   step, record an undo entry before each reversible destructive op:
   - address reconcile: capture prior address list per interface → undo = restore.
   - MTU change: capture prior MTU → undo = restore.
   - admin up/down: capture prior `OperState`/flags → undo = restore.
   - VLAN create: undo = `LinkDel` (only for VLANs THIS apply created, not
     pre-existing ones).
   Irreversible ops (stale-bond `LinkDel`, NIC-resetting ethtool ring changes)
   are moved as LATE as possible in the actuate order and are documented as
   non-rolled-back residual; if a failure occurs after them, the fence path
   (ctrl-disable) is the floor. In practice, once the pure phases + snapshot build
   pass (step 1+2), the actuate step has a very small failure surface (transient
   netlink EBUSY), so the rollback journal handles the realistic cases and the
   fence covers the rest.

4. **`BumpFIBGeneration` error** (`compiler.go:302`) is folded into the
   transaction result rather than discarded — a failed FIB bump means sessions
   may keep stale FIB entries, so it should at minimum be logged at WARN and
   surfaced in the apply result (reviewer question OQ-5).

### 4.4 How the two mechanisms compose in `Manager.Compile`

The apply orchestrator becomes (sketch):

```
Compile(cfg):
  # PURE PLANNING (no host mutation, no helper publish)
  result = planUserspaceShim(cfg)        # planZones + Phases 3-11 pure compile
  snap   = buildSnapshot(cfg, result)    # #2514 already fails closed here
  # -> if either fails: return err, ZERO host mutation, old snapshot live

  lock:
    rollbackSnap = m.lastSnapshot
    # HOST ACTUATION (facet A) — journalled
    host = actuateZoneHostState(result)  # VLANs/addrs/MTU/admin/unmanaged
    if host.err:
       host.rollback(); return err       # reversible ops undone; fence residual
    attachUserspaceShimXDP(result)

    # MAP + HELPER PUBLISH (facet B) — transactional
    if samePlanRefresh:
       applyClassifierMapsTxLocked(snap, rollbackSnap, publish)  # B1/B2
    else:
       programBootstrapMaps + ensureProcess + publish            # restart path
    # -> on publish reject: maps restored (B1) or fenced (B2);
    #    identity not advanced; host already actuated -> see OQ-3
```

The **ordering decision** (host-actuate before or after helper publish) is the
central open question — see §11 OQ-3. Host-first means a helper reject leaves
host actuated but forwarding fenced/rolled-back; helper-first means a host
failure leaves the helper on the new snapshot but host on the old. The plan
recommends **host-first with host rollback + map/helper transaction**, because
host topology is the more expensive thing to churn and the pure-planning pass
already de-risks the host actuation.

---

## 5. Public API preservation

- `Manager.Compile(cfg) (*dataplane.CompileResult, error)` — unchanged signature.
- `Manager.ApplyConfig`, `LegacyDataPlaneAdapter.{ApplyConfig,Compile}` — unchanged.
- `Manager.CompileUserspaceShim(cfg) (*CompileResult, error)` — unchanged
  signature; internally split into plan/actuate but the exported entry point and
  its error semantics (returns error, leaves old shim attached on failure) are
  preserved.
- `snapshotBindingPlanKey` — unchanged behavior (documented, not modified).
- The daemon commit surface (`commitAndApply`, `applyAndSyncCommitted`,
  `applyErrSkipsPeerSync`, `compileErrorMustAbortApply`) — unchanged. A rolled-
  back/fenced apply still returns a non-nil error; `applyErrSkipsPeerSync`
  behavior for the new fenced class must be decided (OQ-4: should a fenced apply
  suppress the peer sync like a required-protocol-gate error does?).

## 6. Hidden invariants the change must preserve

- **applySem serialization**: all of this runs under `d.applySem` +
  `m.mu` (`manager_compile.go:213`). The rollback/fence must run inside the same
  lock hold so no concurrent apply observes the mid-transaction state.
- **populate-before-clear**: preserved — it is what makes the map rollback a
  valid content-driven restore. Rollback re-syncs against the old snapshot, never
  raw-deletes.
- **#3924 non-authoritative enumeration**: the map rollback re-sync must inherit
  the `enumComplete` skip-prune guard, or a rollback during a partial netlink dump
  could prune live VRRP VIP/local keys.
- **Side-effect ordering** (`compiler_iface.go` comments): tx_ports before XDP
  attach; ring/ethtool tuning BEFORE XDP attach (ethtool -G resets the NIC);
  `KeepConfiguration=static` on RETH; DHCP/RETH/fabric interfaces SKIP address
  reconcile. The plan/actuate split must preserve every one of these orderings
  within the actuate step.
- **#1922 protected-interface set** (`compiler_iface.go:1077`): the management
  lifeline must never be brought down or address-stripped — the rollback must not
  re-introduce a strip on a protected interface.
- **#1956 device-map leave-alone**: unmapped NICs stay invisible — the plan pass
  must not enumerate them into the host-op set.
- **HA sync portability**: the `ConfigSnapshot` wire shape is unchanged (no new
  wire fields required for either facet — the rollback anchor is in-memory Go
  state, not on the wire).
- **ctrl two-tier fail-closed** (`failClosedUserspaceCtrlLocked` →
  `blindFailClosedUserspaceCtrlLocked`): the new fence path reuses this, it does
  not introduce a third disable path.
- **`m.ctrlWasEnabled` / `m.ctrlDisabledAt` bookkeeping**: the fence path must
  keep these consistent (they gate the #—ctrl-disabled-duration diagnostics).

## 7. Risk assessment

| Risk class | Level | Notes |
|---|---|---|
| Behavioral regression | **MED** | `compileZones` is the largest, most invariant-dense function in the tree; the plan/actuate split risks reordering a side-effect. Mitigation: pure-motion split with a golden test asserting the actuate order is byte-identical to today's sequence when no error occurs. |
| Lifetime / aliasing | **LOW** (Go) | No borrow-checker; the rollback anchor is a captured slice/pointer copy under lock. Risk is aliasing `m.lastSnapshot` — must deep-copy the tracking fields, not the snapshot pointer. |
| Performance regression | **LOW** | Apply path is control-plane, not per-packet. The pure-planning pass adds one extra config walk per commit (µs-scale). No hot-path change. Reviewer check: the plan pass must not double the netlink `LinkByName`/`AddrList` syscalls — reuse `result.cached*` lookups. |
| Architectural mismatch | **MED** | The #961/#946 dead-end pattern: a half-built transaction abstraction that later has to be ripped out. Mitigation: Path C (fence-only floor) is a strict subset that ships value even if Path A/B rollback is deferred; the shared invariant (§4.1) is the durable contract, not the specific rollback mechanism. |

## 8. Multiple path options

### Path A — split pure-planning from actuation + validate-before-first-destructive-op + rollback journal
- **Facet A**: `planZones`/`actuateZoneHostState` split; pure phases + snapshot
  build run before any host mutation; journalled undo for reversible ops; fence
  for irreversible residual.
- **Facet B**: B1 transactional map rollback + B2 fence escalation.
- **Pros**: closest to true atomicity; most failures are pre-actuation; retains
  previous-good on both facets.
- **Cons**: largest refactor (touches the biggest function in the tree); some
  ops irreversible; highest review cost.

### Path B — two-phase prepare/commit with a journalled undo (keep compileZones shape)
- Keep `compileZones` interleaved, but record an undo entry before each
  destructive op and replay in reverse on any later error (including helper
  publish). One `appliedGeneration` advances only after host + maps + helper all
  succeed.
- **Pros**: smaller structural change than A; explicit undo log.
- **Cons**: undo for every op-type is error-prone; undo-of-undo can fail; the
  failing op's own partial state; doesn't shrink the failure window (host still
  mutates before the fallible phases). Weaker than A on the "validate first"
  axis.

### Path C — keep-ctrl-disabled-on-any-apply-failure fail-closed floor (minimal)
- **Facet B**: on `apply_snapshot` rejection in the `samePlanRefresh` leg,
  disable ctrl (fence). No map restore.
- **Facet A**: reorder so the destructive host actuation runs after the pure
  phases + snapshot build (validate-first), and on any host-actuation failure,
  fence ctrl. No rollback journal.
- **Pros**: much smaller; low hot-path cost; directly converts the
  fail-OPEN mismatch into fail-CLOSED (transit dropped, not mis-steered);
  matches the existing #2138/#5680 fence doctrine.
- **Cons**: a fenced apply drops transit until the next successful commit
  (heavier operator impact than a clean rollback); a mid-host-actuation failure
  still leaves partial host topology (but forwarding fenced, so no
  mis-steer — the security-availability mismatch is closed, availability is
  degraded-safe not mismatched).

### Recommendation
**Ship Path C's validate-first reorder + fence as the floor, plus Path A's Facet-B
B1 map rollback** (the map rollback is cheap and content-driven — high value, low
risk), and **defer Path A's full host rollback journal to a follow-up** unless
reviewers judge the fence-only host floor insufficient. Rationale: the
security-availability mismatch (#4959's core) is fully closed by B1+fence; the
host-topology churn (#4960's core) is fully de-risked by validate-first (most
failures never start host mutation) with fence as the safety net. Full host
rollback (journal) is the remaining increment and can be a scoped follow-up
because, post-reorder, the host-actuation failure surface is small. Reviewers
should explicitly rule on whether the host rollback journal is in-scope-required
or defer-acceptable (OQ-1).

## 9. Test plan

- `go build ./...` clean; `go vet ./pkg/dataplane/... ./pkg/daemon/...`.
- **Go unit tests (new):**
  - `manager_compile` tx test: `samePlanRefresh` + injected `apply_snapshot`
    reject → assert maps restored to old snapshot (B1) OR ctrl disabled (B2);
    assert `publishedSnapshot`/`lastSnapshot`/`lastSnapshotHash` unchanged;
    assert `m.lastIngressIfaces` restored. Use the existing
    `lookupUserspaceCtrlForFailClosedHook` + `addrListForLocalSyncHook` seams and
    a fake control socket.
  - `compileZones` plan/actuate test: injected late-phase error (e.g.
    missing screen profile) → assert ZERO host netlink mutation occurred (mock
    netlink); injected mid-actuate error → assert reversible ops rolled back +
    ctrl fenced.
  - Regression: address-only commit still takes the in-place no-restart path
    (assert `programBootstrapMaps`/`ensureProcess` NOT called) — guards against an
    accidental "expand the plan key" fix.
  - #3924 interaction: rollback re-sync during a partial `AddrList` dump does NOT
    prune live local keys.
- **Existing suites that must stay green:** `pkg/dataplane` (`compiler_test.go`,
  `compiler_rxvlan_failclosed_5268_test.go`, `compiler_nat_counter_*`),
  `pkg/dataplane/userspace` (`maps_sync_*_test.go`, manager tests),
  `pkg/daemon` apply tests. Named-test 5× flake check on the new tests.
- **Rust cargo suite** (`make test-rust`): unaffected (no helper wire change) —
  run to confirm no regression.
- **Smoke (loss userspace cluster, at `/engineer` time, not `/research`):** v4 +
  v6, push + reverse, CoS-off + CoS-on; a commit-fail-injection scenario
  (commit a config that trips a runtime phase) to confirm the DUT retains
  forwarding on the previous-good config and does NOT half-migrate. Per
  `feedback_verify_forwarding_with_sustained_iperf` — sustained iperf3 through the
  real DUT, not curl/200.
- **Failover** (`make test-failover`): the map/host paths touch
  cluster-relevant state (RETH VIPs, fabric ifaces) so a failover smoke is
  required before merge per CLAUDE.md.

## 10. Out of scope (explicitly)

- The config-store-commit-vs-dataplane-apply ordering (`store.Commit` promotes
  before `applyConfigLocked`, `daemon_apply.go:369`). This plan makes the
  DATAPLANE apply internally transactional; it does not make the store commit and
  dataplane apply one two-phase transaction. (The store already retains the old
  active for rollback; a full store↔dataplane 2PC is a separate, larger issue.)
- The Rust-side helper transactionality (#4952/#3789 already merged) — no helper
  wire or handler changes proposed.
- Expanding `snapshotBindingPlanKey` to include local/interface-NAT addresses —
  explicitly rejected in §4.2 (would force a helper restart on address-only
  changes).
- ISSU / rolling-upgrade apply paths beyond the standard commit path.
- The `!samePlanRefresh` full-restart path's own transactionality — it already
  restarts the helper (`ensureProcessLocked`) so a reject there stops the new
  process; only note if reviewers find a fail-open there too (OQ-2).

## 11. Open questions for adversarial review (each invitable to PLAN-KILL)

1. **Host rollback scope.** Is the full host-op rollback journal (Path A Facet A)
   in-scope-REQUIRED for this issue, or is validate-first + fence (Path C Facet A)
   the correct ceiling and the journal a defer-acceptable follow-up? Argue for
   PLAN-KILL if you believe fence-only leaves an unacceptable host-topology
   mismatch.
2. **Full-restart path fail-open?** On the `!samePlanRefresh` branch,
   `programBootstrapMapsLocked` runs, then `ensureProcessLocked`, then
   `apply_snapshot`. If `apply_snapshot` is rejected there but the helper was NOT
   restarted (already-running, plan changed but process reused), are the bootstrap
   maps left ahead of the old snapshot with ctrl enabled — a second instance of
   the #4959 bug on the restart path? If so, the transaction must cover both legs.
3. **Host-first vs helper-first ordering.** §4.4 recommends host-actuate before
   helper publish. Is that right? Helper-first would let a host failure leave the
   helper on the new snapshot with host on the old (a different mismatch). Which
   ordering minimizes the worst-case blast radius, and does the answer change the
   rollback design?
4. **Peer-sync suppression for a fenced apply.** Should a fenced/rolled-back
   apply be added to `applyErrSkipsPeerSync` (like the required-protocol-gate
   class) so a partial-apply node does not push the new config to the standby? Or
   does the committed+active store state mean the peer MUST receive it to avoid
   divergence (the #4034 rationale)? This is a genuine tension between #2138
   (don't propagate a disarm) and #4034 (don't diverge nodes).
5. **`BumpFIBGeneration` handling.** Is folding the discarded FIB-bump error into
   the apply result (WARN + surface) correct, or does a failed FIB bump warrant a
   fence (stale FIB entries could mis-forward after an ifindex/MAC change)?
6. **Rollback re-sync correctness.** Does re-running
   `syncUserspaceClassifierMapsLocked(oldSnap)` truly restore the maps to
   previous-good in all cases — including when the old snapshot's local set was
   itself partially kernel-derived (VRRP VIPs added between the two applies)? Is
   there a case where the "restore" installs a state that never actually existed?
7. **Is atomicity even the right frame?** Could a simpler model — never mutate
   host state on a config that hasn't already been fully validated + snapshot-built
   (pure validate-first), and accept fence-on-any-failure — dominate the
   rollback-journal complexity entirely? I.e., is Path C alone the PLAN-READY
   answer and Path A/B over-engineering?
