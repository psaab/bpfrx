# #1921 — AF_XDP forwarding on virtio_net multi-queue: plan of action

**Status:** DRAFT v4 — addresses Codex r3 PLAN-NEEDS-MAJOR (effective_rx_queues
vs the global-min uniform planner; two stale-text scrubs) + AGY r3
PLAN-NEEDS-MINOR (which CONFIRMED the EBUSY loop root cause in code). Evolution:
r1 ring-mismatch refuted; r2 the all-or-nothing gate refuted (`armed` is a
request flag); r3 the EBUSY loop pinned to a concrete bug — `rebind::handle`
double-stops workers, so `tear_down`'s `had_live_workers` is false and the 500ms
ZC-teardown quiesce is bypassed (verified, §3). Fix: primary = remove the rebind
double-stop so the quiesce applies; surface-reducer = uniform-target channel/RSS
reconciliation across all dataplane NICs (§6). Phase 0 confirms the
first-attempt trigger + quiesce adequacy.

## 1. Issue framing

A freshly-deployed appliance (#1879 image) on virtio_net NICs with multiple
combined channels boots, applies day-0 config, brings interfaces up, and answers
host-inbound ping (control plane healthy) but **forwards zero transit traffic**
(0 sessions, 100% LAN→WAN loss). The helper also loops on `libxdp private
bind: Device or resource busy` (EBUSY) on a subset of queues. mlx5-VF (loss
cluster) and i40e-PF (standalone VM) are unaffected. A primary-sourced
deep-research pass confirmed virtio_net fully supports per-queue AF_XDP
(ZC since ~6.11; appliance kernel 7.0 is fine) — so this is an xpf binding-model
bug, not a virtio limitation.

## 2. Honest scope/value framing

The appliance cannot forward on its most portable, recommended-for-labs NIC
backing (bridges/virtio). Fixing it is what makes the #1879 image a real
forwarding appliance on commodity virtio hosts (the common incus/libvirt case).
The fix is also a latent-correctness issue for ANY deployment where the
configured `workers` count is less than the NIC's RX-queue count — not just
virtio. *If reviewers conclude the value is too small to justify the churn, or
that a path is architecturally wrong, PLAN-KILL / PLAN-NEEDS-MAJOR is an
acceptable verdict.*

## 3. The bug

### Considered and REFUTED — ring-mismatch silent drop

An earlier framing held that the shim's `select_userspace_queue`
(`userspace-xdp/src/lib.rs:1379-1395`, `rx_queue_index % queue_count`) would map
packets from high RX queues onto a low queue's socket and the kernel would drop
them on a bound-ring mismatch — because `ctrl.queue_count` is set to
`max(cfg.Workers, 1)=1` at `maps_sync.go:155`. **Refuted by reading the publish
path.** That `:155` write is `programBootstrapMapsLocked` with `Enabled=0`
(bootstrap only). The *steady-state* authoritative publish is
`applyHelperStatusLocked` (`maps_sync.go:353-357`), which sets
`QueueCount = queueCountFromBindings(status.Bindings)` = `maxQueueID+1` over
registered bindings = **4** on a 4-queue plan. So at the moment `ctrl.Enabled`
flips to 1, `queue_count == bound-queue count`, the modulo is an identity, and
each queue's packets target a socket bound to that same ring. No mismatch. The
shim steering is self-consistent with the bound set; this is **not** the live
failure.

### Confirmed: over-provisioning

`replan_bindings_from_candidates` (`userspace-dp/src/server/helpers.rs:745-779`)
plans a binding for **every** RX queue on every interface — the count comes from
the snapshot's `rx_queues` (`:698`), which Go stamps from sysfs
(`pkg/dataplane/userspace/interfaces.go:173`) — **independent of `workers`**.
With `workers=1`, all 4 queues of a 4-channel virtio NIC are owned by worker 0
and bound as private-UMEM sockets in its setup loop. The bind retry loop spins
20×250ms on EBUSY (`afxdp/mod.rs:310-311`, `afxdp/bind.rs:423`) then `set_error`s.

### Corrected mechanism: per-queue READY withholding (NOT a whole-dataplane gate)

The v1 of this plan claimed a failed bind leaves the binding unarmed and the
all-or-nothing `enabled`/`probeBindingsReady` gates then disable the entire
dataplane. **That is wrong** (Codex r1, verified). `armed` is a control-plane
*request* flag, set uniformly for every registered binding regardless of bind
outcome:

```rust
// userspace-dp/src/server/helpers.rs:485-489  set_bindings_forwarding_armed
binding.armed = armed && binding.registered;   // NOT derived from bind success
```

Bind success is carried by `bound` / `xsk_registered` / `ready`
(`refresh_bindings.rs:226`: `ready = registered && bound && xsk_registered &&
heartbeat_fresh`). So a failed-bind queue is `registered=true, armed=true,
ready=false`. The `all(registered && armed)` gate (`helpers.rs:210-217`) and Go
`probeBindingsReady` (`maps_sync.go:411-419`) therefore do **not** necessarily
trip on a per-queue bind failure. What actually gates per queue is the BPF
binding-map READY flag (`maps_sync.go:97`: `Registered && Armed && Ready`):
READY is withheld for the failed queue, and the shim drops that queue's transit
(`userspace-xdp/src/lib.rs:427`, `binding_not_ready` → `drop_degraded_transit`).
So the proven mechanism is a **per-queue** transit drop on the queues that fail
to bind — not a whole-dataplane disable.

### Unproven: why the live result was 0 sessions / 100% loss

A per-queue drop does not by itself explain a *total* forwarding outage. Two
candidate explanations, to be distinguished by Phase 0 (do NOT assume):
- **(A) All queues fail.** With `workers=1` the bootstrap→day-0-commit sequence
  runs two Compile reconciles; if the second generation rebinds all 4 queues
  before the first generation's `xsk_pool`s are released (virtio pool-disable is
  async), **every** queue EBUSYs → no queue ever READY → all transit dropped →
  0 sessions. This makes a **stale-socket-on-rebind race** the primary cause and
  over-provisioning a multiplier (4 queues to leak instead of 1). The existing
  mlx5 teardown workaround (`PrepareLinkCycle`→`stop_workers`,
  `process.go:968`) is the same problem class; its timing is evidently
  insufficient on virtio.
- **(B) ctrl never enables.** Some other readiness condition
  (`xskReceiveLive` RX-progress probe, neighbor gen) holds `ctrl.Enabled=0`
  because no queue ever shows RX. 

Phase 0 must capture, per queue: bind outcome (`bound`/`xsk_registered`/
`last_error`), `ctrl.Enabled`, and the shim drop reason
(`binding_missing`/`binding_not_ready`) — to pin the real chain before any fix
is chosen. The fix's shape (teardown-hardening vs channel-reconciliation vs
both) depends on the answer.

### CONFIRMED root cause of the EBUSY loop (AGY r3, verified in code)

The rebind recovery path bypasses the very quiesce that exists to prevent this
EBUSY. `rebind::handle` (`userspace-dp/src/server/handlers/rebind.rs:16`) calls
`guard.afxdp.stop()` — which clears `coord.workers.handles` — *before*
`reconcile_status_bindings` → `tear_down`. Inside `tear_down`
(`coordinator/reconcile/teardown.rs:14`), `had_live_workers =
!coord.workers.handles.is_empty()` therefore evaluates **false**, so the
`thread::sleep(500ms)` quiesce at `teardown.rs:44-46` — whose comment says it
"avoids EBUSY when a later snapshot refresh rebuilds the same queue set
immediately after shutdown" (ZC queue teardown is async, not synchronously
reusable) — is **skipped**. New socket creation races the kernel's still-pending
`xsk_pool` teardown → EBUSY → the 5s bind-retry loop fails → the Go busy-binding
watchdog fires after 5s → triggers another `rebind` → double-stop → quiesce
skipped again → **infinite EBUSY/rebind loop**. This is the live failure's
engine. The first-attempt EBUSY trigger (what kicks off the first rebind on a
fresh virtio boot) is still for Phase 0 to confirm, but the *loop* — why it
never recovers — is now code-proven. **Fix:** do not call `guard.afxdp.stop()`
in `rebind::handle`; let the `reconcile`/`tear_down` pipeline stop workers so
`had_live_workers` is captured truthfully and the 500ms quiesce applies. (Phase
0 also validates whether 500ms is adequate for virtio ZC under load, or must be
adaptive.) This likely makes the rebind-double-stop fix the **primary** fix and
channel-reconciliation the surface-reducer.

## 4. What's already shipped / relevant

- `select_userspace_queue` already *intends* ingress-queue-pinned handoff and has
  a partial missing-binding fallback (`lib.rs:404`) — ineffective for Bug 1
  because it keys on `flags==0`, not on a bound-ring mismatch.
- `PrepareLinkCycle`/`stop_workers` (`process.go:968`) is an existing
  teardown-before-rebind primitive (built for mlx5 RETH-MAC EBUSY) we can reuse.
- The Go control plane already owns `ethtool` (`pkg/daemon/rss_indirection.go`)
  — `-X` indirection today, no `-L` channel setting anywhere (confirmed: no
  `set_channels` in tree).
- `workers` is operator config (`set system … workers N`,
  `compiler_system.go:450`), default 1.

## 5. Concrete design — Multiple Path Options

The invariant to restore: **every NIC RSS-active queue has exactly one socket
that actually binds + goes READY.** Today the bound set = sysfs RX-queue count
and `queue_count` tracks the registered set (`queueCountFromBindings`), so the
steering is self-consistent — the break is (1) the confirmed rebind double-stop
that bypasses the ZC-teardown quiesce and loops on EBUSY (§3), and (2) the
over-provisioned bound set, which multiplies the number of queues that must bind
cleanly. (This is NOT a whole-dataplane enable-gate effect — per §3, `armed` is
a request flag, so a failed bind does not trip `enabled`/`probeBindingsReady`;
the per-queue effect is READY withholding → `binding_not_ready` transit drop.)

### Path A (RECOMMENDED) — reconcile NIC channels to `workers`

Pin `ethtool -L <dataplane-if> combined = workers` (clamped to the NIC's
hardware max) **before** any XSK bind, at clean helper startup and after
`stop_workers` on reconcile. Then bind exactly queues `0..workers-1`
(`queueCountFromBindings` then reports `workers`, keeping the shim steering
consistent). Effects:
- NIC delivers only on `workers` RSS queues, all of which are owned by a socket
  that binds → no flow is RSS-hashed to a queue whose binding never goes READY
  (which the shim would drop as `binding_not_ready`, `lib.rs:427`).
- Fewer queues = smaller EBUSY surface and fewer sockets to leak across a
  rebind. (This does NOT by itself prevent the EBUSY race on the surviving
  queues — see teardown co-primary fix and the §3 caveat. It is not a
  whole-dataplane "gate" effect: per the r1 correction, `armed` is a request
  flag, so a failed bind does not trip `enabled`/`probeBindingsReady`.)
- Ordering avoids the "channels too low for existing ZC sockets" refusal: set
  channels only when no XSK is bound (fresh start, or post-`stop_workers`).
- mlx5/i40e: `workers` already == queue count, so `combined=workers` is a no-op
  → no regression.
- **Caveat:** this reduces the bound set but does not by itself prove the EBUSY
  is gone — if the EBUSY is a stale-socket race (§3 hypothesis a), it can still
  fire on the `0..workers-1` set across a reconcile. Phase 0 must confirm.

Tradeoff: virtio default `workers=1` caps the dataplane to one queue (≈ one
core of AF_XDP throughput). Acceptable for the "labs/modest WAN" positioning;
operators raise `set system … workers N` for more. Implementation touches:
`replan_queues` (its queue count comes from the reconciled `effective_rx_queues`
in the snapshot — see §6 for the uniform-target constraint), a new
channel-reconciliation step in the Go control plane applied to **every**
dataplane NIC (not just virtio — see hazard 1) ordered before snapshot build,
and docs.

### Path B — default `workers` to the NIC RX-queue count

When `workers` is unset, derive it from `rx_queue_count` so `queue_count ==
queues`, bind all, RSS uses all. Full parallelism, no channel mutation.
Tradeoffs: higher default CPU (4 workers on a 4-vCPU box leaves nothing for the
control plane); does NOT address Bug 2's EBUSY if it is a stale-socket race
(orthogonal); a NIC with more queues than vCPUs over-subscribes. Weaker venue
fit for the "modest" default.

### Path C — degraded-mode enable + RSS-to-bound-subset

Keep over-provisioning but (a) change the enable gate to "≥1 armed binding per
forwarding interface" and (b) constrain RSS indirection (`ethtool -X`) to the
successfully-bound queues, and (c) harden the shim fallback to redirect by
actual `rx_queue_index` whenever the selected binding's bound ring mismatches.
Most general (tolerates partial binds on any driver) but the largest semantic
change: "enabled" could mask real partial-bind failures, and RSS reprogramming
mid-life is fiddly. Higher risk; recommend only as defense-in-depth on top of A.

### Recommended composition — Phase 0 decides, two likely co-primary fixes

Do NOT pre-commit to a single path. **Phase 0 instrumented repro first** (it is
cheap relative to a wrong fix). Decision rule:

- If Phase 0 shows EBUSY confined to surplus (>`workers`) queues and the
  `0..workers-1` set binds cleanly → **Path D (queue reconciliation)** is the
  fix: stop planning `0..sysfs_rx_count`; plan `0..workers` AND reconcile the
  NIC so it only RSS-delivers to those queues. This is the old "Path A" but
  promoted and made driver-agnostic + ordering-correct (see hazards below).
- If Phase 0 shows EBUSY on the `0..workers-1` set across the bootstrap→day-0
  double reconcile (explanation A in §3) → **teardown-before-rebind correctness
  is co-primary**: the helper must release (and confirm the kernel has torn
  down) the prior generation's `xsk_pool`s before rebinding the same
  `(ifindex, queue_id)`. Reuse/extend `PrepareLinkCycle`→`stop_workers`
  (`process.go:968`); the current timing is insufficient on virtio.

Most likely both are needed: reconcile the queue set (smaller surface, correct
RSS) AND fix the rebind race. Path B (default workers = RX-queue count) and a
full Path C (degraded enable + RSS-constrain) are documented above but are NOT
recommended: B raises default CPU and does not touch the EBUSY race; C is more
work than D for the same outcome (see SMR F3 — gate relaxation alone is
insufficient because `queueCountFromBindings` still counts unarmed surplus and
the shim per-queue READY gate drops those packets anyway).

### Implementation hazards the fix MUST handle (reviewer-surfaced, all verified)

1. **Driver-agnostic, operator-gated reconciliation, never a silent reduction**
   (Codex #4, SMR F1). If we plan `0..workers` but pin channels only on virtio,
   any NIC with `workers < hw RX queues` (e.g. an operator setting `workers=2`
   on a 6-queue mlx5 VF) gets the ring-mismatch back: RSS spreads to queues with
   no socket, `queue_count=workers` makes the modulo map them onto the wrong
   ring → kernel drop. The reconciliation (channel/RSS = bound set) must apply
   to **every** dataplane NIC, with explicit "`workers` = desired queue fanout"
   semantics — and must never reduce a NIC below the fanout the operator
   intends. `rss_indirection.go:164` already special-cases mlx5 workers==1;
   integrate, don't fight it.
2. **`ethtool -L` ordering** (Codex #3). Rust trusts `snapshot.rx_queues`
   (`helpers.rs:698`), stamped by Go from sysfs (`interfaces.go:173`). The
   channel set MUST happen in Go **before** snapshot construction, or the
   snapshot must carry the explicitly-reconciled count. A helper-side pin after
   snapshot receipt is too late.
3. **`ethtool -L` async-teardown retry** (AGY #3). Running `-L` right after a
   helper stop can fail while the kernel is still asynchronously tearing down ZC
   socket contexts — wait/retry with backoff.
4. **Non-fatal channel set** (AGY #4). Many VF drivers don't support `ethtool
   -L`; failure must NOT fail-close the dataplane — log and proceed with the
   actual queue count.
5. **Exclude fabric/generic-mode parents** (Codex #5, AGY #4). Applying `-L` to
   the fabric IPVLAN parent (`ge-0-0-0`, xdpgeneric) can reset the link →
   packet loss + VRRP/control disruption on IPVLAN children, and may EBUSY.
   Exclude fabric parents from channel reconciliation; validate fabric TX still
   works.
6. **Auto-rebind must do teardown-before-rebind, or it loops** (refines AGY #2;
   AGY's "blind spot" framing was REFUTED by Codex r2 and verified false). The
   busy-bindings watchdog DOES fire on the all-queues-EBUSY case:
   `hasBusyBindingsWedgeLocked` (`maps_sync.go:1265-1285`) triggers on
   `registeredArmed > 0 && bound == 0 && ready == 0 && busyErr`, and
   `registeredArmed` counts any registered+armed binding — which a failed-bind
   queue still is (`armed` is a request flag), so the wedge is detected (unit
   test `manager_test.go:2943` covers queue-0-busy). The real concern is that
   the auto-rebind path re-hits the same stale-socket EBUSY and re-wedges; the
   teardown-before-rebind fix must therefore live in the rebind path too, not
   just first bind.

## 6. API / interface preservation

- No control-protocol wire change required for Path A: `ctrl.queue_count` and
  `workers` already exist; we change how the bound set + NIC channels are
  derived, not the schema. (Confirm whether a new snapshot field is needed to
  carry "desired channels" vs computing in the helper.)
- **`effective_rx_queues` invariant — UNIFORM across dataplane NICs (resolves
  Codex r2 #2 and r3 main blocker).** Critical constraint:
  `replan_bindings_from_candidates` (`helpers.rs:745`) takes the GLOBAL MINIMUM
  queue count across all candidate interfaces and emits `0..queue_count` for
  EVERY interface — a single uniform count, NOT per-interface (codified by
  `queue_planner_uses_smallest_queue_count`, `main_tests.rs:609-631`). So the
  reconciliation MUST produce one uniform target that every dataplane NIC
  actually RSS-honors; a per-interface "bind all of NIC B's queues" is
  unimplementable without reworking the planner. Definition:
  - `target = min(workers, min hw-max-combined across reconcilable dataplane
    NICs)` — uniform.
  - For each dataplane NIC (fabric/generic parents excluded — hazard 5), make it
    deliver only to `0..target-1`: prefer `ethtool -L combined target`; if the
    driver lacks `-L` (many VFs), fall back to constraining the **RSS
    indirection table** via `ethtool -X` to `0..target-1` (the codebase already
    drives `-X`, `rss_indirection.go`). Either achieves "NIC delivers only to
    the bound queues."
  - If a NIC supports NEITHER `-L` nor `-X` and natively delivers on more than
    `target`, uniformity is impossible without dropping its high-queue traffic.
    Out of scope: **require homogeneous, constrainable dataplane NICs** (true for
    both venues — all-virtio appliance, all-mlx5 loss). Document this limit; do
    not silently clamp (the wrong-ring drop).
  - The reconciliation is **transactional**: compute `target`, apply to all
    dataplane NICs, verify each honors it, THEN build the snapshot stamping
    `rx_queues = target` uniformly. Rust binds `0..target-1` (global-min planner
    unchanged). Since Rust trusts `snapshot.rx_queues` (`helpers.rs:698`), the
    pin/RSS-constrain must complete in Go before snapshot construction
    (Codex #2/#3); a helper-side recompute is too late.
- `replan_queues` signature unchanged; its queue-count source becomes the
  snapshot's uniform reconciled `target`, not raw sysfs.
- Operator-facing `workers` semantics unchanged; document the new
  channel-reconciliation behavior.

## 7. Hidden invariants the change must preserve

- **Ordering:** channel-set MUST precede any XSK bind and MUST follow
  `stop_workers` on reconcile, or it hits the "channels too low for existing ZC
  sockets" EINVAL (the live symptom). 
- **mlx5/i40e no-op:** `combined=workers` must be a no-op when already equal;
  never reduce a NIC that legitimately wants more queues than `workers` if the
  config intends full fan-out (decide: does Path A clamp mlx5 to workers? On
  loss workers=6=queues so equal — but assert no reduction below the configured
  fan-out).
- **HA / fabric:** fabric parent (ge-0-0-0, xdpgeneric) needs ≥1 TX queue; the
  channel-pin must not zero it. RETH MAC link-cycle path already does
  stop_workers — the pin must integrate with that sequence, not race it.
- **Heartbeat/ready gating** unchanged; the shim's per-queue READY + heartbeat
  path stays.

## 8. Risk assessment

| Class | Level | Notes |
|---|---|---|
| Behavioral regression | MED | channel mutation on dataplane NICs; mlx5/i40e must be provably no-op; fabric TX queue must survive |
| Lifetime/borrow | LOW | no Rust ownership change for Path A (queue-count arithmetic + an ethtool call) |
| Performance regression | LOW-MED | virtio capped to `workers` queues by design; mlx5/i40e unchanged |
| Architectural mismatch | LOW | Path A restores the documented one-XSK-per-ingress-ring invariant; matches deep-research recommendation |

## 9. Test plan

**Repro venue is virtio, NOT the loss mlx5 cluster.** The bug cannot reproduce
on loss (workers==queues). Required:
- **Phase 0 (instrument + repro) — MANDATORY FIRST, decides the fix path:**
  deploy the #1879 appliance on a virtio multi-queue host (≥2 combined channels)
  via `xpf-deploy.py`; confirm the outage and capture, per queue: bind outcome
  (`bound`/`xsk_registered`/`last_error`) and the shim drop reason
  (`binding_missing` vs `binding_not_ready` — existing trace stages in `lib.rs`).
  Capture the FULL ctrl-enable state machine, not just final `ctrl.Enabled`
  (Codex r2 #4): `ctrl.Enabled` transitions, `probeBindingsReady`,
  `neighborSyncReady`, `xskLivenessProven`, `xskLivenessFailed`
  (`maps_sync.go:444-501`). This distinguishes §3 explanation A (all queues
  EBUSY, stale-socket race — `bound==0` everywhere, `last_error` resource-busy)
  from B (ctrl enables then `xskLivenessFailed` flips it back off because no
  queue shows RX) and tells us whether teardown-hardening, queue-reconciliation,
  or both are required.
- **Fix-iteration loop (SMR F4):** after the one-time appliance deploy, iterate
  the fix by pushing rebuilt `xpfd` + `xpf-userspace-dp` into the running VM
  (`scp` + `systemctl restart xpfd`), NOT by re-baking the image (too slow; the
  bake/day-0 path is already covered by #1879).
- **Phase 1 (fix) acceptance on virtio:** clean deploy → LAN→WAN v4+v6 ping +
  iperf3 push/reverse + SNAT session install, 0 transit loss; `show security
  flow session` non-zero; no EBUSY loop; helper `enabled=true`.
- **Regression on loss mlx5 cluster (the standard smoke):** full matrix
  (v4+v6 × push+reverse × CoS off/on × per-class) — prove `combined=workers`
  is a no-op and nothing regresses. This is where the existing smoke gate runs.
- **Failover** (`make test-failover`) if any cluster/bind-lifecycle code is
  touched.
- Rust + Go unit suites; 5× flake on any new/most-affected test.

This double-venue requirement (virtio repro + mlx5 regression) is itself a
reviewer question — see §11.

## 10. Out of scope (explicit)

- Path-C full degraded-mode enable + RSS reprogramming (defer unless Phase 0
  shows EBUSY persists on the `0..workers-1` set).
- In-place upgrade (#1917), distribution (#1922-#1924), forwarding acceptance
  harness (#1926) — separate issues.
- iavf-specific generic-mode tuning beyond making bind succeed.

## 11. Open questions for adversarial review

1. **[RESOLVED during drafting] Ring-mismatch was refuted.** The steady-state
   `ctrl.queue_count` is published by `applyHelperStatusLocked`
   (`maps_sync.go:353-357`) as `queueCountFromBindings` = bound-queue count (4),
   not the bootstrap `:155` `workers=1` (which is `Enabled=0`). So the modulo is
   an identity and there is no bound-ring mismatch. Reviewers: please
   double-check this publish-ordering claim — if a path can leave `queue_count=1`
   live while `Enabled=1`, Bug-1 returns.
2. **Does Path A's channel-pin actually clear the EBUSY**, or is the EBUSY a
   stale-socket race that recurs even on `0..workers-1` across a reconcile?
   Phase 0 must answer before committing to "no teardown work needed."
3. **Channel-pin ownership:** Go control plane (owns ethtool, but must order vs
   helper bind across the control socket) or the helper (owns bind ordering, but
   would need ethtool ioctl/CAP_NET_ADMIN)? Which is less racy?
4. **mlx5 clamp hazard:** should Path A ever *reduce* combined channels? If an
   operator sets `workers` < mlx5 queues intentionally, pinning combined=workers
   reduces RSS fan-out and throughput. Is that desired, or should we instead
   constrain RSS indirection and leave channels alone on mlx5?
5. **Fabric/IPVLAN parent:** does pinning combined on a fabric parent
   (xdpgeneric, ge-0-0-0) break fabric TX or the IPVLAN child? 
6. **Is reducing virtio to 1 queue an acceptable default**, or does the value of
   the appliance demand Path B (workers=queues) so virtio gets multi-core
   throughput out of the box?
