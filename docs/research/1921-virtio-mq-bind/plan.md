# #1921 — AF_XDP forwarding on virtio_net multi-queue: plan of action

**Status:** DRAFT v1 — pending adversarial plan review (Codex + AGY + Claude SMR)
(ring-mismatch "Bug 1" self-refuted during drafting; primary failure is the
EBUSY → unarmed-surplus → dual all-or-nothing enable gate)

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

### Bug — EBUSY over-provision → unarmed surplus binding → all-or-nothing enable (PRIMARY)

`replan_bindings_from_candidates` (`userspace-dp/src/server/helpers.rs:745-779`)
plans a binding for **every** sysfs RX queue (`rx_queue_count`, `:820`) on every
interface — 4 on a 4-channel virtio NIC — **independent of `workers`**. With
`workers=1`, all 4 are owned by worker 0 and bound as private-UMEM sockets in
its setup loop. Surplus binds can fail EBUSY; the deep-research verdict is that
EBUSY means the `(ifindex, queue_id)` is already held — a stale/leaked socket
from a prior bind generation not released before rebind (virtio pool-disable is
async), the same class as the existing mlx5 `SetDeferWorkers` /
`PrepareLinkCycle→stop_workers` workaround (`pkg/dataplane/userspace/process.go:968`),
whose timing is insufficient here. The retry loop spins 20×250ms
(`afxdp/mod.rs:310-311`, `afxdp/bind.rs:423`) then `set_error`s; the failed
binding stays `registered` but never `armed`/`xsk_registered`
(`coordinator/refresh_bindings.rs:226`). The dataplane-enable gate then fails:

```rust
// userspace-dp/src/server/helpers.rs:211-217
state.status.enabled = forwarding_armed && forwarding_supported
    && !bindings.is_empty()
    && bindings.iter().all(|b| b.registered && b.armed);   // ALL — one bad queue zeroes it
```

The same all-or-nothing condition is enforced a **second** time on the Go side:
`applyHelperStatusLocked` computes `probeBindingsReady` by requiring every
registered binding (ifindex>0) to be `Armed` (`maps_sync.go:411-419`); one
unarmed surplus queue keeps `probeBindingsReady=false`, so `ctrl.Enabled` never
flips to 1 (`:444` onward). Result: ctrl flag 0 → shim `cpumap_or_pass` →
XDP_PASS everywhere → kernel path has no SNAT → 0 sessions. **One EBUSY queue
disables the whole dataplane**, via two independent all-or-nothing gates.

### Why the EBUSY fires at all (must be confirmed in Phase 0)

On a fresh standalone appliance boot there is no obvious prior worker generation,
yet surplus queues EBUSY. Leading hypotheses, to be distinguished by an
instrumented repro: (a) the bootstrap→day-0-commit sequence runs two Compile
reconciles; the second rebinds queues whose first-generation XSK sockets the
helper has not yet released (virtio `xsk_pool` disable is async) → stale-socket
EBUSY; (b) some queues simply never bind on first attempt and the retry races
teardown. The fix's durability depends on which — see §5.

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
that actually binds + arms, and the enable gate does not require binds on queues
the NIC will not deliver to.** Today the bound set = sysfs RX-queue count and
`queue_count` already tracks the bound set (`queueCountFromBindings`), so the
steering is self-consistent — the break is purely that surplus/unreliable queues
fail to arm and the two all-or-nothing gates then disable everything.

### Path A (RECOMMENDED) — reconcile NIC channels to `workers`

Pin `ethtool -L <dataplane-if> combined = workers` (clamped to the NIC's
hardware max) **before** any XSK bind, at clean helper startup and after
`stop_workers` on reconcile. Then bind exactly queues `0..workers-1`
(`queueCountFromBindings` then reports `workers`, keeping the shim steering
consistent). Effects:
- Only `workers` queues are planned/bound → **no surplus queues to fail-arm**,
  so neither all-or-nothing gate (helper `enabled`, Go `probeBindingsReady`) is
  held down → forwarding enables on the queues that bound.
- NIC delivers only on `workers` RSS queues, all of which are owned → no flow is
  RSS-hashed to a queue with no socket.
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
`replan_queues` (bind `0..workers`, not `0..rx_queue_count`), a new channel-pin
step in the Go control plane (or helper) gated to dataplane virtio/iavf NICs and
ordered before bind, and docs.

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

### Recommended composition

Path A as the primary fix. Add a **narrow slice of C** as defense-in-depth: the
enable gate should not be held down by a binding for a queue the NIC no longer
delivers on — but with Path A there are no such surplus bindings, so this is a
belt-and-suspenders guard, scoped to "armed per owned queue," not a full
degraded mode. Defer the EBUSY-stale-socket root cause (Path-C teardown
hardening) behind a Phase-0 instrumented repro: if Path A's channel-pin removes
the EBUSY entirely (because we never bind surplus queues, and the pin is ordered
after stop_workers), no further teardown work is needed; if EBUSY persists on
the `0..workers-1` set across reconcile, fix the socket lifecycle then.

## 6. API / interface preservation

- No control-protocol wire change required for Path A: `ctrl.queue_count` and
  `workers` already exist; we change how the bound set + NIC channels are
  derived, not the schema. (Confirm whether a new snapshot field is needed to
  carry "desired channels" vs computing in the helper.)
- `replan_queues` signature unchanged; its queue-count source changes from
  `rx_queue_count` to `min(rx_queue_count, workers)` (or the pinned count).
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
- **Phase 0 (instrument + repro):** deploy the #1879 appliance on a virtio
  multi-queue host (≥2 combined channels) via `xpf-deploy.py`; confirm 100% loss
  + the EBUSY log; add a counter/trace distinguishing ring-mismatch redirect
  drops from not-ready drops to PROVE Bug 1 is live (not just inferred).
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
