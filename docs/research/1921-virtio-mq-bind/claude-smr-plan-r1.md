# Claude SMR plan-review — #1921 virtio-MQ forwarding — round 1

**Reviewing:** `docs/research/1921-virtio-mq-bind/plan.md` @ `96eee9025`
**Posture:** hostile (domain SMR + CPU/arch + SW-design). Entered expecting to
find a hole; found several. One was already self-caught (ring-mismatch) during
drafting — that is a yellow flag that the first-pass diagnosis was loose, so I
re-walked the steer/enable/bind path independently.

**Verdict: PLAN-NEEDS-MINOR** — diagnosis of the *enable-gate* mechanism is
solid and code-grounded; but the fix design has a correctness hole (F1), a
sequencing problem (F2), and an under-specified validation loop (F4) that must
be fixed before implementation.

## What the plan gets right (verified)

- Dual all-or-nothing gate is real and the dominant failure: helper
  `helpers.rs:211-217` (`all(b.registered && b.armed)`) AND Go
  `maps_sync.go:411-419` (`probeBindingsReady` requires every registered binding
  armed). One unarmed surplus queue → `ctrl.Enabled` never set → XDP_PASS → no
  SNAT → 0 sessions. Confirmed both sites.
- The ring-mismatch refutation holds: steady-state `ctrl.queue_count` =
  `queueCountFromBindings` (`maps_sync.go:357`) = bound-set count; the
  `workers=1` write at `:155` is `programBootstrapMapsLocked`, `Enabled=0`.
  Modulo is an identity at steady state. (Reviewers should still confirm no path
  publishes qc=1 with Enabled=1.)
- `rx_queue_count` (helpers.rs:820) drives the planned set independent of
  `workers` — the over-provision is real.

## Findings

### F1 (MAJOR) — the channel-pin must be driver-agnostic, or Path A reintroduces the ring-mismatch on `workers < queues` NICs

§5 Path A says pin channels "gated to dataplane virtio/iavf NICs." That is
wrong. The fix has two coupled halves: (i) bind `0..workers-1` instead of
`0..rx_queue_count`, and (ii) make the NIC only RSS-deliver to those queues. If
(i) is applied to **all** drivers (it is a `replan` change) but (ii) — the
channel pin — is virtio-only, then on any NIC where `workers < hw RX queues`,
the NIC still RSS-spreads across all HW queues while only `0..workers-1` have
sockets. `queue_count = queueCountFromBindings = workers`, so
`select_userspace_queue` returns `rx_queue_index % workers`; a packet arriving
on HW queue `workers..N-1` is mapped onto a low queue's socket bound to a
*different* ring → **kernel bound-ring-mismatch drop**. That is exactly the
"refuted" Bug-1, reintroduced on mlx5/i40e the moment an operator sets `workers`
below the VF's queue count. Today it is latent only because the loss config
happens to set `workers == queues`. **The channel reconciliation must apply to
every dataplane NIC** (or, equivalently, the rule must be: bound set == pinned
RSS/channel set == queue_count, enforced uniformly). Plan must drop the
"virtio/iavf only" gating.

### F2 (MAJOR) — Path A is recommended *before* Phase 0 confirms the EBUSY cause; that's backwards

Path A reduces the bound set, but if even one of the `0..workers-1` queues
EBUSYs (the plan's own stale-socket hypothesis 3a), both gates still fail and
the box still forwards nothing. So Path A is only a complete fix if the EBUSY is
purely an over-provision artifact. The plan's §3 admits the EBUSY cause is
unconfirmed and §5 caveats it — but §5's headline still RECOMMENDS Path A. Re-rank:
**Phase 0 (instrumented virtio repro) decides the path.** State the decision
rule explicitly: if Phase 0 shows EBUSY only on surplus (>workers) queues →
Path A suffices; if EBUSY hits the `0..workers-1` set across the
bootstrap→day-0 reconcile → the durable fix is teardown-before-rebind
correctness (close/await the prior generation's `xsk_pool` before re-bind;
reuse `PrepareLinkCycle`/`stop_workers`, `process.go:968`) and Path A is only a
surface-reducer. Do not pre-commit.

### F3 (MINOR) — "one dead queue zeroes the box" is a real fragility bug independent of virtio; say whether we fix it

Both gates are fail-closed by design (don't forward half-configured). Relaxing
to "≥1 armed" (Path C) is NOT a clean fix on its own: with a surplus binding
registered-but-unarmed, `queueCountFromBindings` still counts it, so the shim
steers packets to the unarmed queue and `lib.rs:427` drops them per-queue
anyway — you'd also need RSS constrained to armed queues. So Path C is only
viable as the *full* (gate + RSS) package, which is strictly more work than
Path A. The plan should state this explicitly so a reviewer doesn't propose
"just relax the gate" as a cheap alternative — it isn't.

### F4 (MINOR) — the fix's build→deploy→retest loop on the virtio venue is unspecified

§9 names the virtio repro venue but not how a *new* xpfd+helper build gets onto
it each iteration. A full re-bake per iteration is far too slow. Specify:
deploy the appliance once via `xpf-deploy.py`, then iterate by pushing the
rebuilt `xpfd` + `xpf-userspace-dp` binaries into the running VM (scp +
`systemctl restart xpfd`), not by re-baking. Note this does not exercise the
day-0/bake path (already covered by #1879) — it isolates the dataplane fix.

### F5 (NIT) — quantify the virtio default

Path A with `workers=1` caps virtio to one AF_XDP queue/core. Fine for the
"modest WAN" positioning, but state the rough ceiling and that operators raise
`set system … workers N` (and that doing so now *also* widens the NIC channel
pin). Confirm the fabric parent's TX queue survives a `combined=workers` pin
(F1 in the plan's §7 already flags this — keep it).

## Bottom line

The enable-gate diagnosis is correct and the bug is real. The fix needs:
driver-agnostic channel reconciliation (F1), Phase-0-decides-path sequencing
(F2), an explicit statement that gate-relaxation alone is insufficient (F3), and
a concrete fix-iteration loop on the virtio venue (F4). Address these and this
is PLAN-READY. None of them is a kill — the core approach (reconcile bound set /
RSS / queue_count to a reliably-bindable count, confirm EBUSY cause first) is
sound.
