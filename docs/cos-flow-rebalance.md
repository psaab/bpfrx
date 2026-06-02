# Reactive cross-worker flow rebalance (`class-of-service flow-rebalance`, #1748)

> **Default-OFF, opt-in.** Absent config ⇒ the userspace-dp controller is
> never constructed, no ethtool ioctl socket is opened, zero ntuple rules are
> installed, and the per-tick decision loop never runs. The forwarding path is
> byte-identical to a build without this feature when the knob is unset.

## What it does

The per-flow throughput coefficient-of-variation (CoV) on shaped ports swings
14–29% under many concurrent flows because RSS hashes the N flows unevenly
across the NIC's RX queues. Each RX queue maps to one worker, so workers serve
different flow *counts*, and a worker's fixed capacity splits among *its*
flows — slow flows on the crowded worker, fast flows on the idle one.

The #1746 equal-flow cap can only clip fast flows *down*; it cannot lift slow
flows. The only lever that lifts slow flows **and** preserves aggregate
throughput is moving an established flow off an overloaded worker onto an idle
one. This controller does that automatically: it observes per-worker byte-rate
imbalance and, when the imbalance persists, installs one exact-5-tuple ntuple
flow-steering rule (`ethtool -N`-style, via a direct `SIOCETHTOOL` ioctl) that
re-pins the heaviest flow on the hottest worker to the least-loaded worker's RX
queue.

Measured in the R1 spike: established-flow mid-flight re-pin took per-flow CoV
from 16.8% → 2.3–4.2% while *raising* aggregate throughput.

## Configuration

```
set class-of-service flow-rebalance imbalance-threshold 130
set class-of-service flow-rebalance rebalance-interval 1
set class-of-service flow-rebalance max-rules 64
```

Each sub-leaf is individually optional, but the `flow-rebalance` block is
created by setting at least one of them. Setting any one sub-leaf enables the
controller; the unset sub-leaves take the defaults below.

| Leaf | Units | Default | Range | Meaning |
|---|---|---|---|---|
| `imbalance-threshold` | percent of mean | 130 | 101–1000 | Move only when the hottest worker's byte-rate exceeds this percent of the mean (130 = 1.30×). |
| `rebalance-interval` | seconds | 1 | 1–3600 | Minimum dwell between rule installs (one move per interval). |
| `max-rules` | rules | 64 | 1–1024 | Hard cap on concurrently-installed ntuple rules per interface. At the cap the controller STOPS — it never evicts an existing rule. |

To disable, delete the block:

```
delete class-of-service flow-rebalance
```

On disable (or any config change to the block), every installed rule is torn
down — a still-live move hands ownership back to the original worker before its
rule is removed, so no flow is dropped and no orphan hardware rule survives.

## Selection logic (why it does not thrash)

Per tick (coordinator status cadence, ~1 Hz — never per-packet):

1. Derive per-worker byte-rate over the window.
2. If `max_worker / mean > imbalance-threshold` **and** it has persisted for at
   least two consecutive ticks (hysteresis), consider a move.
3. Pick the **heaviest** flow on the **hottest** worker whose move to the
   **least-loaded** worker most flattens the per-worker byte-rate vector,
   subject to:
   - **magnitude guard** — the flow's rate must be ≤ ½ the source-destination
     gap, so the move cannot make the destination the new hottest worker;
   - **ε-band** — the projected byte-rate CoV must improve by more than a small
     epsilon, so marginal moves are skipped;
   - **per-flow cooldown** — a flow re-pinned within several intervals is
     ineligible (oscillation guard);
   - **one move per `rebalance-interval`** (dwell).
4. At `max-rules`, STOP (no eviction).

The objective is monotone under the ε-band over a finite flow set, so it
terminates and cannot oscillate.

## Correctness: the move is a barriered ownership transfer

Re-pinning a flow is not free — the old worker (W_old) keeps a stale forward
session entry whose normal GC/purge/terminal cleanup would cascade-delete the
shared session-map entry, conntrack mirror, and SNAT allocation that the new
worker (W_new) is now forwarding against. The controller therefore performs a
genuine ownership transfer:

- **Forward barrier (install):** promote W_new's pre-replicated session to a
  local owner (`RebalancedOwner`) and block on its ack; then demote W_old's
  copy to an inert, cleanup-suppressed `RebalancedOut` and block on its ack;
  *then* install the rule. Because the worker command queues are independent
  per-worker, the ack barrier is what guarantees W_new is committed as owner
  before W_old is demoted — there is always ≥ 1 cleanup owner.
- **Reverse barrier (rollback / teardown of a live move):** restore W_old to
  owner and block on its ack, delete the rule, then demote W_new back to a
  replica. Applying the demote first would re-open a zero-owner window.

`RebalancedOut` is suppressed at every shared-state release/delete site (GC
expiry, worker purge, terminal-filter, SNAT release, `DeleteSynced` broadcast,
peer export, `demote_owner_rg`/`refresh_owner_rgs`). `RebalancedOwner` behaves
like a normal local owner for cleanup/export/sync and demotes to `SyncImport`
on a real RG failover like `ForwardFlow`.

## HA / failover behavior — fairness resets after a failover

> **Operationally important.** After a chassis-cluster failover, the new
> primary node has **no ntuple rules** installed (the rules are local NIC state
> on the node that was active; they do not replicate to the standby in this
> increment). Traffic therefore falls back to plain RSS hashing on the new
> primary.

This is **correct** but **not immediately fair**: the per-flow CoV will jump
back toward the natural RSS imbalance (14–29%) immediately after a failover,
then re-converge toward the balanced floor (~3–4%) as the controller observes
the imbalance on the new primary and re-installs rules over the next several
`rebalance-interval`s. No connectivity is lost across the failover — only the
fairness optimization resets and rebuilds. Forward-only, single-node re-pin is
HA-*correct* (the pre-replicated session substrate forwards on the new worker);
peer rule-mirroring for sustained post-failover fairness is a documented
follow-up (R4), out of scope for this increment.

## Observability

Per-interface Prometheus gauges/counters (`{ifindex}` label):

- `xpf_userspace_flow_rebalance_rules_active` — installed rules now.
- `xpf_userspace_flow_rebalance_installs_total` / `_deletes_total`.
- `xpf_userspace_flow_rebalance_moves_skipped_total{reason}` — why a candidate
  move was not taken (`balanced`, `cooldown`, `magnitude`, `epsilon`,
  `budget_exhausted`, `barrier_failed`, `dwell`, `restore_failed`).
- `xpf_userspace_flow_rebalance_worker_byterate_cov` — the live per-worker
  byte-rate CoV the controller observed at the last tick (this is the metric
  the feature is trying to drive down).

## Hardware support

Exact and masked ntuple steering requires a NIC whose driver supports
`ETHTOOL_SRXCLSRLINS` flow-classification rules (verified on the loss cluster's
mlx5_core SR-IOV VFs). On a NIC without support the controller logs
`EOPNOTSUPP` once and skips that interface; the default forwarding path is
unaffected.

## Scope (this increment)

- **Forward-direction only.** A `-R` / reverse-direction flow needs a reverse
  rule pair (R2, follow-up).
- **Single-node.** No peer rule-mirroring across failover (R4, follow-up —
  see the HA section above).
- **Budget + cooldown**, not a full 1024-rule eviction policy (R5, follow-up).
