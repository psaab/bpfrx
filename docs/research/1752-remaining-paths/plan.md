# #1752 remaining paths — B / A / C-D / E-follow-up

**Status: v2 — folds Codex r1 (PLAN-NEEDS-MAJOR) + AGY r1 (PLAN-NEEDS-MAJOR). Re-dispatched for r2.**

v2 changes after live verification:
- **Path B is NOT killed — it is RE-SCOPED.** The "crypto DEK churn" is a perf
  symbolization artifact (kprobe = 0 calls), but AGY's hypothesis verified: the
  real cost is the **AF_XDP TX/RX wake `sendto()` kick path** (~108K sendto/s),
  which IS software-recoverable via wake-interval tuning.
- Path A defer stands, enriched with AGY's verified concrete sub-levers.
- **Path C re-scoped** from "operator only" to a real software lever (workers are
  already core-pinned; move them off core 0 and give it to the Go control plane).
- **Path E-follow-up = KILL** (AGY: if transient port reuse pre-GC occurs the
  re-assert is structurally necessary, so the ~1% isn't spurious).
- Evidence committed under `evidence/`.

Path E (session in-place refresh) shipped (PR #1753, `380bbb8ed`). This doc
dispositions the four remaining levers on the #1752 umbrella.

## 1. Issue framing

#1752 found `-P48 -p5210` forwarding CPU-bound at 16 Gb/s on a 6-vCPU/6-queue/
6-worker box (no headroom by design). Levers: B (mlx5 "crypto DEK" ~5.6%), A (CoS
shaping ~19%), C/D (core scaling / document), E (session churn — shipped).

## 2. PATH B — RE-SCOPE: TX/RX wake `sendto()` kick reduction (was mis-framed as crypto DEK)

**The crypto-DEK framing is dead (artifact).** Evidence
(`evidence/pathb-crypto-dek-artifact.md`): perf shows ~5.5% in
`mlx5_crypto_modify_dek_key` et al., but a bpftrace kprobe on it fires **0 times
in 8–10 s** of full load (vs `mlx5e_napi_poll` = 3,579,581). mlx5_core ships
compressed (`mlx5_core.ko.xz`); perf rounds PCs in unexported static functions to
the nearest exported symbol — the crypto DEK family at kallsyms `0xc0a801xx`.
`perf annotate` of the symbol disassembles to `mlx5e_port_linkspeed` code,
confirming broken compressed-module resolution.

**The real cost (AGY hypothesis, verified):** the workers kick the AF_XDP TX/RX
rings via `sendto()`: `xsk_sendmsg` ~110K/s, worker `sendto` ~108K/s,
`mlx5e_xsk_wakeup` ~15.5K/s (8 s under load). `mlx5e_xsk_wakeup` is
static/unexported → its samples misattribute to the crypto symbols. The kick is
already gated by `needs_wakeup()` (rings.rs:142-145) + `TX_WAKE_MIN_INTERVAL_NS
= 50_000` (mod.rs:302); RX-wake also uses `sendto` (rings.rs:182-198).

**Lever (real, recoverable):** widen the wake interval / batch more TX before
kicking, cutting the ~108K sendto/s. **Tradeoff:** higher TX latency + ring
backpressure risk — so the win is not free and may be modest.

**Action:** own `/research` for Path B. It must (a) attribute what fraction of
the misattributed bucket is the wake path vs other unexported mlx5 datapath
(perf `--kallsyms` / a debug uncompressed module, or kprobe-time accounting),
(b) propose a wake-interval/batch change, (c) A/B `TX_WAKE_MIN_INTERVAL_NS`
(e.g. 50µs → 100–200µs) measuring CPU **and** TX latency + throughput + retrans,
(d) carry a no-win PLAN-KILL exit if widening the interval doesn't net-recover
CPU without latency regression.

## 3. PATH A — CoS hot-path CPU reduction (~19%): defer to its own gated /research

The only large remaining lever. Sub-profile (CoS-on flat self-time):
`cos_queue_push_back` 5.70% + `pop_front` 3.49% + `service_exact_guarantee_queue`
3.13% + `ingest_cos_pending_tx` 1.90% + `publish_cos_exact_backlog` 1.79% +
`enqueue_cos_item` 1.63% + `drain_shaped_tx` 1.58% + `account_..._enqueue` 1.03%
≈ ~19%. The dominant sub-cost is per-packet enqueue/dequeue (~9.2%).

AGY (verified against `push.rs`/`pop.rs`/`mod.rs`) identified concrete candidate
sub-levers worth carrying into Path A's research — `push_back`/`pop_front` are
NOT a plain queue op; they do promotion probing, local-item counters, snapshot
invalidation, flow accounting, bucket hashing, active-bucket tracking, min-finish
scans, vtime updates, dequeue accounting:
- **flow-hash caching** — stash the classifier's 32-bit hash in
  `TxRequest`/`PreparedTxRequest` (types/tx.rs) to skip re-hashing the 5-tuple in
  `cos_flow_bucket_index` per enqueue;
- **structural-compare bypass** — compare cached u32 hashes in
  `maybe_promote_best_effort` instead of 64-byte `SessionKey` structural match;
- **descriptor-indexed queuing** — queue `u32` frame indices in the round-robin
  rings, not 100+ byte `CoSPendingTxItem` (types/cos.rs);
- **min-bucket O(1)** — short-circuit `cos_queue_min_finish_bucket` for 1 active
  queue + maintain an incremental min-pointer/heap instead of O(N) per packet.

**Action:** still its own gated `/research` (CoS path has #1207/#1545 kill
history; these candidates need design + differential review + smoke). High value,
high risk. Do NOT optimize blindly from this umbrella doc.

## 4. PATH C / D — control-plane core isolation / document

**C is a real software lever (corrected from v1).** Workers are *already*
core-pinned (`sched_setaffinity`, neighbor.rs:737); the futex profile showed the
Go control plane's GC threads run across all 6 cores and preempt the busy-polling
Rust workers. **Lever:** pin the Go process to core 0 (cpuset / `GOMAXPROCS=1` +
affinity) and pin the 6 workers to cores 1–5 — dedicating one core to the control
plane. **Cost:** loses a worker core (6→5 workers), so this is a *tradeoff* A/B,
not a free win, on a box where workers are the throughput unit.

- **Action C:** own small `/research` + A/B (5 workers on clean cores + Go on
  core 0 vs 6 shared workers) measuring aggregate throughput + jitter/RX drops.
- **Action D:** docs-only PR — make the 6/6 = no-headroom sizing explicit
  (existing `docs/userspace-dataplane-architecture.md` already states the
  6-workers-plus-headroom target; extend it). Not "no review" — a sizing/perf doc
  gets a normal doc review, just not the full Codex+Gemini+smoke gauntlet.

## 5. PATH E follow-up — KILL (full skip of the secondary re-assert, ~1%)

AGY's argument (accepted): the re-assert inserts exist because
`restore_entry`/`index_forward_nat_key` unconditionally re-assert; if transient
NAT-port reuse can place a colliding live session before the prior session's GC
window closes, the re-assert is **structurally necessary** for conntrack
correctness — so the ~1% is NOT spurious. Optimizing it away risks
mis-routed/poisoned reverse lookups. The uniqueness-proof + fuzz-test burden far
exceeds ~1% on a CPU-bound box.

**Action:** PLAN-KILL the E follow-up. Path E as shipped (with the re-assert
retained) is the correct terminal state.

## 6. Honest scope/value framing

Real remaining levers, after verification: **A (~19%, high-risk, own research)**;
**B (TX-wake kicks, recoverable but modest + latency tradeoff, own research)**;
**C (control-plane core isolation, tradeoff A/B)**; **D (docs)**. **E-follow-up
killed.** No production code ships from THIS umbrella doc beyond the D docs PR;
A/B/C each spin into their own gated research. *If reviewers think B or C won't
net-recover CPU without a throughput/latency regression, killing them here
(rather than spinning research) is acceptable.*

## 7. Risk assessment

| Path | Verdict | Risk if pursued |
|---|---|---|
| B | own /research (re-scoped to TX-wake) | MED — latency/backpressure tradeoff; win may be modest |
| A | own /research | HIGH — CoS architectural; #1207/#1545 kill pattern |
| C | own /research (A/B) | MED — loses a worker core; may not net-win |
| D | docs PR | LOW |
| E-follow-up | KILL | n/a |

## 8. Test/validation plan

- Path B kill-of-crypto-framing: the kprobe-call-count + annotate evidence
  (`evidence/`) is the proof. Re-scoped B's own research owns the wake-interval A/B.
- Path D docs PR: doc-drift guard.
- A / B / C: deferred to their own research; no code validation here.

## 9. Out of scope

- Implementing A, B (wake tuning), or C (core isolation) — each its own research.
- Naming the exact unexported mlx5_core function under the artifact beyond "TX/RX
  wake path" (would need an uncompressed debug module; the kprobe evidence already
  establishes it is NOT crypto and IS the sendto-kick path).

## 10. Open questions for adversarial review

1. **Path B fraction:** the kprobe proves the ~5.5% is not crypto and the wake
   path runs at ~108K sendto/s — but is the wake path actually the bulk of that
   misattributed bucket, or only part (with the rest being genuinely-inherent
   unexported datapath)? Does the re-scope over-promise recoverable CPU?
2. **Path B tradeoff:** at `TX_WAKE_MIN_INTERVAL_NS=50µs` already gating, is there
   real slack to widen without TX latency / ring-backpressure regression, or is
   the current value near-optimal (→ B should also be killed)?
3. **Path C:** does dedicating a core to the Go control plane (5 workers vs 6)
   plausibly net-win, or does losing a worker on a worker-bound box dominate?
4. **Path A:** are AGY's sub-levers (flow-hash caching, descriptor-indexed
   queuing) actually safe given the CoS fairness invariants, or do they perturb
   the exact-guarantee/vtime semantics (the #1207/#1545 trap)?
5. **Path E-follow-up KILL:** is the "re-assert is structurally necessary"
   correctness argument airtight, or is there a provable uniqueness invariant that
   would make the ~1% genuinely recoverable (→ defer not kill)?
