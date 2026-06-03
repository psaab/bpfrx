# #1752 — P48/5210 CPU-bound at 16 Gb/s: where the cycles go

**Status: v2 — Claude SMR PLAN-READY-WITH-MINORS folded; Codex + AGY r1 pending**

This is a *diagnosis-first* research doc. The empirical profile is already
captured live on `loss:xpf-userspace-fw0` (flow-rebalance OFF, native XDP,
zero-copy XSK, `-P48 -p5210`). The open question for review is **which
optimization path to pursue and in what order**, not "what is the bottleneck"
— that is measured below.

## 1. Issue framing

`iperf3 -P48 -p5210` (shaped iperf-24g class) caps at **16.0 Gb/s with all 6
vCPUs at 100%**. Operator expected headroom. There is none: the VM is
**6 vCPU = 6 mlx5 RX queues = 6 AF_XDP workers**, so the dataplane is sized to
own the whole machine. The research question: where is the CPU going, what is
*addressable in software*, and what is inherent to the sizing.

## 2. Measured profile (ground truth)

Per-core under load: `usr ~60% / sys ~8% / softirq ~28% / idle 0%` ×6.
Datapath healthy: `xdp mode DEFAULT` (native), `ethtool -S` shows all
**1.39 Mpps as `rx_xsk_xdp_redirect`**, zero XDP_PASS/skb leak.

| Cost center | Self-time | Addressable? | Evidence |
|---|---|---|---|
| **CoS exact-guarantee shaping** | **~19%** | **Yes (SW)** | 7 `cos_*` fns; A/B: CoS ON 16.0 → OFF 23.4 Gb/s (+46%) |
| **mlx5 crypto DEK churn** | **~5.6%** | **Likely (config/SW)** | `mlx5_crypto_{modify,fill,create_bulk,pool_remove}_dek*`; HW offload `off [fixed]` but 16 xfrm policies + strongSwan active |
| mlx5 driver RX (zero-copy) | ~28% (softirq) | No (inherent) | `mlx5e_napi_poll`, `xsk_skb_from_cqe_linear`, `xp_raw_get_dma` at 1.39 Mpps |
| flow/session hashbrown churn | ~4.5% | Maybe (SW) | `remove_entry` 2.73 + `insert` 1.72 |
| worker poll/forward core | remainder | Partly | `poll_binding_process_descriptor`, `worker_loop`, `transmit_prepared_queue` |

## 3. Honest scope/value framing

- **Finding 1 (CoS ~19%)** is the headline. The *firm* number is the **~19% CPU
  self-time** freed (flat profile; `cos_*` symbols vanish CoS-OFF). The
  throughput figure is noisier — the CoS-OFF arm hit 23.4 Gb/s **with ~26,835
  retr** (vs ~1,469 CoS-ON), so iperf's sender Gb/s overstates goodput: call it
  **up to ~7.4 Gb/s gross, less in goodput.** Crypto-DEK churn was present in
  *both* A/B arms, so it does not confound this delta. The win is large — but
  the CoS exact-guarantee path has been refactored many times (#959, #1207
  PLAN-KILL, #1545 PLAN-KILL); a CPU-reduction attempt risks another kill.
  Value is large; tractability is the open question.
- **Finding 2 (crypto DEK ~5.6%)** is the cheapest to investigate and possibly
  *free*: forwarded iperf traffic on reth0.80 is not encrypted, so per-packet
  DEK key programming is unexpected. If it is the test-env strongSwan/xfrm
  config (not a production path), the win may be smoke-env-only — that itself is
  worth knowing (it inflates every CoS measurement we take).
- **Finding 3 (driver RX ~28%)** is inherent at 1.39 Mpps on a 6/6 box. Not
  code. Listed for completeness so we don't chase it in software.
- If reviewers conclude no SW path yields meaningful headroom on a 6/6 VM,
  **PLAN-KILL (with the "scale = more vCPUs+queues" conclusion) is an
  acceptable verdict.**

## 4. Path options (the decision under review)

- **Path A — CoS hot-path CPU reduction.** Profile within the CoS path
  (push/pop/service/drain), find the dominant sub-cost, attempt a targeted
  reduction. High value, high kill-risk. Needs its own /research before /engineer.
- **Path B — Root-cause mlx5 crypto DEK churn FIRST.** Determine *why*
  forwarding triggers DEK pool create/remove/reset with HW offload off. Decide:
  config fix (disable an offload/IPsec path on the data VFs), driver/kernel
  interaction, or expected. Cheapest, possibly free, and de-noises all other
  CoS measurements. **Recommended first.**
- **Path C — IRQ/worker core separation.** Requires growing the VM beyond 6
  vCPU + adding RX queues so NET_RX softirq lands off the worker cores. Infra
  change, not code; quantify expected gain before committing.
- **Path D — Document the 6/6 ceiling.** Make explicit that this sizing has no
  headroom and that scaling is vCPU+queue+worker count, not code.

## 5. Concrete next step if approved

Recommended sequencing: **B → (measure) → A or C**.

Path B investigation steps (no production code; diagnostic). Non-invasive
first; the invasive A/B is **gated** on what the trace shows:
1. **(non-invasive, hard gate)** `mlx5_core` DEK trace: `perf record -g` on
   `mlx5_crypto_modify_dek_key`, capture the kernel stack that *calls* it under
   `-P48 5210` (TX completion? ASO? strongSwan rekey timer?). Also confirm
   per-packet vs periodic by sampling rate vs pps.
2. Correlate with `ip xfrm state`/`policy` churn and strongSwan rekey logs.
3. **Only if step 1/2 implicate strongSwan/xfrm**: invasive A/B (stop strongSwan
   + flush xfrm), re-run `-P48 5210`, re-profile. Run this on the **standalone
   test VM** or on fw1 while fw0 holds RG-0 — **never on the live RG-0 primary**,
   because IPsec SA sync reacts to SA teardown. Revert immediately after.
4. Decide config vs driver vs expected; file the fix as a separate /engineer
   issue if there is a clean lever.

## 6. Public API / behavior preservation

None touched in research. Any Path-B config experiment is smoke-env only
(strongSwan stop / xfrm flush on fw0) and reverted after measurement. Path A/C
would each get their own plan + review before code.

## 7. Hidden invariants / risks of the *experiment*

- Stopping strongSwan / flushing xfrm on fw0 must be reverted; the cluster's HA
  IPsec SA sync may react — do it RG-0-primary-only, briefly, and restore.
- CoS A/B teardown must use the full fixture delete (class-of-service + the
  bandwidth-output filter bindings) or `commit check` fails and Pass-A is a
  silent no-op (already hit + handled in the smoke skill).

## 8. Risk assessment

| Class | Level | Note |
|---|---|---|
| Behavioral regression (research) | LOW | diagnostic only, no prod code |
| Measurement validity | MED | throughput noisy + deploy wipes CoS; A/B must re-apply CoS + repeat |
| Architectural mismatch (Path A) | HIGH | CoS path twice PLAN-KILLed for churn-vs-gain |
| Crypto root-cause ambiguity (Path B) | MED | mechanism not yet proven; step 1 trace resolves it |

## 9. Test/validation plan (for the research experiments)

- Each A/B re-applies CoS via `apply-cos-config.sh` and verifies before measuring.
- Repeat each measurement ≥2× (throughput is noisy; per the runnable-repro rule).
- Report raw `[SUM] sender` lines + per-core util + flat self-time deltas.

## 10. Out of scope

- #1751 flow-rebalance (separate; OFF for all these measurements).
- Any actual CoS rewrite (Path A) — that is a future /research+/engineer.
- Growing the VM (Path C infra) — needs operator decision.

## 11. Open questions for adversarial review

1. Is the CoS ON/OFF A/B (16.0 vs 23.4) a fair attribution of ~7.4 Gb/s to
   shaping, or is some of that delta the crypto-DEK churn shifting under load?
   (Both were present in both runs — argue it.)
2. Is `mlx5_crypto_modify_dek_key` on the worker thread truly per-packet, or a
   periodic rekey aliased into the sample window? What stack proves it?
3. With HW crypto offload `off [fixed]` on the VFs, what mlx5 path legitimately
   programs DEKs from a plain-forwarding worker? Is this a known mlx5 6.18
   behavior?
4. Is Path B's strongSwan-stop A/B safe on an HA node, even briefly, given
   IPsec SA sync?
5. Should Path A be attempted at all given #1207/#1545 CoS-path PLAN-KILLs, or
   is the honest answer "document the 6/6 ceiling (Path D) + only chase Path B"?
6. Is there a 5th cost center the table misses (e.g. the ~4.5% hashbrown churn —
   is per-flow session insert/remove reducible)?
