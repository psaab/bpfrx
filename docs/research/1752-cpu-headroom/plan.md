# #1752 — P48/5210 CPU-bound at 16 Gb/s: where the cycles go

**Status: v4 (PLAN-READY) — Codex r2 + Claude SMR r2 PLAN-READY; AGY r1 blockers all folded (r2 infra-truncated). Codex non-blocking nit fixed.**

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
| **CoS exact-guarantee shaping** | **~19% CPU** | **Yes (SW)** | 7 `cos_*` fns; A/B CoS ON 16.0 vs OFF 23.4 Gb/s (gross; goodput TBD) |
| **session refresh remove+restore churn** | **~4.5%** | **Yes (SW), lowest risk** | `update_session` (session/mod.rs:803) does `remove_entry`(:1119)+`restore_entry`(:1176) **per packet** to bump timestamps → `remove_entry` 2.73 + slab `insert` 1.72. In-place `get_mut` recaptures it |
| **mlx5 crypto DEK pool churn** | **~5.6%** | **Unknown — trace first** | `mlx5_crypto_{modify,fill,create_bulk,pool_remove}_dek*`. DEK pool is generic mlx5 crypto machinery used by **both kTLS and IPsec offload**; strongSwan/16-xfrm is *a* candidate, not proven. HW offload `off [fixed]` on VFs |
| mlx5 driver RX (zero-copy) | ~28% (softirq) | Partly | physics inherent at 1.39 Mpps, BUT NAPI budget / busy-poll / IRQ-worker isolation / queue count / XDP-prog cost are levers. `mlx5e_napi_poll`, `xsk_skb_from_cqe_linear`, `xp_raw_get_dma` |
| worker poll/forward + XDP prog | remainder | Partly | `poll_binding_process_descriptor`, `worker_loop`, `bpf_prog_*` (our XDP), `transmit_prepared_queue` |

## 3. Honest scope/value framing

- **Finding 1 (CoS ~19%)** is the headline *CPU* cost — the firm number is the
  **~19% self-time** freed (flat profile; `cos_*` symbols vanish CoS-OFF). The
  throughput figure is softer: the CoS-OFF arm hit 23.4 Gb/s **with ~26,835
  retr** (vs ~1,469 CoS-ON), so iperf's sender Gb/s overstates goodput — state
  it as **~19% CPU; one A/B showed up to +7.4 Gb/s gross sender throughput,
  goodput TBD.** (Caveat: CoS-off changes loss/backpressure/retransmit and
  packet rate, so crypto-DEK was *present* in both arms but not provably
  *constant* — the clean claim is the CPU%, not the Gb/s.) The win is large but
  the CoS exact-guarantee path has prior micro-opt PLAN-KILLs (#1207, #1545) —
  those killed tiny prizes, not a 19% one, but they warn the path is hard.
- **Finding 2 — session refresh churn ~4.5% (NEW, code-grounded, recommended
  first).** `update_session` (session/mod.rs:803) refreshes an established flow
  by `remove_entry` + `restore_entry` — tearing down and rebuilding the
  `key_to_handle` map, forward-NAT index, owner-RG index and slab slot **on
  every packet**, only to rewrite `last_seen_ns`/`expires_after_ns`. A
  steady-state flow should do zero index churn. In-place `get_mut(handle)`
  mutation recaptures ~4.5% at low risk (the key/indices don't change on a
  pure refresh; only update an index if a NAT-relevant metadata field actually
  changed). Lowest kill-risk of any lever — this is the cleanest code win.
- **Finding 3 (crypto DEK ~5.6%)** is cheap to *investigate* but the mechanism
  is **not yet proven**. The mlx5 DEK pool is generic crypto machinery used by
  both kTLS and IPsec offload; "unexpected on plain forwarding" is right, but
  "probably strongSwan/xfrm" is a hypothesis, not a finding. A non-invasive perf
  stack trace must precede any config theory. If it turns out to be a test-env
  artifact, the win may be smoke-env-only — still worth knowing (it inflates
  every measurement here).
- **Finding 4 (driver RX ~28%)** is *mostly* inherent at 1.39 Mpps, but not
  categorically un-addressable: NAPI budget, busy-poll, IRQ/worker isolation,
  queue count, RSS shape and our own XDP-program cost all move it. Separate
  driver physics from xpf/XDP work before declaring any part "not code."
- If reviewers conclude no SW path yields meaningful headroom on a 6/6 VM,
  **PLAN-KILL (with the "scale = more vCPUs+queues" conclusion) is an
  acceptable verdict.**

## 4. Path options (the decision under review)

- **Path E — session refresh in-place mutation (NEW).** Replace the per-packet
  `remove_entry`+`restore_entry` in `update_session` with `get_mut`-based
  in-place field mutation; touch an index only when a NAT-relevant field
  actually changes. ~4.5% CPU, code-grounded, lowest kill-risk. **Recommended
  first code win** — small, isolated, no architectural premise to fail.
- **Path B — non-invasive root-cause of mlx5 crypto DEK churn.** Capture the
  calling stack (kTLS vs IPsec-offload vs rekey timer) BEFORE any config theory.
  Cheap, may be free, de-noises every other measurement. **Recommended in
  parallel with E** (it's diagnostic, not code).
- **Path A — CoS hot-path CPU reduction.** *Gated:* keep ONLY as its own future
  /research that (a) sub-profiles within push/pop/service/drain to a concrete
  dominant sub-cost, and (b) carries an explicit no-code PLAN-KILL exit if that
  sub-cost is not locally reducible. Do not attempt a vague "refactor CoS for
  perf" — that is exactly the #1207/#1545 kill pattern. High value, high risk.
- **Path C — IRQ/worker core separation.** Requires growing the VM beyond 6
  vCPU + adding RX queues so NET_RX softirq lands off the worker cores. Infra
  change, not code; quantify expected gain before committing.
- **Path D — Document the 6/6 ceiling.** Make explicit that this sizing has no
  headroom and that scaling is vCPU+queue+worker count, not code.

## 5. Concrete next step if approved

Recommended sequencing: **E (code win) + B (diagnostic, parallel) → then decide
A (gated) / C / D**. E and B are independent and both low-risk.

**Path E** (the code win, deferred to its own /engineer):
1. Sub-profile `update_session`/`upsert_synced_with_origin` to confirm the
   index-rebuild dominates (not the field writes).
2. Design `get_mut(handle)` in-place mutation preserving the peer-synced
   promotion/rejection branches and the wheel/delta side effects; update an
   index ONLY when its key-relevant input changed (NAT mapping, owner-RG).
3. Property/differential test: in-place path must be observably identical to
   remove+restore for every branch (reject, promote, local-refresh).
4. Re-profile `-P48 5210` to confirm `remove_entry`/`insert` self-time drops.

**Path B** investigation steps (no production code; diagnostic). Non-invasive
ONLY; the invasive A/B is **out of scope on the cluster**:
1. **(non-invasive, hard gate)** `perf record -g` on
   `mlx5_crypto_modify_dek_key` under `-P48 5210`; capture the calling stack
   (kTLS DEK pool? IPsec xfrm-device key-add? rekey timer?) and confirm
   per-packet vs periodic by event-rate vs pps.
2. Correlate with `ip xfrm state`/`policy` churn + strongSwan rekey logs +
   whether kTLS is in use anywhere on the box.
3. **The strongSwan-stop / xfrm-flush A/B is NOT run on any HA cluster node**
   (XFRM state is not RG-scoped; flushing perturbs SA sync, rekey, and the
   measurement). If a config A/B is needed at all, it runs ONLY on the isolated
   standalone test VM. Default: do not run it — the stack trace should suffice.
4. Decide config vs driver vs expected; file a separate /engineer issue only if
   there is a clean, safe lever.

## 6. Public API / behavior preservation

None touched in research. Any Path-B config experiment is **standalone-test-VM
only** (strongSwan stop / xfrm flush) — **never on fw0/fw1 or any HA node** (see
§5/§7) — and reverted after measurement. Path A/C would each get their own plan +
review before code.

## 7. Hidden invariants / risks of the *experiment*

- **No strongSwan-stop / xfrm-flush on any HA cluster node** (corrected from v1).
  XFRM state is not RG-scoped; flushing it perturbs SA sync, rekey and peer
  behavior. Crypto root-cause is the non-invasive stack trace only; any config
  A/B is standalone-VM-only and is the exception, not the default.
- CoS A/B teardown must use the full fixture delete (class-of-service + the
  bandwidth-output filter bindings) or `commit check` fails and Pass-A is a
  silent no-op (already hit + handled in the smoke skill).
- Path E must preserve `update_session`'s peer-synced promotion/rejection
  semantics and the wheel-push / Open-delta side effects exactly — verified by
  differential test before any re-profile.

## 8. Risk assessment

| Class | Level | Note |
|---|---|---|
| Behavioral regression (research) | LOW | diagnostic only, no prod code |
| Path E (session in-place mutation) | LOW-MED | isolated fn; risk is preserving peer-synced/wheel/delta semantics — differential test gates it |
| Measurement validity | MED | throughput noisy + deploy wipes CoS; A/B must re-apply CoS + repeat; Gb/s claim is gross not goodput |
| Architectural mismatch (Path A) | HIGH | CoS path twice PLAN-KILLed; only as gated sub-profile w/ no-code exit |
| Crypto root-cause ambiguity (Path B) | MED | mechanism unproven (kTLS vs IPsec vs rekey); non-invasive trace resolves it; no HA-node config A/B |

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
4. Is Path B's strongSwan-stop A/B safe on an HA node? **(RESOLVED v3: NO — it
   is not run on any HA node; Path B is non-invasive stack-trace only, any
   config A/B is standalone-test-VM only.)**
5. Should Path A be attempted at all given #1207/#1545 CoS-path PLAN-KILLs, or
   is the honest answer "document the 6/6 ceiling (Path D) + only chase Path B"?
6. Is there a 5th cost center the table misses (e.g. the ~4.5% hashbrown churn —
   is per-flow session insert/remove reducible)?
