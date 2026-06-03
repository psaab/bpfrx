# #1752 remaining paths — B / A / C-D / E-follow-up

**Status: DRAFT v1 — pending adversarial plan review (Codex + AGY + Claude SMR)**

Path E shipped (PR #1753, `380bbb8ed`). This doc dispositions the four remaining
levers on the #1752 umbrella. **Headline: Path B is killed by live evidence —
the "crypto DEK churn" is a perf symbolization artifact, not real work.**

## 1. Issue framing

#1752 found `-P48 -p5210` forwarding CPU-bound at 16 Gb/s on a 6-vCPU/6-queue/
6-worker box (no headroom by design). Levers identified: B (mlx5 crypto DEK
~5.6%), A (CoS shaping ~19%), C/D (core scaling / document), E (session refresh
churn — shipped). This research dispositions B, A, C/D, and the E follow-up.

## 2. PATH B — KILL (crypto DEK churn is a perf symbolization artifact)

**Evidence (live, `-P48 -p5210`, this branch):**
- perf flat self-time steadily shows `mlx5_crypto_modify_dek_key` ~3.5% +
  `dek_fill_key`/`create_dek_bulk`/`dek_pool_remove_bulk`/`create_dek_key`/
  `dek_bulk_reset_synced` ≈ **~5.5% total**, reproducible across 4 windows.
- **bpftrace kprobe call counts over 8 s of full load:**
  `mlx5e_napi_poll` = **3,579,581 calls**; `mlx5_crypto_modify_dek_key` =
  **0 calls** (also `dek_pool_remove_bulk` = 0, `create_dek_bulk` = 0 over 10 s).
- strongSwan: no rekey activity in the logs during the run.

**Conclusion:** the DEK functions are **never invoked**. perf attributes samples
whose PCs land in *unexported* mlx5_core datapath code to the nearest *exported*
symbol — which in this build is the crypto DEK family (sparse module symbol
table). The ~5.5% is real mlx5_core RX/TX datapath cost (the same inherent ~28%
driver bucket as `napi_poll`/`xsk_skb_from_cqe_linear`), **not** recoverable
spurious crypto work. The original #1752 framing ("unexpected, possibly free")
was wrong — a measurement artifact, caught by validating the metric (kprobe
call-count) against the perf %.

**Action:** PLAN-KILL Path B. No xpf code/config lever exists. (If anyone
revisits, the only honest follow-up is a kernel-side ftrace
`function_graph`/`/proc/kallsyms`-aware re-symbolization to confirm which real
mlx5_core function the addresses belong to — a kernel-debug exercise, not xpf
work, and not worth it given the cost is inherent driver datapath either way.)

## 3. PATH A — CoS hot-path CPU reduction (~19%): defer to its own gated /research

Still the only real remaining *software* CPU lever. Sub-profile (this branch,
CoS-on, flat self-time):
- `cos_queue_push_back` **5.70%**, `cos_queue_pop_front_inner_with_cap` **3.49%**,
  `service_exact_guarantee_queue_direct_with_info` **3.13%**,
  `ingest_cos_pending_tx_with_provenance` 1.90%, `publish_cos_exact_backlog`
  1.79%, `enqueue_cos_item` 1.63%, `drain_shaped_tx` 1.58%,
  `account_cos_queue_flow_enqueue` 1.03% ≈ **~19%**.

The dominant sub-cost is the **per-packet enqueue/dequeue** of the
exact-guarantee queue (`push_back` + `pop_front` ≈ 9.2%). Path A is real value
(~7.4 Gb/s gross when CoS is off) but **high kill-risk** — the CoS path has two
prior micro-opt PLAN-KILLs (#1207 queue_service skeleton, #1545 mirror clone).

**Action:** do NOT attempt Path A from this umbrella doc. It needs its own deep
`/research` that (a) annotates `cos_queue_push_back`/`pop_front` to a concrete
reducible cost (bookkeeping? bounds checks? cache-line layout? per-flow
accounting?), (b) proposes a targeted change, (c) carries an explicit
no-code-PLAN-KILL exit if the sub-cost is irreducible. File as a separate issue.

## 4. PATH C / D — core scaling / document the ceiling

- **C (IRQ/worker core separation):** the futex profile (#1752 follow-up) showed
  the Go control plane's GC + the dataplane workers share all 6 cores; the
  dataplane busy-polls (no lock contention). Real headroom needs **more vCPUs +
  RX queues** with IRQs/Go pinned off the worker cores — an **operator/infra
  decision**, not xpf code. No code lever on the current 6/6 VM.
- **D (document):** make the 6/6 = no-headroom sizing explicit in operator docs
  (`docs/`), incl. that the 24g shape sits above the box's forwarding ceiling so
  it never engages, and that scaling = vCPU+queue+worker count.

**Action:** ship **D** as a small docs-only PR (no review gauntlet needed per the
triple-review "pure documentation" exclusion). **C** is an operator
recommendation, captured in the same doc; not an xpf change.

## 5. PATH E follow-up — full skip of the secondary re-assert (~1%): defer, gated

Path E retained the 4 secondary-index re-assert inserts for exact parity. Fully
skipping them on the no-reindex hot path recovers the remaining ~1% **only if**
secondary keys are provably unique across all live sessions (incl. the transient
NAT-port-reuse / not-yet-GC'd window). 

**Action:** low priority. If pursued, its own `/research` must (a) prove the
uniqueness invariant from the NAT allocator + identity-reverse bijection +
GC-window analysis, and (b) add a property test that fuzzes for a colliding
live-session pair. ~1% on a CPU-bound box is marginal vs the proof burden.

## 6. Honest scope/value framing

The only substantial remaining CPU lever is **Path A (~19%)**, and it is
high-risk. **Path B is dead (artifact).** C/D are operator/doc. E-follow-up is
~1% behind a hard proof. *If reviewers agree, the right outcome is: kill B,
document C/D, spin Path A into its own gated research, defer E-follow-up — i.e.
this umbrella doc itself produces no production code beyond the D docs PR.*

## 7. Risk assessment

| Path | Verdict | Risk if pursued |
|---|---|---|
| B | KILL | n/a — no lever exists (artifact) |
| A | own /research | HIGH (architectural; #1207/#1545 kill pattern) |
| C | operator note | n/a — infra decision |
| D | docs PR | LOW |
| E-follow-up | defer | MED (uniqueness proof burden vs ~1%) |

## 8. Test/validation plan

- Path B kill: the kprobe-call-count vs perf-% evidence above is the proof; no
  code. (Reviewers: try to refute the artifact claim — is there a path where the
  DEK functions ARE called but the kprobe missed, e.g. inlined/tail-called?)
- Path D docs PR: doc-drift guard only.
- A and E-follow-up: deferred to their own research; no validation here.

## 9. Out of scope

- Implementing Path A (separate gated research).
- Implementing the E follow-up (separate gated research).
- Re-symbolizing mlx5_core to name the real function under the artifact (kernel
  debug, not xpf).

## 10. Open questions for adversarial review

1. **Refute the Path B artifact claim:** is there any mechanism by which
   `mlx5_crypto_modify_dek_key` consumes 3.5% CPU while a kprobe on it fires 0
   times in 8 s (e.g. the kprobe attaching to the wrong symbol, tail-call
   elision, the function being a thunk)? `napi_poll` on the same probe fired
   3.58M times, proving the kprobe mechanism works. Is the artifact conclusion
   sound, or is more evidence needed (kallsyms address-range check, `perf
   annotate`)?
2. Is killing Path B premature — should we re-symbolize to name the real hot
   function first (could it reveal a *different* recoverable lever hiding under
   the misattribution)?
3. Path A sub-cost: is `cos_queue_push_back` at 5.7% plausibly reducible, or is
   it irreducible per-packet enqueue work (→ Path A should also be killed, not
   just deferred)?
4. Is the D docs-only-PR exclusion from the review gauntlet appropriate here?
5. E-follow-up: is ~1% on a CPU-bound box ever worth a uniqueness-proof + fuzz
   test, or should it be explicitly killed rather than deferred?
