VERDICT: PLAN YES

### Q1 (outcome exhaustiveness + flip accounting): SOUND
* **Outcome Exhaustiveness:** In `userspace-dp/src/afxdp/session_glue/mod.rs:1148-1330`, every return path of `resolve_flow_session_decision` evaluates to either a locally live-backed entry (`ExistingResolved`), a hit whose local backing was transient-purged (`ResolvedWithoutLocalBacking`, via `session_glue/mod.rs:1178-1193` -> `promote.rs:181`), a newly installed miss (`SeedInstalled`), or a refused miss (`SeedRefused`). The four-outcome set is exhaustive across all execution paths. Treating `ResolvedWithoutLocalBacking` as a genuine miss end-to-end applies the `#4400` guard (`poll_descriptor/mod.rs:1634-1644`) to bare closes while preserving the full seed transaction and deterministic NAT reacquire (`allocator.rs:1265`) for SYN/data.
* **Flip Accounting Balance:** The `MissingNeighborSeed → ForwardFlow` class transition (§5.2(iii), §5.8) calls `session_limit_inc` at the flip (following `install.rs:555-562`), emits the single `Open` delta at the flip (`install.rs:226-234`), and enforces `Open → Close` stream ordering before applying any accepted close mark. Across all lifecycles:
  1. *Flip-then-reap:* `inc` (+1) at flip, `Open` (+1) at flip; removal sink (`session/mod.rs:1817`) decrements (-1) and emits `Close` (+1) at reap. Net limit: 0, Net stream: Open → Close.
  2. *Flip-then-operator-delete:* `inc` (+1) at flip; operator delete decrements (-1) and emits `Close` (+1). Net limit: 0, Net stream: Open → Close.
  3. *Flip-then-failover:* `inc` (+1) at flip; owner teardown decrements (-1) and drains `Close`. Unflipped seeds retain `is_transient_local_seed = true` (`counted = false`), emitting zero Open/Close deltas and zero limit increments/decrements.
  Accounting is balanced across all paths.

### Q2 (identity substrate + reciprocity): SOUND
* **Session ID Guard & Fallback:** Stamping the node-unique `session_id` (`install.rs:143-148`) on published shared/DNAT records (replacing zero writes at `poll_descriptor/mod.rs:4811`), carrying it on `ExpiredSession` (`entry.rs:337`), and validating it at both seed-alias cleanup and flipped seed Close drain (`session_delta.rs:420`) guarantees that a stale cleanup attempt against a key/NAT reused by a newer generation will fail the `session_id` match and leave the newer generation intact. Falling back to key-based cleanup for legacy zero-id records preserves master compatibility without introducing mixed-version leaks.
* **Reverse-Hit Family Reciprocity:** On a reverse-hit close (§5.5), re-probing the forward entry requires key+NAT reciprocity (`expire.rs:476-496`) matching the reverse entry's tuple and translation. If a forward replacement occurred (`NAT1 != NAT2`), reciprocity fails, resulting in `REFUSE-DEMOTE` (no mark, no propagation, no Close emission, orphan reverse ages out `is_reverse`-silent). This closes wrong-generation marks across all close paths:
  * *Hit path (site 1):* Gated by reciprocity check (`lookup.rs:48`, `expire.rs:476-496`).
  * *Companion propagation (`propagate_tcp_state_to_companion`):* Executes only post-borrow after reciprocity validation (`session/mod.rs:1232-1278`).
  * *Reverse synth (site 2b):* Gated by `Local` scope check and key+NAT identity agreement (`shared_ops.rs:638-665, 857-865`).
  * *Update session (site 2):* Closing packets are suppressed by Rule 5 (`closing packets never promote`).
  * *Fabric return (site 6):* Bare closes dropped (`#4453`); fabric return seeds lack an anchor and soft-refuse.
  * *Tunnel (site 5):* Outbound trusted local; inbound lands on site 1 pre-packet validation.
  * *NAT64/Hairpin (site 8):* Forward-wire matches never mark directly (`lookup.rs:258-293`); promote path blocked by Rule 5.

### Q3 (whole-plan sweep): SOUND
* **Plan Sweep:** No new traces are exposed by v10.3.0. All six Section 11 convergence questions are answered comprehensively in the plan text (§1, §2, §3, §5.2, §5.5, §5.8, §7, §10.5, §10.6, §11).

### NEW TRACES
None.
