# AGY hostile plan-review — round 93 (v10.10.0)

Reviewer: AGY (direct binary: agy --print-timeout 11m --print, env -C worktree, built-in-file-tools-only). Verdict: UNSOUND — the first AGY non-SOUND in 10 rounds — with exactly two editorial findings, both stale same-dispatch-install stragglers from the v10.10.0 fold (plan.md:2175-2178 §9 test bullet; plan.md:694/700 §5.2 (iv)). All three substantive v10.10.0 folds were verified against code (install-free exclusion of all five state mutations; reservation-outcome retention condition; overdue-skip pin closure) and the stress tests (single-packet flow; second-packet-during-buffer) passed. The two stragglers are folded in v10.10.1.

## Verbatim review

UNSOUND

### Summary of Findings
1. `docs/research/6461-blind-rst/plan.md:2175-2178` — **Stale same-dispatch install text in Section 9 (Test Plan)**: Line 2177 states under `ResolvedWithoutLocalBacking cold/miss re-entry` that "the seed/aliases install with the OWNED P2 and later cleanup releases P2". This directly contradicts the v10.10.0 round-93 fold (`plan.md:3-6, 428, 1580-1596, 2122-2130`), which made the initial `ResolvedWithoutLocalBacking` re-entry **INSTALL-FREE** (no install, no publication, no `MissingNeighborSeed`, no flow-cache insertion on the re-entry dispatch). The install of seed/aliases with $P2$ occurs only on the *subsequent* packet's genuine miss dispatch (`plan.md:2137-2139`).
2. `docs/research/6461-blind-rst/plan.md:694, 700` — **Unscoped install/publication listing in Section 5.2**: Lines 694 and 700 list "install, publication" among the target stages of the `ResolvedWithoutLocalBacking` miss-decision pipeline without explicitly noting that install and publication are deferred to the second packet's genuine-miss dispatch (unlike the updated text at lines 428, 1580-1596, and 2122-2130).

---

### Detailed Review and Verification

#### (a) Verification of the Install-Free Claim against `MissingNeighbor` Arm and Consumers
* **Code Trace**: `userspace-dp/src/afxdp/poll_descriptor/mod.rs:4015-4816` (MissingNeighbor arm), `poll_descriptor/mod.rs:3900` (flow cache insert), `poll_descriptor/mod.rs:5126` -> `userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:199` (reinjection epilogue), and `userspace-dp/src/afxdp/session_glue/mod.rs:1194-1196`.
* **State Mutations in Earlier Same-Dispatch Shape**:
  1. *Session Table Install*: Calling `install_with_protocol_with_origin` at `poll_descriptor/mod.rs:4792/4816`, performing `remove_entry` / `insert` in the worker `SessionTable`.
  2. *HA Publication & Open Delta*: Emitting `SessionOpen` delta / calling `replicate_session_upsert`.
  3. *Flow Cache Mutation*: Inserting `FlowCacheEntry` at `poll_descriptor/mod.rs:3900` (`binding.flow.flow_cache.insert(entry)`).
  4. *NAT Allocator & Port Reservation*: Allocating source NAT / DNAT pool ports (`allocate_translation` or persistent reacquire).
  5. *Metadata & Counters*: Mutating session admission counters (`session_limit_inc`), policy counters, and metadata flags.
* **Document Exclusion Verification**: Section 3 Site 9 (`plan.md:428`), Section 5.2 (`plan.md:690-705`), Section 5.8 (`plan.md:1580-1596`), and Section 9 (`plan.md:2122-2130`) explicitly exclude all five state mutations on the initial `ResolvedWithoutLocalBacking` dispatch. The derived fresh decision serves *only* that packet's forward/buffer. The next packet re-resolves against the table (which now yields `None`), taking the clean miss path to install and seed.
* **Upstream Equivalence Rationale**: Upstream (`session_glue/mod.rs:1194-1196`) keeps the purged packet in the HIT branch on the retained lookup (`hit.lookup.clone()`), forwarding/buffering without a same-dispatch install. The earlier same-dispatch install+Open shape had collapsed the pre-existing #6599 exposure from two packets to one; install-free restores upstream 2-packet equivalence.

#### (b) Verification of Reservation Outcome Recording and Flag-Agnostic Purge
* **Code Trace**: `userspace-dp/src/afxdp/session_glue/commands/upsert_synced.rs:80` (lines 91 & 105 call `reserve_synced_source_nat_allocation` / `reserve_synced_nat64_allocation`) and `userspace-dp/src/afxdp/session_glue/promote.rs:48-59`.
* **Verification**: `should_keep_synced_hit_transient` (`promote.rs:48-59`) checks `origin.is_peer_synced() && !owner_rg_is_locally_active(...) && is_translated_forward_session_key(...)` and is flag-agnostic. Upstream purges transient-purged entries regardless of whether the packet carries closing flags. Under v10.10.0, close-aware retention is scoped to entries with a *succeeded* synced reservation (`upsert_synced.rs:80`). Entries with failed reservations take upstream's flag-agnostic purge even for closing packets, ensuring upstream self-cleans conflicted $P1$ state on any packet.

#### (c) Verification of Overdue-Skip Closing the Re-queue Pin
* **Code Trace**: `userspace-dp/src/session/expire.rs:130-168` and `userspace-dp/src/session/wheel.rs:39-50`.
* **Verification**: In `wheel.rs:46-50` (`target_tick_for`), when the minimum absolute deadline $D \le \text{now\_ns}$, $\text{delta} = 0$, mapping the target to `now_tick`. Under the previous adopt-S2 rule, re-materialization updated $K$'s wheel slot with $D \le \text{now\_ns}$, re-queuing $K$ into the current wheel tick (`now_tick`). A stream of one packet per tick ahead of a phase-shifted GC pass could re-queue $K$ indefinitely. In v10.10.0, when $D \le \text{now\_ns}$, adopt-S2 skips the upsert wholesale (no remove/recreate, no restamp, no wheel re-queue). $K$ remains on its existing wheel slot to be reaped on schedule by GC, while the packet forwards with $S2$, closing the re-queue pin.

#### (d) Stress Testing New Shapes
1. **Flow receiving only a single packet**: Packet 1 derives its fresh decision, buffers/forwards, and exits. Because no session table entry, `MissingNeighborSeed`, flow-cache entry, or HA Open delta was created on dispatch, no orphaned state or resource leak lingers in the system. Nothing waits on a second packet.
2. **Second packet arriving while packet 1 is buffered for ARP**: Packet 1 is queued in `PendingNeighPacket`. Packet 2 arrives, performs a session lookup, finds `None` (since packet 1 installed no entry), re-resolves as a genuine clean miss (`SeedInstalled`), installs the session entry, emits Open, and queues in `PendingNeighPacket`. When ARP resolves, `retry_pending_neigh` transmits both buffered packets using their respective decisions cleanly.

#### (e) Full-Document Consistency Sweep
* **Finding 1 (`plan.md:2175-2178`)**: Section 9 contains stale text describing same-dispatch install ("the seed/aliases install with the OWNED P2"), contradicting the install-free contract established in round 93.
* **Finding 2 (`plan.md:694, 700`)**: Section 5.2 lists "install, publication" in the RWoLB pipeline without explicit scoping to the second packet's genuine-miss dispatch.
