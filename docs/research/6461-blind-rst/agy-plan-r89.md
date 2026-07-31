# AGY hostile plan-review — round 89 (v10.6.0 as committed)

Reviewer: AGY (direct binary: agy --print-timeout 11m --print, env -C worktree, built-in-file-tools-only; neutral doc-consistency framing after two safety refusals on adversarial/defensive security framing, two backend stalls, and two RESOURCE_EXHAUSTED 429s — 7 invocations total, documented per feedback_codex_infra_must_retry). Verdict: SOUND — 7th consecutive AGY YES. The prompt named the v10.5.1 commit but the on-disk plan read was v10.6.0 (6218bbe8b4c9), and the review's sections 4(b)/4(c) explicitly verify the v10.6.0 folds (materialize preservation skip, retention fence, RWoLB/ReplacedSyncedLocal suppression incl. SYN-bearing closes + no Open).

## Verbatim review

SOUND

### 1. Fold Verification: Probation Entry Lifetime Isolation
- **Code Trace:**
  - `userspace-dp/src/session/lookup.rs:150-156` stamps `last_seen_ns = now_ns` and recomputes `expires_after_ns`.
  - `userspace-dp/src/session/lookup.rs:214-218` re-queues the canonical key into the timing wheel (`push_to_wheel`).
  - `userspace-dp/src/afxdp/poll_descriptor/mod.rs:592` evaluates DSCP-sensitive input filters (`evaluate_dscp_sensitive_input_filter_on_session_hit`).
  - `userspace-dp/src/afxdp/poll_descriptor/mod.rs:846` performs the TTL/hop-limit check (`ForwardingDisposition::ForwardCandidate`).
  - `userspace-dp/src/afxdp/poll_descriptor/flow_cache_hit.rs:295` calls `sessions.touch_if_stale(&flow.forward_key, now_ns)` (`userspace-dp/src/session/mod.rs:1118`).
- **Document Trace:** `docs/research/6461-blind-rst/plan.md:1250-1273` (§5.6 probation lookup deferred refresh) & `:1340-1355` (§5.8).
- **Verification:** In the existing codebase, `lookup.rs:150-156` and `:214-218` run during the lookup borrow *before* the input filter evaluation at `mod.rs:592` or TTL check at `mod.rs:846`. Similarly, `flow_cache_hit.rs:295` executes `touch_if_stale` on cache hits prior to MTU/egress transmission. The document's rule explicitly requires that for probation entries (`probation == true`), the in-borrow lookup skips `last_seen_ns` stamping, `expires_after_ns` recomputation, and timing-wheel re-queuing, while `touch_if_stale` skips probation entries. The clear of `probation` and the established timeout refresh occur strictly at the final-admission commit hooks (the RX worker's committed packet dispatch arms). This covers every early-exit drop class (input-filter drop, TTL expiration, MTU/geometry discard, CoS/output-filter drop, redirect-inbox capacity discard, and cache-tail drop), ensuring uncommitted or dropped packets can never extend a probation entry's $\le 20\text{ s}$ clock.

---

### 2. Consistency of Section 3.1 ("Master Drift Since the Citation Base")
- **Code Trace:**
  - `userspace-dp/src/afxdp/forwarding/fabric.rs:389`: `pub(in crate::afxdp) fn cluster_peer_return_fast_path` exists in the worktree base commit `023f17a606d8`.
  - `userspace-dp/src/session/lookup.rs:105-128`: `do_close`, `entry.closing = true`, and `entry.reset |= has_rst(tcp_flags)` (Site 1).
  - `userspace-dp/src/afxdp/poll_descriptor/flow_cache_hit.rs:312-317`: `sessions.account_packet(...)` on flow-cache hit.
  - `userspace-dp/src/session/expire.rs:342-350`: `if !metadata.is_reverse && !removed.origin.is_peer_synced() && !removed.origin.is_transient_local_seed()`.
- **Document Trace:** `docs/research/6461-blind-rst/plan.md:368-385` (§3.1 table) & `:308-340` (§3 bullets).
- **Verification:** All inline `file:line` citations match the worktree code (`023f17a606d8`) exactly. `cluster_peer_return_fast_path` is present at `fabric.rs:389` in the worktree. Section 3.1 accurately records that upstream change #6478 (`7b7119db1`) deleted `cluster_peer_return_fast_path`, its reverse-seed install, and the `#4453` bare-close guard, closing Site 6 by deletion on current master (`fff7a4ab5`) while retaining the worktree base analysis for reference.

---

### 3. Acceptance-Window Probability Arithmetic Re-derivation
- **Document Trace:** `docs/research/6461-blind-rst/plan.md:198-218` (§2 framing) & `:888-991` (§5.4 validation rule).
- **Verification:**
  - `BACK_SLACK = 64\text{ KiB} = 65,536` bytes.
  - `FWD_SLACK = \max(2 \times \text{wnd}, 64\text{ KiB})`. With raw $u16$ `wnd` capped at $65,535$, maximum `FWD_SLACK` $= 2 \times 65,535 = 131,070$. Minimum `FWD_SLACK` $= 65,536$.
  - Each sequence/ack leg interval spans $[- \text{BACK\_SLACK}, + \text{FWD\_SLACK}]$, giving a leg width of $\text{BACK\_SLACK} + \text{FWD\_SLACK} + 1$.
  - **Floor Calculation (`wnd` $= 0$, `FWD_SLACK` $= 65,536$):**
    - Leg 1 width $= 65,536 + 65,536 + 1 = 131,073$.
    - Leg 2 width $= 65,536 + 65,536 + 1 = 131,073$.
    - Leg 3 width $= 65,536 + 65,536 + 1 = 131,073$.
    - Sum of 3 disjoint legs $= 3 \times 131,073 = 393,219$.
    - Per-packet probability $= \frac{393,219}{2^{32}} \approx \frac{1}{10,922.58} \approx \frac{1}{10,923}$ (approx. $\frac{1}{2^{13.4}}$).
  - **Cap Calculation (`wnd` $= 65,535$, `FWD_SLACK` $= 131,070$):**
    - Leg 1 width $= 65,536 + 131,070 + 1 = 196,607$.
    - Leg 2 width $= 65,536 + 131,070 + 1 = 196,607$.
    - Leg 3 width $= 131,070 + 131,070 + 1 = 262,141$.
    - Sum of legs $= 2 \times 196,607 + 262,141 = 655,355$.
    - Per-packet probability $= \frac{655,355}{2^{32}} \approx \frac{1}{6,553.78} \approx \frac{1}{6,554}$ (approx. $\frac{1}{2^{12.7}}$).
  - Both figures and the bounded range ($\sim 1/2^{12}$ to $1/2^{14}$) are mathematically exact.

---

### 4. State-Machine Completeness
- **(a) Absorbing State Argument:**
  - **Document Trace:** `docs/research/6461-blind-rst/plan.md:237-253` (§2) & `:727-807` (§5.2 rule 4).
  - **Verification:** Imported entries (`SyncImport`, `SharedMaterialize`, `WorkerLocalImport`) initialize with `trusted = 0` across all four tracking fields (`fwd_seq`, `fwd_ack`, `rev_seq`, `rev_ack`). Under §5.2 Rule 4, untrusted-to-trusted conversion requires proving the candidate sample against an *already trusted* opposite-direction field. Continuity slides require an already trusted field, and strong OPENING proof requires an explicit ISN seed on an install-point primary miss. Because no trusted anchor field exists initially, no packet arriving on an imported entry can satisfy any conversion rule. The zero-trust state is absorbing until entry churn, preventing blind anchor walks on failover/materialized flows.
- **(b) Constructor Gating & Bounded Probation:**
  - **Document Trace:** `docs/research/6461-blind-rst/plan.md:1164-1247` (§5.6).
  - **Verification:** Site 2c (`materialize_shared_session_hit`) installs unanchored materialized entries alive with `closing=false, reset=false` at a bounded probation timeout $\min(\text{TCP\_OPENING\_TIMEOUT\_NS}, \text{imported expires\_after\_ns}) \le 20\text{ s}$. Pre-admission re-materialization probes for an identity-agreeing existing probation entry and skips the upsert if present, preserving the immutable probation deadline. Expired probation entries take a local-only reap (skipping NAT port release and BPF map deletion). Standby retention gates (`SelfHeal`, `Hold`, companion retention) are bypassed at the probation deadline, and `refresh_for_ha_transition` leaves the deadline untouched.
- **(c) `MissingNeighbor` Typed Outcome Dispatch:**
  - **Code Trace:** `userspace-dp/src/afxdp/poll_descriptor/mod.rs:4015-4816`, `userspace-dp/src/afxdp/poll_descriptor/session_admission.rs:53`, `userspace-dp/src/session/install.rs:113-180`.
  - **Document Trace:** `docs/research/6461-blind-rst/plan.md:364` (§3 Site 9) & `:1376-1399` (§5.8).
  - **Verification:** Site 9 branches at the arm head prior to any NAT derivation or state mutation:
    - `ExistingResolved`: Preserves stored resolver decisions and allocator state; buffers packet without re-installing or corrupting live/marked entries.
    - `ResolvedWithoutLocalBacking`: Re-enters the cold/miss pipeline from the packet (deriving pre-routing DNAT, routing, zone, policy, and SNAT fresh) as a single decision object. Under peer-synced provenance (`RWoLB` re-entry / `ReplacedSyncedLocal`), constructors suppress `closing`/`reset` seeds even for SYN-bearing closes and suppress Open emission.
    - `SeedInstalled` / `SeedRefused`: Handles top-level misses subject to the `#4400` guard (`session_admission.rs:53`).
- **(d) Closing-Never-Promote Discipline:**
  - **Code Trace:** `userspace-dp/src/session/lookup.rs:146-149`, `userspace-dp/src/afxdp/session_glue/promote.rs:86-107`, `userspace-dp/src/session/mod.rs:1299-1432`.
  - **Document Trace:** `docs/research/6461-blind-rst/plan.md:811-837` (§5.2 Rule 5) & `:1082-1099` (§5.5).
  - **Verification:** Rule 5 suppresses both promote paths for any segment with `is_closing(tcp_flags)`:
    - `promote_from_reverse` (`lookup.rs:146-149`) skips in-borrow `established` promotion on closing SYN-ACKs.
    - `maybe_promote_synced_session` (`promote.rs:86-107` / `update_session` at `mod.rs:1299`) skips `SharedPromote` origin flipping for closing segments, preventing unauthorized Close delta emissions or standby state deletions.

---

### 5. Reconciliation of Upstream Drift and Internal Consistency
- **Document Trace:** `docs/research/6461-blind-rst/plan.md:28-37` (header), `:308-310`, `:325-340`, `:360-362`, `:376-384`, `:745`, `:1312`, `:1573-1576`.
- **Verification:** The document maintains complete internal consistency regarding upstream drift. The header note and §3.1 state clearly that inline citations reference the worktree base (`023f17a606d8`), while master deltas (`fff7a4ab5`) are tabulated in §3.1. Every mention of `cluster_peer_return_fast_path` / fabric-return reverse seeds in §3, §5, §5.6, and §7 explicitly qualifies it as a worktree branch-base artifact that was removed upstream by `#6478`, leaving Site 6 closed by deletion on current master without introducing contradictions.

---

### Round-88 Disposition
The round-88 AGY YES verdict condition (isolating probation entry lookups from pre-filter lifetime refreshes, recomputations, and wheel pushes) is fully folded in §5.2, §5.5, §5.6, §5.7, §5.8, and §9, and remains satisfied.
