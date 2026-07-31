# AGY hostile plan-review — round 104 (v10.21.0)

Reviewer: AGY (direct binary). Verdict: SOUND — full (validation x transition) combination walk, staging verification, dedup/capacity verification.

## Verbatim review

SOUND

### Staff Engineer Design-Document Consistency Review: `docs/research/6461-blind-rst/plan.md` (v10.21.0)

**Branch / Commit:** `research/6461-blind-rst` (`52e363b8640f` base `023f17a606d8` / master `fff7a4ab5`)  
**Scope:** Round-104 folds verification, two-field outcome split, staged placeholder OUT, dedup/capacity-4 displaced set, `UpsertRefused` composition & teardown gating, and overall design consistency sweep.

---

### 1. Checklist Verification

#### (a) Verification of the Two-Field Split (`validation` × `transition`)
The single `MaterializeOutcome` enum has been split into two independent, orthogonal fields (`plan.md:1693-1764`):
1. `validation: Option<CloseValidation>` (`None` | `Some(Accepted)` | `Some(Refused)`) — present only when the driving packet carries closing flags.
2. `transition: TransitionResult` (`None` | `Installed` | `AdoptedPreservingDeadline` | `UpsertRefused` | `OverdueSkipped`) — defined in `userspace-dp/src/afxdp/session_glue/mod.rs`.

**Producer Matrix (`materialize_shared_session_hit`, site 2c):**
- In Part A, an imported replica carries no trusted baseline (`plan.md:1308-1310`), so every closing-flagged site-2c materialization produces `validation = Some(Refused)`. Non-closing packets produce `validation = None`. (Phase 2 wire anchors may later produce `Some(Accepted)`).
- `transition` independently produces `Installed` (fresh probation S2 installed alive), `AdoptedPreservingDeadline` (adopted S2 on non-overdue probation K preserving `min()` deadline), `OverdueSkipped` (upsert skipped wholesale because K is overdue $D \le \text{now}$), or `UpsertRefused` (synced upsert refused due to a non-peer predecessor, `install.rs:310-315`).

**Consumer Matrix Audit:**
- **(i) Terminal Teardown (`poll_descriptor/mod.rs:698-714, 768-784, 824-840`):** Evaluated strictly on `transition`. For `OverdueSkipped` and `UpsertRefused`, teardown is **SKIPPED**. Reasoning: For `OverdueSkipped`, S2 was not installed and K remains under GC; for `UpsertRefused`, S2 was not installed and the surviving non-peer predecessor's identity diverges from S2. Running teardown under S2's identity would incorrectly release NAT and delete companions of the surviving predecessor. For `Installed` and `AdoptedPreservingDeadline`, teardown runs normally if the packet is terminally denied by host-inbound/lo0/junos-host policy.
- **(ii) Anchor Commit Hook:** Does not write on `OverdueSkipped`, `UpsertRefused`, or `validation == Some(Refused)`. Non-closing committed packets on `Installed`/`AdoptedPreservingDeadline` clear probation and apply the established refresh at final admission (`plan.md:1400-1403`).
- **(iii) Flow-Cache Insert (`poll_descriptor/mod.rs:3900-3959`):** Suppressed for `OverdueSkipped` and `UpsertRefused` because S2 is not present in the session table.
- **(iv) Probation Clear + Refresh:** Explicitly blocked on `OverdueSkipped` ($D \le \text{now}$). Overdue entries reap under GC on their existing wheel slot without clock resurrection (`plan.md:1376-1383`).
- **(v) Ownership Promotion (`promote.rs:86-90`):** Guarded by the `probation` flag on K; skipped wholesale for `OverdueSkipped` and `AdoptedPreservingDeadline` while probation remains set.
- **MissingNeighbor Composition (`poll_descriptor/mod.rs:4015, 4662-4829`):** Both `OverdueSkipped` and `UpsertRefused` branching to MissingNeighbor take the live-backed `ExistingResolved` buffer-only arm. They never enter the `SeedEligible` / seed-transaction block, preventing raw-flags seed overwrites of installed predecessors or active probation rows.

---

#### (b) Staging of Placeholder OUT vs Purge-Decision Ordering
- **Sequence in `session_glue/mod.rs:1157-1198`:**
  1. `lookup_session_across_scopes` runs first. If a fabric-wire placeholder $P$ exists, $P$'s key/decision are substituted with the shared canonical session's key/decision. The placeholder identity $P$ is **STAGED** on the lookup hit object, not committed immediately.
  2. `keep_transient` is evaluated (`:1178-1180`).
  3. If `keep_transient == true` (purge path): `purge_translated_synced_hit` (:1181-1193) runs and `resolved` receives `hit.lookup.clone()`. `materialize_shared_session_hit` is **NOT** called. The staged placeholder $P$ is discarded. $P$'s cache family remains valid in the flow cache, preserving master's exact cache behavior for $P$.
  4. If `keep_transient == false`: `materialize_shared_session_hit` (:1197) is called. It **COMMITS** the staged placeholder $P$ into `displaced: DisplacedSet`.
  5. For non-materializing callers (`icmp_embed/nat_match_v4.rs:78-95`, `nat_match_v6.rs:100-125`, `return_resolution.rs:20-28`), materialization is never invoked, so the staged $P$ is discarded.

This staging guarantees no speculative cache invalidations occur on the purge path or non-materializing lookups.

---

#### (c) Dedup & Capacity-4 Bounds vs Producer Exclusivity
- **Fixed Array Capacity:** 4 identity families (`(key, NAT decision, orientation)`).
- **Exclusivity Audit of the 4 Potential Producers:**
  1. *Shadowed Placeholder $P$:* At most 1 per lookup (`lookup_session_across_scopes`).
  2. *Removed Canonical Predecessor $K$:* At most 1 per upsert (`upsert_synced_with_origin`, `install.rs:295-322`, `_previous`).
  3. *Newly Installed / Adopted S2 Family:* At most 1 per materialization site (site 2c).
  4. *Promote Step Preimage:* At most 1 per dispatch (`maybe_promote_synced_session`, `promote.rs:71-140`, returning its displaced preimage via a named OUT parameter).
- **Bounds Guarantee:** Because each role is mutually exclusive and produces at most 1 family per site-2c materialization dispatch, the maximum number of identity families generated in a single transition is $1 + 1 + 1 + 1 = 4$.
- **Deduplication:** Deduping by `(key, NAT decision, orientation)` merges any overlapping identity families (e.g. when S2 key/orientation matches $K$ or $P$). Array overflow is impossible by construction.
- **The Single EMPTY Case:** A site-2c transition yields an EMPTY `DisplacedSet` **only** on an `OverdueSkipped` transition where no shadowed placeholder was present ($P = \text{None}$). Every other transition contains at least S2, $K$, or $P$.

---

#### (d) Surviving Surface Stress & Residual Audit
- **Imported Entry Absorbing State (`plan.md:313-335`):** Imported/synced entries carry no trusted baseline. Closes soft-refuse, causing entries to linger until inactivity timeout (300 s default) unless master's flag-agnostic transient purge removes them. Delivery is never blocked; endpoints terminate cleanly.
- **Path-Switch Stall (`plan.md:960-968`):** Unobserved traffic stretches freeze the anchor; returning traffic lands outside `FWD_SLACK` and stays untrusted. The entry idles out naturally. Fail-toward-refuse is strictly preserved to prevent anchor-walking attacks.
- **Async `EINVAL` & Queue Eviction Tails (`plan.md:612-638, 783-795`):** Post-commit driver/queue drops can leave anchors slightly ahead. Attackers gain no advantage over direct blind closes (~1/6,554–1/10,923 guess probability), bounded by 1 inactivity timeout.
- **Re-scoped Master Exposures (#6522, #6599, #6600):** 
  - `#6522` (unconditional NAT release on reap): split to its own track (`plan.md:2738-2750`).
  - `#6599` (transient-purge Open provenance integrity): master-identical dispatch retained (`plan.md:2753-2774`).
  - `#6600` (import-window reservation race): master-identical behavior retained (`plan.md:2775-2780`).

---

#### (e) Full-Document Consistency Sweep
- All round-104 folds are harmonized across §1 (Status), §3 (Citations & Master Drift), §5.1–§5.8 (Concrete Design), §7 (Invariants), §9 (Test Plan), and §11 (Open Questions).
- Line numbers and citations to base `023f17a606d8` and master `fff7a4ab5` match the worktree source structure.

---

### 2. Summary of Findings

1. **[`docs/research/6461-blind-rst/plan.md:4-11`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L4-L11): Outcome Split and Producer Precedence**  
   *Verification:* The two-field model (`validation: Option<CloseValidation>`, `transition: TransitionResult`) eliminates the precedence ambiguity between validator refusal and materialization outcomes (`Installed`, `AdoptedPreservingDeadline`, `UpsertRefused`, `OverdueSkipped`).

2. **[`docs/research/6461-blind-rst/plan.md:1745-1764`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1745-L1764): Consumer Gating on `UpsertRefused` & `OverdueSkipped`**  
   *Verification:* `UpsertRefused` correctly joins `OverdueSkipped` in bypassing terminal teardown (`poll_descriptor/mod.rs:698, 768, 824`), suppressing flow-cache insertion, and routing MissingNeighbor dispositions to `ExistingResolved` buffer-only handling.

3. **[`docs/research/6461-blind-rst/plan.md:1807-1825`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1807-L1825): Placeholder OUT Staging**  
   *Verification:* Staging the placeholder OUT across `lookup_session_across_scopes` (`session_glue/mod.rs:1157-1197`) and committing it to `displaced` only inside `materialize_shared_session_hit` prevents invalidating flow-cache entries during transient purges or non-materializing lookups.

4. **[`docs/research/6461-blind-rst/plan.md:1776-1806`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1776-L1806): Displaced Set Capacity & Dedup**  
   *Verification:* Fixed capacity 4 is mathematically exact for the 4 exclusive producers ($P + K + \text{S2} + \text{promote preimage}$). Deduplication by `(key, NAT decision, orientation)` prevents overflow and ensures cache invalidation accuracy.

5. **[`docs/research/6461-blind-rst/plan.md:2400-2426`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L2400-L2426): Test Plan Completeness**  
   *Verification:* §9 contains comprehensive coverage for two-field outcomes, staged placeholder invalidation, `UpsertRefused` composition, and overdue skip invariants under per-descriptor and batch-level cache invalidations.
