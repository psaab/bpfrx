# AGY hostile plan-review — round 98 (v10.15.0)

Reviewer: AGY (direct binary). Verdict: UNSOUND with three specification-completeness findings: (1) §11 Q3(c)'s 'retained close' phrasing survived the marker retraction; (2) the alias-complete invalidation text omitted the reverse companion key reverse_session_key(key, decision.nat); (3) §5.8's OverdueSkipped summary omitted the ownership-promote and probation-clear/refresh consumers. The full consumer walk, the retraction completeness, the alias analysis, and the surviving-surface stress tests were all verified sound. Folded in v10.15.1.

## Verbatim review

UNSOUND

### Finding 1: Stale Retracted-Marker Terminology in Section 11
**Trace:** [plan.md:2497](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L2497)
**Details:** Section 11 Question 3(c) retains obsolete terminology from the retracted close-retained marker design: `(c) the account_packet wording (counters/flags advance per the pre-existing #2501 accounting — including on a retained close, the round-95 Codex 6 telemetry-only carve-out; the anchor rides the distinct post-admission hook)`. In v10.15.0, the close-aware purge gate and close-retained marker were fully retracted, making the transient-purge path flag-agnostic (`userspace-dp/src/afxdp/session_glue/promote.rs:48-59`) and forwarding on the retained lookup decision (`userspace-dp/src/afxdp/session_glue/mod.rs:1194-1196`). There are no "retained closes" or `close_retained` markers in the v10.15.0 design. The phrase "including on a retained close" contradicts the v10.15.0 retraction and must be removed/updated to reflect master-parity accounting on purged dispatches.

---

### Finding 2: Incomplete Alias Key Specification for Probation Flow-Cache Invalidation
**Trace:** [plan.md:1373](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1373), [plan.md:2262](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L2262)
**Details:** In §5.6 and §9, the probation local-only reap invalidation specification states: `invalidates the flow-cache entries for ALL of the entry's keys (canonical + forward-wire aliases — flow_cache.rs:578-580 vs entry.rs:337-343)`. `FlowCacheEntry` keys by `flow.forward_key` ([flow_cache.rs:578-580](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/flow_cache.rs#L578-L580)), whereas `ExpiredSession` carries the session table's canonical key `key` ([entry.rs:337-343](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/entry.rs#L337-L343)). For translated bi-directional sessions (SNAT/DNAT/NPTv6/NAT64), reverse flow traffic creates a flow-cache entry keyed by `reverse_session_key(key, decision.nat)`. Explicitly listing only `canonical + forward-wire aliases` omits the reverse companion key (`reverse_session_key`), which would leave stale reverse flow-cache entries un-invalidated upon a probation local-only reap. The specification must explicitly include `reverse_session_key(key, decision.nat)` alongside canonical and forward-wire alias keys.

---

### Finding 3: Incomplete Downstream Consumer Set Enumeration for `OverdueSkipped`
**Trace:** [plan.md:1582-1586](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1582-L1586)
**Details:** §5.8 summarizes the downstream consumers of `OverdueSkipped` as `honored by the terminal teardown (suppressed — the dispatch installed nothing), the anchor commit hook (no write), and the flow-cache insert (suppressed)`. While §5.6 correctly details that an overdue probation entry skips upsert wholesale, §5.8's summary sentence omits two critical downstream consumers from its explicit enumeration:
1. **Ownership Promotion (`maybe_promote_synced_session`):** Must be suppressed / cannot engage because no local entry is installed or returned.
2. **Probation Clear + Refresh:** Must be suppressed (`commit-hook clear+refresh NEVER applies to an overdue probation entry`) to prevent resurrecting an overdue entry for a full established timeout.
To ensure completeness, §5.8 must explicitly list all 5 downstream state consumers (terminal teardown, anchor commit hook, flow-cache insert, probation clear/refresh, ownership promotion).

---

### Consistency Sweep & Checklist Verification Summary

#### (a) Verification of the Retraction
- **Status:** Complete in live mechanics, with one textual artifact identified in Finding 1.
- **Code Alignment:** 
  - `promote.rs:48-59` (`should_keep_synced_hit_transient`) is verified to be completely flag-agnostic (`origin.is_peer_synced() && !owner_rg_is_locally_active() && is_translated_forward_session_key()`).
  - `session_glue/mod.rs:1194-1196` forwards on `hit.lookup.clone()` when `keep_transient` is true, without local session installation.
  - Cold next hops take master's seed transaction (`MissingNeighborSeed`).
  - Section 7 accurately documents the close-on-purged-provenance sequence (close #1 purges; SYN-bearing close #2 clean-misses and installs fresh state with an Open delta) as pre-existing master behavior (#6599 family).

#### (b) Verification of the `OverdueSkipped` Consumer Set
- **Status:** Incomplete summary enumeration (Finding 3).
- **Consumer Walk:**
  1. *Terminal Teardown (`session_glue/mod.rs:467-581`):* Suppressed (prevents destroying the entry family of the incoming S2 decision).
  2. *Anchor Commit Hook:* Suppressed (no anchor write on skipped materialize).
  3. *Flow-Cache Insert:* Suppressed.
  4. *Probation Clear + Refresh:* Suppressed (prevents resurrecting overdue S1 state).
  5. *Ownership Promotion:* Suppressed / Cannot engage (no local entry to promote).
  6. *Accounting (`account_packet`):* Operates pre-admission on flow volume (RT_FLOW volume semantics) as on master / unaffected.

#### (c) Verification of Alias-Complete Invalidation
- **Status:** Omission of reverse companion key in text specification (Finding 2).
- **Coverage:** Invalidation at probation local-only reap must cover:
  1. Canonical key (`key`)
  2. Reverse companion key (`reverse_session_key(key, decision.nat)`)
  3. Forward-wire alias key (for NAT64 / hairpin wire translations)

#### (d) Stress Test of the Surviving Surface
- **Demote Gate (§5.1–§5.5):** 40 B POD `TcpSeqAnchor` on canonical forward entry; 6 gating rules (closing segment no-update, seq slide `seg_len > 0` + serial max, ack slide `has_ack` + per-stream `FWD_SLACK`, provenance trust matrix, closing-never-promote); post-borrow reciprocity check (`NAT1 == NAT2`); inert refused close. All sound and consistent.
- **Constructor Gates & Probation Discipline (§5.6, §5.8):** Site 2b local scope + key/NAT identity agreement requirement; Site 2c alive install at `min(TCP_OPENING_TIMEOUT_NS, expires_after_ns)`; re-materialization atomic adoption of S2 with `min(deadline)` encoding (`last_seen_ns = now_ns`, `expires_after_ns = D - now_ns`); local-only reap (no NAT release, no BPF family-key delete, no Close delta); retention fence bypassing SelfHeal/Hold/companion-retention at deadline. All sound.
- **`ReplacedSyncedLocal` Skip (§5.6):** Primary miss install self-authenticates only when displacing nothing synced. Closing-flagged packet on `ReplacedSyncedLocal` skips displacement (`take_synced_local` skipped, synced victim preserved) and delivers locally. All sound.
- **Site-9 Typed Outcomes (§3, §5.8):** Arm-head resolve outcome branch (`ExistingResolved` buffer-only; `PurgedRetained` warm-path retained lookup forward; `SeedEligible` cold-path master seed transaction). All sound.
