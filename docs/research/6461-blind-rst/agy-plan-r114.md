# AGY hostile plan-review — round 114 (v10.30.0)

Reviewer: AGY (direct binary). Verdict: UNSOUND with two straggler findings: the §5.8 consumer header still said six and the §9 OverdueSkipped propagation assertion still tested the sixth (establishment-promote) consumer. Everything else verified SOUND, including the mutual-exclusion proof and the identity-bound token. Folded in v10.30.1.

## Verbatim review

UNSOUND

### Finding 1: Stale consumer count in section header
**Location:** `docs/research/6461-blind-rst/plan.md:1856`
```markdown
- **Consumers (six, normative — the establishment promote is the sixth, v10.29.0, round-113 Codex 3):**
```
**Trace & Analysis:**
The section header at `plan.md:1856` still specifies "six" consumers from v10.29.0. However, sub-bullet `(vi)` at `plan.md:1920` explicitly documents that in v10.30.0 (round-114 fold) the establishment promote was removed from the report consumers via the mutual-exclusion proof. This leaves exactly five normative consumers, as correctly noted in the Status summary (`plan.md:4`) and §11 (`plan.md:3140`). The header count at line 1856 was left un-updated during the round-114 fold.

---

### Finding 2: Un-folded test plan oracle assertion for establishment promote report consumer
**Location:** `docs/research/6461-blind-rst/plan.md:2652-2659`
```markdown
- **OverdueSkipped propagation (v10.17.0, round-100 Codex 2/3):** the
  report is initialized `MaterializeReport::NONE` on every resolve
  path and set from the materializer's OUT report (all four
  transitions, not only the overdue skip — v10.24.0, round-107
  Codex 6); the poller hoists it at
  `poll_descriptor/mod.rs:509` and carries it past the `:883`
  reduction; assert each of the SIX consumers honors it (teardown
  suppressed at all three sites — `:698-714`, `:768-784`, `:824-840`;
  no anchor write; no cache insert; no clear+refresh; no ownership
  promote; AND no establishment-promote apply — the candidate is
  computed post-borrow and the apply is deferred to the end of the
  resolve, after the materialize produces the report, v10.29.1
  round-113 AGY)
```
**Trace & Analysis:**
The unit test oracle for `OverdueSkipped` propagation at `plan.md:2652-2659` still asserts that establishment-promote apply defers to the end of resolve and checks `MaterializeReport` as one of "SIX consumers". 

This directly contradicts the core round-114 fold landed in v10.30.0 (`plan.md:4`, `plan.md:1920`, `plan.md:3140`):
1. The mutual-exclusion proof (`userspace-dp/src/afxdp/shared_ops.rs:583-590`, `lookup.rs:146`) proves an establishment candidate (`is_reverse == true`) and a fabric-wire placeholder substitution (`!is_reverse`) are mutually exclusive. No dispatch ever produces both an establishment candidate and a shared materialization report.
2. Consequently, establishment promote was removed from report consumers and does not defer or check `MaterializeReport`.
3. The test suite assertion at line 2652–2659 retains the obsolete v10.29.1 deferred consumer check, making the §9 test specification unsound against the v10.30.0 design.

---

### Verification Summary

1. **Mutual-Exclusion Proof (Checklist a):** **SOUND.**
   An establishment promote candidate requires `entry.metadata.is_reverse == true` (`userspace-dp/src/session/lookup.rs:146`). Fabric wire placeholder substitution requires `!is_reverse` (`userspace-dp/src/afxdp/shared_ops.rs:583-590`). In `lookup_session_across_scopes` (`shared_ops.rs:602-635`), a local hit with `is_reverse == true` yields `ResolvedSessionLookup::local_query` and never triggers `is_fabric_wire_placeholder` or shared materialization. A clean local miss or forward-wire placeholder substitution never hits a local reverse entry. Thus, no dispatch ever has both an establishment candidate and a `MaterializeReport`. Removing establishment promote from report consumers is mathematically sound.

2. **Identity-Bound Matched Token (Checklist b):** **SOUND.**
   The optional token `Option<(SessionKey, NatDecision, bool, u64)>` riding the lookup return, resolution result, and cache entry captures canonical key, NAT decision, orientation (`is_reverse`), and `install_epoch`. Same-key replacement paths (`install.rs:323`, `upsert_synced.rs:65-79`, `session/mod.rs:1384`) advance `install_epoch` via `next_epoch()`. The commit hook and cache-hit re-probe verify full identity agreement, suppressing authority mutations (clear, refresh, anchor update, overdue handling) on epoch or NAT/orientation mismatch. Storing the packet query key separately on `FlowCacheEntry.key` preserves cache hashing, lookup, and dedup invariants (`flow_cache.rs:578-581`, `:962-989`, `:1046-1065`).

3. **Surviving Five Consumers (Checklist c):** **SOUND.**
   (1) Terminal teardown skip across 3 sites (`poll_descriptor/mod.rs:698-714`, `:768-784`, `:824-840`); (2) Anchor commit hook write skip; (3) Flow-cache insert skip (`:3900-3959`); (4) Probation clear+refresh skip on overdue; (5) Ownership promote skip on `OverdueSkipped` and `(Site2c, Refused)`.

4. **Surviving Surface & Pre-filter Split (Checklist d):** **SOUND.**
   The atomic transaction for establishment promote apply (`established = true`, established/per-app timeout recomputation, `last_seen_ns = now_ns`, wheel re-queue) prevents stranding entries on opening timeouts. The pre-filter split properly isolates state-machine evaluation (`established`/timing) from post-admission commit-point anchor learning.
