# Triage result — ps-review-039-a1g

- **Subsystem:** Remaining Rust infra modularity audit (wg, event_stream, cold_path_hist, coordinator/wg_control, types/cos, shared_cos_lease, protocol/binding, types/forwarding, server/helpers, event_emit, coordinator/status)
- **Review base:** f70146951583823a5ace87b0b11a2e58f46e8db9
- **Triaged against origin/master SHA:** 95b33d49634d56086269a62a92e213dae7926f88 (base == master? review base is an ancestor; triaged against current master)
- **Repo tell:** Evidence blocks cite `/home/ps/git/avacado-xpf/userspace-dp/...` (the avacado fork). The files map 1:1 to real bpfrx; two paths carry a spurious `afxdp/` prefix (`afxdp/event_stream/mod.rs` → real `src/event_stream/mod.rs`; `afxdp/protocol/binding.rs` → real `src/protocol/binding.rs`). All cited files exist on bpfrx origin/master with LOC matching the review's totals. Not confabulated — fork-path cosmetic + minor path slips.
- **Outcome counts:** 5 findings → 0 GENUINE-RESIDUAL, 5 NOT-MATERIAL. 0 correctness bugs in the entire review (it is a modularity/reviewability audit: every finding is refactor-class (A) mechanical-split or (D) do-not-split; no (B)/(C) correctness class, no input→wrong-output trace).

## Nature of this review

This is a file-size / modularity audit, not a defect audit. Findings 1–2 recommend
mechanical code-motion splits; Findings 3–5 are explicit negatives ("DO NOT SPLIT" /
"OPTIONAL, defer"). None allege a wrong output, crash, or reachable defect. The
project's split rule (`docs/engineering-style.md` line 218, verified on master) is:

> A `.rs` file that crosses ~2,000 LOC of **production code (excluding `mod tests`)**
> is a smell. By the time it hits ~3,000 LOC the next change to that file should
> split it before adding to it.

The threshold metric is **production LOC excluding `mod tests`** — not total LOC.
Two findings misstate their premise by using total LOC.

## Per-finding disposition

### Finding 1 — wg_control.rs "2280 LOC monolith, over 2000 threshold" (Medium) → NOT-MATERIAL

- **Symbols exist:** yes. `run_wg_control_loop` @332, `dispatch_inbound` @1307, `CmsgBuf`
  @1101, `wg_recvmsg` @1127, `parse_outer_ecn_from_cmsg` @1176. File is 2280 total LOC.
- **Premise is wrong against the project's own rule.** The single `mod tests` block starts
  at line 1577, so **production LOC = 1576**. That is *below* the ~2,000 prod-LOC smell line
  and far below the ~3,000 "MUST split" line. The review claims "File crosses the 2000 LOC
  monolith threshold" by counting total LOC (2280) — it conflates total with the
  prod-LOC-excluding-tests metric that engineering-style.md line 218 explicitly defines.
- **No correctness impact / no failure scenario.** This is a reviewability advisory, not a
  bug. The "two functions exceed 200 LOC" observation is real but the project has no hard
  200-LOC function rule (engineering-style tracks god-functions as a smell, #961, not a gate).
- **Disposition: NOT-MATERIAL.** A defensible "split before the next WG feature pushes prod
  LOC past 2000" advisory at INFO severity, but the file is not currently over any documented
  threshold and there is no defect. Not a residual. (Dedup claim "no prior wg_control split
  filed" is accurate; git log shows the file is actively maintained but never split.)

### Finding 2 — server/helpers.rs "1292 LOC dumping ground" (Low/Med) → NOT-MATERIAL

- **Symbols exist:** yes. `refresh_status` @16, `build_synced_session_entry` @422,
  `replan_queues` @1033. File is 1304 total LOC. Header quoted accurately ("Pure relocation.
  Bodies byte-for-byte identical.", Issue 69.1).
- **Premise overstates size.** Tests start at line 739 → **production LOC ≈ 738**, well under
  the 2,000 smell line. The review's own inventory table claims "prod ~1200" — also an
  overcount (actual ~738). The `refresh_status` "311 LOC" sub-claim is plausible but the
  function is a cold 1/s status aggregator, not a defect.
- **"Dumping ground" is subjective.** The header documents this as an intentional main.rs
  extraction (Issue 69.1); the file is a cohesive daemon-loop-helper module. No correctness
  bug, no failure scenario.
- **Disposition: NOT-MATERIAL.** Reviewability nit resting on an inflated LOC premise; no defect.

### Finding 3 — event_stream/mod.rs 1693 LOC (Low, self-labeled OPTIONAL) → NOT-MATERIAL

- **File exists** at `src/event_stream/mod.rs` (1693 LOC; codec.rs 1165, producer.rs 466 also
  confirmed). Review path had spurious `afxdp/` prefix but resolves.
- The finding itself concludes "**OPTIONAL... leave as-is and revisit when adding next event
  kind**" and rates it "(D) DO-NOT-SPLIT also defensible today." No action proposed, no defect.
- **Disposition: NOT-MATERIAL** (self-deferred; no correctness impact; 1693 total, ~1200 prod
  by the review's own count — under threshold).

### Finding 4 — wg/engine.rs + wg/cookie.rs "DO NOT SPLIT" (negative) → NOT-MATERIAL

- Explicit negative finding (Severity: N/A). Files exist (engine.rs 1805, cookie.rs 1435
  total; both under the prod-LOC threshold). Recommends **no action**. The hot-path
  preservation analysis is descriptive, not a defect claim.
- **Disposition: NOT-MATERIAL** (informational negative concluding correctly that no split is
  warranted; nothing to fix or file).

### Finding 5 — 7 files (cos, forwarding, binding, cold_path_hist, shared_cos_lease, event_emit, status) "DO NOT SPLIT" (negatives) → NOT-MATERIAL

- All 7 files exist on master with LOC matching the review (cos.rs 1786, forwarding.rs 1079,
  binding.rs 1168, cold_path_hist.rs 1866, lease.rs 1460 + epoch 565 + vtime 238 + backlog 210,
  event_emit.rs 1492, status.rs 1195). All under the prod-LOC threshold once tests are
  excluded. Explicit negatives recommending no action.
- **Disposition: NOT-MATERIAL** (informational negatives; nothing to fix or file).

## Summary

Zero genuine residuals. The review is a competent modularity survey whose only two
"actionable" items (Findings 1, 2) rest on total-LOC counts rather than the project's
documented production-LOC-excluding-tests threshold — under that correct metric,
wg_control.rs (1576 prod) and helpers.rs (738 prod) are both below the ~2,000 smell line,
so neither is a mandatory split and neither is a defect. Findings 3–5 propose no action.
No correctness bug, no reachable failure scenario, nothing to drive. Consistent with the
task's expectation that this heavily-hardened cohort (#4517–#4685) yields ~0 residuals.
