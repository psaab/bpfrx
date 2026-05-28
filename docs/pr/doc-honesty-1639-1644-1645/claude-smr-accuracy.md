# Claude SMR — Accuracy Self-Review: doc-honesty (#1639 + #1644 + #1645)

Docs-only PR. Every corrected claim is grounded against `origin/master`
(`dbfbf680c`) or a verified issue measurement. I reviewed each edit
hostilely against its own source-of-truth to confirm I did not replace
one wrong claim with another overclaim.

## #1639 — `docs/userspace-jit-design.md` Phase 6 CoS row

**Before:** `**DONE** — ... small-class guarantees honoured under 6×
oversubscription; ~3-7× per-class throughput improvement on
100m/1g/3g/6g classes`

**After:** `**WIRED / NOT YET MEETING GATE**` — wire surface + commit
warning shipped (#1618), smoke fixture activates the knob (#1629), but
the scheduler does not honour small-class guarantees: under
`guarantee-rate 0.7` it still equalizes ~20%/class instead of meeting
the small-class ≥95% gate (#1630). Root cause: the v8 epoch-cap clamp
discards lagged rate credit (`rotate_epoch_v8.rs`). Gain column →
`regression open, see #1630/#1614`.

**Source of truth:**
- #1614 OPEN, #1630 OPEN (verified via `gh issue view`).
- #1630 body measurement: 100m/1g/3g/6g classes receive 19/20/22/23%
  of configured shape under `guarantee-rate 0.7`, `shaping-rate 25g`.
- Root cause is the latest converged finding in #1630 comments
  (`/engineer` STOP-and-report): the v8 rotation clamp
  `elapsed.min(EPOCH_DURATION)` at `rotate_epoch_v8.rs:218` discards
  `rate × (lag − EPOCH_DURATION)` rate credit when a rotation lags past
  one epoch; a diagnostic probe relaxing the clamp lifted solo ceilings
  to ~94-95%. File `rotate_epoch_v8.rs` exists on master
  (`userspace-dp/src/afxdp/types/shared_cos_lease/rotate_epoch_v8.rs`).

**Hostile check:** Did I overclaim the root cause as "fixed/known-safe"?
No — I phrase it as "root cause proven," which matches the #1630
converged diagnosis, and I keep the feature status as NOT meeting the
gate with the regression tracked open. I did not assert a fix exists.
The "#1618 wire surface shipped" and "#1629 fixture" sub-claims are
both stated in #1630/#1639 bodies. I removed the fabricated "~3-7×"
multiplier entirely — that number had no measurement backing it.

**Scope guard:** I did NOT touch the Phase 1 row or any "~2ms" line in
this file (owned by in-flight #1636). Only the Phase 6 row changed
(`git diff` shows 1 line, +1/-1).

## #1644 — `docs/dpdk-dataplane.md` + `docs/dataplane-decision-dpdk-vs-vpp.md`

**Before (both, "Current State"):** source "remains in-tree until Phase
3 of #1525 deletes it"; commit-rejection "planned in Phase 1 (#1526;
not yet on master)."

**After (both):** retirement complete — source deleted from master
(#1528 mechanical removal, #1527 boot decoupling), only docs remain;
commit-rejection live on master (#1526) via `validateDataplaneTypeStrict`
in `pkg/config/compiler.go` (returns `ErrDPDKDataplaneRetired`), while
`compileSystemDataplaneType` still parses the `dpdk` token for
legacy-config compatibility.

**Source of truth:**
- `git ls-tree -r --name-only origin/master | grep -i dpdk` returns
  only `docs/...` paths — no `dpdk_worker/` or `pkg/dataplane/dpdk/`
  source. Confirms deletion.
- `git show origin/master:pkg/config/compiler.go` shows
  `validateDataplaneTypeStrict` (called from `compileExpanded` at
  `compiler.go:266`) returning `ErrDPDKDataplaneRetired` when
  `cfg.System.DataplaneType == dataplaneTypeDPDK` (`compiler.go:372-383`).
  This is the actual hard commit-time rejection.
- `git show origin/master:pkg/config/compiler_system.go` shows
  `compileSystemDataplaneType` *accepting* `dpdk` as a known type and
  only parsing the token ("dpdk parses for legacy-config compatibility
  but is rejected at commit per #1525"); the rejection itself is in
  `validateDataplaneTypeStrict`, not here.

**Correction (Copilot review, r1):** the first draft cited
`compileSystemDataplaneType` as the rejecting function. Copilot
correctly flagged that this function only parses the token — the hard
rejection returning `ErrDPDKDataplaneRetired` is
`validateDataplaneTypeStrict` in `pkg/config/compiler.go`. Both DPDK
docs and this note were corrected to point at the right function/file.
- PR refs #1526/#1527/#1528 are the retirement-chain PRs named in the
  #1644 issue body and confirmed CLOSED COMPLETED there.

**Hostile check:** Did I attribute deletion to the wrong PR? The issue
body and CLAUDE.md both state `dpdk_worker/` + `pkg/dataplane/dpdk/`
are "removed in #1527/#1528" — I credit #1528 mechanical removal +
#1527 boot decoupling, consistent with both. I did NOT touch the
"[Retired] Historical Decision/Design" sections (lines ~61+ / ~44+),
which are explicitly preserved as as-of-2026-03-02/2026-03 reference
and correctly framed as historical; editing them would misrepresent
the decision-time record. Only the "Current State" bullets changed.

## #1645 — `docs/userspace-cold-start-resolution.md`

**Before:** four lines presenting cold connect as resolved to ~2ms
(L16 "~2ms delay after all fixes", "Total cold latency: ~2ms", table
rows "Cold TCP connect ... ~2ms" and "Neighbor resolution ... ~2ms").

**After:** added an accuracy banner; reframed each "~2ms" as the
intended target and added "currently measured ~3.371s under a cold
neighbor cache (post `ip neigh flush`)" with the 260 ms-probe vs
2000 ms-timeout gap as cause; mitigation tracked by #1636.

**Source of truth:**
- #1636 body: measured wall-clock cold connect = 3.371 s after
  `ip neigh flush all` (transcript: 1779989031.725 − 1779989028.354 =
  3.371 s). The 260 ms probe schedule vs 2000 ms
  `PENDING_NEIGH_TIMEOUT_NS` gap is documented in the same body, in
  `neighbor_dispatch.rs`.

**Hostile check:** Did I hardcode 3.371s as a permanent resolved value?
No — I phrase it as "currently measured ~3.371s" + "mitigation tracked
by #1636" and explicitly say "once it lands these figures will be
updated to the post-fix measurement." I did NOT delete the ~2ms design
target (kept as the goal), so when #1636 lands the editor has the
target and the to-be-replaced current value both visible. This is a
different file from `userspace-jit-design.md`, so no conflict with
#1636's own doc-update checkbox.

## Cross-cutting accuracy

- No source under `userspace-dp/src/`, `pkg/`, `cmd/`, `test/` touched
  (`git diff --stat` = 4 docs only).
- No new claim introduced that I cannot cite to master state or an
  issue measurement.
- No harness/control tags in any GitHub-bound text.

**Verdict: CLEAN.** All three corrections are grounded; no new
overclaim introduced.
