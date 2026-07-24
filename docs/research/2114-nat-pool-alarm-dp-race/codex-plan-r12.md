# Codex hostile plan-review — round 12 (plan v12 @ `5f3aff8c1`)

Reviewer: Codex (companion task `task-mrymdz90-yppxbx`, session
`019f9307-c330-7610-8bcd-d92b8ee4a383`; dispatched from the worktree,
read-only). Verbatim output below; fold adjudications recorded in plan v13.

---

Fold verification:
1. NOT-FOLDED — Plain commit, explicit confirmation, and demotion converge through clearPendingConfirmLocked (pkg/configstore/store_commit.go:245,743,784,678-702); SyncApply resolves or defers at pkg/configstore/store.go:717-760; timeout and boot recovery resolve at pkg/configstore/store_commit.go:913-937 and pkg/configstore/store_persist.go:149-220. Only the retry bypasses resolveConfirmRemovalLocked (pkg/configstore/store_persist.go:439-444). The Resolved→hash mismatch→expired→H→re-arm order and confirmGen timer guard are correct (pkg/configstore/store_commit.go:717-726,856-865), but tombstone linearization, retry identity, write-failure semantics, and downgrade compatibility remain broken; regression (x) at plan.md:1373-1378 covers none of those failure cases.
2. PARTIAL — Same-version canonicalization holds: ReadActiveMeta decodes at pkg/configstore/db.go:377-380 before Load mutations at pkg/configstore/store_persist.go:65,74; JSON preserves the ordered Keys/Children slices, Annotation, and Inactive fields used by Format (pkg/config/ast.go:10-45,124-127; pkg/config/ast_format.go:80-145). No explicit second recovery round-trip is required, and the extra work is commit-paced (pkg/configstore/store_commit.go:397-524), not a packet hot path. The hash-basis transition is nevertheless unversioned, and the claimed SyncApply arm does not exist.
3. FOLDED — The normative text consistently names the canonical round-tripped decoded-tree Format basis and rejects literal on-disk bytes (plan.md:692-735,1499-1502).
4. FOLDED — Regression viii now uses production CommitConfirmed, checks GuardedHash against a freshly decoded ReadActiveMeta tree, and restarts without hand-built persistence files (plan.md:738-745,1360-1367; pkg/configstore/store_commit.go:368-524; pkg/configstore/db.go:95-103).

New findings:

MAJOR — Tombstone durability is not the resolution linearization point. clearPendingConfirmLocked first cancels the timer, bumps confirmGen, and discards rollback state, then calls the durable resolver (pkg/configstore/store_commit.go:678-702,717-726). A crash after that logical confirmation but before the tombstone lands—or any WriteConfirm failure—leaves the old matching pending record, so restart re-arms an already-confirmed window. Demotion ignores resolution errors (pkg/configstore/store_commit.go:780-792). This contradicts "genuinely pending" at plan.md:762-769 and the absolute invariant at plan.md:1198-1209. The plan must pin tombstone-before-logical-resolution or explicitly define and test the residual failure semantics.

MAJOR — Tombstone retry debt is not generation-safe. confirmRemoveDegraded is only an unkeyed boolean (pkg/configstore/store.go:152-166), and retry operates on whichever confirm.json currently exists (pkg/configstore/store_persist.go:439-449). After deletion failure for resolved record A, a new CommitConfirmed can write genuinely-pending record B at pkg/configstore/store_commit.go:503-524; the pre-arm cleanup handles only confirmResolvePendingPersist (pkg/configstore/store_commit.go:631-649). Re-driving "tombstone→removal" then tombstones/deletes B. Cancellation also clears the in-memory record content at :717-726, so rereading disk cannot distinguish stale A from fresh B without identity. Pin record identity or explicit new-arm supersession and add delete-failure→new-arm→retry→restart coverage.

MAJOR — The claimed compatibility envelope does not cover confirm.json. plan.md:769-772 says the Resolved field rides wrapEnvelope, but WriteConfirm explicitly uses no #1917 envelope and writes bare/encrypted JSON (pkg/configstore/db.go:199-218); ReadConfirm directly unmarshals it (pkg/configstore/db.go:242-280). A full tombstone is therefore accepted by an old binary with Resolved ignored and re-armed; a minimal tombstone is rejected by current validation before recovery can inspect Resolved. Furthermore, writerVersion is informational (pkg/configstore/db.go:23-35); actual rejection uses EnvelopeFormatVersion/EnvelopeMinReaderVersion (pkg/configstore/envelope.go:111-126,237-253). The compatibility mechanism and tombstone shape must be decided now, not deferred to /engineer.

MAJOR — Changing the meaning of nonempty GuardedHash has no migration rule. confirmRecord has no hash-basis discriminator, and only an empty hash is recognized as legacy (pkg/configstore/db.go:182-191; pkg/configstore/store_persist.go:149-159). A pre-v12 binary hashes the raw promoted tree at pkg/configstore/store_commit.go:543-548 while active persistence normalizes through JSON at pkg/configstore/db.go:435-440; upgrading inside an invalid-UTF-8 window therefore makes v12 stale-drop a live record. Conversely, master mutates an inactive retired leaf before comparing at pkg/configstore/store_persist.go:65,159, so downgrading a v12 pre-migration record stale-drops it. Require a versioned hash basis plus legacy policy/tests, or explicitly block upgrade/downgrade during pending windows.

MINOR — The "SyncApply arm" cited at plan.md:157-158,724-725 does not exist. The sole production confirm-record arm is writeConfirmState at pkg/configstore/store_commit.go:524,535-550. SyncApply instead cancels and resolves a local window (pkg/configstore/store.go:697-760), and the daemon explicitly documents that peer SyncApply arms no timer (pkg/daemon/daemon_apply_commit.go:710-713). Correct the arm-site inventory.

NEEDS-REVISION

---

## Orchestrator fold adjudication (into v13)

All 4 MAJOR + 1 MINOR code-verified before folding:

- M1 (linearization) VERIFIED — `cancelPendingConfirmTimerLocked`
  (`store_commit.go:717-726`) stops the timer, bumps `confirmGen`, and
  NILS the in-memory record content BEFORE the durable removal. Folded:
  tombstone-first ordering — (1) durable read-mutate-write tombstone
  (the linearization point), (2) in-memory resolution, (3) best-effort
  delete; write-failure proceeds in-memory + debt; the irreducible
  residual (write-fail + crash before retry) documented, strictly
  smaller than today's whole-deletion window; confirm NOT made
  durability-gated (would invert disk failure into rollback).
- M2 (retry not generation-safe) VERIFIED — `confirmRemoveDegraded`
  unkeyed bool; retry removes whatever confirm.json exists
  (`store_persist.go:439-444`); pre-arm cleanup handles only
  `confirmResolvePendingPersist` (`store_commit.go:631-649`). A
  resolved-A/delete-failed → arm-B sequence lets the retry destroy B's
  genuinely-pending record on master TODAY. Folded: arm supersedes the
  debt by overwrite (`writeConfirmState` clears the flag with a journal
  note) + regression (x4).
- M3 (envelope claim) VERIFIED — also found independently by Claude SMR
  (m1) and AGY (Attack 1). `WriteConfirm` has no envelope; the
  additive-JSON-field contract (`db.go:200-205`) is the evolution
  mechanism; the real floor (`envelope.go:111-123`) governs
  `active.json` only. DECIDED in v13 (not deferred): additive fields +
  documented downgrade semantics.
- M4 (unversioned hash basis) VERIFIED — no discriminator on
  `confirmRecord`; upgrade-in-window (invalid UTF-8) and
  downgrade-in-window (inactive retired leaf) both spuriously
  stale-drop a LIVE record. Folded: additive `HashBasis:
  "canonical-v1"` + dual-basis recovery compare + (x6) tests.
- m1 (SyncApply arm) VERIFIED — sole arm is `writeConfirmState`
  (`store_commit.go:524,535-550`); SyncApply cancels/resolves
  (`daemon_apply_commit.go:710-713`). Folded.

AGY r12's two remediations converged independently with Claude SMR
m1/m2 and are folded identically (additive-field decision;
read-mutate-write full-record tombstone — the minimal form trips the
#5637 gate at `db.go:275-281` and wedges recovery at
`store_persist.go:141`).

Verdict recorded: **NEEDS-REVISION (4 MAJOR, 1 MINOR)**.
