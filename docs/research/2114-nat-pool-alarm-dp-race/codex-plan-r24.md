# Codex hostile plan-review — round 24 (plan v24 @ db70b9ac8)

Task: task-mrzjrwtg-0bq72q (session 019f965f-707a-76f2-bd78-5baa34dbfe6f).
Verdict: NEEDS-REVISION (2 MAJOR, 4 MINOR). Raw companion output follows verbatim.

---

Fold verification:

1. FOLDED — D destroys only after a PERMANENT-class read; transient EACCES/short-read/master-key I/O retains D untried with no write/delete. Acceptance copies agree. docs/research/2114-nat-pool-alarm-dp-race/plan.md:1903-1914,2253-2262,3229-3237.

2. PARTIAL — WriteConfirm can atomically replace an unreadable inode without reading it, and W-before-D consistently generalizes D2. However, “restore FAILURE → d-i” fails to distinguish pre/post-rename outcomes, and the promised slot-keyed D crash regression is absent from §9. pkg/configstore/db.go:207-218; pkg/fsatomic/fsatomic.go:278-369; plan.md:1672-1713,1681-1684,3229-3239,3257-3273.

3. FOLDED — Both normative copies scope the guarantee to restore-first ordering and admit restore-failure→delete→crash-before-next-W. plan.md:1717-1725,2923-2930,2965-2970.

4. PARTIAL — HashBasis and NORMAL/exceptional downgrade legs landed, but the FirstCommit rationale is factually wrong and a stale body copy still claims it trips H “on any reader.” plan.md:1863-1894,2114-2122; pkg/configstore/store_persist.go:166-194,231-247.

5. PARTIAL — Exact schema copies exist, but §5.1 still specifies “aggregate bool + mask + enum”; other test copies omit RestartRecoveryOwed precedence. plan.md:2057-2071,2277-2287,2597-2601,3249-3255,3309-3323.

New findings:

MAJOR 1 — The permanent-error state machine contradicts itself. W’s (w-u) and D’s (d-i) require repair writes after PERMANENT ReadConfirm failures, while the global taxonomy says every such debt terminalizes and becomes probe-only with no writes. Invalid master-key length concretely makes both the read permanent and the subsequent WriteConfirm fail before rename. The specific-table interpretation retries indefinitely on the capped 1s→60s loop; the global interpretation terminalizes. Explicitly carve W/D out and pin repair-write failure ownership, health state, and remediation. plan.md:1672-1684,1785-1824,1895-1907; pkg/configstore/crypto.go:262-270,443-465; pkg/configstore/store_commit.go:611-628; pkg/configstore/store_persist.go:389-465.

MAJOR 2 — The old-reader downgrade oracle is wrong. Recovery first assigns s.active=rec.PrevTree; FirstCommit=true does not replace it with an empty tree. It instead forces compiled=nil, everCommitted=false, committed=0 and, after re-arm, first-commit/bootstrap handling. Because synthetic PrevTree is the current tree, the proposed “revert-to-identical → consumed” test can pass while committed/runtime posture is broken. Assert serialized FirstCommit=false plus compiled configuration, committed marker, and non-bootstrap outcome. plan.md:1867-1894; pkg/configstore/store_persist.go:166-194,231-247; pkg/configstore/store_commit.go:867-908; pkg/daemon/daemon_apply_commit.go:645-675.

MINOR 1 — (w-u) must qualify restore failure by phase. Pre-rename leaves unreadable A for d-i; post-rename leaves live C visible, so W remains owed and D’s mandatory re-read must reach d-iii, not reuse the earlier permanent result. Add both phase regressions, including slot-keyed D. plan.md:1678-1684,1705-1713; pkg/fsatomic/fsatomic.go:354-367.

MINOR 2 — Health schema remains internally inconsistent: §5.1 retains the exact aggregate-first schema rejected in r23, and duplicate acceptance text omits RestartRecoveryOwed. plan.md:2337-2341,2597-2601,3249-3255.

MINOR 3 — Operator ownership is unpinned. The runbook permits repairing confirm.json while W overwrites any differing record; single-Store ownership excludes only another Store, not hand edits. State that confirm.json is Store-owned and repairs are advisory, or define a repair-wins/stop-daemon procedure. plan.md:1533-1539,1654-1663,1933-1940,2026-2034.

MINOR 4 — The residual incorrectly says a crash leaves the window recordless only “until the W retry restores it.” A crash destroys the process-local W debt; seconds describe the exposure before a crash, not healing afterward. plan.md:1719-1725,1924-1929,2965-2970; pkg/configstore/store_persist.go:397-401.

NEEDS-REVISION

Codex session ID: 019f965f-707a-76f2-bd78-5baa34dbfe6f
Resume in Codex: codex resume 019f965f-707a-76f2-bd78-5baa34dbfe6f
