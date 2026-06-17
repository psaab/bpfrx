# AGY r1 — PR #1941 (#1930 INC-2). Verdict: REQUEST-CHANGES (6 findings, all fixed)

1. CRITICAL — candidate node preempts before the promotion gate verifies
   (ManualFailover is in-memory, lost across the reboot; candidate boots
   election-eligible). FIX: drainIfKernelCandidateArmed (pkg/daemon) — on a boot
   where the kernel journal is ARMED, ForceSecondary (hold secondary) until the
   promote gate runs, IF the peer is a healthy primary.
2. HIGH — self-recovery fires during manual maintenance / #1917 binary roll
   (both drain without a kernel-roll lease). FIX: self-recovery now acts ONLY on
   leaseExpiredOurs (the crashed-orchestrator fingerprint); leaseNone/leaseOther
   never trigger it.
3. lease write non-atomic (truncate-before-write). FIX: in-guest temp+mv rename.
4. holder shell/format-string injection (% / ' in hostname). FIX: sanitize to
   [A-Za-z0-9._:-].
5. revert leaves a stranded lease (suppresses self-recovery for the TTL). FIX:
   restoreKnownGood clears the local lease (ClearRollLease).
6. revert retains a stale promotion marker. FIX: restoreKnownGood clears it
   (ClearPromotionMarker).

AGY job: rescue-mqhg0cn1-tjqx3j.
