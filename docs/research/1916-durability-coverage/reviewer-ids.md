# Reviewer ID ledger — #1916 research

Convergence requires Claude SMR + Codex + AGY all PLAN-READY on the FINAL rev.

| Round | Reviewer | Task/Job ID | Verdict | Artifact |
|---|---|---|---|---|
| r1 | Codex | foreground nohup (pid 3107657), log /tmp/1916-codex-r1.log | PLAN-NEEDS-REVISION | codex-plan-r1.md |
| r1 | AGY | adversarial-review-mqi20zjh-cz48fd | PLAN-NEEDS-REVISION | agy-plan-r1.md |
| r1 | Claude SMR | n/a | PLAN-NEEDS-REVISION | claude-smr-plan-r1.md |
| r2 | Codex | (pending) | | codex-plan-r2.md |
| r2 | AGY | (pending) | | agy-plan-r2.md |
| r2 | Claude SMR | n/a | | claude-smr-plan-r2.md |

## r1 convergent findings (all addressed in plan r2)
1. Incomplete Path A inventory (Claude C1 / AGY#2 / Codex#4) — missed pkg/dataplane (compiler.go tuneInterfaceBuffers, compiler_iface.go ensureVLANSubInterface), pkg/dataplane/userspace (process.go tuneSocketBuffers), pkg/ra (sender.go ensureLinkLocal). Codex: RETH procfs in giant applyConfigLocked → refactor to helpers, don't allowlist the whole func.
2. authorized_keys ownership (AGY#1 / Codex#3 / Claude L) — keep-chown-after NOT behavior-preserving; fchown temp BEFORE rename.
3. TLS over-claim (AGY#4 / Codex#1) — mismatch possible with pre-existing stale pair.
4. failover waiver false (AGY#5 / Codex MEDIUM) — daemon_reth/linksetup feed RETH boot naming.
5. timezone class (AGY#3 / Codex MEDIUM) — demote to AtomicGeneratedConfig or make localtime symlink durable.
6. sshd class inconsistency §2 vs §4/§5 (Codex MEDIUM) — settle.
7. TLS cert class vs pinning harm (Codex#2) — settle both-DurableState or drop pinning harm.
8. DNS B-route underspecified (Codex MEDIUM) — must check isCrossDeviceOrBusy on fsatomic err, no WithResolveSymlinks.
