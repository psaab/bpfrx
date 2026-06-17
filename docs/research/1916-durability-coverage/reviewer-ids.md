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

## r2 verdicts (all PLAN-NEEDS-REVISION)
| Round | Reviewer | Task/Job ID | Verdict | Artifact |
|---|---|---|---|---|
| r2 | Codex | foreground nohup pid 3117577, log /tmp/1916-codex-r2.log | PLAN-NEEDS-REVISION | codex-plan-r2.md |
| r2 | AGY | adversarial-review-mqi2c6h9-7bi6qk | PLAN-NEEDS-REVISION | agy-plan-r2.md |
| r2 | Claude SMR | n/a | PLAN-NEEDS-REVISION (M1: cert non-loopback → DurableState) | claude-smr-plan-r2.md |

## r3 (final) — pending re-review
| r3 | Codex | (pending) | | codex-plan-r3.md |
| r3 | AGY | (pending) | | agy-plan-r3.md |
| r3 | Claude SMR | n/a | | claude-smr-plan-r3.md |

## r2 findings addressed in r3 (§13 changelog)
- Claude SMR M1: cert=DurableState (non-loopback https-interface bind refutes r2 loopback premise)
- Codex HIGH#1: D5 strict unlink contract (ignore only ENOENT, abort on other error)
- Codex HIGH#2: /etc/timezone added to §2.B; count fixed (36 real, 4 comment)
- Codex MED#1: caller wiring — persistence failure returns nil err + in-memory cert; HTTPS stays installed
- Codex MED#2 / AGY #6b: canary receiver-aware keying relpath::recv.method
- Codex LOW: WithOwner vs WithPreserveExisting precedence
- AGY #3: timezone early-return crash loophole (check both halves)
- AGY #6a: cgo-free lookupUIDGID, no os/user

## r3 verdicts
| Round | Reviewer | Task/Job ID | Verdict | Artifact |
|---|---|---|---|---|
| r3 | Codex | foreground nohup pid 3124282, log /tmp/1916-codex-r3.log | PLAN-NEEDS-REVISION (1 new MED: timezone control-flow) | codex-plan-r3.md |
| r3 | AGY | adversarial-review-mqi2o2iw-sdrhj3 | PLAN-READY | agy-plan-r3.md |
| r3 | Claude SMR | n/a | PLAN-READY | claude-smr-plan-r3.md |

## r4 (final) — pending re-review (only Step 2b timezone case-split changed)
| r4 | Codex | (pending) | | codex-plan-r4.md |
| r4 | AGY | (pending) | | agy-plan-r4.md |
| r4 | Claude SMR | n/a | | claude-smr-plan-r4.md |
