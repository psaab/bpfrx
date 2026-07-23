# Claude SMR — hostile plan review r5 (#5275)

Reviewing `plan.md` @ r6. r4 confirmed the architecture is VIABLE (not PLAN-KILL)
and enumerated the exact contracts a complete fail-closed spec needs. r6 folds
every one of them. I checked each fold against the r4 finding and the source.

## Codex r4 findings → r6 folds (each verified present + source-grounded)

- **§1 composed-reason hold + daemon-owned standalone state:** r6 §2 makes the
  arm-state daemon-owned and installed OUTSIDE the `cfg.Chassis.Cluster != nil`
  block (kernel_selfrecover.go:58 returns when `d.cluster==nil`, so the #1930 hold
  cannot be the standalone mechanism); `effectiveHold = dataplaneUnproven ||
  kernelTrialUnpromoted`, each owner clears only its reason (rejoin/reset
  failover.go:170 must not clear the dataplane reason). ✓
- **§1 withdrawal scrub + RG0:** r6 §3 adds a verified withdrawal-only scrub of
  inherited direct-VIP/link-local/RA/VRRP/Kea/FRR before yield, and an explicit
  held-RG0 read-only (applyRG0OwnershipTransition:417 emits nothing for a
  created-Secondary). ✓
- **§2 proof at final boundary:** r6 §5 moves the proof AFTER the RETH
  link-cycle/reapply (DeferWorkers workerless snapshot @ daemon_apply_dataplane.go:467;
  deferred snapshot @ manager_compile.go:257), requires candidate digest + helper
  generation + exact bindings + program-instance identity + readback-fail=unarmed +
  the second reapply returning proof-not-debt. ✓
- **§2 bridge/flowtable barrier:** r6 §6 adds a bridge-family barrier + flowtable
  disable/flush/readback alongside inet FORWARD + ip_forward=0 (bridge domains @
  compiler_iface.go:975). ✓
- **§2 release ordering:** r6 §5 clears the hold LAST (proof → forwarding → barrier
  removal → clear hold). ✓
- **§2/§5 revocable facade:** r6 §7 replaces `d.dp=nil` with a shared revocable
  facade (gRPC/CLI capture aliases at construction, daemon_run_servers.go:88 /
  daemon_run.go:597; bootstrap-exit exploit). ✓
- **§3 atomic hold+yield + pre-proof heartbeat:** r6 §4 makes yield =
  advertised-weight-zero in the fixed 5-byte record (heartbeat.go:93; legacy peers
  promote on weight-zero; stored weight unchanged; auth covers it), atomic with the
  hold, and splits a pre-proof heartbeat-only start from the full machinery. ✓
- **§4 staged surface transaction:** r6 §9 gives the explicit 6-step transaction for
  B AND committed-empty→first AND remove-all→add; §8 the three-route apply gate
  (armPending / armFailed / armed). ✓
- **§5 phasing honesty:** r6 §10 corrects "each PR independently correct" — PR1 is
  standalone + INERT under cluster config; PR2 lands hold+yield atomically; PR3 the
  staged transaction. ✓

## Residual (MINOR — `/engineer`-time, not blockers)

- **N1 — facade scope.** The revocable facade must wrap EVERY `d.dp` capture
  (gRPC/REST/CLI/sampler/GC/session-sync/event-stream/watchdog); an audit of every
  capture site + a per-consumer revocation test is the guard. r6 §11 risk (2) names
  it; the audit is an implementation deliverable.
- **N2 — bridge/flowtable barrier feasibility.** A bridge-family drop + flowtable
  flush is the right primitive; confirm the repo's nft machinery (daemon_nft.go) can
  express it atomically and that no legitimate management L2 path is caught. First
  thing to validate in PR1.
- **N3 — the design is large.** r6 is honest that this is a foundational
  architecture (revocable runtime + arm-state + barrier), not a small fix. The
  phasing is real work per PR; the user should weigh scope vs the HIGH severity at
  go/no-go. This is the central decision the `/research` surfaces.

## Verdict

r6 is a complete design contract: every Codex r1–r4 finding is folded with a named
mechanism and a source coordinate, the architecture is viable and precedented
(#1930 for the election piece), and the two genuine design choices (yield =
advertised-weight-zero; the phased scope) are surfaced for the human. Remaining
items are implementation audits, not architecture gaps. This is the `/research`
deliverable — a plan the human can approve for `/engineer` with eyes open to the
real (large) scope.

VERDICT: PLAN-READY
