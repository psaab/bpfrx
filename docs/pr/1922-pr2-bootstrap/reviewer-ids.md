# #1922 PR-2 — SAFE-BOOTSTRAP daemon (Items 2-4 + 1b) — reviewer task IDs

Branch: `engineer/1922-pr2-bootstrap` (off origin/master with PR-1/Item-1a merged).
Plan: `git show origin/research/1922-safe-bootstrap-daemon:docs/research/1922-safe-bootstrap-daemon/plan.md`

## Engineer-time resolutions (documented per the plan)

- **OQ-B (first-commit gate scope):** RESOLVED blunt. `commitAndApply`
  refuses ANY plain first commit in bootstrap mode with guidance to use
  `commit confirmed <minutes>`. The confirmed-commit path is the escape
  hatch; no separate `commit no-confirm` form is introduced (avoids the
  reflexive-lockout foot-gun the plan flagged). Day-0 path bypasses (resolves
  NOT-bootstrap before any interactive session).
- **OQ-C (lifeline detection):** RESOLVED ladder = active IPv4 default route,
  else active IPv6 default route, else refuse-and-stay-bootstrap (console).
  Recorded by PCI+MAC. Multi-homed/policy-routed mgmt is the operator-override
  residual via `system management-interface`.
- **OQ-D (protected set):** RESOLVED auto-exempt-from-claim (skip the
  unmanaged strip), normal mgmt-zone policy still applies. Explicit non-fxp0
  `system management-interface` narrows fxp0 off the auto-protection.
- **Lifeline-identification path:** PCI bus address is the primary key (MAC
  tiebreaker), resolved to current name at reconcile time. The
  `system management-interface` typed leaf is the operator override; its
  config-mode `set` grammar is DEFERRED (default-route signal is the primary
  no-config path).

## Reviewers

| Reviewer | Task ID | Round | Verdict |
|---|---|---|---|
| Codex | bvo39rwsi (r1) / 019ed26c-5f23-7d91-9015-15433bb64d78 (r2) | r1→r2 | r1 NEEDS-CHANGES (2 release-blockers) → **r2 MERGE-READY** → r3 NEEDS-CHANGES (1 OQ-D blocker) → **r4 MERGE-READY** |
| AGY | adversarial-review-mqh69wa0-bkp0t6 (r1) / adversarial-review-mqh6o06z-wfmlzb (r2) | r1→r2 | r1 NEEDS-CHANGES (1 CRITICAL) → **r2 MERGE-READY** → r3 NEEDS-CHANGES (1 OQ-D blocker) → **r4 MERGE-READY** (2 Low folded) |
| Claude SMR | n/a | r1 | reviewed — route-detect semantics, bootstrapFromFile-not-gated, exit-startup writer guard, gate-race-benign all checked; no new blockers |
| Copilot | n/a (gh add-reviewer) | r1 | COMMENTED — 5 findings; 1 dup of fixed release-blocker, 4 folded |

## Round-2 (AGY) low-severity findings folded (commit after r2)

- **AGY r2 Low — applyConfigLocked nil cfg.** Added an explicit top-level
  `if cfg == nil { return nil }` guard (no production caller passes nil; the
  bootstrap-exit block and the historical cfg.Warnings deref made the
  contract ambiguous).
- **AGY r2 Low — extractPCIAddr OOB.** `len(p) >= 10` could index `p[10]`
  out of bounds on a 10-char component; hardened to `>= 11` (a PCI address is
  >= 12 chars). Pre-existing code, hardened now that the lifeline path calls it.

## Live validation (loss userspace cluster)

- Deploy to loss:xpf-userspace-fw0/fw1 (worktree binary, hash-verified): both
  nodes boot NORMAL (node-id + day-0 import → everCommitted → not bootstrap).
  Zero `entering BOOTSTRAP` log lines — the regression-safe path holds.
- `show chassis cluster status`: healthy HA, node0 primary / node1 secondary,
  RG0+RG1 Monitor-failures None, takeover/transfer ready, peer version
  exchanged (heartbeat live).
- test-connectivity (cluster): LAN→WAN iperf3 IPv4 TCP PASS, IPv6 TCP PASS,
  cross-zone + RETH VIP v4/v6 + mtr paths PASS. (heartbeat/fabric direct-ICMP
  + external-IPv6-internet failures are env/topology artifacts, not
  forwarding-path regressions — protocol heartbeat verified live above.)
- **make test-failover (loss cluster): 14 passed, 0 failed.** Zero-drop
  failover across unclean crash (sysrq reboot), rejoin-as-secondary
  (no auto-preempt), and manual failover; 9.88 Gbps throughput; 11/11
  sessions synced. The HA-node-guard change causes NO cluster-boot/failover
  regression.

## Live SAFE-BOOTSTRAP behavior validation (standalone VM bpfrx-fw, final binary f75dcf2f)

The new bootstrap path was exercised live on a wiped standalone VM (no
node-id, native NIC names, no config) — the genuine foreign-host case:

- **Fresh → bootstrap**: `entering BOOTSTRAP mode: no committed configuration
  found`; `bootstrap lifeline: recorded management NIC identity interface=enp5s0
  pci=0000:05:00.0 mac=10:66:6a:ed:0c:86`; `renamed management NIC to fxp0
  from=enp5s0` (ONLY mgmt renamed — enp6s0..enp10s0f0np1 stayed native);
  `dataplane arm and boot-time config apply suppressed`; no xpf-userspace-dp
  helper; fxp0 kept 10.0.100.50/24 + default route; CLI `show system uptime`
  responds; only `10-xpf-fxp0.{link,network}` written (static-snapshot
  bootstrap .network), no other takeover files.
- **First-takeover gate (OQ-B)**: a plain `commit` in bootstrap is REFUSED —
  "system is in bootstrap mode: commit the takeover config with 'commit
  confirmed <minutes>'".
- **commit confirmed → exit + full takeover**: `exiting bootstrap mode ...
  reason="first non-empty config applied"`; all NICs renamed
  enp6s0→ge-0-0-0 … enp10s0f0np1→ge-0-0-4; `bootstrap exit: startup takeover
  complete`; ge-* up + addressed. `commit` (confirm) → `commit complete`,
  on-disk marker flips to `committed=1`, a second plain commit succeeds
  (bootstrap one-way exit stable), fxp0 mgmt reachable throughout.
- **Item 1b (first-commit-confirmed timeout → enterBootstrapMode)**: with a
  `commit confirmed 1`, after the 60s timeout: `commit confirmed (first
  commit) timed out; rolling back to BOOTSTRAP mode (removing
  interface/FRR/dataplane takeover, keeping the management lifeline)`;
  `bootstrap rollback complete`; fxp0 kept 10.0.100.50/24 (mgmt reachable);
  on-disk marker `committed=0` (never-committed, NOT an empty committed tree).
- **AGY/Codex CRITICAL fix, live**: after the Item-1b rollback (committed=0),
  a daemon RESTART RE-ENTERS bootstrap ("no committed configuration found")
  — proving the empty-tree-compiles-non-nil misclassification is fixed on a
  real box, not just in unit tests.
- **Protected-set / mgmt-never-downed**: fxp0 retained its address across
  bootstrap, takeover, Item-1b rollback, and restart — never brought down.

## Round-3 (Copilot) findings folded

- **store.go (degraded-retry committed=1)** — duplicate of the Codex
  release-blocker, already fixed (persistMarkerCommitted). Reviewed pre-fix.
- **store.go Load (Copilot, real)** — Load did not seed persistMarkerCommitted
  from the on-disk marker, so a degrade path firing before any commit/sync
  could heal a never-committed DB to committed=1. FIX: Load sets
  `persistMarkerCommitted = committed`. Test:
  TestLoadNeverCommittedRestartStable.
- **daemon_apply.go message (Copilot)** — the plain-commit refusal said
  "first commit"; after a confirmed-but-empty commit the daemon is still in
  bootstrap. Reworded to "system is in bootstrap mode".
- **bootstrap.go protectedInterfaces (Copilot)** — removed the redundant/
  misleading `if mgmtLeaf == defaultMgmtInterface` no-op branch; fxp0
  narrowing is now purely "don't add fxp0 when an explicit leaf is set".
- **bootstrap.go writeBootstrapLifelineNetwork (Copilot)** — snapshot the
  interface addressing ONCE instead of twice (removed the duplicate netlink
  walk).

## Round-1 findings folded (commit 640de42e6)

Both Codex and AGY independently found the SAME root cause — an empty config
tree compiles to a NON-nil `*config.Config` — from two angles; both fixes are
required for a post-first-commit-rollback box to stay bootstrap across restart:

1. **AGY r1 CRITICAL — predicate ordering.** `computeBootClass` checked
   `hasActiveConfig` before `everCommitted`; the empty rolled-back tree
   compiles non-nil → misclassified normal. FIX: check `!everCommitted`
   first. Test: `post-rollback-restart-empty-compiled`.
2. **Codex r1 release-blocker — degraded-retry marker loss.** The #1799
   persist-retry loop re-wrote `committed=1`, losing the never-committed
   marker on a failed-then-healed first-commit-rollback write. FIX:
   `persistMarkerCommitted` field feeds the retry loop the correct bit.
   Test: `TestFirstCommitRollbackDegradedRetryKeepsNeverCommitted`.

Codex r2 verified both resolved + no new findings → MERGE-READY. Findings
1/2/5/6 from Codex r1 confirmed BENIGN (HA-guard logs-not-bootstraps; dp
construct/suppress/exit/teardown lifecycle correct; protected-set parser
grammar intentionally deferred; cli.go rollback hook is fallback-only).
