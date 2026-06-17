# #1930 INC-3 (PR #1942) — reviewer task IDs

Final increment of the #1930 kernel/OS-upgrade umbrella. PR body carries
`Closes #1930`.

## Round 1 (rev ddf1ef7bd — pre-fix, against origin/master)

| Reviewer | ID / handle | Verdict | Findings |
|----------|-------------|---------|----------|
| Codex | `019ed3e3-a92b-74a2-b2dc-f6c5b1eebcb0` | changes requested | HIGH-1 Go/Python parity (signed Atoi vs uint16), HIGH-2 cross-orchestrator lease window, LOW-1 bake.py false-fallback message |
| AGY adversarial | `adversarial-review-mqhl3rjd-b2vwcw` | 1 CRITICAL | CRITICAL: `--allow-mixed-ha` passed unconditionally to the OLD-image second node → unknown-flag abort |
| Claude SMR | (in-conversation) | MERGE-READY r1 | gate soundness, parity, never-both-down, protocol-versions all PASS at the design level |
| Copilot | `copilot-pull-request-reviewer` | commented (STALE) | 5 inline comments all reviewing the pre-r3 rev; the fail-closed + drain-deadline items were already addressed in ddf1ef7bd |

## Fixes applied (rev 2)

- AGY CRITICAL: feature-detect `--allow-mixed-ha` on the node's running xpfd
  (`_node_drain_supports_mixed_ha`, `drain --help` stderr-merged) before
  appending it; warn + fall back to exact-equality when absent.
- Codex HIGH-1: parse `session-sync-protocol-version` / `configdb-*` as
  `ParseUint(.,16)` in Go (was signed `Atoi`) to match Python `_u16`; new
  regression test `TestParseImageVersions_NegativeSessionSync_FailsClosed`.
- Codex HIGH-2: hold the cross-orchestrator lease on a mid-roll abort (only
  clear on clean per-node completion or dry-run), so a second orchestrator is
  blocked from draining the still-primary peer; drain peer-alive/takeover-ready
  precheck remains the hard backstop.
- Codex LOW-1: corrected the bake.py warning — the gate reads ONLY the manifest
  and FAILS CLOSED; there is no staged-binary re-run fallback.

## Round 2 (re-review on rev ca6b493f0)

| Reviewer | ID / handle | Verdict | Findings |
|----------|-------------|---------|----------|
| AGY adversarial | `adversarial-review-mqhldwad-flea8q` | r1 fixes CONFIRMED; 1 new HIGH | SSH backend arg-splitting: `_node_exec` space-joins ssh remote argv so `sh -c "<script>"` (lease helpers + the new --allow-mixed-ha probe) is shredded. Pre-existing pattern, also affects the new probe. |
| Codex | `task-mqh5wz5m-b4ic03` (companion) | round 2 in progress | (folded below when posted) |
| Claude SMR | (in-conversation, r2 doc) | MERGE-READY r2 | all r1 fixes verified correct |

### Round-2 fix (rev 3)
- AGY HIGH (SSH arg-splitting): `_node_exec` now `shlex.quote`-joins the ssh
  remote argv into one string the remote shell reconstructs verbatim — fixes
  the new probe AND the pre-existing `_acquire_lease`/`_clear_lease` `sh -c`
  helpers over the ssh backend (incus backend was already fine).
- Latent probe bug found while verifying: Go's flag usage prints
  `-allow-mixed-ha` (single dash), so the probe now matches the bare
  `allow-mixed-ha` token rather than `--allow-mixed-ha`. Verified the probe
  detects the flag over BOTH incus- and ssh-style pipelines.
