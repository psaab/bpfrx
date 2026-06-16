# #1917 in-place upgrade — reviewer task-id ledger

Record Codex task IDs + AGY job IDs per round so continuations can fetch by id
(Codex companion is ONE job globally; long sessions hit "No jobs recorded").

## Round 1
- Codex: task-mqg8kjut-tleotn
- AGY: adversarial-review-mqg8kzn5-d7t8ps (wedged-queued, cancelled), re-dispatched adversarial-review-mqg8v8n6-7gchnc (also wedged, cancelled); stray --help launched adversarial-review-mqg8y667-304xf8 (succeeded but wrong prompt); REAL round-1 = adversarial-review-mqg95ecx-rqahpj -> PLAN-NEEDS-REVISION (4 novel blockers: dh_installsystemd auto-restart, kernel-verify-needs-boot, non-atomic manifest, upgrade-cmd bootstrapping)
- Claude SMR: in-conversation

## Round 2
- Codex: task-mqg9b1ml-ohvzsn
- AGY: adversarial-review-mqg9bbwp-77zben (result flaked to intent-log; round-1 4 blockers all folded into v3/v4; r1 brain artifact cd31d3a1 captures position)
- Codex r2 verdict: PLAN-NEEDS-REVISION (3 blockers: envelope unknown-field empty-load, stale /usr/local/sbin alt, watchdog unspecified) -> fixed in v4
- Claude SMR: in-conversation

## Round 3 (confirmation)
- Codex: task-mqg9kz3s-nehkub
- AGY: adversarial-review-mqg9l5qv-r9zvc8 -> PLAN-NEEDS-REVISION (5 NEW confirmed blockers: daemon-not-fail-closed/daemon_run.go, dpkg-deletes-versioned-dir, needrestart, softdog-early-boot, GRUB_DEFAULT=saved) -> all folded v6

## Round 4
- Codex: task-mqg9vrhv-gfg9dc -> PLAN-NEEDS-REVISION (1 blocker: two-package contradiction) -> fixed v7
- AGY: adversarial-review-mqg9vzn3-z7z98r -> PLAN-NEEDS-REVISION (5 confirmed + Gaps A/B/C + stale paths) -> folded v7
- AGY: adversarial-review-mqga2k1c-glunnk

## Round 5 (final confirmation)
- Codex: task-mqga29vu-0wxirw
- AGY: adversarial-review-mqga2k1c-glunnk

## Round 5 verdicts
- Codex: task-mqga29vu-0wxirw -> 3 wording-consistency blockers (fixed v8)
- AGY: adversarial-review-mqga2k1c-glunnk -> PLAN-READY (+ 2 non-blockers folded)
- Claude SMR: PLAN-READY (empirically verified envelope fail-closed)

## Round 6 (Codex consistency re-confirm)
- Codex: task-mqga8cko-fzl6l5
