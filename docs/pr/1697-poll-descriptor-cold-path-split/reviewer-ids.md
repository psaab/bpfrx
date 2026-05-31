# #1697 reviewer task IDs

## Plan review round 1 (commit fd471ee3c)
- Codex: task-mpt40s8e-dannse
- AGY: adversarial-review-mpt40vtg-n4ss4x
- Claude-SMR: in-conversation (hostile self-review)

## Plan review round 2 (commit d9732fcb7)
- Codex: task-mpt47iej-rf6r7j
- AGY: adversarial-review-mpt47lvp-6o91qh
- Claude-SMR: PLAN-READY (v2 implements the round-1 F1 fix + #[cold] recommendation; no new defect)

## Round 2 verdicts
- Codex (task-mpt47iej-rf6r7j): PLAN-NEEDS-MINOR — 3 precision wording edits, all applied
- AGY (adversarial-review-mpt47lvp-6o91qh): PLAN-READY
- Claude-SMR: PLAN-READY
=> PLAN-READY, proceeding to implementation.

## Code review round 1 (PR #1704, HEAD 06dce5270 -> review-fix below)
- Codex (task-mpt4q07u-og7vij): MERGE-NEEDS-MINOR — single finding: the
  emit_input_filter_log_match call in emit_cached_input_filter_log is on
  one line (rustfmt collapsed it), technically not byte-for-byte vs the
  old multiline form, though behavior-identical. Codex offered "restore
  multiline OR soften the claim". rustfmt re-collapses the multiline
  form (the call now fits the width), so the byte-for-byte claim in
  filter.rs was softened to behavior-identical + an explicit
  formatting-delta note. Everything else verified clean: tail split
  behavior-identical (filter.rs:239/242/267 == base mod.rs:365-376,
  FilterLogMatch is Copy), inline policy correct, borrow clean, moved
  tests clean.
- AGY (adversarial-review-mpt4q7ot-x2ha7w): MERGE-READY — AST-brace
  normalized diff confirms 10 moved fns byte-identical modulo
  visibility/inline attrs; tail split behavior-identical; 1599 tests
  pass; the one umem latency-skew test failure was an unrelated timing
  flake that passed on standalone re-run.
- Claude-SMR (claude-smr-code-r1.md): MERGE-READY — verified pure code
  motion by diff + F1 absence by objdump (guarded jne, no unconditional
  per-packet call into emit_cached_*).
- Copilot: COMMENTED — only an audit-drift flag, verified FALSE alarm
  (artifact in sync, mod.rs 2437 matches).
=> 4-way code gate: Codex NEEDS-MINOR (addressed), AGY/SMR MERGE-READY,
   Copilot COMMENTED-false-alarm. Converged.

## Smoke (loss:xpf-userspace-fw0/fw1)
- Pass A (CoS disabled): single-stream v4/v6 push+rev all 0 retrans
  (8.2-8.8 Gb/s); -P12 -R multi-stream v4 22.8 Gb/s 0 retrans, v6
  22.6 Gb/s 0 retrans (first v6 run showed 136 retrans = warm-up, 3
  clean re-runs confirmed).
- Pass B (CoS enabled): 24/24 per-class cells 0 retrans; shaped classes
  hit configured rates (iperf-a ~96 Mb/s shaped push / 6.1 Gb/s rev,
  iperf-b ~958 Mb/s, iperf-c 2.86 Gb/s, iperf-d/e/f ~5 Gb/s), reverse
  ~5.6-6.1 Gb/s throughout.
