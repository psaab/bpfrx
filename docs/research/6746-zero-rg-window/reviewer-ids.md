# Reviewer ID ledger — #6746 zero-RG-window research

## Round 1 (plan v1 @ cc6860d5d)

- **Codex** — two documented dispatch attempts, both infra-blocked by a
  hard account usage cap ("You've hit your usage limit ... try again at
  Aug 10th, 2026 6:57 AM"; today is Aug 4):
  1. codex-companion `task` (default routing after task-resume-candidate
     reported available but the candidate was a stale cross-issue thread;
     not resumed) — usage-limit error before any review tokens.
  2. codex-companion `task --fresh` with the full attack-surface prompt —
     identical usage-limit error.
  Not a transient 429 (6-day account cap); proceeding 2-of-3 (Claude SMR +
  AGY) per the codex-infra-blocked exception. A further retry is due
  before the final convergence comment; the cap does not lift until
  Aug 10, so Codex participation this session is not expected.
- **AGY** — background bash task `bxobxbfd5`, direct `agy
  --print-timeout 9m --print "$(cat /tmp/agy-6746-r1-prompt.txt)"`;
  output `/tmp/agy-6746-r1.out`; verdict doc `agy-plan-r1.md`.
  Verdict: PLAN-READY (1 MINOR — pin the M2
  `desiredForwardingArmedLocked()==false` assertion explicitly in §9; 1
  NIT — 12 anchors spot-verified). All 7 attack surfaces
  CONFIRMED-CLOSED.
- **Claude SMR** — `claude-smr-plan-r1.md`. Verdict: DEMAND-REVISION
  (1 MAJOR — M1's unstated owner_rg>0 premise for the framed interface-NAT
  resolution; 3 MINOR — deferred pendingXSKStartup trace, empty-sender
  audit into the plan, operator-arm interleaving; 1 NIT — §9 M2 pin +
  no-empty-update assertion, concurring with AGY's MINOR).

## Round 2 (plan v2)

- **Codex** — still usage-capped (see round 1); one further documented
  retry before the final comment.
- **AGY** — pending dispatch on v2.
- **Claude SMR** — pending (r2 verifies the v2 folds).
