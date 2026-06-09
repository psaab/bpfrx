# Claude SMR hostile plan-review — #1800 r1 (`758f35ea3`)

**Verdict: PLAN-NEEDS-MINOR**

Self-review, hostile posture. The triage structure holds, but three findings:

## Finding 1 (must-fix) — U2's gate is under-specified: it contains a pkg/cluster change

§3 gates U2 (#1786, #1791, #1795) on "Go tests; cluster smoke". But #1795
edits `pkg/cluster/sync_conn.go`. CLAUDE.md is categorical: "Any change
touching cluster, VRRP, session sync, or failover code MUST pass
`make test-failover` before commit" — there is no log-level-only exemption,
and the rule's value is precisely that nobody adjudicates "trivial" by hand.
v2 must add `make test-failover` to U2's gate (cheap; it just ran 13/0 on
Path A).

## Finding 2 (must-fix) — §5.5's "recovery-only is sufficient" needs its load-bearing premise stated and verified

The claim only holds if the poisoned-lock `?` is the ONLY early-exit inside
the demotion block. I verified the quoted region (ha.rs:39-76 in #1790's
evidence) shows exactly one fallible operation — the `commands.lock()` —
but the plan must (a) state explicitly that with inline `into_inner`
recovery the SAME call completes all propagation (no partial state can
form, so no "repair on retry" machinery is needed), and (b) commit U9's
implementer to verifying there is no other `?`/`return Err` in
`update_ha_state` between the store and the end of the demotion side
effects at implementation time. Without that stated premise, "recovery-only"
reads as hand-waving against the partial-propagation concern.

## Finding 3 (minor) — U6 leaves two interaction checks dangling into /engineer

§5.2 recommends Option A but defers "commit-confirmed interaction" and
"HA config-sync on secondary persist failure" as open questions. For a
semantics change to commit, those two should be resolved IN THIS PLAN
(v2, after Codex/AGY weigh in) — not discovered mid-implementation. If
either turns out hairy, the correct v2 move is downgrading U6 to Option B
(loud degradation), which has no such interactions.

## Verified clean

- U11 Option A is NOT pair-atomicity-racy: each bulk insert writes both keys
  under one acquisition, so interleaved learners produce last-writer-wins
  pairs, never a mixed pair. The TOCTOU between equality-read and bulk only
  affects staleness ordering, not consistency. (Worth restating in §5.7 so
  the implementer doesn't re-derive it.)
- U10 Option A's VM-pause analysis is sound for both roles: the paused node's
  monotonic doesn't advance (no false local fire on resume); the unpaused
  peer's detection of genuine silence is correct behavior, not a false
  positive.
- Sequencing (U1/U2 first, #1786 before the next overnight capture) and the
  per-unit-KILL convention are right for a 16-issue batch.
- Scope fences (#1319-class gaps out, #1782 PR-2 separate) are correct.

Required for v2: fold Findings 1-2; resolve or downgrade per Finding 3 once
the other reviewers' U6 verdicts land.
