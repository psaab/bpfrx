---
status: DRAFT v4 — second pass on the 3 Tier B survivors (#837, #936, #937)
issues: #837, #936, #937
phase: Closure proposal — pushing on the user-decision-gated cases
prior: plan.md (v1→v3 closed #786/#793/#794/#917; kept these 3)
---

## 1. Why a second pass

The first Tier B pass (commit `ea0b7ba1` earlier today) closed 4
shipped/superseded issues but kept 3 open with refined gating
notes. This v4 plan pushes harder on each of the 3 to see if
honest closure is reachable now that the gating notes are written.

The user-set workflow (`feedback_difficult_path_pragmatism.md`)
favors closure when the pattern is:
- **Long-term direction with no incremental seam + no measured
  trigger** → close-as-wontfix-with-rationale (the #946 pattern)
- **Awaits user-decision that's been pending for weeks** → bring
  the decision to the surface; close as wontfix if user is
  effectively saying "not now"
- **Blocked on upstream blocker that's itself wontfix** →
  close transitively (with explicit reopen trigger)

## 2. Per-issue v2 assessment

### #837 — Slice C-a: full HOL-finish cross-binding MQFQ

**v1 verdict (4 hours ago):** keep open as parked/gated, per
`docs/pr/838-afd-lite/findings.md:145`:
> "Do not retire #837. It captures the larger redesign that
> would be needed for true cross-binding MQFQ; if mouse-latency
> data later shows we need it, the design context is preserved."

**v2 challenge:** how much longer does that preservation note
hold? The note was written 2026-04-?? in the context of #838's
plan-only commits being dropped. It's 2-3 weeks old. The history
since:

- #841 (Slice B) outage regression
- #842 revert
- #843 post-mortem (open, no prereqs landed)
- #836 PLAN-READY NO with 7 HIGH issues
- Today: #946 closed wontfix-with-rationale on the same
  "no incremental seam" grounds

**Argument for closure:** #946 closure pattern applies here too.
- Phase-1-equivalent shipped (#917 V_min)
- Full scope structurally blocked (no immutable-snapshot seam)
- No measured trigger (no mouse-latency data forcing it)
- Reopen path is concrete (#843 prereqs + measurement + seam plan)

**Argument against closure:** the explicit "Do not retire #837"
note is still on disk. Updating that note before closing would
be the right sequence.

**v4 recommendation:** **close #837 as wontfix-with-rationale**,
update `docs/pr/838-afd-lite/findings.md:145` in the same closure
PR to reflect "as of 2026-05-05, retired wontfix; reopen on
{measurement, prereqs, seam}". Same template as #946. The two
issues are structurally equivalent: parent umbrella for a redesign
that's blocked on the same constraints.

### #936 — Cross-worker MQFQ shared per-flow vtime

**v1 verdict:** keep open, awaits user trade-off decision (~43%
aggregate-throughput hit on degenerate distribution for CoV → 0).

**v2 challenge:** the user has had ~3 weeks since the issue was
reframed (per Gemini hostile review) and the trade-off was made
explicit. No comment indicating acceptance. The default for an
unactioned trade-off-gated issue is wontfix.

**v4 recommendation:** **close #936 as "trade-off declined by
default."** The reopen trigger is explicit user agreement to
accept the ~43% aggregate hit; if/when that happens, file a
fresh issue or reopen. Closing surfaces the question; if the
user actually wants the trade-off, they reopen now.

If user explicitly wants to keep #936 open as "decision pending,
not declined," that's their call — but the keep-open should be
their decision, not the triage's default.

### #937 — Cross-binding flow re-steering (RSS-degenerate case)

**v1 verdict:** keep open, distinct mechanism from #936; aggregate-
cap problem real but blocked on shared-UMEM availability or
alternative XDP redirect.

**v2 challenge:** #937 is transitively blocked on #776 (cross-NIC
shared-UMEM). #776 is itself topology-blocked on this lab per
`docs/shared-umem-plan.md`. The "alternative XDP redirect" path
hasn't been proposed concretely; it's hypothetical.

**v4 recommendation:** **close #937 as "blocked on #776; no
independent path on this lab."** Reopen trigger: if shared-UMEM
unblocks (#776 closes "fixed" not just "wontfix") OR a concrete
ingress-XDP redirect mechanism is proposed (currently hypothetical).

## 3. Recommendation summary v4

| # | v1 verdict | v4 verdict | Justification |
|---|---|---|---|
| #837 | keep parked | **close wontfix** | Same pattern as #946 closure; update preservation note in same PR |
| #936 | keep (user decision) | **close as trade-off declined by default** | 3 weeks unacted; user can reopen if trade-off accepted |
| #937 | keep | **close as blocked on #776** | Transitive close; reopen on shared-UMEM unblock |

**If all three close:** Tier B = 7 closed, 0 open. Aggregate today:
**18 close, 17 stay open** if Tier S #781 also closes via
measurement gate.

**If any reviewer pushes back:** keep-open with the v1 reasoning
remains valid. v4 is genuinely more aggressive than v1 on closure;
honest reviewers may push back.

## 4. Hostile review questions

1. Does the #946-closure pattern actually apply to #837? Both are
   "umbrella tracker for redesign with no incremental seam + no
   measured trigger." Or does the explicit `838-afd-lite/findings.md`
   preservation note make #837 categorically different?

2. Is "trade-off declined by default" a fair characterization of
   3-week-unacted-on user decision, or is it putting words in the
   user's mouth? Should the issue be tagged with a deadline-style
   reopen condition instead of closed?

3. Does closing #937 as transitively-blocked on #776 hold up if
   #776 itself is open (not closed-fixed)? Transitive close
   normally requires the upstream issue to itself be closed-fixed,
   not just open.

## 5. Verdict request

PLAN-READY → execute the v4 closures.
PLAN-NEEDS-MINOR → tweak rationale per finding, then close.
PLAN-NEEDS-MAJOR → keep all three open; v4 is too aggressive.
PLAN-KILL → premise wrong; revert to v1 keep-open.
