# Claude-SMR hostile plan review — #1691 v1 @ e88c653b

Reviewer seat: domain SMR (CoS/QoS fairness) + SW design. Hostile.

## Verdict: PLAN-NEEDS-MINOR

The plan's architecture is correct — this IS the research's own Path B
"do first", it documents physics rather than asserting a mechanism, and
it correctly keeps §3.B (#1692) out of scope. Two concrete gaps must be
fixed before implementation; neither is a KILL.

## Findings

### F1 (MINOR, must-fix) — The flat per-flow-CoV gate lives in the #1614 ISSUE BODY, and the plan does not name it as the concrete dropped artifact.

I grepped all three plan-named artifacts plus the #1614 issue body:

- `test/incus/cos-simul-load-smoke.sh`: computes `cov` (line 132) and
  reports `cov_pct` (line 140/156) but has **NO CoV pass/fail gate** —
  `gates` dict (lines 161-199) contains only gate_1/2/3/8. So there is
  nothing to delete in the harness for the CoV drop.
- `docs/fairness-regimes.md`: already uses the #1217 structural form
  `observed_CoV ≤ Cstruct + 0.05` (lines ~110-117, ~1010). No flat bar.
- **#1614 issue body, acceptance criteria line 113:**
  `[ ] Per-flow CoV ≤ 5% under simultaneous load (today: 7-18%).`
  THIS is the literal flat per-flow-CoV gate the rescope drops.

The task is "re-scope the #1614 acceptance gates" — the gate being
dropped physically resides in the #1614 issue body checklist. The plan
§4 Edit set 2 item 2 says "state the flat per-flow-CoV gate is DROPPED"
and "cite #1220/#1244" but never identifies #1614 body line 113 as the
artifact. Fix: the doc rescope must name the #1614 body "Per-flow CoV ≤
5%" criterion explicitly as the dropped gate, and the #1691 PR (or a
comment on #1614) must record the drop so the parent issue's checklist
is reconciled with the #1217 structural replacement. Note #1614's own
body line 164 ALREADY cites #1217 — so the body is internally
inconsistent (line 113 flat gate vs line 164 structural ref); the
rescope resolves that inconsistency.

### F2 (MINOR, should-fix) — Ungating 3g/6g in the verdict JSON is silent; a verdict.json reader could misread silence as pass.

The plan keeps 3g/6g %-shape printed (good) but removes them from
`gate_1_small_class_guarantees`. A downstream consumer that scans
`gates` for per-class pass/fail would see 3g/6g simply absent and might
infer "not failing = ok". Fix: emit an explicit non-gating marker for
3g/6g in the verdict (e.g. a `reported_ungated` list or a comment-bearing
field) citing #1692, so the absence is intentional and documented in the
artifact, not just in the surrounding doc. Cheap; closes the silent-gap.

### F3 (resolved, no action) — ~22-24 G single-cluster scoping.

The draft doc language scopes the number to "the loss userspace
cluster" rather than presenting it as a universal constant. That is the
correct discipline. The #1578 ceiling is the documented forwarding
ceiling for this hardware path. Not a kill, no change needed beyond
keeping the cluster-scoping explicit in the final prose.

### F4 (resolved, no action) — §3.B mechanism containment.

The plan's §9 out-of-scope and the doc's starvation discriminator both
correctly defer the 3g/6g MECHANISM to #1692 and make no mechanism
claim. The discriminator ("below guarantee-protected share WITH
measurable aggregate headroom") is the research's own §3.B signal
definition (small4+24g reached 18 G of ~24 G with 3g/6g at ~52%), so it
is grounded, not circular — it points at #1692 for resolution, which is
correct for a Path-B-doc-only PR.

## Required before implementation
- F1: name #1614 body line 113 ("Per-flow CoV ≤ 5%") as the dropped
  gate in the doc rescope; reconcile the parent issue checklist.
- F2: emit an explicit ungated-marker for 3g/6g in verdict.json.
