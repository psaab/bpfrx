# Claude SMR — hostile plan review r1 (#3612)

Base: origin/master @ f1d00ffeb. Reviewing `plan.md` r1. Posture: hostile —
try to KILL or break the plan, not confirm it.

## Verdict: PLAN-READY (PATH A) — with 3 required folds, 0 blockers

The plan survives hostile scrutiny. The divergence is real, reachable, and
correctly root-caused; PATH A is the right direction; the risk table and test
plan are honest. Three items must be folded before /engineer; none change the
verdict.

## Attacks attempted and outcomes

**A1 — "Is it unreachable? (→ PLAN-KILL)"** Checked
`pkg/config/compiler_applications_collision.go`. The commit gate rejects only
DUPLICATE names and cross-namespace name conflicts — NOT two *distinct-named*
applications overlapping on the same protocol+port. So the §2.2 config
(`aaa-tcp` protocol-only + `zzz-https` tcp/443) commits cleanly. **Reachable —
KILL refuted.** REQUIRED FOLD F1: add this reachability confirmation to §3 (the
plan asserts reachability but does not prove the absence of a gate; I proved it).

**A2 — "Wrong symbol / stale line numbers."** The issue body cites
`lookup_directional` at policy.rs:1646 and a symmetric `lookup`. Confirmed
against the WORKTREE (not the stale main checkout at 0160fbfb9): the ONLY
`AppCatalog` resolver is `lookup_directional` (`policy.rs:1607`) + `lookup_forward`
/`lookup_admitted` wrappers; there is NO bare `AppCatalog::lookup`. The plan
targets `lookup_directional`. Correct. (Reviewers using the main checkout will
see a different, stale file — insist on the worktree.)

**A3 — "The acceptance claim 'classifies identically appid-on vs appid-off' is
false."** Partially lands. Even after PATH A, the paths STILL diverge on
SET MEMBERSHIP: appid-on uses the full predefined+user catalog; appid-off uses
user apps + a 15-entry `builtinFallbacks`, NOT `config.PredefinedApplications`
(plan S1). So a predefined-only overlap would not be made identical by PATH A.
The plan acknowledges S1 as out-of-scope, but the §8 item-5 fixture and item-8
smoke MUST be restricted to USER-defined apps (present in both sets) or the
parity test will falsely fail. REQUIRED FOLD F2: state explicitly in §5.3/§8
that the parity fixture uses only apps in `cfg.Applications.Applications`, and
that the "identical" acceptance is scoped to user-app overlaps (predefined-set
coverage is S1). This keeps the acceptance claim honest.

**A4 — "Binary specificity itself re-diverges (exact vs range)."** Tested the
existing `app_catalog_overlap_lowest_id_wins` range-vs-exact sub-case
(id 2 range 8000-8100 vs id 20 exact 8050, session 8050 → id 2). Under binary
specificity BOTH are port-constrained → same tier → lowest id → id 2. Identical
to today, and matches the disabled path (both `portBased`, name/id tiebreak).
So binary does NOT re-diverge on exact-vs-range. The 3-tier alternative
(Open Q1) would ITSELF re-diverge from the binary disabled path unless both
move together — the plan correctly recommends binary. Attack refuted; the plan's
reasoning here is right. (Keep Open Q1 for the user, but the recommendation is
sound.)

**A5 — "Enforcement is actually affected."** Grepped label consumers: all are
display/filter (`show`/`clear` app filter, RT_FLOW, API, CLI). Enforcement is
`CompiledApplications::matches` (`policy.rs:1452`), independent. The plan's
"display-only" claim holds — BUT Open Q5 correctly demands the engineer re-grep
`val.AppID` consumers before merge. Keep that gate; do not drop it.

**A6 — "Same-tier regression / test churn."** Both sub-cases of
`app_catalog_overlap_lowest_id_wins` are same-tier (all port-based) → survive
PATH A with only a comment update. Verified. Low churn confirmed.

## Nits (fold if cheap, not blockers)

- N1: §5.3 says the Rust test can "reconstruct ids deterministically from
  sorted-name order." Make the fixture self-describing (record expected id AND
  name) so the Rust test does not re-implement the Go sort — otherwise a sort
  bug hides in both sides. (Already gestured at; make it mandatory.)
- N2: R1 (relabel-on-upgrade) — add that the relabel is toward the MORE specific
  name, i.e. a strict improvement, so no operator "lost" a label; it converges
  to the appid-off answer they already saw.

## Watch-items for /engineer

- Run FULL `cargo test -p userspace-dp` and full `go test ./pkg/appid/...
  ./pkg/dataplane/...` — no filtered subsets (campaign lesson: filtered runs
  mask REDs).
- The parity fixture is the make-or-break deliverable; a fix without it just
  moves the divergence around. Do not merge PATH A code without the fixture test
  going RED-before / GREEN-after on a cross-tier row.
