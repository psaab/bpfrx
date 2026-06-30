# Claude SMR — hostile plan review r1

Target: `docs/research/3075-3395-stable-id/plan.md` @ `027e7c6f7` (off
`origin/master 49765c603`). Posture: hostile. Goal: find reasons to PLAN-KILL or
force major revision. No rubber-stamp.

## Verdict r1: NEEDS-REVISION (converging toward split PLAN-READY)

The thesis ("two schemes, not one allocator") is correct and well-grounded — I
tried to break it and could not. The zone half (Option C) is close to
PLAN-READY. The **policy half is over-scoped**: P1's close-path plumbing is the
single riskiest, least-justified piece in the document, and the plan does not
weight it honestly against simply doing nothing (the #3322 residual already
covers the field). Two zone-half verification gaps must close before PLAN-READY.
Details below, each invitable to a kill of that sub-part.

## What survives hostile scrutiny (state it, so the convergence is honest)

1. **"Symptom not mechanism" holds.** I checked: zone id is u16 everywhere
   except the same-host event-stream u8 (`codec.rs:338-360`, `zones.rs:40`); the
   #2391 cap exists *because* of that u8 (`compiler_validate_strict.go:3316-3327`
   literally says "a u8 field"). Policy id is u32 on every surface — no width
   pressure. So the binding constraints genuinely differ; a single allocator
   cannot be optimal for both. Rejecting the #3395 prior verdict's unified
   allocator is the right call.

2. **Option C reuses a reviewed precedent verbatim.** `tunnelid.go` is the same
   "pure function of the name, both nodes agree by construction, commit gate +
   fail-closed belt" shape. Low architectural risk for the zone half.

3. **Option C does fix the HA path, and the plan does not over-claim.** The HA
   bug is the SEND-side `zoneNameByID(val.IngressZone)` reverse lookup of a
   *stale local numeric id*; a stable id is never stale, so the lookup is always
   correct. The plan correctly scopes the zone-DELETE orphan case as separate
   (handled by the existing zone-delete flush), not as something C fixes. Honest.

## BLOCKING — zone half (must close before PLAN-READY)

### Z1. "No cross-version interop" for the widen is asserted, not proven.
The plan leans entirely on "the #1917 STOP→FLIP→START .deb cut replaces daemon +
helper atomically and the event stream is drained fresh." That is the load-
bearing claim for the entire MED wire-compat risk, and it is not verified in the
doc. The failure mode is concrete and bad: the **helper (Rust `codec.rs`) WRITES**
the frames; the **daemon (Go `eventstream.go`) READS** them. If the cut leaves a
new helper (u16 writer) talking to a not-yet-restarted old daemon (u8 reader) —
or any persisted/queued event-stream bytes survive the restart — zone ids in
`[27:29]` decode as garbage and sessions land in the wrong zone *during the
upgrade window*. Required revision: cite the exact #1917 sequencing that
guarantees (a) helper and daemon are both replaced before either processes a
frame, and (b) no event-stream buffer persists across the restart. If that
guarantee cannot be shown, the widen needs an explicit record-version
negotiation (reader accepts both widths until the writer advertises the bump) —
which the plan currently only gestures at ("bump the event-stream record
version" + "extend the dual-length tolerance"). Make the version-negotiated read
path a REQUIRED step, not a footnote.

### Z2. Group-scoped zone collision gate is hedged with "if".
The plan says the gate must use node0/node1 expansion discipline "if zones can be
group-scoped." That `if` is a research gap — resolve it. Zones are configured
under `security zones security-zone <z>`, and `groups node0 { security ... }`
apply-groups are a first-class pattern in this codebase (the tunnel gate's Views
2/3 exist precisely because interfaces can be group-scoped). If a zone name can
be supplied or differ per node via `${node}`/apply-groups, a name-hash collision
that exists only post-expansion on one node will split config-sync exactly like
the tunnel Defect-A. Required: confirm zones can be group/`${node}`-scoped and
specify the three-view gate concretely (or prove zones are never group-scoped and
drop the discipline). No `if`.

## BLOCKING — policy half (re-scope or defer)

### P1-is-over-scoped. The close-path plumbing is the problem.
The plan's own §8 rates P1 architectural risk MED specifically because "#3322
flagged the close path does NOT hold PolicyState." That is the tell. `ef72285df`
deliberately punted the peer/wire side; threading a live `PolicyState` reference
into the SESSION_CLOSE emit path is new surface in a hot-ish path (close events
fire per session teardown), and it buys only the close-log half of a Medium
forensic edge. Meanwhile P1 leaves the HA-peer-after-reorder residual exactly
where #3322 left it — so even "full" P1 is not a complete fix; it's a partial fix
with new plumbing.

I am not convinced the close-path work clears the bar. Two cleaner outcomes the
plan should put on equal footing instead of burying P0 as a "fallback":

- **P0 (live-rows only).** Re-resolve the current policy_id only at the ~1s
  conntrack refresh (`bpf_map/mod.rs:344-355`), which already runs and already
  holds the live state. Fixes `show security flow session` — the most-viewed
  surface — with NO close-path change, NO new PolicyState reference, NO wire.
  This is the proportionate fix.
- **PLAN-DEFER #3395 entirely.** The severe instance (#3322 hit-counter) is
  fixed; the residual is documented in `feature-gaps.md`. Doing nothing is
  defensible for a Medium forensic edge.

Required revision: promote **P0 to the recommended policy fix** (or PLAN-DEFER),
and move P1's close-path plumbing into "Out of scope / future" alongside P2.
Recommending P1-with-close-plumbing as the headline policy fix is the one place
this plan over-reaches.

### P2 + #3395-full: agree it's deferred — keep it dead.
Three two-sided wire growths + version bump for the HA-peer display is correctly
out of scope. No change needed; just don't let a later round resurrect it.

## NON-BLOCKING (fold or note)

- **Re-resolution data structure (perf).** §8 says "bound the lookup" but does
  not specify it. A naive per-refresh per-session `current_policy_id_for_rule_id`
  is O(sessions × rules). Specify: `PolicyState` exposes a
  `HashMap<rule_id, u32>` rebuilt ONCE per snapshot, O(1) per session at refresh.
  Given the CLAUDE.md control-socket-contention rule, an O(n²) refresh is a real
  regression risk — make the O(1) map a stated requirement, not an afterthought.
- **Deleted-rule close fallback.** §5.2 covers deleted-rule fallback for live
  rows; state the same for the close log (deleted rule → frozen id → possibly
  stale close log, accepted because the rule is gone).
- **Zone C vs B is a closer call than the plan admits.** Option B (flush on
  ordering-perturbing remap) is stateless, no-Rust, no-wire, no-gate — and an
  ordering-perturbing zone edit while sessions are live is *rare* on a 3-8 zone
  box, so B's churn is rare too. The honest decider is NOT "C avoids churn" (the
  churn is rare); it is "do you also want to kill #2391 / the u8 cap and unify
  with #1873?" If yes → C. If you only want the bug gone cheaply → B is smaller.
  The plan should present this as the maintainer's real choice, not assume C.
- **Shared helper §5.3.** Correctly optional. Lean toward NOT extracting it in
  the same change — `tunnelid.go` works; a standalone `StableZoneID` is lower
  risk than a refactor that touches the shipped tunnel gate.

## What would make r2 PLAN-READY
1. Z1: prove the #1917 atomic cut drains the event stream, OR make
   version-negotiated dual-width read a required step.
2. Z2: resolve the group-scoped `if` — specify the three-view gate or prove it
   unneeded.
3. Re-scope policy: P0 (live-rows-only) becomes the recommended fix (or
   PLAN-DEFER #3395); P1 close-path plumbing → out of scope with P2.
4. Fold the non-blocking notes (O(1) map, deleted-rule close, C-vs-B framing).

With those, the converged verdict is: **PLAN-READY for #3075 (Option C)** and
**PLAN-READY for #3395 (P0) or PLAN-DEFER #3395** — explicitly NOT a unified
allocator, explicitly NOT P1-close-plumbing/P2 this cycle.
