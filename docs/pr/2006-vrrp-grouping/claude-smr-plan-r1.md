# Claude-SMR hostile self-review — #2006 plan r1

Reviewer stance: hostile. Goal is to break the plan, not bless it. The plan
claims PLAN-READY (in-package) with a default of "close as substantially-done"
and a subpackage PLAN-KILL. Below I try to falsify each load-bearing claim.

## Verdict
**Plan is SOUND. Default disposition (Option A, close-as-done) is correct;
Option B is a safe-but-marginal extra; Option C (subpackage) PLAN-KILL is
correctly argued.** Findings below are refinements, not blockers. Net: APPROVE
with the §F nit folded in.

---

## A. "track.go already exists / #2006 is substantially done" — VERIFIED, not overstated
Hostile angle: maybe the agent confused a stale worktree or misread which issue
the commits reference (the [[feedback_verify_agent_branch_base]] hazard).

- Checked: worktree HEAD `9979a89a0`, branch `research/2006-vrrp-grouping` off
  `origin/master` (freshly fetched). Not a stale base.
- `git log -- pkg/vrrp/track.go` → `a40b1f747 "#2006: extract interface trackers
  ... into track.go"` and `a1037fc48 "#2006: document the pkg/vrrp track.go
  split"`. The commit subjects literally cite #2006. This is not an
  interpretation; it is the recorded history.
- `pkg/vrrp/track.go` exists (228 LOC) and README "File layout" enumerates
  manager/instance/packet/track/vrrp. The decomposition is real.

No overstatement. The plan's central premise holds.

**Hostile residual:** the plan should make explicit that it is OK for an issue to
have been partially self-resolved by intervening commits — and that the right
move is to *recognize* it rather than re-do work. The plan does this in §2/§11.
Fine.

## B. Subpackage cycle claim — is it actually a cycle, or just inconvenient?
Hostile angle: Go cycle claims are often overblown; sometimes a shared
`internal/` package dissolves the cycle cleanly, so "PLAN-KILL" may be lazy.

- The plan's strongest, non-handwavy point is the **method-receiver** rule:
  `track.go` defines methods on BOTH `*vrrpInstance` and `*Manager`. Go forbids
  declaring a method on a type from another package — so a standalone
  `package track` is *impossible by language rule*, independent of cycles. I
  verified track.go's receivers: 3 on `*vrrpInstance`, 6 on `*Manager`. The
  claim is correct and is the decisive (language-level, not preference-level)
  argument. This is stronger than #2002/#2004's cycle-only argument.
- The `Manager`↔`vrrpInstance` coupling: I confirmed manager.go's 14× `vi.cfg`,
  6× `vi.mu`, plus newInstance/openSocket/stop/run/etc. A split forces exporting
  the type + ~20 methods + ~15 fields. Even if a third `internal` package broke
  the *cycle*, you still pay the export-everything cost on failover-critical
  code for zero benefit. The plan acknowledges the internal-package escape hatch
  in §4.2(b) and rejects it on cost/benefit, not on impossibility — that is the
  honest framing. Good: it does not overclaim "impossible" where it is merely
  "not worth it"; it reserves "impossible" for the receiver rule where that word
  is literally true.

Cycle/PLAN-KILL reasoning survives hostile probing.

## C. "In-package move has zero import-graph change" — TRUE but check imports
Hostile angle: moving socket helpers could orphan or duplicate imports and the
plan might be glib about it.

- The plan explicitly calls out `goimports` and names the likely import shift
  (manager.go drops `encoding/binary` since `htons` is its only user there;
  socket.go gains binary/ipv4/unix/...). It flags "confirm `htops`/`htons` was
  the only `binary` user" — correct caution. I sanity-checked manager.go: the
  only `binary.` use is in `htons`. So the import drop is real and the plan's
  caution is appropriate.
- Verdict: not glib. Acceptable.

## D. Test plan — does it actually gate on failover, and is the gate honest?
Hostile angle: the plan might wave `make test-failover` as required but then
quietly let Option A skip it, masking a real change.

- §7.1 is explicit: failover gate is MANDATORY for any *source* change (Option
  B), and explicitly NOT required for Option A *because nothing is built or
  deployed*. That is the correct distinction — the policy gates code/behavior
  changes, and a pure issue-comment is neither. The plan does not use Option A
  as a loophole to skip the gate on a real change; it only skips it when there
  is literally no change. Honest.
- The plan correctly notes the legacy regression cluster invocation
  (`make CLUSTER_ENV= test-failover`) consistent with CLAUDE.md, and a smoke on
  the loss userspace cluster only if Option B is deployed. Reasonable.

**Hostile nit (D1):** §7.1 says Option B "cannot change behavior" yet still
mandates failover. Good — it resists the temptation to argue the gate away.
Keep that phrasing; it is the right discipline for failover code (a "can't
possibly break" move-only refactor is exactly the kind that silently breaks
when someone fat-fingers a BPF offset).

## E. Is Option B worth doing at all? — Plan already self-flags this
Hostile angle: the plan might push a cosmetic refactor that spends scarce
failover-test budget for nothing — exactly the kind of gold-plating to reject.

- The plan's §3/§8/§9/§11 repeatedly and explicitly rate Option B as
  low-value and recommend Option A (close-as-done) as the default. It does not
  push the cosmetic change. This is the correct altitude — it surfaces the
  option for the maintainer without advocating make-work. APPROVE.

## F. Gaps / things the plan should add (only real nit)
- **F1 (minor, fold in):** The plan should state the concrete close-comment
  text for Option A and note that #2006's issue body LOC (instance.go 1266,
  manager.go 872) are now stale (instance.go 1203, manager.go 724) due to the
  track.go extraction — so a reader of the issue is not confused that "the files
  didn't shrink as the issue implied." Minor; can live in the PR/issue comment.
- **F2 (checked, not a gap):** Are there OTHER unexported symbols shared across
  files that a future subpackage attempt would trip on (beyond the ones cited)?
  I spot-checked: `vrrpProto`/`vrrpHeaderLen` (packet.go consts) are used in
  instance.go too — another cross-file unexported coupling that reinforces the
  in-package conclusion. The plan's cycle case is if anything *understated*, not
  overstated. No action needed.
- **F3 (non-issue):** No `docs/pr/2002-*`/`2004-*` plan-kill docs exist in this
  worktree to cross-reference. The plan cites the #2002/#2004 pattern from the
  research brief rather than a file. Acceptable — the cycle argument here stands
  on its own (the receiver rule) and does not depend on those docs.

## G. Behavior-preservation invariants — covered?
The issue enumerates must-preserve invariants: 30ms RETH advert, NODAD, async
GARP burst, priority-cost clamp [1,254], owner-255 exemption. For Option A these
are untouched (no change). For Option B, none of those live in the socket
helpers being moved — they live in instance.go (`getPriority` clamp is in
track.go, GARP in instance.go, NODAD in `addVIPs`). So Option B's move surface
does not intersect any invariant. The plan's move-only discipline + failover
gate covers the residual risk. Adequate.

---

## Final
APPROVE. PLAN-READY (in-package). Subpackage = correctly PLAN-KILLED via the
language-level method-receiver rule (stronger than #2002/#2004's cycle-only
argument). Default disposition close-as-done is right; Option B is a safe,
clearly-labeled, low-value optional. Fold F1 into the issue comment. No blocking
findings.
