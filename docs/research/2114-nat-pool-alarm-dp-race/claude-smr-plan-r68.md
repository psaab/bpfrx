# Claude SMR hostile plan-review — round 68 (plan v69 @ `ee70003a3`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. v69 is the
document-level execution of the r28 split: the G+H+H2 follow-up unit moved
verbatim to `followup-seed.md`; plan.md is now the PR-1-only plan-of-action.
This round's verdict surface is PR-1 only. Every code claim below re-verified
against the worktree tree during this pass (grep + targeted reads).

## A. Extraction fidelity (the new r68 question)

**(a) PR-1 content lost?** Walked every cut boundary against the v68
pre-image (git show f9d0b3eb7). The four cut ranges held only follow-up
content: §4 A1's work items G (3351-3546), H (3547-3719), H2 (3720-6542),
bootstrapFromFile+H-tests (6543-6600); §5.1's daemon PLUS blocks and
follow-up package bullets; §6's H2 signature sentence; §7 invariant 12's
H/H2 body; §8's follow-up sentences; §9's [FOLLOW-UP] legs (8150-9150).
Retained and verified present in v69: the A1 cell + accessor code block,
the canary redesign, the fwdstatus narrowing block with its deletion
inventory, §5.1's PR-1 bullets (dpSlot/dpCell, forwarding_status,
fwdstatus, canaries, grpcapi/cli-untouched), §5.2's 5-site writer table,
§5.3's nine snapshot rules, §5.4's untruncated 134-row table, §6's core,
§7 items 1-11 + 12-pointer, §8 cells, §9 CORE items 1-8, §10, §11.
NO PR-1-load-bearing loss found.

**(b) Follow-up dependency smuggled into PR-1?** Attacked the §4.7 claim
("PR-1 neither ships nor depends on G/H/H2") from three directions:
(i) §9 CORE tests reference no gate/latch/tombstone symbol — verified by
reading items 1-8 in v69; (ii) §5.4's RACE-3 rows read "serialized /
RACE-3 (pre-gate)" — the parenthetical describes master's CURRENT
ungated state, not a dependency; the conversion is uniform regardless of
the gate; (iii) the sampler narrowing, canaries, and writer conversion
compile and stand alone — none imports follow-up state. NO smuggled
dependency found.

**(c) Does PR-1 make any pre-existing hazard WORSE?** The one behavioral
delta I could construct: the kind-gated typed-nil guard normalizes a
typed-nil interface to cell-nil, where master today publishes the typed
nil and later nil-derefs on method use. That is strictly safer, and it is
documented in the plan (§4 A1 code comment). No worsening found.

## B. Fresh attacks on the PR-1 core (all line numbers re-verified)

**Attack 1 (FAILED) — writer-site undercount.** Plan §5.2 claims exactly 5
writers. Independent grep: `d\.dp =` outside tests hits
`daemon_run_bringup.go:448,464,469,497` + `daemon_run_naming.go:234` —
exactly 5, matching the table. FAILED.

**Attack 2 (FAILED) — reader-audit count fabricated.** §5.4's preamble:
"163 greppable lines ... minus 29 full-line comments = 134 executable
references (5W + 129R)". Reproduced: 159 lines for `d\.dp\b` + 4 for
`a\.daemon\.dp\b` = 163; full-line comments 29; 163-29 = 134. The
methodology is stated and reproduces exactly. FAILED.

**Attack 3 (FAILED) — deleted-adapter callers left dangling.** The
narrowing deletes `IsLoaded`/`GetMapStats`/`Status` from the daemon
adapter and removes `userspaceDataplaneStatus()`. Grep: the daemon's
`forwardingStatusDataplane()` has exactly one production caller
(`daemon_run.go:595`, NewSampler); `userspaceDataplaneStatus`/
`userspaceDataplaneCachedStatus`/`forwardingStatusDataplane` have no
callers outside `daemon_forwarding_status.go` except :595. The gRPC/CLI
Build paths (`server_show_forwarding.go:21`, `cli_show_chassis.go:21`)
call their own package-local constructors — untouched. FAILED.

**Attack 4 (FAILED) — Build-misrouting of the collapsed adapter.**
`Build` keys userspace identity on `Status()`-presence
(`builder.go:116-123`); the collapsed adapter has no `Status`, and
`NewSampler`'s retyped parameter makes a wrong-type pass a compile
error. The negative-satisfaction unit test pins it. FAILED.

**Attack 5 (FAILED) — RACE-1 start-ordering claim.**
`watchClusterEvents` is spawned at `daemon_run_bringup.go:203`; the
publication write `d.dp = dp` lands at :469 in the same Run goroutine —
the watcher genuinely reads pre-publication and concurrently. The race
is real on master and the cell closes it at the memory-ordering level.
FAILED.

**Attack 6 (FAILED) — typed-nil kind-gate hole.** `reflect.Interface`
cannot be a dynamic kind; struct values are skipped (IsNil would
panic); the nillable six (Chan/Func/Map/Pointer/Slice/UnsafePointer)
are all gated; `dp == nil` is checked before `ValueOf`. A struct with a
nil pointer FIELD still publishes — but that is master's exact
semantics today (non-nil interface), not a regression. FAILED.

**Attack 7 (SUCCEEDED as nit m1) — the narrowed
`forwardingStatusDataplane()` drops the `d == nil` guard leg.** Current
code nil-checks the receiver (`daemon_forwarding_status.go:123-125`:
`if d == nil || d.dp == nil { return nil }`). v69's contract reads "nil
iff `d.opts.NoDataplane`" — evaluating `d.opts` on a nil `*Daemon`
panics. The sole production caller (`daemon_run.go:595`) holds a
non-nil d, so nothing today breaks; but the guard costs one line, the
"iff" phrasing contradicts the file's defensive shape, and a future
test/fixture caller with a nil receiver would panic instead of getting
nil. Pin: the narrowed constructor keeps `d == nil ||` (
`if d == nil || d.opts.NoDataplane { return nil }`). MINOR.

**Attack 8 (FAILED) — RACE-3 closure overclaimed.** v69 claims
memory-ordering closure only; the dispatch-ordering exposure (timer
fires against partial init) is explicitly deferred to G with the honest
statement that PR-1 leaves it exactly as exposed as master. Read
§5.4's APPLY rows: each says "serialized / RACE-3 (pre-gate)" — the
claim is precise, not overclaimed. FAILED.

## C. Findings

### MAJOR (0)

None.

### MINOR (1)

**m1.** Keep the `d == nil ||` guard leg in the narrowed
`forwardingStatusDataplane()` (`daemon_forwarding_status.go:123-125`):
the v69 "nil iff `d.opts.NoDataplane`" contract panics on a nil
receiver where the current defensive shape returns nil. One clause in
§4 A1's narrowing block / §5.1.

## D. Structure confirmation (§11 q6)

CONFIRM — the r28 split executed faithfully at v69; PR-1 is
self-contained; the follow-up seed carries the open findings honestly.

## Verdict

**PLAN-READY-WITH-NITS** (0 MAJOR, 1 MINOR — the nil-receiver guard
pin). A v70 containing only this pin is PLAN-READY by inspection from
me.
