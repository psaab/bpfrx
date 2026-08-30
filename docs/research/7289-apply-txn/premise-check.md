# #7289 premise check — measured at `origin/master` f32aacbac

Written BEFORE the plan, because four of the claims the issue and the stranded
#4960 plan rest on do not survive contact with master, and two of them change
the answer rather than the wording.

Method: every row below is a quote or a grep result from the worktree at
`f32aacbac`. Where a claim does not reproduce, the cited base is checked with
`git show <base>:<path>` so FIXED-SINCE is separated from NEVER-TRUE — they
have opposite implications for the sibling claims.

## A. Confirmed

| claim | evidence |
|---|---|
| Phase 2 `compileZones` is the FIRST destructive host mutation in `CompileConfig` | `compiler.go:376`, and the comment at `:363-370` enumerates VLAN create/link-up, address delete/add, `LinkDel`/`LinkSetDown` via `stripUnmanagedInterfaces`, ethtool and /proc/sys writes |
| Nothing after it has an undo path | same comment, verbatim: "nothing after it has an undo path" |
| No undo log exists anywhere | `grep -rln "undoLog\|undo_log\|UndoLog\|rollbackHost" pkg/` → **no output** |
| Every netlink MUTATION in the compiler package is in `compiler_iface.go` | `grep -rnE "netlink\.(Link(Add\|Del\|SetUp\|SetDown\|SetMTU\|...)\|Addr(Add\|Del\|Replace)\|...)"` returns `compiler_iface.go` lines only; `compiler.go` matches are comments |
| `preflightCheckIfindexCaps` + `attachUserspaceShimXDP` run after Phase 2 and cannot be hoisted | `loader.go:309` `runPostMutationSteps`; the preflight consumes `result.pendingXDP`, which only `compileZones` populates |
| stranded research branch still at `ad300b881` | `git log --oneline -1 origin/research/4960-apply-txn` |

## B. NEVER-TRUE — the stranded plan's §4.4 two-phase claim

`docs/research/4960-apply-txn/plan.md` §4.4, annotated **"(verified r1 N1)"**:

> Destructive host mutation is concentrated in exactly two phases — Phase 2
> `compileZones` (first) and Phase 11 `compilePortMirroring` (last,
> `compiler.go:1704`, netlink at `:1758/:1811`).

At master `compilePortMirroring` spans `compiler.go:1870-1917` and its only
mutation is `dp.SetMirrorConfig(...)` — a DataPlane-interface call, not host
netlink. Its `netlink.` references are `netlink.LinkByName`, which is a READ.

This is NOT fixed-since. At the research branch's own merge base
`c7ed438e0`, the same function had the identical shape — `netlink.LinkByName`
at the very lines the plan cites as mutation sites. The claim was false when
written, and a hostile review round marked it verified.

**Consequences.** (1) The in-tree "first and ONLY destructive netlink mutation
in this function" comment is CORRECT and the stranded plan is wrong, so the
blast radius is smaller than that plan assumes. (2) The stranded plan's
"(verified ...)" annotations cannot be relied on; anything reused from it needs
re-deriving. The issue's instruction to "start from the stranded plan, not from
scratch" stands, but as a source of ARGUMENTS, not of facts.

## C. DRIFTED — three acceptance clauses need re-scoping, not deletion

1. **The two soft VLAN-name skips are no longer in the same state.**
   `compileFirewallFilters` (`compiler_filter.go:222`, `:243`) still
   `continue`s, but #6893 added structured `recordUnappliedFilterBinding` on
   BOTH the physical-interface miss and the VLAN sub-interface miss, so the
   consequence is recorded. `compilePortMirroring` (`compiler.go:1870+`) is
   still a bare `slog.Warn(...); continue` with nothing recorded. The
   acceptance clause treats them as one item; they are two.

2. **`publishSnapshotFailClosedLocked` has partial recovery the issue does not
   mention.** `manager_compile.go:555`: #7468 guarantees a status/reconcile
   loop survives a rejected publish (`ensureStatusLoopLocked`), and
   `retainPreviousClassifierPlanLocked` handles the maps-mutated-in-place case.
   There is still NO re-convergence for HOST state.

3. **#7079 is listed as "adjacent, already tracked" but appears LANDED** — the
   bpffs cleanups now run after `CompileConfig` (`loader.go:287`).

## D. NOT IN THE ISSUE — two shipped mechanisms the plan must compose with

These are the reason this research does not need to invent a transaction model,
and neither the issue nor the stranded plan mentions either.

### D.1 A fail-closed transit barrier already exists, and is already #1960-analysed

`pkg/daemon/daemon_transit_gate.go:25-55`. Kernel transit forwarding is
CONDITIONAL on `Daemon.dataplaneArmed`: `ip_forward` / `ipv6...forwarding` are
driven to 0, plus an unconditional forward-hook DROP in the inet AND bridge
families (#7191), on every path landing in `setDataplane(nil)`. Management
survives on purpose — `ip_forward` governs forwarded packets only, so SSH,
gRPC/REST/CLI, the cluster heartbeat and DHCP are untouched.

So "keep the control plane disabled" (clause 2 option b) is **not** the brick
the issue implies. The doctrine's own resolution is already implemented.

**But it does not fire here.** Every `setDataplane(nil)` call site is in
bringup/naming (`daemon_run_bringup.go:470,490,616`, `daemon_run_naming.go:264`)
— **none is on the apply path**.

### D.2 The codebase has ALREADY chosen option (c) for this failure class

`pkg/daemon/daemon_apply_dataplane.go:176-191`, #5679, verbatim:

> an ORDINARY (non-abort-class) full-apply failure does NOT disarm the
> dataplane — the dataplane ApplyConfig leaves the OLD compiled policy live and
> forwarding while store.Commit has already promoted+persisted the NEW config.
> ... Capture the failure as a DEFERRED commit error ... the applied config
> never advanced, so an identical re-commit / the feed onUpdate retry (#5646,
> via applyConfigResult) re-applies and **self-heals**.

That is re-drive-to-convergence — clause 2's option (c) — already shipped for
the DATAPLANE half, with an abort class (`compileErrorMustAbortApply`) already
distinguished from the ordinary class.

**The gap #7289 actually names is that Phase 2's HOST mutation sits outside
that guarantee.** "The applied config never advanced" is true of the compiled
policy and false of the VLANs and addresses already created.

## E. The state the divergence actually leaves, stated once

Not "host and dataplane diverged" in the abstract. Measured:

- host: NEW topology (VLANs created, addresses reconciled, possibly interfaces
  downed/deleted by `stripUnmanagedInterfaces`);
- dataplane: ARMED, forwarding, on the OLD snapshot and OLD policy;
- transit barrier: OPEN, because nothing unarmed;
- configstore: NEW config promoted and persisted, commit reported as failed
  (#5679 deferred error).

So the hazard is not an outage. It is **enforcement of the old policy over the
new topology, while the operator has been told the commit failed** — and a
tightening commit is the sharp case, exactly as #5679 says for its own half.

### D.3 The re-drive re-runs Phase 2, but nothing triggers it

`applyActiveConfigResult()` re-applies the ACTIVE config from the top, so a
re-drive DOES re-enter `ApplyConfig` -> `CompileUserspaceShim` ->
`CompileConfig` -> Phase 2. The mechanism option (c) needs therefore exists and
already reaches the mutation that needs converging.

Its TRIGGERS are the whole problem. Every call site:

- `daemon_feeds.go:57` — a dynamic-address feed refetch (#5646)
- `daemon_run_bringup.go:541` — bringup
- `daemon_dhcp.go:101` — a DHCP lease event

All three are event-driven and **none is unconditional**. There is no timer, no
retry queue, and no consumer of the #5679 deferred error that re-drives. On an
appliance with static addressing and no dynamic feeds, nothing ever fires, so
#5679's "self-heals" is conditional on an event that may never come — or on the
operator re-committing by hand, which is the intervention the issue is trying
to remove.

**This is the finding that sizes the work.** Option (c) is largely shipped:
the re-drive path exists, re-enters Phase 2, and has an abort/ordinary split
(`compileErrorMustAbortApply`). What is missing is (i) whatever part of Phase 2
is not idempotent under re-entry, and (ii) a TRIGGER, for which the #7468
status loop is already guaranteed to be running after a rejected publish and
`manager_compile.go` already uses the phrase "retry-debt consumer".
