# #2083 — renameInterface leaves an interface renamed-but-DOWN when the final LinkSetUp fails

**Status:** v2 — revised after round-1 adversarial plan review (both
reviewers converged: the v1 rename-back design was WRONG). v2 simplifies
to "bring up under the new name + actionable error".

## Issue framing

`renameInterface(oldName, newName)` in `pkg/daemon/linksetup.go` does a
three-step netlink dance: `LinkSetDown` → `LinkSetName` → `LinkSetUp`.

The first two steps already roll back partially:

- `LinkSetDown` failure returns immediately (interface untouched).
- `LinkSetName` failure brings the link back up before returning
  (`_ = netlink.LinkSetUp(link)`).

But the **final** `LinkSetUp` failure (line ~339) returns the error
*without any recovery*:

```go
if err := netlink.LinkSetUp(link); err != nil {
    return fmt.Errorf("link up %s: %w", newName, err)
}
```

At that point the interface has already been **renamed** to `newName`
and is administratively **DOWN**. The interface is left stranded DOWN.

Audit severity: **LOW** (rare netlink-failure path). Robustness fix.

## Round-1 plan review outcome (why v2 differs from v1)

Two independent hostile reviewers reviewed v1 (which proposed *renaming
the interface back to `oldName`* on failure). Both rejected that design:

- **Reviewer A: PLAN-NEEDS-MAJOR (near KILL).** The rename-back
  **re-creates the collision** that `device_map.go` phase-1 exists to
  break. Phase 1 temp-renames a NIC that squats on a wanted final name
  to `xpf-tmp-N` to free that name; if rename-back fires, the NIC goes
  back onto the wanted name and phase-2's rename of the *intended*
  occupant hits **EEXIST** — strictly worse than today (today leaves the
  squatter DOWN at the temp name, collision half-broken, and phase-2
  succeeds). v1 also mis-cited the lifeline caller (it is
  `bootstrap.go:776`, not `:507`).
- **Reviewer B: PLAN-NEEDS-MINOR.** The v1 "false symmetry" argument is
  the root error: a `LinkSetName` failure means the rename *did not
  happen* (so rolling back the down is correct), but a `LinkSetUp`
  failure means the rename **already succeeded** — so the correct
  recovery is to **finish the job (bring it up under `newName`)**, not
  undo it. Bringing it up under `newName` is correct for *all five*
  callers, removes the device-map regression, and removes the only
  wrong-link/EEXIST window. This is also what "keep it SIMPLE" asks for.

Both reviewers independently arrived at the same corrected design. v2
adopts it.

### v1's load-bearing claim was false

v1 argued: "if you `LinkSetUp` under `newName`, the next reconcile sees
`nic.name == target` and never retries the rename." Reviewer B verified
against the real loop and showed this is *the desired terminal state*:
the rename **did** succeed; the interface is up under the correct name;
there is nothing left to retry. The rename did not need re-doing — only
the bring-up flickered, and re-issuing the bring-up resolves it
completely. (Confirmed: `enumerateAndRenameInterfaces` compares
`assignName(...)` to the **live** kernel name from `enumeratePCINICs`
reading `/sys/class/net`; once up under `newName == target`, the NIC is
correctly skipped next pass.)

## Honest scope/value framing

The win is small and bounded: it closes a rare window where a transient
`LinkSetUp` netlink error leaves an interface renamed-but-DOWN. The fix
makes the interface end up **UP under its correct new name** even when
the first bring-up fails transiently, and makes the error message
actionable for field debugging. If reviewers still conclude the gain is
too small, PLAN-KILL is acceptable — but the current code's stranded-DOWN
end state is a clear (if rare) defect, and the v2 fix is ~6 lines plus a
test.

## Callers (corrected; all best-effort log-and-continue)

| Site | Context |
|---|---|
| `linksetup.go:81` | positional rename to vSRX name (`ge-0-0-N`, `fxp0`, ...) |
| `device_map.go:198` | phase-1 temp-rename to break a stale-udev collision |
| `device_map.go:245` | phase-2 rename mapped NIC to final logical name |
| `device_map.go:264` | phase-3 restore stranded NIC to a predictable name |
| `device_map.go:564` | identity-resolution restore (`err == nil` guard) |
| `bootstrap.go:776` | lifeline rename of mgmt NIC to `fxp0` |

Every site treats the return as advisory (`slog.Warn` then continue). No
site uses `errors.Is`. So the v2 fix changes no caller and only improves
the interface's on-the-wire end state and the error string. Crucially,
v2's "bring up under newName" is safe at **every** one of these sites
(the v1 rename-back was not — it broke `:198` and `:264`).

## Concrete design (v2)

### 1. Introduce package-level netlink seams for the link ops

Matches the package's established idiom (`deriveKernelNameFn`,
`linkDir`, `lifelineRecordFileForTest`, and the `rssExecutor` interface).
There is a reusable `testLink`/`mockLinkByName` scaffold in
`vip_readiness_test.go` the test will reuse.

```go
// netlink link operations, injectable for tests. Default to the real
// vishvananda/netlink package functions. Tests swap these (with
// t.Cleanup restore); tests that touch them MUST NOT call t.Parallel().
var (
    nlLinkByName  = netlink.LinkByName
    nlLinkSetDown = netlink.LinkSetDown
    nlLinkSetName = netlink.LinkSetName
    nlLinkSetUp   = netlink.LinkSetUp
)
```

`renameInterface` calls the seam vars instead of `netlink.*`. The
existing `LinkSetName`-failure rollback `_ = netlink.LinkSetUp(link)`
becomes `_ = nlLinkSetUp(link)` (no behavior change). `LinkByName` in
`device_map.go:556` is a separate call outside the rename dance and is
left untouched (out of scope).

### 2. On final LinkSetUp failure: retry the bring-up under newName, return an actionable error

The rename already succeeded; the link is DOWN under `newName`. Re-issue
the bring-up once more on the same cached handle (set operations act by
**ifindex**, which is stable across the rename — verified against
`vishvananda/netlink@v1.3.1`: `LinkSetUp`/`LinkSetName` operate on
`base.Index`, so the stale `.Attrs().Name` is irrelevant). If the retry
also fails, return a precise error so the operator/next-reconcile can
act:

```go
if err := nlLinkSetUp(link); err != nil {
    // The rename to newName already succeeded; the link is DOWN under
    // newName. Do NOT undo the rename — that would re-create collisions
    // the device-map phase-1 path deliberately broke. Retry the bring-up
    // once on the same handle (set ops act by ifindex, stable across the
    // rename). If it still fails, surface an actionable error: the
    // interface is correctly named, and the next networkctl reload /
    // reconcile will bring it up.
    if retryErr := nlLinkSetUp(link); retryErr != nil {
        return fmt.Errorf(
            "renamed %s -> %s but could not bring it up "+
                "(interface is correctly named but DOWN; "+
                "next reconcile/networkctl reload will retry): %w",
            oldName, newName, retryErr)
    }
    return nil
}
return nil
```

Rationale for a single immediate retry: the first `LinkSetUp` may fail on
a transient netlink condition; one cheap retry on the rare error path
costs nothing and often recovers. We do NOT loop (no oscillation risk),
and on persistent failure we return — the daemon's `networkctlReload`
runs right after every caller loop (`linksetup.go:99`,
`device_map.go`, `bootstrap.go:783`) and systemd-networkd will bring a
configured link up; the next reconcile is the durable backstop. The
interface is left **correctly named** in all cases (UP if the retry
worked, DOWN-but-correctly-named otherwise — recoverable by networkd,
never stranded under the old name or a temp name).

> Single-retry is a deliberate "keep it simple" choice; if reviewers
> consider even one retry gold-plating, the fallback is to drop the retry
> and return the wrapped error directly (the interface is still correctly
> named and networkd/next-reconcile recovers it). Flagged in open
> questions.

### 3. No rename-back, no double-fault branch

v1's three-branch compound-error handling and rename-back are removed
entirely. This is correct for all five callers and eliminates the only
realistic wrong-link/EEXIST window (which v1's re-resolution introduced).

## Public API preservation

- `renameInterface(oldName, newName string) error` — signature unchanged.
- All six call sites unchanged (log-and-continue). Richer error string.
- No new exported symbols. Seam vars are unexported.

## Hidden invariants the change must preserve

1. **ifindex stability.** Set ops act by ifindex; the cached `link`
   handle stays valid for the retry `LinkSetUp` despite the stale name.
   (Verified against netlink v1.3.1.)
2. **Best-effort caller contract.** `renameInterface` is leaf-level; the
   caller loops are unchanged; no early-return skips remaining NICs.
3. **No collision re-creation.** Because v2 never renames back, the
   device-map phase-1 collision-break invariant (`device_map.go:186-221`)
   is preserved — the failed NIC stays under `newName`/`tmpName`, never
   bounced back onto a freed name.
4. **No temp-name persistence.** v2 never restores an `xpf-tmp-*` name
   (the device-map phase-3 hazard a rename-back would have hit).
5. **Idempotent reconcile.** If the interface ends up DOWN-but-correctly-
   named, the next `networkctlReload`/reconcile brings it up; no rename
   retry needed (the rename already succeeded).
6. **Control plane only.** No hot-path allocation concerns.

## Risk assessment

| Class | Level | Notes |
|---|---|---|
| Behavioral regression | LOW | Real path unchanged (seam vars = real funcs). New code runs only on the rare final-LinkSetUp-failure branch, which previously stranded the link DOWN. v2 is safe for all five callers (v1 was not). |
| Lifetime / handle staleness | LOW | Retry reuses the cached handle; set ops are by ifindex (stable). No re-resolution, no wrong-link window. |
| Performance regression | NONE | Control plane, rare error path; at most one extra `LinkSetUp` syscall on failure. |
| Architectural mismatch | LOW | Seam idiom matches `device_map.go`'s function-var seams and `vip_readiness_test.go`'s `mockLinkByName`. |

## Test plan

New file `pkg/daemon/linksetup_rename_test.go`. Reuses the `testLink` /
`mockLinkByName` scaffold from `vip_readiness_test.go`. Each test swaps
the four seam vars and restores via `t.Cleanup`. **None call
`t.Parallel()`** (package-global seam state).

The seam is recorded via a small in-test recorder capturing the ordered
sequence of `(op, name)` tuples so assertions are on the exact call
sequence, not just the error string (non-tautological).

1. **TestRenameInterfaceBringsUpUnderNewNameAfterTransientUpFailure** —
   `LinkByName` → stub; `LinkSetDown` ok; `LinkSetName(newName)` ok;
   first `LinkSetUp` fails, second `LinkSetUp` succeeds. Assert:
   - returns `nil`.
   - recorded sequence is `down → setname(newName) → up(fail) → up(ok)`.
   - **NO `setname(oldName)`** ever issued (guards against rename-back
     leaking back in). *Non-tautological:* deleting the retry makes this
     return a non-nil error → test fails.
2. **TestRenameInterfacePersistentUpFailureReturnsActionableError** —
   both `LinkSetUp` calls fail. Assert:
   - returns non-nil error mentioning both `oldName` and `newName` and
     the word "DOWN" / "reconcile".
   - error wraps the underlying `LinkSetUp` error via `%w`
     (`errors.Is(err, sentinelUpErr)` is true).
   - recorded sequence shows the rename to `newName` happened and **no
     rename-back** to `oldName`. *Non-tautological:* if the impl renamed
     back, the recorded sequence assertion fails.
3. **TestRenameInterfaceSuccessPathUnchanged** — all ops succeed on the
   first try. Assert: returns `nil`; sequence is exactly
   `down → setname(newName) → up`; no retry, no rename-back.
4. **TestRenameInterfaceLinkSetNameFailureStillRollsBackUp** —
   regression guard on the pre-existing `LinkSetName`-failure path:
   `LinkSetName(newName)` fails; assert a `LinkSetUp` is issued on the
   original handle and the error mentions the rename failure. (Confirms
   v2 didn't disturb the existing partial rollback.)
5. **TestRenameInterfaceLinkSetDownFailureReturnsEarly** — `LinkSetDown`
   fails; assert no `LinkSetName`/`LinkSetUp` issued, error returned.
   (Cheap completeness guard.)

Gates:
- `go build ./...` clean
- `go vet ./pkg/daemon/...`
- `go test ./pkg/daemon/...` (named tests 5× for flake)
- Full Go suite `go test ./...`

**No smoke** — control-plane-only change, no dataplane impact, per the
engineering instruction. The HA/cluster smoke matrix does not exercise
this error branch.

## Docs

The rollback-on-failure is an internal robustness detail of
`renameInterface`. I will update the function's doc comment to describe
the bring-up-under-newName recovery (the in-code contract). CLAUDE.md's
"Interface Management (networkd)" section documents `.link` rename
behavior at the operator level; the failure-recovery detail is not an
operator-visible contract change, so no operator-doc edit is required.
(Stated here per the docs-as-contract rule.)

## Out of scope

- `netlink.LinkByName` at `device_map.go:556` (not part of the rename
  dance).
- Looping/backoff retries inside `renameInterface` (networkd + next
  reconcile is the durable retry).
- Any change to caller error-handling (they remain log-and-continue).

## Open questions for adversarial review (v2)

1. **Single retry vs no retry.** v2 does one immediate `LinkSetUp`
   retry on failure. Is that worthwhile, or is even one retry
   gold-plating a rare path (just return the wrapped error)? Either is
   defensible; which does the project prefer?
2. **Is "DOWN-but-correctly-named, recovered by networkd" actually
   guaranteed?** networkd brings up configured links on reload — but is
   there a case (e.g. an interface with `ActivationPolicy=always-down`
   or no `.network`) where networkd would NOT bring it up, leaving it
   DOWN after all? For the rename callers the `.link`/`.network` is
   written before the rename, so it should be configured — confirm.
3. **ifindex-stability assumption.** v2 reuses the cached handle for the
   retry on the premise that set ops act by ifindex. Confirm against the
   pinned netlink version that no set op re-resolves by name internally.
4. **Error wrapping.** Single `%w` chain wrapping the `LinkSetUp` error.
   Confirm no caller needs to distinguish this from other errors (all
   currently log-and-continue — verified).
5. **Test non-tautology.** Do the recorder-sequence assertions fail if
   (a) the retry is deleted and (b) a rename-back is (re)introduced?
   Both should fail — confirm the assertions are tight enough.
6. **Anything still over- or under-engineered** relative to "keep it
   simple"?
