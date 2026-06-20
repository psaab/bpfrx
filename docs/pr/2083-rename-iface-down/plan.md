# #2083 — renameInterface leaves an interface renamed-but-DOWN when the final LinkSetUp fails

**Status:** DRAFT v1 — pending adversarial plan review

## Issue framing

`renameInterface(oldName, newName)` in `pkg/daemon/linksetup.go` does a
three-step netlink dance: `LinkSetDown` → `LinkSetName` → `LinkSetUp`.

The first two steps already roll back partially:

- `LinkSetDown` failure returns immediately (interface untouched).
- `LinkSetName` failure brings the link back up before returning
  (`_ = netlink.LinkSetUp(link)`).

But the **final** `LinkSetUp` failure (line 339) returns the error
*without any rollback*:

```go
if err := netlink.LinkSetUp(link); err != nil {
    return fmt.Errorf("link up %s: %w", newName, err)
}
```

At that point the interface has already been **renamed** to `newName`
and is administratively **DOWN**. The caller
(`enumerateAndRenameInterfaces`, also `device_map.go` and
`bootstrap.go`) logs the error and continues. The interface is left
stranded: it carries the new name (so the `.link` file matches and the
next reconcile sees "name already correct" → no re-rename), yet it is
DOWN, so no traffic flows and the next reconcile never brings it up.

Audit severity: **LOW** (rare netlink-failure path). This is a
robustness fix, not a hot path.

## Honest scope/value framing

The win is small and bounded: it closes a rare failure window where a
transient `LinkSetUp` netlink error would otherwise strand an interface
renamed-but-down until the next daemon restart that happens to re-trip
the rename (which it won't, because the name already matches). The fix
makes the failure **self-healing on the next reconcile** and makes the
error message actionable.

If reviewers conclude the fix is too small or the risk of the rollback
path outweighs the stranding window, PLAN-KILL is an acceptable verdict
— but note the current code has an obvious asymmetry (the `LinkSetName`
failure rolls back, the `LinkSetUp` failure does not), so at minimum the
symmetry argument favors a fix.

## What's already shipped / relevant context

- `renameInterface` is called from three sites, all best-effort
  (log-and-continue): `linksetup.go:81`, `device_map.go:198/245/264/564`,
  `bootstrap.go:507`.
- No site currently *acts* on the specific error — they all log it. So
  the fix's externally-visible contract is unchanged for callers; the
  improvement is in the interface's on-the-wire state after the failure
  and in log/error clarity.
- The package already uses a clean injectable-seam idiom for the RSS
  executor (`rssExecutor` interface, `realRSSExecutor{}`) and for the
  command runner (`runCommandTimeout`). There is **no** existing seam for
  the bare `netlink.*` link calls in this file — `renameInterface`
  references the package-level functions directly, which is why it has no
  unit test today.

## Concrete design

### 1. Introduce package-level function seams for the netlink link ops

Add unexported package vars in `linksetup.go` that default to the real
netlink functions, so tests can inject failures:

```go
// netlink link operations, injectable for tests. Default to the real
// vishvananda/netlink package functions.
var (
    nlLinkByName  = netlink.LinkByName
    nlLinkSetDown = netlink.LinkSetDown
    nlLinkSetName = netlink.LinkSetName
    nlLinkSetUp   = netlink.LinkSetUp
)
```

Rewrite the body of `renameInterface` to call the seam vars instead of
`netlink.*` directly. `device_map.go:556` (`netlink.LinkByName`) is a
*separate* call outside `renameInterface` and is left untouched (out of
scope; not part of the rename dance).

This is the minimal seam needed; it changes no behavior on the real
path (the vars are initialized to the exact same functions).

### 2. Roll back on final LinkSetUp failure

Replace the final block:

```go
if err := nlLinkSetUp(link); err != nil {
    // The interface is now renamed to newName but DOWN. Best-effort
    // recovery: rename it back to oldName and bring it up so it is not
    // stranded renamed-but-down. The next reconcile will retry the
    // rename cleanly. We must re-resolve the link by its NEW name
    // because the cached `link` object's name is stale after
    // LinkSetName.
    upErr := err
    if relink, relErr := nlLinkByName(newName); relErr == nil {
        if nameErr := nlLinkSetName(relink, oldName); nameErr == nil {
            _ = nlLinkSetUp(relink)
            return fmt.Errorf(
                "link up %s after rename %s -> %s failed; "+
                    "rolled interface back to %s: %w",
                newName, oldName, newName, oldName, upErr)
        } else {
            // Could not rename back. Try at least to bring the link up
            // under its new name so it is not left DOWN.
            _ = nlLinkSetUp(relink)
            return fmt.Errorf(
                "link up %s after rename %s -> %s failed, and rollback "+
                    "rename %s -> %s also failed (%v); interface remains "+
                    "named %s — re-run reconcile/restart to retry: %w",
                newName, oldName, newName, newName, oldName, nameErr,
                newName, upErr)
        }
    }
    // Could not re-resolve the renamed link to attempt rollback; bring
    // up by the cached handle as a last resort.
    _ = nlLinkSetUp(link)
    return fmt.Errorf(
        "link up %s after rename %s -> %s failed; could not re-resolve "+
            "to roll back: %w", newName, oldName, newName, upErr)
}
```

**Why rename-back instead of just LinkSetUp-under-new-name?** If we only
bring it up under `newName`, the `.link` file written *before* the
rename (in the caller) matches `newName`, so the next reconcile sees the
name as already-correct and never retries — the interface would stay up
but the *rename attempt is silently considered done*. The desired
behavior per the issue is "recoverable on the next reconcile": renaming
back to `oldName` means the next reconcile's `nic.name != target` check
fires again and re-attempts the full down→rename→up sequence cleanly.

If the rollback rename *also* fails (double-fault), we fall back to
bringing the link up under whatever name it currently has so it is at
least not left DOWN, and we surface a precise compound error.

### 3. Keep the existing partial-rollback paths using the seam

The existing `LinkSetName`-failure rollback (`_ = netlink.LinkSetUp(link)`)
becomes `_ = nlLinkSetUp(link)` for consistency. No behavior change.

## Public API preservation

- `renameInterface(oldName, newName string) error` — signature
  unchanged.
- All three call sites unchanged (they already log-and-continue on
  error; the error string is now richer but they only `slog.Warn` it).
- No new exported symbols. The seam vars are unexported.

## Hidden invariants the change must preserve

1. **Stale link handle after LinkSetName.** The cached `link` object's
   `Attrs().Name` is `oldName`; after a successful `LinkSetName` it no
   longer reflects reality. The rollback path re-resolves by `newName`
   via `nlLinkByName` before attempting to rename back — it does NOT
   reuse the stale handle for the rename-back. (It only uses the stale
   handle as the very-last-resort `LinkSetUp` when re-resolution itself
   fails.)
2. **Best-effort caller contract.** Every caller treats the return as
   advisory (log-and-continue). The fix must not start *returning early
   in a way that skips remaining interfaces* — it doesn't; `renameInterface`
   is leaf-level and the caller loop is unchanged.
3. **Idempotent reconcile.** After rollback to `oldName`, the next
   `enumerateAndRenameInterfaces` pass must re-attempt the rename. The
   `.link` file (written by the caller before the rename) already names
   `newName`, and `recoverOriginalName` reads it — so the rename retry
   stays correct. Verified: the caller writes the `.link` first, then
   renames; on retry the OriginalName recovery still works.
4. **No new allocations on the hot path.** N/A — this is startup/reconcile
   control plane, not packet path.
5. **No partial-state on the double-fault.** If rename-back fails we do
   not loop or panic; we bring up under the current name and return a
   compound error. The interface is up (not DOWN) even in the worst case.

## Risk assessment

| Class | Level | Notes |
|---|---|---|
| Behavioral regression | LOW | Real path unchanged (seam vars = real funcs). New code only runs on the rare final-LinkSetUp-failure branch, which previously did nothing useful. |
| Lifetime / handle staleness | LOW-MED | Mitigated by re-resolving via `nlLinkByName(newName)` rather than reusing the stale cached handle for the rename-back. Reviewers should confirm this is correct. |
| Performance regression | NONE | Control plane, rare error path. |
| Architectural mismatch | LOW | Seam idiom matches the existing `rssExecutor` pattern in the same package. No new architecture. |

## Test plan

New unit test file `pkg/daemon/linksetup_rename_test.go`:

1. **TestRenameInterfaceRollsBackOnLinkSetUpFailure** — inject seams so
   `LinkByName` returns a stub link, `LinkSetDown`/`LinkSetName` succeed,
   the FIRST `LinkSetUp` (the post-rename one) fails. Assert:
   - `renameInterface` returns a non-nil error mentioning both names and
     "rolled" / "roll back".
   - The rollback rename-back to `oldName` was issued (record calls in a
     recorder).
   - A final `LinkSetUp` was issued after the rename-back (interface not
     left DOWN).
   - **Non-tautological:** the test fails if the rollback rename-back or
     the recovery LinkSetUp is removed from the implementation (assert
     the exact call sequence, not just the error string).
2. **TestRenameInterfaceDoubleFaultBringsUpUnderCurrentName** — final
   LinkSetUp fails AND the rollback rename-back also fails. Assert: error
   is the compound message; a LinkSetUp was still issued so the interface
   is not left DOWN.
3. **TestRenameInterfaceSuccessPathUnchanged** — all ops succeed; assert
   the call order is down→name→up and no rollback calls fire (guards
   against the rollback path leaking into the happy path).
4. **TestRenameInterfaceLinkSetNameFailureStillRollsBackUp** — regression
   guard on the pre-existing `LinkSetName`-failure path (it must still
   issue a LinkSetUp on the original handle).

Seam restoration: each test saves and restores the four package vars via
`t.Cleanup` to avoid cross-test contamination.

Gates:
- `go build ./...` clean
- `go test ./pkg/daemon/...` pass (named tests 5×)
- `go vet ./pkg/daemon/...`
- Full Go suite `go test ./...`

**No smoke** — this is a control-plane-only change with no dataplane
impact, per the engineering instruction. The HA/cluster smoke matrix
does not exercise `renameInterface`'s error branch.

## Docs

CLAUDE.md's "Interface Management (networkd)" section documents the
`.link` rename behavior. The rollback-on-failure is an internal
robustness detail of `renameInterface`, not an operator-visible contract
change, so no operator doc update is strictly required. I will add a
one-line note to the function's doc comment describing the rollback
behavior (the in-code contract). If reviewers want a CLAUDE.md/networkd
doc line, I will add it — flagged as an open question below.

## Out of scope

- The `netlink.LinkByName` at `device_map.go:556` (not part of the
  rename dance).
- Retrying the rename automatically inside `renameInterface` (the issue
  says keep it simple; the next reconcile is the retry mechanism).
- Any change to caller error-handling (they remain log-and-continue).

## Open questions for adversarial review

1. **Rollback target choice.** Is renaming back to `oldName` the right
   recovery, or should we leave it at `newName` and just bring it up?
   (Plan argues rename-back is required for next-reconcile retry; is
   that reasoning sound, or does it risk an oscillation if the rename
   itself is what keeps failing?)
2. **Oscillation risk.** If `LinkSetUp` fails persistently (e.g. a
   hardware fault), every reconcile will down→rename→fail→rename-back.
   Is that churn acceptable for a rare path, or should we add a guard?
3. **Stale-handle correctness.** Is re-resolving via
   `nlLinkByName(newName)` before the rename-back correct, and is the
   last-resort `LinkSetUp(link)` on the stale handle safe (the handle
   still references the same ifindex even if the name is stale)?
4. **Double-fault behavior.** On rename-back failure we bring up under
   the current (new) name. Is "up-but-name-stuck" a better or worse end
   state than "down-but-recoverable"? (Plan picks "up" so traffic can
   flow; the name is wrong but the `.link` matches it.)
5. **Test seam vs. real netlink.** Is the four-var function seam the
   right test approach, or is there a preferred interface-based seam in
   this codebase that I should mirror instead?
6. **Should the error be returned at all,** given all callers only log
   it? (Yes — keeping the error lets a future caller act on it, and the
   richer message aids field debugging; but confirm no caller should now
   *abort* on it.)
