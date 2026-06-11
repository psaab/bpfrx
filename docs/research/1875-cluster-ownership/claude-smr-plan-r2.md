# Claude SMR hostile plan review — #1875 r2

Reviewer: Claude (in-conversation SMR, hostile pass). Plan v2 @ a0cedf04f1fc.

## Verdict: PLAN-NEEDS-REVISION (two concrete v3 amendments; design shape ratified)

The v2 single-acquire-point restructure resolves my r1 F1-F4 and the
Codex/AGY r1 structural findings cleanly. Hostile re-derivation of the
deadlock matrix and the two-holders question found one REQUIRED
amendment and one RECOMMENDED amendment.

## S1 (REQUIRED): the sg re-exec can strip the marker → deadlock inside a cell

Scenario: an agent shell NOT yet in incus-admin group context runs a
cell — `with-cluster.sh "cell" -- bash -c 'make cluster-deploy ...'`.
The cell holds the lock and exports the marker. The inner
`cluster-setup.sh` hits the group re-exec at cluster-setup.sh:41-50:
`exec sg incus-admin -c "${local_env}$(printf '%q ' "$0" "$@")"` —
and `local_env` deliberately re-injects ONLY `BPFRX_CLUSTER_ENV`. That
explicit re-injection exists precisely because the author did not
trust `sg` to preserve arbitrary env. If `sg` drops or resets
`XPF_CLUSTER_LOCK_HELD` on any platform/config (shadow-utils variants
differ on env handling), the re-exec'd `cmd_deploy` sees no marker →
re-execs into `with-cluster.sh` → blocks forever on the lock its own
ancestor cell holds. This is a *deadlock inside the happy path* and
the §9.2 matrix as written would not catch it (the matrix tests an
"env-preserving re-exec", assuming the property under test).

Fix (cheap, mirrors existing code): the sg re-exec's `local_env`
prefix must also forward `XPF_CLUSTER_LOCK_HELD` (printf %q, only when
set), exactly as it does `BPFRX_CLUSTER_ENV`. §9.2d must test the
marker surviving the *actual* `sg incus-admin -c` path on the dev box,
not a simulated env-preserving exec.

## S2 (RECOMMENDED): two-holders counter-example exists; detect the split at acquire time

§12 Q4 asked for a counter-example — here it is. Holder A acquires on
inode I. Someone (agent cleanup reflex, tmpfiles aging) `rm`s the lock
path; a new acquirer B does `exec 9>>` creating inode J, flocks J
successfully, and v2's post-acquire inode revalidation PASSES — path
and fd both resolve to J. A and B now both believe they own the
cluster. The never-rm doc rule is the primary mitigation but is
exactly the kind of convention this plan argues is fragile.

Cheap structural detection: record the **lock inode** in the owner
file (A wrote `... inode=I`). B's acquire-time check: if the owner
file names a LIVE pid with a lock inode ≠ B's own fd inode, the mutex
has been split — fail closed with the split-mutex diagnosis (mirrors
the #1868 fail-closed philosophy). This sharpens invariant 4: the
owner file stays non-blocking for *waiting* diagnostics, but acquire
gains one fail-closed integrity assertion. False-positive surface
(stale owner + recycled pid) is rare and self-heals when the recycled
pid exits; the failure direction is refuse-to-run, never
clobber. §9.2g then becomes concretely testable: rm-while-held → B
aborts naming both inodes.

## Ratifications (hostile re-check, no findings)

- Re-exec argv handling: `exec with-cluster.sh "purpose" -- env
  XPF_CLUSTER_SKIP_BUILD=1 "$0" deploy "$target"` passes argv as an
  array end-to-end; no re-quoting hole provided `with-cluster.sh`
  runs `"$@"` directly (must be a stated implementation requirement,
  not `bash -c "$*"`).
- Marker ancestry: with-cluster.sh runs the cell as a *child* (not
  exec), so the recorded pid stays alive as the fd-9 holder for the
  cell's lifetime; A3's exec-into-wrapper preserves the pid for the
  nested case. Reparenting of disowned background children breaks
  ancestry → degrades to waiting, never skipping. Correct direction.
- Double-build: `XPF_CLUSTER_SKIP_BUILD` is `env`-scoped to the
  re-invocation, not exported into the cell. No leak.
- AGY r1 fail-fast override (§11.2): I re-judged with the 25-40 min
  cell duration — blocking + periodic stderr reports remains right;
  a 300s default timeout makes spurious aborts the common case.

## §12 answers

1. Inode revalidation: KEEP, and extend per S2 (owner-recorded inode)
   — together they close both halves of the unlink race.
2. Re-exec holes: S1 is the hole (sg env stripping). Argument
   re-quoting is clean per ratification above.
3. Raw outer-flock deprecation: acceptable, no compat shim; a
   `flock -n` probe shim is unsound (free-at-probe proves nothing) —
   reject permanently.
4. Two-holders: YES under rm-while-held (S2); with S2 + never-rm doc
   the design fails closed instead.
