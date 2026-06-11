# Claude SMR hostile code review — PR #1878 r1 (head 280e73a6f16c)

Reviewer: Claude (in-conversation SMR). Implementation vs converged
plan docs/pr/1875-cluster-ownership/plan.md.

## Verdict: MERGE-READY (no blocking findings; 3 observations recorded)

Hostile walk, every new/changed path under `set -euo pipefail`:

- **Marker validation** (cluster-lock.sh): `${marker%:*}`/`${marker##*:}`
  split is safe for paths without colons (canonical /tmp paths);
  numeric guard precedes `kill -0`; the PPid walk regex-guards each
  hop and any failure returns 1 — degrade direction is always
  *waiting*. Verified by selftest d1-d4 (live non-ancestor, dead,
  wrong-path, garbage).
- **Wait loop**: WINDOW = min(30, remaining-timeout) — the selftest
  caught the original fixed-30s-window bug (sub-30s timeouts couldn't
  fire); the fix is correct and case (a) pins it (exit 75 at ~1s).
  WAITED accumulates across revalidation retries, which is the right
  timeout semantics.
- **Acquire sequence ordering**: flock → dev:ino revalidation →
  split-mutex probe → atomic owner write (tmp+mv) → trap → marker
  export → `"$@" 9>&-`. The reentrant path execs BEFORE any trap is
  installed, so a nested exit can never remove the outer owner file
  (selftest c pins owner survival).
- **Split-mutex probe**: aborts only when the recorded pid is alive
  AND its `/proc/<pid>/fd/9` still resolves to the recorded dev:ino —
  exactly the plan's adopted Codex/AGY r3 mechanism. Selftest g pins
  abort (70) + inode naming + post-holder reclaim. False-negative
  surface: a pre-#1875 raw-flock holder has no owner file — correctly
  reported as "no owner metadata", not aborted (raw holders contend
  via the kernel lock itself, so no split is possible unless someone
  rm'd the path, which the docs now forbid loudly).
- **Reentrancy chain live**: `cluster-setup.sh deploy all` →
  build → exec with-cluster.sh → `env XPF_CLUSTER_SKIP_BUILD=1
  cluster-setup.sh deploy all` → marker valid → suppress + rolling
  deploy — ran against the real loss cluster, lock+purpose visible,
  RC=0, both nodes at this branch's exact HEAD sha. No double build
  (the locked re-invocation skipped it — verified in the deploy log:
  single build phase).
- **ORIG_ARGS**: captured at top level from the script argv; quick
  verbs re-exec the *original* argv so `${2:-all}` defaulting is
  applied identically in the re-invocation. deploy passes the
  resolved target explicitly.
- **sg forwarding**: `"${!BPFRX_@}" "${!XPF_@}"` lists only set
  scalars; XPF_CLUSTER_LOCK/OWNER are always set post-source so the
  loop body is exercised on every sg re-exec; printf %q makes values
  shell-safe across the rebuilt command string (selftest h pins the
  boundary shape).
- **wg-interop**: `XPF_CLUSTER_LOCK="${WG_CLUSTER_LOCK}"` before
  sourcing binds the marker check to the path `inc()` actually flocks
  — one cell covers cluster-setup, apply-cos, and wg-interop because
  all three resolve to /tmp/xpf-cluster.lock. The else-branch is
  byte-identical to the previous `inc()`.
- **apply-cos-config.sh**: header sits before flag parsing, re-execs
  with the untouched `"$@"`; `$*` in the purpose string is safe under
  `set -u` with zero args.

## Observations (non-blocking)

1. A waiter that starts between a holder's flock success and its
   owner write reports the *previous* holder for <1ms. Diagnostics
   only; not worth a barrier.
2. `fuser` (psmisc) may be absent on minimal hosts — all call sites
   are `|| true`-guarded; the report degrades gracefully.
3. Selftest case (e) corrupt-owner emits a cosmetic bash "ignored
   null byte" warning on stderr; the case still proves no-crash under
   `set -e`, which is the requirement.
