# #1875 — Cluster ownership serialization for the loss userspace cluster

**Status: DRAFT v2 — revised after r1 (Codex task-mqa0tpqd-em6hzd,
AGY adversarial-review-mqa0rv7z-t9pfyg, Claude SMR — all three
PLAN-NEEDS-REVISION on v1, all three endorsing Path A direction and
rejecting Path C). Pending r2 convergence.**

## 1. Status

DRAFT v2. Research-only branch `research/1875-cluster-ownership`. No
production code; this is TEST-INFRA / process hardening. PLAN-KILL or a
docs-only close remain acceptable verdicts, though all three r1
reviewers independently answered §11 Q1 "Path C is not sufficient".

## 2. Issue framing

During the 2026-06-11 multi-agent session, the #1736 S2b closure run on
`loss:xpf-userspace-fw{0,1}` was repeatedly destroyed by a concurrent
agent's deploy-iterate loop: `/usr/local/sbin/{xpfd,xpf-userspace-dp}`
were replaced and xpfd restarted at ~5-10 minute cadence. Consequences
observed live (issue body):

- Two "deterministic wedge on PR head" diagnosis runs actually executed
  a foreign `g7b076ee2e` build — hours spent chasing a stale-binary
  artifact presented as an engine bug.
- A closure attempt with a verified-quiet 15-minute window still lost
  the race to a mid-phase foreign deploy (caught only because PR #1868
  had just added `check_build_identity`).
- Every foreign restart flipped VRRP mastership and wiped CoS.

Root cause is structural, not behavioral: the project has an advisory
`/tmp/xpf-cluster.lock` flock convention, but

1. **nothing forces deploys to take it** — `cluster-setup.sh deploy`
   (and the `make cluster-deploy` alias every agent uses) touches the
   cluster lock-free;
2. **the convention is per-command**, so a multi-minute measurement
   phase is a sieve: each individual `incus` call is serialized but the
   *cell* (deploy → apply-cos → measure) is not;
3. **lock-usage is asymmetric across scripts**: `wg-interop.sh`
   self-locks per cluster command inside `inc()` (wg-interop.sh:64-71),
   so outer-wrapping it in `flock /tmp/xpf-cluster.lock` **deadlocks**
   (the inner `flock` opens a new open file description and blocks on
   the caller's own lock — Codex r1 reproduced this locally). Other
   scripts (`reverse-key-collision-probe.sh:47`) document "caller must
   wrap me in the flock". A third (`test-mouse-latency-matrix.sh:54`)
   self-locks a *different* file with `flock -n`. An agent cannot know
   which protocol a given harness speaks without reading it;
4. **lock holders are invisible**: a bare `flock` wait gives no
   holder identity; in a prior session a killed flocked pipeline left
   an orphaned child holding the inherited lock fd and the queue
   behind it was undiagnosable for ~3 hours.

## 3. Honest scope/value framing

This is process/test-infra work. Zero packets, zero production code.
The win is measured in *operator-days not wasted*: the 2026-06-11
incident burned most of a day on a misdiagnosed "wedge" plus a failed
closure run, and the same clobber class has recurred across the
fairness campaigns (deploy wipes CoS mid-measurement). The cost is
~200 lines of shell + docs. The counter-position was put to all three
r1 reviewers — PR #1868's `check_build_identity` already converts
silent clobbers into loud, attributable aborts; maybe detection +
codified convention suffices — and all three rejected it (§11 Q1):
the convention already existed in three script headers and MEMORY when
the incident happened, the *default tooling path* (`make
cluster-deploy` → lock-free `cmd_deploy`, Makefile:211 →
cluster-setup.sh:580) violates it, and convention text is
context-fragile for LLM agents (MEMORY.md is only partially loaded —
its own header warns so). Detection without serialization retries
forever on a busy cluster.

Honesty boundary, unchanged from v1: among *cooperating same-host
agents* an advisory lock is the entire requirement. Adversarial
robustness (fencing, leases, cross-host coordination) is explicitly
NOT needed and plan drift in that direction is over-engineering. The
mechanism *narrows* the bypass surface (a hand-rolled `incus file
push` loop still bypasses it); #1868 detection remains the backstop
for non-cooperating paths, and A5 adds an explicit CLAUDE.md
prohibition on hand-rolled binary pushes.

## 4. What's already shipped (verified on master @ 9a536f810)

| Mechanism | Where | What it covers | Gap left |
|---|---|---|---|
| Advisory flock convention `/tmp/xpf-cluster.lock` | wg-interop.sh `inc()` (lines 64-71, `WG_CLUSTER_LOCK` in wg-interop.env:56); comment-documented in reverse-key-collision-probe.sh:47-49; docs/wg-interop-runbook.md:49 | Serializes individual incus commands among lock-takers | Voluntary; per-command not per-cell; deploys don't take it; no holder identity |
| `check_build_identity` (PR #1868) | wg-interop.sh:240-265 — fail-closed, `-dirty`-aware, prefix-matches running `Software version: ...-g<sha>` against checkout HEAD; called at preflight, P1, and mid-wait | Detects foreign builds in-flight, names the SHA | Detection only, wg-interop-only; the run still dies; other harnesses have no equivalent |
| `verify-dataplane` deploy pre-flight (#1864/#1869) | cluster-setup.sh deploy_vm (~lines 660-720) | New binary's shim verified before touching the live daemon | Protects against *bad* binaries, not *foreign* ones |
| Mouse-latency matrix mutex | test-mouse-latency-matrix.sh:54-62, `flock -n` on `/tmp/test-mouse-latency-matrix.lock` | Two matrix invocations can't interleave | Different lock file; doesn't compose with the cluster lock |
| Smoke serialization discipline | MEMORY `feedback_smoke_serialized_single_agent` | One smoke at a time via agent protocol | Memory-resident convention; the 2026-06-11 deploy loop ignored it because *deploy* isn't *smoke* |

Conclusion: detection is shipped (#1868), per-binary safety is shipped
(#1869), but **acquisition is still 100% voluntary and the two most
damaging writers — `cluster-setup.sh deploy` and multi-minute
measurement cells — have no lock integration at all.**

## 5. Concrete design — paths

### Path A (recommended, revised in v2): one acquire point + codification

The v1 shape had two independent acquire implementations (with-cluster
wrapper + in-process acquire in cluster-setup.sh). r1 killed the
in-process variant twice over: Codex F2 showed `deploy_vm`'s many
post-acquire `incus` children (cluster-setup.sh:674, :734, :743)
inherit the lock fd, so a killed deploy shell leaves an `incus` child
as a zombie holder — the exact 3-hour bug; AGY showed sourced-library
EXIT traps clobber consumer traps and double-release owner metadata
from bypassed nested acquires. **v2 therefore has exactly ONE process
that ever holds the lock: `with-cluster.sh`.** Everything else either
re-execs through it or honors its reentrancy marker.

**A1. Shared helper library `test/incus/cluster-lock.sh`** (sourced).
Canonical paths are hard-coded defaults (`/tmp/xpf-cluster.lock`,
`/tmp/xpf-cluster.owner`); `XPF_CLUSTER_LOCK`/`XPF_CLUSTER_OWNER` env
overrides exist for the dry-run test matrix only. Provides two
functions, installs no traps, has no global side effects:

- `xpf_cluster_lock_held()` — returns 0 iff the reentrancy marker is
  valid **for this lock path**. Marker format (Codex F4 + AGY §3 + SMR
  F2 converged): `XPF_CLUSTER_LOCK_HELD="<lockpath>:<holderpid>"`.
  Valid iff: lockpath component equals this consumer's lock path, AND
  holderpid is numeric, alive (`kill -0` inside a guarded
  conditional), AND an ancestor of the current process (PPid walk via
  `/proc/<pid>/status`, AGY's `is_lock_holder_ancestor` sketch —
  closes the backgrounded-daemon env-leak false-skip). On any parse
  failure: returns 1 (treat as not held; worst case is a blocking
  wait, never an unserialized run).
- `xpf_cluster_owner_report()` — diagnostics-only, `set -e`-safe by
  construction (AGY §4: `owner=$(cat "$OWNER" 2>/dev/null || true)`,
  here-string `read -r`, regex-guard pid before `kill -0`,
  `fuser -v "$LOCK" 2>&1 || true`). Reports holder pid + liveness +
  user + branch + purpose + acquire timestamp + **lock-path inode**
  (`stat -c %i`, SMR F1: makes a split-lock from a deleted/recreated
  lock file diagnosable). A dead recorded pid prints an explicit
  orphan/SIGKILL diagnosis line with the fuser output.

**A2. Lock-cell wrapper `test/incus/with-cluster.sh`** (executable —
the single acquire point):

```
./test/incus/with-cluster.sh "purpose string" -- cmd args...
```

Acquire sequence (all r1 mechanics findings folded in):
1. If `xpf_cluster_lock_held` → exec the command directly (reentrant
   cell-in-cell; no trap installed, no owner write — AGY's
   acquired-only-trap rule).
2. `exec 9>>"$LOCK"` (append — never truncate; 0666 best-effort on
   create), then a wait loop of `flock -w 30 9` iterations (SMR F3:
   contends immediately instead of sleeping through free windows);
   between iterations print `xpf_cluster_owner_report` to stderr.
   Default: wait forever (§11 Q2 resolution, 2-of-3 reviewers);
   `XPF_CLUSTER_LOCK_TIMEOUT=<s>` opts into a bounded wait that aborts
   loudly with the holder report.
3. Post-acquire inode revalidation (SMR F1): `stat -c %i` of the path
   vs `stat -L -c %i /proc/$$/fd/9`; mismatch (file unlinked/replaced
   between open and lock — agent "cleanup" reflex or systemd-tmpfiles
   /tmp aging) → close fd, reopen, retry.
4. Atomic owner write: temp file + `mv` onto `$OWNER` containing
   `<pid> <iso8601> <user> <git-branch> <purpose>`; EXIT trap (own
   dedicated process, nothing to clobber) removes it.
5. `export XPF_CLUSTER_LOCK_HELD="$LOCK:$$"`, then run the command
   with **fd 9 closed** (`"$@" 9>&-`) so no child or grandchild ever
   inherits the lock fd — killing a cell's process tree releases the
   lock immediately (AGY §1B verified the mechanics incl. subshells).
   Exit status is captured (`rc=0; "$@" 9>&- || rc=$?`) and propagated
   after the trap-driven owner cleanup.

No process-group management in v1 (§11 Q3 resolution, Codex + SMR;
AGY's `trap 'kill -TERM -$$' EXIT` counter-proposal is unsound as
written — `with-cluster.sh` is not a process-group leader, so `-$$`
would signal the *caller's* group including the invoking agent shell).

Standard measurement-cell usage:

```bash
./test/incus/with-cluster.sh "1736 S2b closure" -- bash -c '
    make cluster-deploy &&
    ./test/incus/apply-cos-config.sh loss:xpf-userspace-fw0 &&
    WG_PEER_TYPE=container ./test/incus/wg-interop.sh all'
```

**A3. `cluster-setup.sh` mutating verbs re-exec through A2.**
Mutating verbs are `deploy`, `start`, `stop`, `restart`, `create`,
`destroy`, **and `init`** (Codex F5: `cmd_init` creates/deletes
networks and profiles, cluster-setup.sh:199/:205/:234). Dispatch shape:

```bash
# inside cmd_deploy, after the local make build (the multi-minute
# build must never hold the lock):
if ! xpf_cluster_lock_held; then
    exec "$SCRIPT_DIR/with-cluster.sh" \
        "cluster-setup deploy ${target} ($(git -C "$PROJECT_ROOT" rev-parse --abbrev-ref HEAD 2>/dev/null || echo '?'))" \
        -- env XPF_CLUSTER_SKIP_BUILD=1 "$0" deploy "$target"
fi
# reentrant path continues into deploy_vm / deploy_rolling
```

`XPF_CLUSTER_SKIP_BUILD=1` makes the re-invoked `cmd_deploy` skip the
already-done build. The re-exec gives the fd-close-for-children
property to the whole deploy for free (Codex F2 resolved), installs
zero traps in cluster-setup.sh (AGY trap-clobber resolved), and the
marker makes the nested invocation lock-free. The quick verbs
(start/stop/restart/create/destroy/init) re-exec the same way without
the skip-build env. Read-only verbs (`status`, `logs`, `journal`,
`ssh`) stay lock-free — `ssh` is interactive and must never hold the
cluster lock. `BPFRX_CLUSTER_ENV` and the rest of the caller env pass
through `with-cluster.sh` untouched (it adds exactly one variable).
The marker must survive both the `exec sg incus-admin -c` re-exec at
cluster-setup.sh:41-50 (sg preserves exported env) and the
`with-cluster.sh` boundary; the dry-run matrix proves it (§9.2d)
rather than assuming it.

**A4. `wg-interop.sh` `inc()` honors the marker** — resolves the
self-lock asymmetry:

```bash
inc() {
    local q; q=$(printf '%q ' incus "$@")
    if xpf_cluster_lock_held; then
        sg incus-admin -c "$q"
    else
        flock "${WG_CLUSTER_LOCK}" sg incus-admin -c "$q"
    fi
}
```

Standalone invocation keeps today's per-command locking byte-for-byte
(the else-branch is today's code); cell invocation gets whole-run
ownership with no deadlock.

**A5. Docs codification** (the Path-C content, folded in):

- `docs/engineering-style.md` cluster-discipline section — the lock
  protocol table (*who locks what*): deploys self-lock via re-exec;
  measurement cells use `with-cluster.sh`; scripts must either honor
  the marker via `cluster-lock.sh` or document "caller locks"; never
  kill another holder (the lock serializes you — wait or coordinate);
  **never `rm` the lock or owner files** (SMR F1: flock binds the
  inode — deleting the path silently splits the mutex, reintroducing
  the incident; recovery is `kill <holder-pid>`, never `rm`); queue
  diagnosis recipe: `cat /tmp/xpf-cluster.owner` + `fuser -v
  /tmp/xpf-cluster.lock`.
- **Raw outer-flock one-liners are deprecated for self-locking verbs**
  (Codex F3): `flock /tmp/xpf-cluster.lock bash -c "make
  cluster-deploy"` now self-waits (the inner re-exec can't see a raw
  caller's lock). Update the two places that teach the raw pattern —
  reverse-key-collision-probe.sh:47-49 comment and
  docs/wg-interop-runbook.md:49 — to point at `with-cluster.sh`. Raw
  per-command flock around *non-self-locking* commands (plain `incus
  exec` one-liners) remains valid and contends correctly.
- `CLAUDE.md` cluster test-environment section: 3-4 lines — use
  `with-cluster.sh` for any multi-command cluster work; deploys
  self-lock and may visibly queue; **never hand-roll `incus file
  push` binary deploys to the loss cluster** (SMR F4); never kill
  other holders; never rm the lock file.
- `docs/wg-interop-runbook.md`: note the cell-mode marker bypass.

### Path B: ownership lease file with TTL + identity gates everywhere

Rejected (unchanged from v1, unchallenged in r1). flock already gives
the one property a lease buys — no stale lock survives a crashed
holder — without TTL's false-expiry hazard mid-long-measurement and
renewal plumbing in every harness. Identity gates everywhere is
shotgun duplication of #1868; gates detect, they don't prevent.
Cooperating agents don't need steal semantics.

### Path C: docs-only close

Rejected by all three r1 reviewers independently (Codex: "the
convention already exists ... while `make cluster-deploy` still
reaches lock-free `cmd_deploy` today"; AGY: "a convention that is not
enforced by the default tooling is not a convention"; SMR: convention
text is context-fragile — MEMORY.md partial loading). Kept here as the
documented kill-path: if r2 reverses, A5 ships alone and the issue
closes.

### Path D: A + B hybrids

Any TTL/lease addition on top of A remains over-engineering per §3.
The only B element worth keeping is already in A: holder *identity*
metadata (owner file), without TTL semantics.

## 6. Public API preservation

- `cluster-setup.sh` verb set and arguments unchanged; `make
  cluster-deploy` unchanged. Behavior delta: mutating verbs may now
  *block* (with a visible held-by report on stderr) instead of
  clobbering — that is the feature. Internal-only addition:
  `XPF_CLUSTER_SKIP_BUILD` env.
- `wg-interop.sh` CLI unchanged; standalone behavior byte-identical.
- `/tmp/xpf-cluster.lock` path and meaning unchanged. Existing raw
  per-command `flock /tmp/xpf-cluster.lock <non-self-locking-cmd>`
  one-liners keep working and contend correctly with the new
  acquirers. **Exception (breaking, deliberate, documented):** raw
  *outer-wrapping of the now-self-locking verbs* self-waits; A5
  updates the two in-tree teachers of that pattern (Codex F3).
- New surface: `with-cluster.sh`, `cluster-lock.sh`, the
  `XPF_CLUSTER_LOCK_HELD=<lockpath>:<pid>` marker contract,
  `/tmp/xpf-cluster.owner`. Lock/owner files created 0666 best-effort
  (AGY Q6: lets a second cooperating user contend on the same lock
  under /tmp's sticky bit).

## 7. Hidden invariants the change must preserve

1. **Lock is never held across `make build`** — `cmd_deploy` builds
   first, then re-execs into the lock. A cell that builds *inside*
   `with-cluster.sh` holds the lock during the build; that is the
   caller's explicit choice (sometimes wanted for closure runs).
2. **Exactly one process ever holds the lock fd** (`with-cluster.sh`),
   and it runs its child with fd 9 closed. No other script may
   `exec 9>>` the canonical lock. This single invariant subsumes v1's
   fd-inheritance hazards and makes kill-the-tree equal
   release-the-lock (Codex F2).
3. **Marker validity is path+pid+ancestry, never a bare boolean**
   (Codex F4, AGY §3, SMR F2). Any validation failure degrades to
   *waiting*, never to *skipping*.
4. **Owner file is diagnostics only** — no code path may block on
   owner-file state; all reads are `set -e`-tolerant (AGY §4A/§4C);
   writes are atomic (tmp+mv) and happen only while holding the lock;
   only the acquiring process installs the cleanup trap (AGY §2).
5. **`set -euo pipefail` discipline is a testable requirement, not a
   warning** (Codex F6): §9.2 exercises stale-owner, corrupt-owner,
   absent-owner, and dead-pid paths under `set -euo pipefail`.
6. **sg re-exec transparency**: the marker must survive
   `exec sg incus-admin -c` (cluster-setup.sh:41-50) — exported env
   does; proven by §9.2d rather than assumed.
7. **Append-only open of the lock file; never truncate, never rm**
   (SMR F1) — inode identity is the mutex; post-acquire inode
   revalidation closes the unlink race.
8. **Remote-host reality**: the lock is host-local on the dev box; all
   agents drive `loss:` from this box, so /tmp is the correct shared
   namespace. Driving the cluster from a second machine bypasses
   everything (documented, out of scope, cooperating-agents
   assumption).

## 8. Risk assessment

| Class | Level | Notes |
|---|---|---|
| Behavioral regression | LOW | Worst credible bug: a deadlock (self-wait) from a marker-validation bug — caught by the §9.2 matrix; recoverable by killing own process; degraded mode is *waiting*, never unserialized clobbering. No dataplane code touched. |
| Lifetime/borrow-checker | N/A | Shell + docs only. |
| Performance regression | LOW | Deploys may queue behind a measurement cell — intended. A hung holder blocking everyone is mitigated by the named-holder report + liveness flag; operator decides (never auto-steal, no force-bypass env — a bypass flag is exactly what an impatient agent would reach for). |
| Architectural mismatch | LOW-MED | The honest hazard is *adoption*: hand-rolled deploy loops bypass the hook (SMR F4). Mitigated three ways: the default path (`make cluster-deploy`) is the safe path; CLAUDE.md prohibits hand-rolled pushes; #1868 detection backstops non-cooperators. Residual risk accepted and documented. |

## 9. Test plan

1. `bash -n` on all touched scripts; `shellcheck` if available.
2. **Dry-run contention matrix on /tmp** (no cluster, overridden lock
   path), all under `set -euo pipefail`:
   (a) cell A holds via `with-cluster.sh "A" -- sleep 30`; cell B
   blocks and prints A's pid/purpose/timestamp/inode;
   (b) `kill -9` cell A's whole tree → B acquires within one `flock
   -w` window (orphan-release proof);
   (c) nested `with-cluster.sh` inside a cell runs immediately
   (reentrancy), installs no second trap, and does NOT remove the
   owner file on exit (AGY double-release check: owner file still
   present until the outer cell exits);
   (d) marker survives an env-preserving re-exec and a `bash -c`
   boundary; a *forged/stale* marker (live but non-ancestor pid; dead
   pid; mismatched lock path) is rejected → acquire proceeds normally;
   (e) stale owner file + free lock → acquire proceeds, report flags
   dead pid; corrupt/empty owner file → no crash under `set -e`;
   (f) exit-status propagation: cell command exiting 3 →
   `with-cluster.sh` exits 3, owner file removed (SMR F9);
   (g) unlink race: delete the lock file while A holds → a new
   acquirer's inode revalidation prevents a silent split (it must
   never report acquired on a different inode without flagging the
   split in its report);
   (h) `XPF_CLUSTER_LOCK_TIMEOUT=5` against a held lock → loud abort
   with holder report, non-zero exit.
3. `wg-interop.sh` `inc()` smoke (read-only `inc info` path) with and
   without a valid marker.
4. ONE live guarded `cluster-setup.sh deploy` on the loss userspace
   cluster through the new re-exec path (the lock serializes against
   any concurrent holder — wait, never kill), followed by
   `./test/incus/apply-cos-config.sh loss:xpf-userspace-fw0` (deploy
   wipes CoS) and the standard iperf3 sanity check.
5. No Go/Rust changes expected; if any land, `go build ./...`.

## 10. Out of scope (explicitly)

- Per-harness `check_build_identity` rollout to fairness/mouse-latency
  scripts (worthy follow-up; detection layer, separable).
- Cross-host locking, lease/steal semantics, CI enforcement,
  force-bypass escape hatches.
- Process-group/session management in `with-cluster.sh` (v2 keeps
  close-fd only; revisit only if the wrapper-SIGKILL-children-survive
  edge is ever actually hit).
- Retrofitting every existing script to take cells automatically —
  only `cluster-setup.sh` (the universal writer) and `wg-interop.sh`
  (the asymmetry exemplar) change; others adopt via docs + the helper.
- The smoke-runner agent-protocol (`feedback_smoke_serialized_single_agent`)
  — unchanged; this mechanism is the OS-level backstop beneath it.

## 11. r1 open questions — resolutions (for r2 ratification)

1. **Path C sufficiency** — NO, 3-of-3 (Codex: default path reaches
   lock-free `cmd_deploy` today; AGY: unenforced convention is not a
   convention; SMR: context-fragility + the convention failed twice in
   the same incident).
2. **Blocking vs fail-fast deploy** — block by default with periodic
   held-by reports; optional `XPF_CLUSTER_LOCK_TIMEOUT`. 2-of-3
   (Codex + SMR); AGY preferred `flock -w 300` fail-fast. Rationale
   for overriding AGY: a measurement cell legitimately holds for
   25-40 min, so any short default timeout makes spurious aborts the
   *common* case, and an aborting deploy invites exactly the
   lock-bypass retry behavior the mechanism exists to prevent; the
   periodic stderr report is the agent-visible affordance AGY's
   timeout was reaching for. r2 AGY: please re-judge this specific
   trade with the 25-40 min cell duration in evidence.
3. **fd-close tradeoff** — close-fd, no process-group kill in v1
   (Codex + SMR; AGY's `kill -TERM -$$` is unsound as written — see
   A2 note).
4. **Marker hardening** — adopted beyond Codex's stated minimum:
   path-bound `<lockpath>:<pid>` + liveness + ancestor walk (AGY §3
   leak scenario judged real; the check is ~12 lines and failure
   degrades to waiting, never skipping).
5. **create/destroy/init locking** — lock all three (Codex found
   `init` missing in v1). No `XPF_CLUSTER_FORCE` bypass (AGY's
   suggestion declined: the named-holder report + `kill <pid>` is the
   operator recovery path; a bypass env is an attractive nuisance for
   agents).
6. **Location/permissions** — /tmp retained (path is load-bearing in
   three shipped scripts + runbook); 0666 best-effort creation (AGY);
   never-rm rule + inode report (SMR F1).

## 12. Remaining open questions for r2

1. Is the post-acquire inode revalidation (A2 step 3) worth its ~6
   lines, or is the never-rm doc rule + inode-in-report sufficient
   (the systemd-tmpfiles /tmp-aging race is real but slow)?
2. Does the `cmd_deploy` re-exec (`exec with-cluster.sh ... -- env
   XPF_CLUSTER_SKIP_BUILD=1 "$0" deploy ...`) have a hole the §9.2
   matrix misses — e.g. argument re-quoting through the re-dispatch,
   or `BPFRX_CLUSTER_ENV` interaction with the sg re-exec path?
3. Is deprecating raw outer-flock of self-locking verbs (A5/Codex F3)
   acceptable, or does muscle-memory need a compat shim (e.g.
   detecting a caller-held flock via `flock -n` probe — rejected so
   far as unreliable: a free-at-probe-time lock proves nothing)?
4. Any reviewer counter-example where two cooperating processes both
   end up holding the canonical lock under this design?
