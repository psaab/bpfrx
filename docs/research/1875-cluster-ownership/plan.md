# #1875 — Cluster ownership serialization for the loss userspace cluster

**Status: DRAFT v1 — pending adversarial plan review**

## 1. Status

DRAFT v1. Research-only branch `research/1875-cluster-ownership`. No
production code; this is TEST-INFRA / process hardening. PLAN-KILL or a
docs-only close are both acceptable verdicts.

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
   (the inner `flock` opens a new file description and blocks on the
   caller's own lock). Other scripts (`reverse-key-collision-probe.sh`)
   document "caller must wrap me in the flock". A third
   (`test-mouse-latency-matrix.sh`) self-locks a *different* file with
   `flock -n`. An agent cannot know which protocol a given harness
   speaks without reading it;
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
~150 lines of shell + docs. The counter-position is real: PR #1868's
`check_build_identity` already converts silent clobbers into loud,
attributable aborts, and one could argue detection suffices and
conventions cover the rest — **if reviewers conclude the shipped
identity gates + a docs codification suffice, PLAN-KILL of the
mechanism (Path C, docs-only close) is an acceptable verdict.**

Important honesty point: among *cooperating same-host agents* an
advisory lock is the entire requirement. Adversarial robustness
(lease enforcement, fencing tokens, remote-host locks) is explicitly
NOT needed and any plan drift in that direction is over-engineering.

## 4. What's already shipped (verified on master @ 9a536f810)

| Mechanism | Where | What it covers | Gap left |
|---|---|---|---|
| Advisory flock convention `/tmp/xpf-cluster.lock` | wg-interop.sh `inc()` (line 64-71, `WG_CLUSTER_LOCK` in wg-interop.env:56); comment-documented in reverse-key-collision-probe.sh:47-49; docs/wg-interop-runbook.md:49 | Serializes individual incus commands among lock-takers | Voluntary; per-command not per-cell; deploys don't take it; no holder identity |
| `check_build_identity` (PR #1868) | wg-interop.sh:240-265 — fail-closed, `-dirty`-aware, prefix-matches running `Software version: ...-g<sha>` against checkout HEAD; called at preflight, P1, and mid-wait | Detects foreign builds in-flight, names the SHA | Detection only, wg-interop-only; the run still dies; other harnesses (fairness, mouse-latency, failover) have no equivalent |
| `verify-dataplane` deploy pre-flight (#1864/#1869) | cluster-setup.sh deploy_vm (lines ~660-720) | New binary's shim verified before touching the live daemon | Protects against *bad* binaries, not *foreign* ones |
| Mouse-latency matrix mutex | test-mouse-latency-matrix.sh:54-62, `flock -n` on `/tmp/test-mouse-latency-matrix.lock` | Two matrix invocations can't interleave | Different lock file; doesn't compose with the cluster lock |
| Smoke serialization discipline | MEMORY `feedback_smoke_serialized_single_agent` | One smoke at a time via agent protocol | Memory-resident convention; the 2026-06-11 deploy loop ignored it because *deploy* isn't *smoke* |

Conclusion from the audit: detection is shipped (#1868), per-binary
safety is shipped (#1869), but **acquisition is still 100% voluntary
and the two most damaging writers — `cluster-setup.sh deploy` and
multi-minute measurement cells — have no lock integration at all.**

## 5. Concrete design — paths

### Path A (recommended): mechanism + codification

Three small pieces, one shared protocol. All shell, all in
`test/incus/`, plus docs.

**A1. Shared lock library `test/incus/cluster-lock.sh`** (sourced, not
executed). Defines:

```bash
# Env knobs (defaults): XPF_CLUSTER_LOCK=/tmp/xpf-cluster.lock
#                       XPF_CLUSTER_OWNER=/tmp/xpf-cluster.owner
# Reentrancy marker:    XPF_CLUSTER_LOCK_HELD (set while a cell holds the lock)

xpf_cluster_lock() {  # xpf_cluster_lock "<purpose>"
    # No-op when XPF_CLUSTER_LOCK_HELD is set (caller already in a cell).
    # Otherwise: exec 9>>"$XPF_CLUSTER_LOCK"; loop on flock -n 9 with a
    # held-by report every 15s sourced from the owner file:
    #   "waiting for cluster lock — held by pid 12345 (alive) since
    #    2026-06-11T12:03:11 purpose: deploy engineer/1736-wg-interop"
    # If the recorded pid is dead, say so explicitly and print
    # `fuser -v $XPF_CLUSTER_LOCK` output (the orphaned-flock-child
    # diagnostic — this exact situation cost 3 hours once).
    # On acquire: write "<pid> <iso8601> <user> <git-branch> <purpose>"
    # to $XPF_CLUSTER_OWNER, install an EXIT trap that removes it,
    # export XPF_CLUSTER_LOCK_HELD=$$.
}
```

Owner-file writes happen only while holding the lock, so they cannot
race. A SIGKILLed holder leaves a stale owner file but the kernel
releases the flock; waiters report "pid dead" and proceed — stale
metadata never blocks anyone (the lock is the mutex, the owner file is
diagnostics only).

**A2. Lock-cell wrapper `test/incus/with-cluster.sh`** (executable):

```
./test/incus/with-cluster.sh "purpose string" -- cmd args...
```

Sources A1, acquires, then runs the command with **fd 9 closed**
(`"$@" 9>&-`) so grandchildren never inherit the lock fd — killing a
cell's process tree releases the lock immediately instead of leaving a
zombie holder. Exit status of the command is propagated. This is the
standard way to make a *measurement cell* (deploy → apply-cos →
measure) atomic:

```bash
./test/incus/with-cluster.sh "1736 S2b closure" -- bash -c '
    make cluster-deploy &&
    ./test/incus/apply-cos-config.sh loss:xpf-userspace-fw0 &&
    WG_PEER_TYPE=container ./test/incus/wg-interop.sh all'
```

**A3. `cluster-setup.sh` mutating verbs self-lock.** `cmd_deploy`
sources A1 and calls `xpf_cluster_lock "deploy <branch> <target>"`
**after** the local build (the multi-minute `make build` must not hold
the lock) and before any instance is touched; same one-liner in
`start|stop|restart|create|destroy`. Read-only verbs (`status`, `logs`,
`journal`, `ssh`) stay lock-free — `ssh` is interactive and must never
hold the cluster lock. Because of the A1 reentrancy marker, a deploy
inside a `with-cluster.sh` cell does not deadlock.

**A4. `wg-interop.sh` `inc()` honors the marker** — resolves the
self-lock asymmetry:

```bash
inc() {
    local q; q=$(printf '%q ' incus "$@")
    if [[ -n "${XPF_CLUSTER_LOCK_HELD:-}" ]]; then
        sg incus-admin -c "$q"
    else
        flock "${WG_CLUSTER_LOCK}" sg incus-admin -c "$q"
    fi
}
```

Standalone invocation keeps today's per-command locking (long phases
deliberately don't hold the lock); cell invocation gets whole-run
ownership with no deadlock.

**A5. Docs codification** (the Path-C content, folded in):

- `docs/engineering-style.md` cluster-discipline section: the lock
  protocol table — *who locks what*: deploys self-lock; measurement
  cells use `with-cluster.sh`; scripts must either honor
  `XPF_CLUSTER_LOCK_HELD` or document "caller locks"; never kill
  another holder (the lock serializes you — wait or coordinate);
  `cat /tmp/xpf-cluster.owner` + `fuser -v /tmp/xpf-cluster.lock` is
  the queue-diagnosis recipe.
- `CLAUDE.md` cluster test-environment section: 3-4 lines pointing at
  the protocol (agents read CLAUDE.md, not engineering-style.md, first).
- `docs/wg-interop-runbook.md`: note the cell-mode bypass.

### Path B: ownership lease file with TTL + identity gates everywhere

A lease file (`holder, purpose, expiry`) that writers must refresh;
expired leases are stealable; every harness grows a
`check_build_identity` equivalent. **Rejected.** flock already gives
the one property a lease buys (no stale lock survives a crashed
holder — the kernel releases it) without TTL's two failure modes:
false expiry mid-long-measurement (exactly the runs we're protecting)
and clock/renewal plumbing in every harness. Identity gates everywhere
is shotgun duplication of #1868; gates *detect*, they don't *prevent*,
so runs still die. Cooperating agents don't need steal semantics.

### Path C: docs-only close

Codify A5's content and close. Cheapest, and defensible: #1868 already
makes interference loud. **Why it's not recommended:** the 2026-06-11
incident happened *with* the convention already in MEMORY and in three
script headers — the offending deploy loop used `make cluster-deploy`,
which has no lock hook, so even a perfectly obedient agent following
the documented happy path clobbers others. A convention whose default
tooling violates it is not a convention. Mechanism cost is ~150 lines
of shell. If reviewers disagree, C is the close.

### Path D: A + B hybrids

Any TTL/lease addition on top of A is over-engineering per §3. The
only B element worth keeping is already in A: holder *identity*
metadata (owner file), without TTL semantics.

## 6. Public API preservation

- `cluster-setup.sh` verb set and arguments unchanged; `make
  cluster-deploy` unchanged. Behavior delta: mutating verbs may now
  *block* (with a visible held-by report) instead of clobbering — that
  is the feature.
- `wg-interop.sh` CLI unchanged; standalone behavior byte-identical
  (the `inc()` else-branch is today's code).
- `/tmp/xpf-cluster.lock` path and meaning unchanged — existing ad-hoc
  `flock /tmp/xpf-cluster.lock sg incus-admin -c ...` one-liners keep
  working and correctly contend with the new acquirers.
- New surface: `with-cluster.sh`, `cluster-lock.sh`,
  `XPF_CLUSTER_LOCK_HELD` env contract, `/tmp/xpf-cluster.owner`.

## 7. Hidden invariants the change must preserve

1. **Lock is never held across `make build`** (multi-minute) — acquire
   after build inside `cmd_deploy`; `with-cluster.sh` users own this
   tradeoff explicitly (a cell that builds inside the cell holds the
   lock during the build, which is sometimes *wanted* for closure
   runs).
2. **`flock` fd inheritance**: `with-cluster.sh` must close fd 9 for
   the child (`9>&-`) or killing a cell leaves orphan holders — the
   exact 3-hour failure being fixed. Conversely cluster-setup.sh's
   internal acquire holds the fd for its own process lifetime, which
   is correct (deploy dies → lock released).
3. **Reentrancy is env-marked, not fd-detected** — `XPF_CLUSTER_LOCK_HELD`
   must be exported by every acquirer and honored by every nested
   acquirer, or A3+A4 deadlock inside A2 cells. This is the single
   most regression-prone invariant; the test plan covers it.
4. **Owner file is diagnostics only** — no code path may *block* on
   owner-file state (stale files must never wedge the queue).
5. **`set -euo pipefail` interaction**: the flock-wait loop and
   `kill -0` liveness probes must not trip `-e` in either consumer.
6. **sg incus-admin re-exec** (cluster-setup.sh:41-50) happens before
   command dispatch; the lock acquire must live *after* the re-exec so
   the lock fd isn't dropped across `exec sg`.
7. **Remote-host reality**: the lock is host-local on the dev box; all
   agents drive `loss:` from this box, so /tmp is the correct shared
   namespace. Document that driving the cluster from a second machine
   bypasses everything (out of scope, cooperating-agents assumption).

## 8. Risk assessment

| Class | Level | Notes |
|---|---|---|
| Behavioral regression | LOW | Worst credible bug: a deadlock (self-wait) from a missed reentrancy marker — caught by the dry-run matrix in §9; recoverable by killing own process. No dataplane code touched. |
| Lifetime/borrow-checker | N/A | Shell + docs only. |
| Performance regression | LOW | Deploys may queue behind a measurement cell — intended. Risk of a *hung* holder blocking everyone: mitigated by holder report + liveness flag; operator decides (never auto-steal). |
| Architectural mismatch | LOW-MED | The honest hazard is *adoption*: a mechanism nobody invokes is Path C with extra files. Mitigated by hooking the default path (`make cluster-deploy` → `cmd_deploy` self-locks) so the laziest agent is the safest one. |

## 9. Test plan

No cluster traffic is required to validate this (the mechanism is
host-local shell), but one live guarded deploy proves the end-to-end
path:

1. `bash -n` + `shellcheck` (if available) on all touched scripts.
2. **Dry-run contention matrix on /tmp** (no cluster): (a) cell A holds
   via `with-cluster.sh "A" -- sleep 30`; cell B blocks and prints A's
   pid/purpose/timestamp; (b) `kill -9` cell A's tree → B acquires
   within one poll interval (orphan-release proof); (c) nested
   `with-cluster.sh` inside a cell runs immediately (reentrancy);
   (d) `cluster-setup.sh`-style internal acquire inside a cell does
   not deadlock (env marker honored); (e) stale owner file + free lock
   → acquire proceeds, reports stale pid.
3. `wg-interop.sh` standalone smoke of `inc()` (a read-only `inc info`
   path) with and without `XPF_CLUSTER_LOCK_HELD` set.
4. ONE live guarded `cluster-setup.sh deploy` on the loss userspace
   cluster under the new self-lock (the lock serializes against any
   concurrent holder — wait, never kill), followed by
   `./test/incus/apply-cos-config.sh loss:xpf-userspace-fw0` (deploy
   wipes CoS) and the standard iperf3 sanity check.
5. No Go/Rust changes expected; if any land, `go build ./...`.

## 10. Out of scope (explicitly)

- Per-harness `check_build_identity` rollout to fairness/mouse-latency
  scripts (worthy follow-up; detection layer, separable).
- Cross-host locking, lease/steal semantics, CI enforcement.
- Retrofitting every existing script to take cells automatically —
  only `cluster-setup.sh` (the universal writer) and `wg-interop.sh`
  (the asymmetry exemplar) change; others adopt via docs + the helper.
- The smoke-runner agent-protocol (`feedback_smoke_serialized_single_agent`)
  — unchanged; this is the OS-level backstop beneath it.

## 11. Open questions for adversarial review

1. **Is Path C actually sufficient?** #1868 detection + codified
   convention, zero new mechanism. If you believe agents will follow a
   documented `with-cluster`-style convention without the default
   `make cluster-deploy` path enforcing it — argue it and this becomes
   a docs PR + close. PLAN-KILL of the mechanism is acceptable.
2. **Blocking vs fail-fast default for deploy:** A3 blocks (with
   report). Should deploy instead `flock -w 1800` and abort loudly, so
   an unattended agent doesn't silently queue for hours? Which failure
   mode is worse for LLM agents — invisible queueing or spurious abort?
3. **fd-close tradeoff (A2):** closing fd 9 for the cell's children
   means a SIGKILL of *only* the wrapper (children surviving) releases
   the lock while the cell's commands still run. Keeping the fd open
   inverts it (orphan holders, the 3-hour bug). Is close-fd the right
   side, or should the wrapper run the cell in a new process group and
   kill it on exit-trap to close both holes?
4. **Reentrancy via env** can leak: a cell that backgrounds a daemonish
   child leaves `XPF_CLUSTER_LOCK_HELD` set in its environment forever,
   letting that child later skip locking. Acceptable for cooperating
   agents, or does the marker need the holder pid + liveness check
   (`XPF_CLUSTER_LOCK_HELD=<pid>` honored only if that pid is alive and
   an ancestor)?
5. **Should `create`/`destroy` lock at all?** They're rare,
   catastrophic-if-raced, but also the verbs an operator runs when the
   cluster is already broken — a stuck lock could block recovery.
   Lock, or document-only?
6. **Owner-file location/permissions:** /tmp, single-user assumption
   (all agents run as `ps`). Any reason to prefer `/run/user/$UID` or
   per-lock `chmod` hygiene given the multi-user /tmp sticky bit?
