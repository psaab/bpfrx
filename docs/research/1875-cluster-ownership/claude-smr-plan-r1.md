# Claude SMR hostile plan review — #1875 r1

Reviewer: Claude (in-conversation SMR, hostile pass). Plan v1 @ c261a735e.

## Verdict: PLAN-NEEDS-REVISION (minor — all v2-addressable; mechanism choice itself is sound)

The Path A shape (advisory flock + owner metadata + reentrancy marker +
default-path hook) is the right altitude for cooperating same-host
agents, and the plan's strongest *unstated* argument for mechanism over
docs-only deserves to be stated: **convention text is context-fragile.**
MEMORY.md is explicitly only partially loaded into agent contexts (its
own header warns this), and the 2026-06-11 offender ran with the
serialization discipline already codified in memory — `deploy` simply
wasn't `smoke` in its reading. A convention that must be *in context*
to work is weaker than a hook in the default tool path. That kills
Path C for me unless Codex/AGY produce a counter-argument.

## Findings

### F1 (HIGH, must fix in v2): the `rm`-the-lock-file footgun is undocumented and unmitigated

flock locks the *inode*, not the path. If anyone removes
`/tmp/xpf-cluster.lock` while a holder is active (a plausible "stale
lock cleanup" reflex — exactly what an agent does when it believes a
lock is stuck), every subsequent acquirer opens a *new* inode and the
mutex is silently split: two "holders" both believe they own the
cluster, which is the original incident reintroduced *by the fix*.
Related: Debian systemd-tmpfiles ages /tmp — a long-idle lock file can
be unlinked by the janitor with the same effect. v2 must (a) document
NEVER deleting the lock/owner files as part of A5, (b) have the
wait-loop report include the inode (`stat -c %i`) so a split-lock is
diagnosable, and (c) consider `flock`-then-`stat`-revalidate (open,
lock, fstat vs stat path, retry on mismatch) — cheap and closes the
janitor race. (c) may be judged YAGNI; (a)+(b) are not.

### F2 (MED): reentrancy marker is not coupled to the lock path

A4's `inc()` skips locking whenever `XPF_CLUSTER_LOCK_HELD` is set, but
the marker doesn't say *which lock* the cell holds. A cell started with
`XPF_CLUSTER_LOCK=/tmp/other.lock` (the env knob A1 itself introduces)
would set the marker while holding the wrong lock, and `inc()` would
then run unserialized against `/tmp/xpf-cluster.lock` holders. Fix
options: export `XPF_CLUSTER_LOCK_HELD="$XPF_CLUSTER_LOCK"` and have
consumers honor it only when it equals their lock path; or drop the
path knob entirely (the per-host canonical path is the point —
test-mouse-latency-matrix.sh:54 hard-codes /tmp for exactly this
reason, Copilot D.1). I recommend dropping the knob: hard-code both
paths, no env indirection except the HELD marker.

### F3 (MED): wait-loop mechanics — use `flock -w N` not `flock -n` + sleep

A `flock -n` + `sleep 15` poll loop has a thundering-herd hole: all
waiters wake on release at poll granularity and acquisition order is
arbitrary across 15s windows (kernel flock has no FIFO promise either,
but a blocking/`-w` wait at least contends immediately instead of
sleeping through a free window — a 14s free-lock gap invites a
*non-cooperating* fresh process to slip in). `flock -w 15 9` in the
report loop gets both: prompt acquisition and the periodic held-by
report. Also: the owner file must be written immediately after acquire
(before any other action) or waiters report the *previous* holder for
the gap — plan already implies this but v2 should state the ordering.

### F4 (MED, adoption realism): the incident's writer may not have used `cluster-setup.sh` at all

A3 hooks `cmd_deploy`, which captures `make cluster-deploy`. But agent
deploy-iterate loops sometimes hand-roll `incus file push` + `systemctl
restart` (faster than the rolling deploy). The plan's §8 "laziest agent
is the safest" claim is only true if the lazy path is also the fast
path. v2 should add to A5 an explicit CLAUDE.md prohibition: "never
hand-roll binary pushes to the loss cluster; deploys go through
`cluster-setup.sh deploy` (it locks) or inside a `with-cluster.sh`
cell" — and acknowledge in §3 that the mechanism narrows, not closes,
the bypass surface; #1868 detection remains the backstop for
non-cooperating paths.

### F5 (LOW): Q2 answer — block by default, with loud periodic reports, no default timeout

For LLM agents the failure asymmetry is clear: a spurious abort mid-
campaign (timeout) produces retry-or-bypass behavior (worse: an agent
that bypasses the lock "just this once"); a blocking wait with a
visible `waiting for cluster lock — held by pid/purpose/since` line
every 15s is exactly the affordance an agent needs to decide to wait
or reschedule. Optional `XPF_CLUSTER_LOCK_TIMEOUT` env for callers who
want fail-fast; no default timeout.

### F6 (LOW): Q3 answer — close-fd is the right side; don't add process-group kills in v1

The 3-hour orphan-holder queue actually happened; the inverse hazard
(wrapper SIGKILLed, children continue unlocked) requires someone to
have targeted the wrapper pid specifically with SIGKILL — a SIGTERM/
SIGINT/kill-of-tree all release correctly. Cooperating-agents
assumption covers it. Process-group management adds job-control
subtleties (setsid breaks interactive Ctrl-C semantics) for a hazard
nobody has hit.

### F7 (LOW): Q5 answer — lock `create`/`destroy`, and the recovery concern is answered by F5

A stuck lock blocking recovery is a non-issue once the wait loop names
the holder and the holder is killable by the operator (never by
agents). Document the operator recovery recipe: read owner file →
`kill <pid>` (TERM) → lock releases via fd close. Never `rm` the lock
file (F1).

### F8 (LOW): Q6 answer — stay in /tmp

Same-user cooperating agents; /tmp is the existing convention and the
path is load-bearing in three shipped scripts + runbook. Moving to
/run/user/$UID would silo the lock per-user and break the (remote)
possibility of a second user coordinating. Keep /tmp, note the sticky-
bit multi-user caveat in docs, done.

### F9 (NIT): §9 dry-run matrix should also cover exit-status propagation

Add: cell command exiting 3 → `with-cluster.sh` exits 3 (under
`set -euo pipefail` in the wrapper, with the EXIT trap still removing
the owner file).

## Open question 1 (Path C sufficiency) — answered

No. Two reasons the plan should absorb: (1) context-fragility of
convention text (above); (2) the convention already failed *twice in
the same incident* — the deploy loop ignored it, and the closure
operator's "verified-quiet 15-minute window" was itself the documented
best practice and still lost the race. Detection without serialization
retries forever on a busy cluster.
