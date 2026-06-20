# Plan: #2006 — group pkg/vrrp flat files into manager/instance/packet/track

> **Recommendation: PLAN-READY (in-package, RESIDUAL-ONLY) — or NO-OP / close.**
> The core of #2006 (the `track.go` extraction) is **already on master**
> (commits `a40b1f747`, `a1037fc48`, both titled `#2006: ...`). The four-file
> layout the issue proposes already exists. Subpackaging (`pkg/vrrp/manager/`,
> `pkg/vrrp/instance/`, ...) is **infeasible** — it hits the Go method-receiver /
> import-cycle wall, the same class of wall that PLAN-KILLED #2002/#2004.
> The only remaining *optional* in-package code-motion is moving the three
> socket-open helpers (~150 LOC) out of `manager.go` into a `socket.go` file.
> That is a pure file rename within `package vrrp` (zero import-graph change),
> so it is safe — but the value is marginal and the issue may simply be closed
> as substantially-done. This plan covers both dispositions.

Branch: `research/2006-vrrp-grouping`
Base: `origin/master` @ `9979a89a0` (worktree HEAD). Issue LOC were verified at
`b1ef3ed16`; master has since drifted — see §2.

---

## 1. Problem statement / scope

The issue (agy-review-013 Part II.5) asks to group the flat `pkg/vrrp/` files
into logical sub-modules so the subsystem's four concerns are separated:

```
pkg/vrrp/
  manager.go    # redundancy-group coordinator
  instance.go   # state machine, promotions/demotions
  packet.go     # V2/V3 advert parser/builder/checksums
  track.go      # interface link/route trackers
```

It is explicitly **behavior-preserving code motion only** and **SENSITIVE**:
VRRP is failover code. The 30ms RETH advert timing, NODAD, async GARP burst,
priority-cost demotion clamp [1,254], and owner-255 exemption must be preserved
exactly.

**Two sub-questions this plan must resolve (per the research brief):**

1. **Subpackages or in-package?** Does the issue want files moved into NEW Go
   packages (`pkg/vrrp/manager/`, etc.), which would risk the import-cycle wall
   that just plan-killed #2002/#2004? Or grouping within the SAME `package vrrp`
   (file renames only, no new package boundary, like the #1699 in-package
   split)?  →  **Resolved in §4. The issue means in-package; subpackages are
   infeasible.**

2. **Failover gating.** Any change touching pkg/vrrp MUST pass
   `make test-failover` before commit (project policy, CLAUDE.md). →  **Encoded
   in §7 test plan as a hard gate.**

---

## 2. Current state of master (the decisive finding)

The issue was filed against `b1ef3ed16`, when `pkg/vrrp/` was four flat files:
`instance.go` (1266), `manager.go` (872), `vrrp.go` (250), `packet.go` (205) —
no `track.go`. **Since then, the issue's headline work has already been done:**

| commit      | subject                                                              |
|-------------|---------------------------------------------------------------------|
| `a40b1f747` | `#2006: extract interface trackers from instance.go/manager.go into track.go` |
| `a1037fc48` | `#2006: document the pkg/vrrp track.go split`                        |

Current `pkg/vrrp/` on `9979a89a0` (non-test files):

| file         | LOC  | role |
|--------------|------|------|
| `vrrp.go`    | 250  | `Instance` config type + `CollectInstances`/`CollectRethInstances`/`RethVIPsForRG` config extraction |
| `packet.go`  | 205  | `VRRPPacket` Marshal/Parse + IPv4/IPv6 checksums |
| `instance.go`| 1203 | `vrrpInstance` FSM, RX receivers, advert send, VIP add/remove, GARP/NA |
| `manager.go` | 724  | `Manager` coordinator: instance diff/lifecycle, sync-hold, RG force/resign, **+ socket-open helpers** |
| `track.go`   | 228  | interface tracking (#1814): effective-priority primitives + singleton link-watcher/poller |

The `pkg/vrrp/README.md` "File layout" section **already documents this exact
four-file split** (manager/instance/packet/track + vrrp.go). The four-cluster
decomposition the issue requested is, in substance, **complete**.

**Residual delta vs the issue's literal layout:** the three socket-open helpers
(`openPerInterfaceSocket`, `openAfPacketReceiver`, `openIPv6Socket`) plus the
tiny `htons` byte-order helper still live in `manager.go` (lines 505–711, ~205
LOC of the 724). They are conceptually closer to "packet/transport plumbing"
than to the RG-coordinator role of `Manager`. This is the only meaningful
remaining grouping move. It is OPTIONAL (see §3 Option B).

---

## 3. Options considered

### Option A — Close #2006 as substantially-done (NO-OP code change)
The track.go extraction the issue named is merged; README documents the layout;
the package compiles, vets, and the four concerns are separated. File a one-line
closing comment noting `a40b1f747`/`a1037fc48` and that the residual socket-helper
move is cosmetic. **Lowest risk, zero failover exposure.** Strong default.

### Option B — Residual in-package move: `socket.go` (RECOMMENDED if any code change)
Move `openPerInterfaceSocket`, `openAfPacketReceiver`, `openIPv6Socket`, and
`htons` from `manager.go` into a new `pkg/vrrp/socket.go`, still
`package vrrp`. Update `manager.go`'s now-unused imports (`encoding/binary`,
`golang.org/x/net/ipv4`, `golang.org/x/sys/unix` may shift — verify with
`goimports`). Update README "File layout" to add the `socket.go` bullet and
amend the `manager.go` bullet (drop "socket helpers"). **Pure file rename
inside one package — no import-graph change, no exported-surface change, no
symbol renames.** ~205 LOC moved.

### Option C — Subpackages (`pkg/vrrp/manager/`, `pkg/vrrp/instance/`, ...) — REJECTED
See §4 cycle analysis. Infeasible without a large export-everything blast
radius and forbidden cross-package method receivers. PLAN-KILL for this option.

**Plan recommendation: Option A (close as done) as the primary disposition;
Option B available if the maintainer wants the literal socket-helper grouping.
Option C is rejected.**

---

## 4. Subpackage-vs-in-package resolution + cycle analysis (the #2002/#2004 wall)

### 4.1 What the issue means
The issue's "Suggested layout" lists bare filenames (`manager.go`, `instance.go`,
`packet.go`, `track.go`) **inside the single `pkg/vrrp/` directory** — not
subdirectories. The disposition line calls it "Behavior-preserving code motion
only" and "Keep the move mechanical." Combined with the fact that the project
already executed the track.go half as in-package file moves (commit `a40b1f747`,
which did NOT create a `pkg/vrrp/track/` package), the **intended meaning is an
in-package file grouping** — the #1699-style split, not a package boundary.

### 4.2 Why subpackages are infeasible (cycle / method-receiver wall)
Even if one *wanted* to subpackage, Go's rules make it impossible without a
massive export blast radius and an unbreakable cycle:

- **Cross-package method receivers are forbidden.** `track.go` defines methods
  on **two** types owned by two different would-be packages:
  - `(vi *vrrpInstance)`: `getPriority`, `setTrackDown`, `trackedInterface`
    (the type `vrrpInstance` would live in `instance/`)
  - `(m *Manager)`: `ensureLinkWatcherLocked`, `runLinkWatcher`,
    `runLinkPoller`, `pollTrackedLinks`, `applyTrackedLinkState`,
    `seedTrackState` (`Manager` would live in `manager/`)
  Go does **not** allow `package track` to declare a method on a type defined in
  `package instance` or `package manager`. The track concern is *intrinsically*
  split across the instance and manager receivers — it cannot be its own
  package at all. This alone kills the 4-package layout.

- **`manager` ↔ `instance` would be mutually dependent.**
  - `manager.go` reaches into `vrrpInstance` internals **pervasively**:
    `vi.cfg` (14×), `vi.mu` (6×), `vi.getState` (5×), plus `newInstance`,
    `openSocket`, `stop`, `run`, `suppressPreempt`, `restorePreempt`,
    `setDesiredPreempt`, `updateConfig`, `triggerPreemptNow`, `triggerResign`,
    `forcePreemptOnce`, `suppressGARP`, `garpEpoch`, `desiredPreempt`,
    `addVIPs`, `sendGARP`, `key`. Putting `vrrpInstance` in `instance/` would
    force exporting the type, ~20 methods, and ~15 struct fields — turning a
    private state machine into a public API surface for one in-tree caller.
  - `instance.go` depends on manager-owned constructs: it sends `VRRPEvent` on
    the manager's `eventCh`, calls the manager-supplied `onEventDrop`, and uses
    `VRRPPacket` (packet/). The event type and channel wiring are co-owned.
  - These two-way unexported couplings mean an `instance` ↔ `manager` split
    either (a) creates a direct import cycle, or (b) requires hoisting the
    shared types/contract into a third `internal` package and exporting most of
    the instance internals — a large, risky churn on **failover-critical code**
    for **zero functional benefit**.

- **Same class of wall as #2002/#2004.** Those refactors were plan-killed
  because the flat files shared unexported symbols that would force an import
  cycle once split across package boundaries. `pkg/vrrp` is a *stronger* case of
  the same pattern: a private state-machine type (`vrrpInstance`) and a
  coordinator (`Manager`) that mutate each other's internals under shared locks,
  with a cross-cutting tracking concern (`track.go`) that defines methods on
  BOTH. Subpackaging is a PLAN-KILL for Option C.

### 4.3 In-package grouping has NO import-graph change
Within a single `package vrrp`, files are just organizational. Moving the socket
helpers (Option B) changes no import edges, no exported surface, and no symbol
resolution — `go build`/`go vet`/`go test` see an identical package. This
mirrors the already-merged #1699-style in-package split and the already-done
track.go move. Safe pure code-motion.

### 4.4 Conclusion
- **Subpackages: REJECTED (PLAN-KILL for Option C).** Forbidden cross-package
  method receivers on the track concern + pervasive two-way unexported coupling
  between `Manager` and `vrrpInstance` = unbreakable cycle / export-everything.
- **In-package: feasible and already 80% done.** The four concerns are already
  in four files. Only the socket-helper grouping (Option B) remains, and it is
  cosmetic.

---

## 5. Detailed change set

### If Option A (recommended primary): no source change
- Post closing comment on #2006 referencing `a40b1f747` + `a1037fc48` + README
  File-layout section; note socket helpers are the only residual and are
  cosmetic.
- No commit to source, no `make test-failover` needed (no source change).

### If Option B (literal socket grouping):
1. Create `pkg/vrrp/socket.go` (`package vrrp`). Move verbatim, no edits to
   bodies:
   - `openPerInterfaceSocket` (manager.go ~505–553)
   - `openAfPacketReceiver` (manager.go ~559–645, incl. the BPF SockFilter
     program — copy byte-for-byte; the jump-offset comments are load-bearing)
   - `openIPv6Socket` (manager.go ~650–704)
   - `htons` (manager.go ~707–711)
2. Fix imports in both files with `goimports -w` (manager.go likely drops
   `encoding/binary`; socket.go gains `binary`, `ipv4`, `unix`, `net`, `fmt`,
   `slog`). Verify nothing else in manager.go still needs the dropped imports
   (`htons` was the only `binary` user there — confirm).
3. Leave `vipsEqual` and `instanceKey` in `manager.go` (they are coordinator
   concerns, not socket plumbing).
4. Update `pkg/vrrp/README.md` File-layout: add `socket.go` bullet; amend
   `manager.go` bullet to drop "socket helpers".
5. `_Log.md` entry per project logging rules.

**Hard constraints for Option B (mechanical-move invariants):**
- No function-body edits. `git diff` must show only deletions from manager.go +
  identical additions in socket.go + import-line churn + README/log.
- No symbol renames, no signature changes, no exported-surface change.
- The AF_PACKET BPF filter array and its offset comments move byte-identical.

---

## 6. Files touched

- Option A: none (issue comment only).
- Option B: `pkg/vrrp/manager.go` (deletions), `pkg/vrrp/socket.go` (new),
  `pkg/vrrp/README.md`, `_Log.md`.
- No callers change (the moved helpers are unexported and only called within the
  package — verified: 15 external packages import `pkg/vrrp` but none reference
  these helpers).

---

## 7. Test plan

### 7.1 Mandatory failover gate (project policy)
**Per CLAUDE.md: "Any change touching cluster, VRRP, session sync, or failover
code MUST pass `make test-failover` before commit."** Even though Option B is a
pure intra-package file move that cannot change behavior, the policy is
unconditional for any pkg/vrrp source change. Plan REQUIRES, before commit of
Option B:

```
make CLUSTER_ENV= test-failover     # local regression cluster (xpf-fw0/fw1)
```
Expect zero-drop failover across reboot-during-iperf3. Record pass/fail counts.

> If Option A (no source change) is chosen, `make test-failover` is not required
> because nothing is built/deployed — but the disposition comment should say so
> explicitly.

### 7.2 Build / static
- `go build ./pkg/vrrp/` — clean (baseline already verified clean on this
  worktree).
- `go vet ./pkg/vrrp/` — clean (verified clean on baseline).
- `gofmt -l pkg/vrrp/` — empty.
- `git diff --stat` sanity: Option B should be a near-zero net-LOC change
  (move-only).

### 7.3 Unit tests (in-package, must stay green unchanged)
- `go test ./pkg/vrrp/...` — `vrrp_test.go` (2067 LOC), `instance_garp_test.go`,
  `track_test.go` must all pass with no edits (move-only cannot affect them).

### 7.4 Dependent packages
- `go build ./...` and `go test ./pkg/daemon/... ./pkg/api/... ./pkg/grpcapi/...
  ./pkg/cli/...` — the 15 importers compile/test unchanged.

### 7.5 Smoke (loss userspace cluster) — only if Option B is deployed
- `make cluster-deploy` then a short HA failover smoke per CLAUDE.md to confirm
  RETH VRRP adverts still flow at 30ms and VIPs migrate. Re-apply CoS after
  deploy (deploy wipes CoS).

---

## 8. LOC / threshold

- Largest file today: `instance.go` 1203 LOC. `manager.go` 724.
- Option B reduces `manager.go` by ~205 LOC (to ~520) and creates
  `socket.go` ~210 LOC. No file is pathologically large; `instance.go` at 1203
  is the only candidate for further splitting but the issue does not ask for it
  and it is one cohesive concern (the FSM + its RX/TX). Net change is move-only;
  total package LOC unchanged.
- Threshold judgment: this is well under the size where a refactor pays for the
  failover-test risk. The marginal benefit of Option B is low; Option A
  (close-as-done) is the higher-value disposition.

---

## 9. Risks

| risk | severity | mitigation |
|------|----------|------------|
| Failover regression from accidental body edit during move | HIGH (failover code) | Move-only discipline; `git diff` review proving identical bodies; mandatory `make test-failover` gate (§7.1) |
| Dropped/duplicated import after move breaks build | LOW | `goimports`, `go build ./...` |
| BPF SockFilter array mis-copied (offsets are load-bearing) | MED | Copy byte-for-byte; offset comments move with it; AF_PACKET RX exercised by failover smoke |
| Over-engineering: spending failover-test budget for cosmetic gain | MED | Prefer Option A; only do Option B if maintainer wants literal layout |
| Subpackaging attempted anyway → cycle/compile wall | (avoided) | Option C explicitly rejected in §4 |

---

## 10. Rollback

- Option A: nothing to roll back (comment only).
- Option B: `git revert` the single move commit; pure file motion reverts
  cleanly with no data/runtime state involved.

---

## 11. Recommendation & disposition

**PLAN-READY (in-package).** Subpackaging is a PLAN-KILL (Option C, §4 — the
track concern cannot be its own package and `Manager`↔`vrrpInstance` coupling is
an unbreakable cycle). The in-package grouping the issue actually intends is
**already substantially merged** (`a40b1f747`/`a1037fc48` did the track.go
split; README documents the four-file layout).

Two acceptable dispositions, maintainer's choice:
- **Option A (default, recommended): close #2006 as substantially-done.** The
  four-concern decomposition exists; the only residual is a cosmetic
  socket-helper grouping.
- **Option B: ship the residual `socket.go` move** as a mechanical, failover-
  gated, move-only PR if the literal issue layout is wanted.

Either way: **no subpackages.** Any code change must pass `make test-failover`
before commit (§7.1).
