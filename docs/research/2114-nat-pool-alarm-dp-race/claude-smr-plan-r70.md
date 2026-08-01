# Claude SMR hostile plan-review — round 70 (plan v71 @ `3f4d46d39`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. My r69 pass
returned PLAN-READY-WITH-NITS on v70's A3 while Codex r69 falsified two of
its load-bearing claims (the universal-gate API/behavior incompatibility;
the false cilium/ebpf teardown premise) — my r69 pass checked the
happens-before but did NOT audit the exported-signature surface or the
test-pinned mapless contracts. That miss is recorded; this pass attacks
the v71 four-class redesign directly. All line numbers re-verified against
the worktree.

## A. Fold verification (r69 findings → v71)

### 1. Codex M1 (four-class contract) — FOLDED

The partition covers the exported surface: class-1 (error signatures)
gate; class-2 (`IsLoaded() bool` loader.go:456, `SessionCount() (int,int)`
dataplane.go:299, `GetMapStats() []MapStats` :415) neutral outcomes
identical to today's missing-map path; class-3 (`ClearNATRuleCounters`
maps_nat.go:395, `ClearGlobalCounters` maps_counters.go:176,
`ClearNATRuleCounterOffsets` maps_nat.go:389 — all verified to carry the
#2218 mapless-success shape with test pins at manager_nat_test.go:320 /
manager_counters_test.go:455) ungated, with their `m.maps` lookups and
Start's population loops moved under `m.mu`; class-4 (Map :1151, Program
:1156, NewEventSource :1161, XDPLinks :1195, TCLinks :1199,
GetPersistentNAT :1146) gate to nil. Verified the class-3 mechanism
against the real code: `ClearNATRuleCounters` takes `m.mu` only INSIDE
`ClearNATRuleCounterOffsets` (maps_nat.go:390-393) and looks up
`m.maps["nat_rule_counters"]` unlocked at :400 today — so the fold ADDS
the locked lookup (a `mapsLocked`-style helper; the wrapper must not hold
`m.mu` across the internal offset clear — `sync.Mutex` is non-reentrant),
and `Start` (`apply.go:208`) calls `Load()` holding NO `m.mu` while
`loader_userspace_shim.go` takes none today, so the population-loops-under-
`m.mu` change cannot deadlock against Start. FOLDED.

### 2. Codex M2 (teardown retraction) — FOLDED

§7 item 12 now claims ADMISSION + VISIBILITY only; §10 names the
shutdown-window link-map race (Close :1206-1216 range vs attach writes
:534/:1124 after the apply-drain timeout) as a pre-existing residual with
the correct cilium/ebpf citation (map.go:273 — verified verbatim: "It is
not safe to close a map which is used by other goroutines."). The
entry-Store(false) (AGY r69) narrows the entrant window without claiming
a drain. A3 neither widens nor narrows the residual window itself — the
population m.mu adds no new shutdown ordering. FOLDED.

### 3. Codex m1 (blocked-Start determinism) — FOLDED

§9 4a now specifies the synthetic per-manager loader seam with fixed
entered/resume barriers and REAL overlap (the root Start invokes the
retired Load path, apply.go:208 — verified). The AST-generated inventory
pairing makes the matrix self-enforcing. FOLDED.

### 4. Codex m2 (replay premise correction) — FOLDED

Verified: desired state is recorded BEFORE the dataplane call
(daemon_ha.go:290-291 `getOrCreateRGState` + `SetCluster`), and
`reconcileRGStateLoop` runs immediately on startup and retries
unconditionally every 2s (`needsApply = tr.Changed || s.NeedsApply()`,
:604/:809). v71 records pending-owner + publish-after-Start as VIABLE but
not adopted with three corrected reasons — the (a)/(b)/(c) comparison is
honest (the gate standardizes the backend boundary for ALL callers incl.
the bootstrap-arm window's request-time callers, which pending-owner does
not protect). FOLDED.

### 5. Codex m3 (fwdstatus test legs) — FOLDED

The transition test gains nil-receiver / NoDataplane / empty-cell→userspace
legs — the exact gap (nil-at-construction early-return retention,
daemon_forwarding_status.go:123) is now pinned. FOLDED.

### 6. Codex m4 (comments + file inventory) — FOLDED

§5.5 sweeps daemon_run.go:373, daemon_ha_sync.go:297,
daemon_natpoolalarm_race_test.go:11; the §4 bullet now names the README +
test rewrite alongside the 3 fwdstatus files. FOLDED.

## B. Fresh attacks on the v71 delta

**Attack 1 (FAILED) — class-3 m.mu population deadlocks.** `Start` holds
no `m.mu` (apply.go:208 → Load, verified); `loader_userspace_shim.go`
references no `m.mu` today (grep-empty); the hybrids take `m.mu` only
inside the offset-clear helper. No lock-order cycle: m.mu is a leaf lock
in this path. FAILED.

**Attack 2 (FAILED) — the userspace adapter bypasses the shim gate.** The
watcher's `d.dp.HA().SetRGActive` lands on
`userspace/manager_ha.go:657 UpdateRGActive`, which takes the userspace
manager's own `m.mu` and calls `m.bpfShim.UpdateRGActive` — the SHIM's
gated method (maps_fabric.go:38). The class-1 gate covers the watcher
path end-to-end. (The userspace manager's own Start-populated state —
`haGroups` etc. — is under its own m.mu at :657-660, separate from the
shim race.) FAILED.

**Attack 3 (FAILED) — class-2 neutral divergence.** Pre-arm on master,
`SessionCount`'s map lookup misses → zeros; `GetMapStats` iterates an
empty map → empty; `IsLoaded` reads the flag → false. The v71 neutral
outcomes are byte-identical to those paths. FAILED.

**Attack 4 (FAILED) — the entry-Store(false) opens a re-arm gap.** After
Close-entry false, a subsequent Start (helper-restart stopLocked paths
don't reset loaded; reusable Teardown does — per the v66 taxonomy) re-
Stores(true) at :164 after re-population; the gate re-arms with the
backend. No stuck-false path: :164 is on every load. FAILED.

## C. Findings

### MAJOR (0)

None. The four-class contract survives contact with the exported-signature
surface, the pinned contracts, and the lock graph.

### MINOR (0)

None this round — the r69 nit pair (getter family, carve-out) was folded
in v71 and verified above; no new nit survived the v71-specific attacks.

## D. Structure confirmation (§11 q6)

CONFIRM — §4.7 stands; v71 keeps PR-1 self-contained.

## Verdict

**PLAN-READY**. (Not a rubber stamp: r68/r69 each caught real defects in
the preceding fold — the armed-state race itself, then the universal-gate
falsification. v71's four-class redesign answered both with mechanisms I
could not break in this pass: the class-3 m.mu shape, the retracted
teardown claim, and the corrected alternative rationale all verify against
the tree.)
