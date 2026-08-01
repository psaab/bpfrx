# Claude SMR hostile plan-review — round 71 (plan v72 @ `f04a5eca8`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. r70's SMR
returned PLAN-READY on v71 while Codex r70 found the partition
incomplete (error-signature no-ops, required-side-effect hybrids) — my
r70 pass class-checked only the headline methods, not the full exported
set. Recorded. This pass enumerates the full exported `*Manager`
surface against the v72 partition and attacks the gate-vs-arming-path
ordering. All line numbers re-verified against the worktree.

## A. Fold verification (r70 findings → v72)

### 1. Codex M1 (partition completion) — FOLDED, with nit m1

Full enumeration of the exported `*Manager` set against the v72
classes (loader.go / maps_*.go / apply.go / compiler.go):

- Class-1 (fallible, gate before first Start-state access): the
  maps_fabric pair, the Set*/Clear*/Read*/Iterate*/Batch* maps_*
  families with error returns and no required pre-error side effects,
  AddTxPort (validation-first, pinned). Verified the class-2 no-ops'
  shapes: `ClearSessionCounts` (skip-on-absent `continue`,
  maps_screen.go:57-75), `ClearStaticNATEntries` (`if ok` guards,
  maps_nat.go:258-286), `UpdatePolicyScheduleState` (deliberate nil,
  #3780 comment verified at maps_policy.go:244-255). Class-3
  expansion verified: `ClearZoneCounters` (:227-235 — offset-first,
  mapless nil), `ClearAllCounters` (:245-262 — ClearGlobalCounters
  first, later missing-interface error; the test pin at
  manager_counters_test.go:509-565 verified to require the side
  effect). Class-4 corrections verified: `New()` allocates
  programs/maps/xdpLinks/tcLinks/PersistentNAT (loader.go:89-100);
  PersistentNATTable carries its own `sync.RWMutex`
  (persistent_nat.go:51-56); `server_show_nat_test.go:15-20` pins the
  pre-Start GetPersistentNAT path. The AST-matrix totality net is
  stated. FOLDED — with m1: the ATTACH family is not explicitly
  placed (see B.1).

### 2. Codex m1 (gate placement) — FOLDED

"Gate before the first Start-state access; pure validation may
precede" — AddTxPort's ifindex validation (loader.go:982-991) runs
before `m.maps["tx_ports"]`, test-pinned (constants_test.go:187-220).
FOLDED.

### 3. Codex m2 (class-4 corrections) — FOLDED

GetPersistentNAT/XDPLinks/TCLinks moved to the ungated construction
set with the correct reasoning; NewEventSource's
`(nil, ErrDataplaneNotArmed)` honors its signature. FOLDED.

### 4. Codex m3 (exact-schedule residual + narrowed-not-closed) — FOLDED

§7 item 12 and §10 now describe the late-admission-after-release
schedule (stopPolicySchedulerLoop's unbounded applySem acquisition,
daemon_scheduler.go:170-183 — verified verbatim) with the live-path
writer citations (:575 insertion, :661 deletion; :1124 TC-only).
§4.7's blanket "exactly as exposed" is now "no hazard worsened; two
windows narrowed without closure claimed". FOLDED.

### 5. Codex m4 (comment sweep) — FOLDED

The three new sites join §5.5 plus the /engineer residual-prose grep.
FOLDED.

## B. Fresh attacks on the v72 delta

**Attack 1 (SUCCEEDED as nit m1) — the attach family is unplaced in
the partition text.** `AttachXDP` (loader.go:489) reads
Start-populated state (`m.programs`/`m.maps`) and writes `m.xdpLinks`
(:575) — class-1 by the rule — but it is also ON the arming path:
`CompileUserspaceShim` (:173+) → `attachUserspaceShimXDP` (:211) →
`m.AttachXDP` (:221/:247). A class-1 gate on AttachXDP would break the
arm itself IF attach ever ran before the `:164` Store(true). Verified
the ordering: `LoadUserspaceShim` (:152-166) Stores true as its last
step and never calls the attach flow; the attach flow runs only via
CompileUserspaceShim, which the userspace manager drives AFTER Load.
So the gate is safe TODAY — but the plan never says so, and a future
reordering (attach folded into Load) would silently deadlock the arm
against the gate. One clause: the attach family is class-1 with the
ARMING-ORDER invariant stated (attach runs strictly post-Store(true),
pinned by the §9 matrix asserting AttachXDP pre-arm returns the typed
error — which doubles as the reorder tripwire). MINOR.

**Attack 2 (FAILED) — class-3 iteration escape.** The hybrids iterate
the looked-up map (ClearStaticNATEntries collects keys then deletes);
the scoped-lock text says the LOOKUP moves under m.mu — but the
iteration happens after the lookup returns. Is the race closed?
Population writes the map HEADER entries only during Start; once a
hybrid observes the entry under the locked lookup, population is
either before the Store(true) (hybrid sees the fully-populated map —
wait, the hybrid does not check loaded). Hmm: a hybrid iterating
`zm` while Start populates OTHER entries of the same map — the
lookup under m.mu serializes against the population loops under m.mu,
so the lookup itself cannot race; but the returned `zm` (*ebpf.Map)
is a library handle — iteration via the handle is library-safe
regardless of Go-map population (the Go map holds handles; iteration
touches the kernel map, not the Go map). The fatal case was Go-map
read-during-write, closed by the scoped lookup lock. FAILED.

**Attack 3 (FAILED) — population-under-m.mu stalls the status poll.**
The population loops run once per arm (≤2 per process); the m.mu
hold is two short insert loops; the 1 Hz poll's m.mu sections are
elsewhere (userspace manager's own mu, not the shim's). Even on the
shim's m.mu, a one-time millisecond hold during arm is noise. FAILED.

**Attack 4 (FAILED) — dual-class method breaks the matrix.** The
matrix assigns by contract outcome; a method with both gated and
ungated behavior would have shown up as a v70/v71 miss (the no-ops
and hybrids). The remaining surface is uniform within classes.
FAILED.

## C. Findings

### MAJOR (0)

None. The v72 partition survives a full-surface enumeration.

### MINOR (1)

**m1.** Name the attach family (`AttachXDP`/`DetachXDP`/`AttachTC`/
`DetachTC`) in class 1 explicitly, with the arming-order invariant:
the arm path's attach runs strictly after the `:164` Store(true)
(`LoadUserspaceShim` never attaches; the attach flow is
CompileUserspaceShim-driven, post-Load), and the §9 matrix's
pre-arm AttachXDP assertion doubles as the reorder tripwire.

## D. Structure confirmation (§11 q6)

CONFIRM — §4.7 stands; v72 keeps PR-1 self-contained.

## Verdict

**PLAN-READY-WITH-NITS** (0 MAJOR, 1 MINOR — the attach-family
placement clause). A v73 containing only this pin is PLAN-READY by
inspection from me.
