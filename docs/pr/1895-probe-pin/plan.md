# #1895 — probe-pin install failures must hold RPM state, not false-PASS

Status: PLAN v2 — adjudicated by the quad together with the code (this
is a verification-grade defect fix, not an architecture refactor; the
plan and implementation ship in the same PR). v2 folds in Codex r1:
pins are pre-held while the band is reprogrammed (MAJOR-1), a missing
routing manager marks all pins failed (MAJOR-2), and the rollback
invariant is stated as best-effort with the band clear() as backstop
(MEDIUM).

## Defect

`probePinManager.Apply` (pkg/routing/probe_pin.go:149-205, single
commit `938d0bee3` from #1827 PR-1a) logs-and-continues on every
per-pin programming failure and returns nil unconditionally. The
daemon (pkg/daemon/daemon_rpm.go:208-216) then starts RPM regardless,
and RPM (pkg/rpm/rpm.go:405-417) applies `m.marks[key]` via SO_MARK
with no knowledge of whether the kernel rule/route behind that mark
installed.

## Mechanism (why every failure mode is a false PASS)

All four per-pin failure modes collapse to a silently-unpinned probe:

1. **Invalid target/next-hop** (`:155-160`) — pin skipped, probe runs
   with SO_MARK but matches no fwmark rule → main-table routing.
2. **Missing egress link** (`:169-174`, boot ordering / RETH churn) —
   same.
3. **`RuleAdd` failure** (`:181-186`) — same.
4. **`RouteAdd` failure after `RuleAdd` succeeded** (`:195-200`) — the
   fwmark rule points at an EMPTY band table; Linux fib-rule
   processing falls through on empty-table lookup (-EAGAIN → next
   rule) → main-table routing. Additionally the rule is never rolled
   back (no `RuleDel`), leaving stale kernel state for the next
   `clear()` to sweep.

The probe then follows the default route and reports the *pinned
uplink* healthy: **false PASS** → ip-monitoring never fails over a
dead pinned uplink. For multi-WAN this suppresses failover exactly
when it is needed.

The right-shaped sink already exists: `ErrProbeSetup`
(pkg/rpm/icmp.go:106) with hold-state semantics at
pkg/rpm/rpm.go:313-328 (#1843 PR-1a design: capability/environment
errors hold the test's current state — no counters, no status change,
no events, no Transition). Pin programming failures are exactly that
class but never reach it.

## Fix shape

### (a) pkg/routing — per-test install results + rule rollback

(Rollback is best-effort: if the rollback RuleDel fails, the stale
rule is logged and swept by the next apply's band clear(); the pin is
reported failed either way, so the probe holds — the safe direction.)

`probePinManager.Apply(pins []ProbePin) map[string]error` — returns a
map keyed by `ProbePin.TestKey` containing ONLY the pins that failed
to install, with the wrapped install error. Empty/nil map = all pins
installed. The always-nil `error` return is dropped (it carried no
information; sole non-test caller is the daemon, updated in the same
PR).

On the `RouteAdd`-failure path the already-added fwmark rule is rolled
back with `RuleDel` so a partial install never persists (rollback
failure is logged and the pin still reported failed; the band `clear()`
on the next apply remains the backstop).

`Manager.ApplyProbePins` passthrough signature follows.

### (b) pkg/daemon — thread results into rpm.Manager + retry

Every band reprogram (full apply AND retry) runs with the pinned
probes pre-held: `applyProbePinsHeld` holds the UNION of every
currently-marked live test and the new pin set
(`rpm.HoldPinsForReprogram`) before the clear-then-program — live
goroutines whose keys were removed, or whose deterministic mark is
about to be reassigned, must not send against the band in flux either
(Codex r2). Publication of the real results: the retry path publishes
immediately (probe set unchanged under an unchanged hash); EVERY full
apply — installer-backed or not (Codex r3) — uses one shared ordering:
hold the union first, mutate, publish only AFTER `rpm.Apply` (old
goroutines drained by StopAll, new marks in place). The first probe
cycle after an RPM config change may therefore hold, bounded by one
test-interval, which is the safe direction. Residual window =
gate-check→sendto of a probe already past the gate (Codex r1/r2:
acceptable). When no routing manager exists at all but pins are
configured, every pin is marked `errNoProbePinInstaller` (Codex r1
MAJOR-2) under the same hold/publish ordering (Codex r3: publishing
the new-keys-only set before Apply reopened the gate for an old held
pin being removed from config).

`reconcileRPM` passes the failed-pin map to the RPM manager via a new
additive setter (`SetPinInstallResults`, mirroring `SetRethMap`)
BEFORE `rpm.Apply`, so probes start with failure knowledge.

Retry: the config-hash gate previously meant a boot-ordering failure
(egress link not yet present) stayed failed until the next RPM config
change. Now, while any pin is failed (`d.rpmPinsFailed`, guarded by
`rpmMu`), a hash-gated reconcile retries `ApplyProbePins` ONLY (no
probe restart — probe state is preserved; the deterministic mark
assignment cannot change while the hash is unchanged) and updates the
manager via the setter. Recovery is therefore picked up on any
subsequent commit or RG transition (`reconcileIPMonGating`).
Residual: there is no timer-based retry; a failed pin with zero
subsequent reconcile triggers stays held (visible via the gauge, the
rate-limited Warn, and stalled TotalSent/LastProbeAt in
`show services rpm`). Held is the safe direction — the pre-#1895
behavior was false PASS.

A `probePinApply func([]routing.ProbePin) map[string]error` test seam
on Daemon (nil = `d.routing.ApplyProbePins`) lets the daemon-level
retry test run without a netlink handle.

### (c) pkg/rpm — failed pins probe nothing and hold state

`Manager` gains `pinFailed map[string]error` (same lock as `marks`).
`executeProbe` gates first: for a next-hop test whose key is in
`pinFailed` — or that has NO mark assigned at all (band-exhaustion
belt-and-braces; commit validation caps this on the strict path) — it
returns an `ErrProbeSetup`-wrapped error WITHOUT opening a socket. The
existing hold-state branch (rpm.go:321) then holds the test: no
SO_MARK probe is ever sent on an unbacked pin, no counters move, no
transition fires, ip-monitoring keeps its prior signal.

When the daemon clears the failure (successful retry),
`SetPinInstallResults` replaces the map and the next probe tick
resumes normally — no probe restart needed.

### (d) Operator visibility

- Per-pin install failures already Warn-log in pkg/routing (kept,
  with the failure now also carried in the returned map).
- The probe loop's existing rate-limited Warn ("holding test state")
  now fires for pin failures with the pin cause in `err`.
- New gauge `xpf_rpm_probe_pin_install_failures` (count of currently
  failed pins) via the established optional-Fn pattern in pkg/api
  (`RPMPinFailedFn`, like `FRRReloadDegradedFn`): the defect class is
  *silence*, so an alertable surface is justified; wire-additive only
  (omitted when nil).

## API shape (additive summary)

| Surface | Before | After |
|---|---|---|
| `routing.probePinManager.Apply` | `error` (always nil) | `map[string]error` (failed pins only) |
| `routing.Manager.ApplyProbePins` | `error` | `map[string]error` |
| `rpm.Manager.SetPinInstallResults` | — | new setter (call before `Apply`; replaces map) |
| `rpm.Manager.PinInstallFailureCount` | — | new accessor (metrics) |
| `api.Config.RPMPinFailedFn` | — | new optional Fn → gauge |
| `Daemon.rpmPinsFailed` / `probePinApply` | — | unexported state + test seam |

`rpm.Manager.Apply` signature unchanged. HA §4.4 gating unchanged:
pins are built from the same `effective` (gated) config on both the
routing and rpm sides, so keyspaces always agree.

## Hidden invariants preserved

- **Mark determinism**: rpm derives marks from the SAME
  `BuildProbePins` call shape; a hash-gated pin retry cannot change
  marks, so live probes never race a mark reassignment.
- **Reconcile-vs-probe-loop**: `pinFailed` is read per-probe under
  `m.mu.RLock` (same discipline as `marks`); the setter replaces the
  whole map under `m.mu.Lock`. The pre-existing transient window where
  in-flight probes overlap a band reprogram (every config commit)
  is unchanged in size; the retry path reuses it.
- **Hold-state semantics** (#1843): unchanged branch; pin failures
  enter through the same `errors.Is(err, ErrProbeSetup)` check.
- **Probe state preservation**: the hash gate still prevents probe
  restarts on unrelated commits; the retry path deliberately does NOT
  call `rpm.Apply`.

## Test matrix

pkg/routing (fake `probePinOps` extended with failure injection):
- `RuleAdd` fails → key in failed map; no route added; no rule left.
- `RouteAdd` fails after `RuleAdd` → key in failed map; **rule rolled
  back** (band empty).
- Missing egress link → key in failed map.
- Invalid target/next-hop → key in failed map.
- Mixed two-test success/failure → only the bad key fails; the good
  pin's rule+route fully installed.
- Existing determinism/clear/cap tests unchanged.

pkg/rpm:
- Failed pin → `executeProbe` returns `ErrProbeSetup`; ICMP listen
  seam asserts NO socket was opened.
- `runSingleTest` with failed pin → state held: TotalSent unchanged,
  LastStatus unchanged, no transition fired.
- Recovery: `SetPinInstallResults(nil)` → probing resumes (fake conn
  pass), transition fires.
- Next-hop test with no assigned mark → `ErrProbeSetup`.
- Non-pinned test unaffected by other tests' failures.

pkg/daemon:
- Hash-gated reconcile retries failed pins via the seam, updates the
  manager, and stops retrying once the install succeeds; gating test
  unchanged.

Gates: `go build ./...`, full `go test ./...` (unmasked), `-race` on
pkg/rpm + pkg/routing.

Live (loss userspace cluster, lock protocol): configure an
ip-monitoring policy whose probe-pin egress interface is broken,
prove the test enters setup-held state (journal Warn + stalled
`show services rpm` + gauge) instead of false-PASSing; restore and
prove probing resumes after a reconcile trigger.

## Out of scope

- Timer-based pin retry (documented residual; held-state is safe).
- The audit's `pkg/routing/probepin/` plan/apply/status split.
- Surfacing pin status in `show services rpm` columns (journal +
  gauge + stalled counters cover the operator story).
- #1893/#1894 (independent configstore findings from the same audit).
