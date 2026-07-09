# #4662 — daemon_run.go `Run()` decomposition (Increment 1: shutdown-phase extract + phase-boundary comments)

**Status:** CONVERGED v2 — implemented. Codex PLAN-NEEDS-MINOR + Claude SMR
PLAN-READY-WITH-MINOR converged (Gemini infra-blocked, 2 documented ACP-init
retries → proceed 2-of-3 per feedback_codex_infra_must_retry). Both reviewers
independently found the SAME minor: the plan's 1709 start was inconsistent with
keeping `d.applyCancel()` (at what was line 1705) in the helper. **Applied fix:**
Phase 7 starts at the `#2926` apply-cancel abort comment (was line 1696), so the
helper owns the COMPLETE teardown; the extracted body 1696-1858 is byte-identical
to the original region (verified line-for-line). Test posture (both reviewers
rejected the full-Run structural test): pure-code-motion → NO dedicated test; the
gate is `go build ./...` + `go vet` + the existing 30+ daemon test suite +
`go test ./...` + a clean-restart smoke (the graceful-shutdown path; a
crash-based test-failover does NOT exercise runShutdownSequence). Reviewer docs:
codex verdict inline in reviewer-ids ledger; claude-smr-plan-r1.md.

## 1. Issue framing
`Daemon.Run` (`pkg/daemon/daemon_run.go:175`) spans ~1691 LOC to the next
top-level decl (`enableForwarding` at :1867). It is an ordering-sensitive
lifecycle: resolver-before-compile, naming-before-dataplane,
callbacks-before-probes, apply-cancel-before-teardown, and a specific
HA→RA→VRRP→cluster→session-sync→dataplane shutdown order. codex-review-174 #21
(maintainability-HIGH) flags it as un-reviewable in one function: "cannot
safely review an ordering change inside 1690 lines." The ask is a **mechanical
extraction with phase-boundary comments and zero behavior change** — driven
through /triple-review because the ordering is load-bearing.

## 2. Honest scope/value framing
This is a maintainability refactor, not a perf or correctness change. The win
is reviewability: today any future edit to Run() ordering is unreviewable
because the phases are undelimited and the function is 1691 lines. There is no
runtime win (identical machine behavior). **If reviewers conclude the churn
isn't worth it, PLAN-KILL is an acceptable verdict** — but the maintainability
cost of a 1691-LOC lifecycle function is real and recurring (every daemon
lifecycle PR re-reads it).

To keep each increment provable, this /triple-review scopes **Increment 1
only**:
1. Extract the self-contained **shutdown sequence** (lines 1709-1866, the
   `// Cancel context to stop background goroutines` block through
   `return runErr`) into a new method `runShutdownSequence`.
2. Add **phase-boundary comment banners** delineating the remaining inline
   phases of Run() (config-load/bootstrap, interface-naming, manager-init,
   signal/context setup, background-service starts, main-block/wait) — WITHOUT
   extracting them. Those extractions are deferred to Increments 2+ (separate
   /triple-reviews), because they thread many shared locals and interleave
   `defer`s (see §7).

Increment 1 reduces Run() by ~157 LOC and establishes the phase structure +
the extraction pattern. Tracker #4662 stays OPEN with the Increment-2+ roadmap.

## 3. What's already shipped / partially decomposed
Several lifecycle steps are ALREADY extracted methods that Run() calls:
`setupBootstrapLifeline`, `applyStep0Tunables`, `initEventEngine`,
`applyStartupNamingForConfig`, `runBootstrapExitStartup`, `teardownSNMP`,
`stopFlowExporter`, `stopIPFIXExporter`, `stopArchiveTimer`,
`stopAndDiscardNATPoolAlarm`, `restoreStep0TunablesOnShutdown`,
`runHAShutdownUpdate`. The shutdown sequence already delegates most teardown to
`d.*` methods — so extracting the sequence wrapper is low-risk; its body is
mostly `if d.X != nil { d.X.Stop() }` calls in a fixed order.

## 4. Concrete design (Increment 1)

### 4a. `runShutdownSequence`
The block at 1709-1866 references exactly three pure locals; everything else is
a `d.*` struct field or created inside the block. New signature:

```go
// runShutdownSequence performs the ordered teardown after Run()'s main block
// returns: cancel apply ctx → signal-stop → wait background goroutines →
// SNMP/flowexport/feeds/RPM/archive/event-engine/ipmon/natpoolalarm/FRR/LLDP →
// HA RG-deactivate (non-hitless) → RA withdraw → VRRP → cluster → session-sync
// → dataplane close/teardown → restore step0 tunables. Order is load-bearing
// (see per-step comments preserved verbatim). Returns runErr unchanged.
func (d *Daemon) runShutdownSequence(wg *sync.WaitGroup, stop func(), runErr error) error {
    // ... statements 1709-1866 verbatim, byte-identical order ...
    return runErr
}
```

Run()'s tail becomes:
```go
    return d.runShutdownSequence(&wg, stop, runErr)
```
(`wg` is a `sync.WaitGroup` value local; pass by address so `wg.Wait()` inside
the helper waits the same instance. `stop` is the
`signal.NotifyContext`/`NotifyStop` func; `runErr` is Run()'s accumulated error.)

### 4b. Phase-boundary comment banners
Insert `// ===== PHASE N: <name> =====` banners at the existing phase
transitions (identified from the current inline comments), no code moved:
- PHASE 1: Config load + bootstrap (~180-346)
- PHASE 2: Interface naming + bootstrap lifeline (~347-439)
- PHASE 3: Manager init (routing/FRR/IPsec/RPM/ipmon/event-engine/DHCP/cluster/
  VRRP/dataplane) + first applyConfig (~440-580)
- PHASE 4: Signal + apply-cancel context + event buffer + WaitGroup (~581-604)
- PHASE 5: Background-service starts (event stream, cluster comms, DHCP, feeds,
  RPM, LLDP, event-options, DHCP relay, port mirroring, SNMP, neighbor
  resolution, VRRP watcher, reconcile loop, HTTP/gRPC API, CLI/daemon block)
  (~605-1552)
- PHASE 6: Main block / wait (~1553-1708)
- PHASE 7: Shutdown sequence → `runShutdownSequence` (extracted)

## 5. Files touched
- `pkg/daemon/daemon_run.go` — extract `runShutdownSequence`, add banners.
- `pkg/daemon/daemon_run_shutdown_4662_test.go` (NEW) — a lifecycle test that
  exercises Run()→shutdown on a minimal config-only daemon and asserts clean
  teardown (idempotent stop, no panic, returns the injected runErr). RED on a
  deliberate reorder is impractical to assert directly; instead the test guards
  that the extracted method is CALLED and returns runErr unchanged (a structural
  guard), and the FULL existing daemon test suite (30+ files) is the behavior
  gate.
- `_Log.md` — action log.

## 6. Public API preservation
`Run(ctx) error` signature unchanged. `runShutdownSequence` is unexported. No
caller outside daemon_run.go. No struct field added/removed.

## 7. Hidden invariants the change must preserve
1. **Defer timing (THE hazard).** Run() holds `defer stop()`,
   `defer d.applyCancel()`, and `defer cancel()` (HA-shutdown timeout ctx). The
   shutdown region at 1709-1866 contains ONE defer: `defer cancel()` at the HA
   `context.WithTimeout` (~1782). Extracting the region moves that `defer
   cancel()` to fire at `runShutdownSequence` return instead of `Run` return.
   **Behaviorally equivalent** — `cancel` only releases the 2s timeout context
   used inside the HA RG-deactivate loop; by the time the helper returns that
   context has served its purpose, and cancelling at helper-return (before Run's
   outer `defer stop()`/`defer applyCancel()`) is the same observable order for
   that context. The OTHER two defers (`stop`, `applyCancel`) stay in Run() and
   are UNAFFECTED (they are declared in PHASE 3/4, outside the extracted region).
   The explicit `stop()` call at 1710 and `d.applyCancel()` at ~1706 remain in
   the extracted body — they run before the outer `defer stop()`/`defer
   applyCancel()`, exactly as today (double-call is idempotent).
2. **Statement order byte-identical.** Every statement in 1709-1866 stays in the
   exact same order in the helper. No reordering, no merged conditionals.
3. **`wg` identity.** Passed by pointer so `wg.Wait()` waits the same instance
   the background goroutines `wg.Add`/`wg.Done` against.
4. **`runErr` passthrough.** The helper returns `runErr` unchanged; Run()
   returns the helper's result. No error swallowed.
5. **No behavior gate on config-only vs full-dataplane path.** The shutdown
   region already branches on `d.dp != nil`, `d.cluster != nil`, etc.; those
   guards move verbatim.

## 8. Risk assessment
| Class | Level | Note |
|-------|-------|------|
| Behavioral regression | LOW | Byte-identical statement move; only defer-timing nuance (§7.1), which is equivalent |
| Lifetime/borrow (Go: nil-deref/goroutine leak) | LOW | `wg` by pointer; all `d.*` guards preserved |
| Performance | NONE | Identical machine behavior |
| Architectural mismatch | LOW | Not a redesign — a wrapper extract of an already-delegating teardown |

## 9. Test plan
- `go build ./...` clean.
- `go test ./pkg/daemon/...` green (30+ daemon test files — the behavior gate).
- `go test ./...` green.
- `gofmt -l` clean on the touched file.
- 5× flake check on the new lifecycle test + the heaviest existing daemon test.
- No cluster smoke required (config-only lifecycle change, no dataplane/HA
  wire/session-sync semantics altered) — BUT because the shutdown region
  includes the HA RG-deactivate + VRRP/session-sync stop ordering, run ONE
  `make test-failover` on the loss cluster as a belt-and-suspenders check that
  the reordered-into-a-method teardown still fails over + rejoins cleanly.

## 10. Out of scope (explicitly)
- Extracting PHASE 1-6 (config-load, naming, manager-init, background-services,
  main-block). Those thread 10-20 shared locals (`cfg`, `activeCfg`,
  `userspaceDP`, `er`, `eventBuf`, `wg`) and interleave the `defer stop()` /
  `defer applyCancel()` declarations — extracting them requires promoting locals
  to struct fields or a phase-context struct, which is a design decision for a
  later /triple-review. Increment 1 deliberately touches only the defer-clean
  tail.
- Any logic change, timeout change, or ordering change.

## 11. Open questions for adversarial review
1. Is the `defer cancel()` timing shift (§7.1) truly equivalent, or is there an
   observable difference (e.g. does anything read that timeout context after the
   helper returns but before Run returns)? Trace `shutdownCtx`/`cancel` usage.
2. Is passing `wg` by pointer correct, or does any code path re-copy it? Confirm
   `wg` is only `.Add`/`.Done`/`.Wait`'d, never reassigned.
3. Does the explicit `stop()` at 1710 + `defer stop()` double-call have any
   non-idempotent side effect? (`signal.NotifyContext` stop is documented
   idempotent — confirm the actual construction used here.)
4. Is a 157-line extraction worth a /triple-review, or should Increments 1-3 be
   bundled into one larger plan? (Argument for small: each is independently
   provable; argument for large: fewer review cycles.)
5. Should the phase-boundary banners use the existing inline comments verbatim
   or is renaming them a scope creep that muddies the diff? (Plan: keep existing
   comments, ADD banners only.)
6. Is the structural test (§5) meaningful, or should Increment 1 ship with NO
   new test and rely purely on the existing suite + build (true pure-code-motion
   posture)?
