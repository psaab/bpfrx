# #2075 — Reconcile NetFlow v9 / IPFIX exporters on config commit

**Status:** DRAFT v1 — pending adversarial plan review

## 1. Issue framing

`pkg/flowexport` exporters (NetFlow v9 + IPFIX) are
started/stopped **only** at daemon boot/shutdown:

- `startFlowExporter` / `startIPFIXExporter` are invoked only in the
  one-shot boot sequence (`daemon_run.go:838/843` and the `er==nil`
  fallback at `857/858`).
- `stopFlowExporter` / `stopIPFIXExporter` are called only at shutdown
  (`daemon_run.go:1475/1476`).
- `applyConfigLocked` (`daemon_apply.go`) re-runs `applySyslogConfig`
  (step 14b) and `updateFlowTrace` (step 16) but has **zero**
  flowexport references.

Consequence: any runtime commit that changes
`forwarding-options sampling` (collector address/port, source-address,
1-in-N input-rate), adds/removes a sampling instance, changes which
zones sample, or toggles a v9 export-extension is silently ignored
until a daemon restart. Worse: if flow export is *not* configured at
boot but is *added* in a later commit, no exporter ever starts.

The fix: reconcile the flow exporters on every commit in the apply
path, mirroring how `reconcileRPM` / `reconcileIPMon` / SNMP /
`updateFlowTrace` already reconcile their subsystems.

## 2. Honest scope / value framing

This is an observability-subsystem correctness fix: committed config
must take effect without a daemon restart. No crash, no dataplane
impact, no perf-path change. The win is operator-facing: NetFlow/IPFIX
sampling config edits become live on `commit`, matching every other
service in the apply path.

If reviewers conclude the change is unnecessary or that the latent
callback-leak is out of scope, that is a legitimate finding — but the
core "config is stored but never enforced" defect is real and
triage-confirmed.

## 3. The hard part: the EventReader callback model

`startFlowExporter` registers a session-close handler via
`er.AddCallback(...)` (daemon_flow.go:163) that **closes over the
boot-time `ec` and `exp`**. The `EventReader` callback list
(`pkg/logging/ringbuf.go`) is **append-only** with only a clear-ALL
primitive (`ClearCallbacks`) — there is **no per-callback removal**.
The same EventReader carries callbacks for the flow exporter, the
IPFIX exporter, and `updateFlowTrace` (the trace writer).

Therefore a naive "stop then start again" reconcile is **broken**:
the old boot-time closure stays in `er.callbacks` forever, pointing
at a closed exporter, and `ClearCallbacks` would also nuke the
trace-writer callback. Every commit would append yet another closure
(unbounded leak + writes to closed exporters).

> Note — pre-existing latent leak: `updateFlowTrace`
> (daemon_flow.go:379) already appends a NEW `tw.HandleEvent`
> callback on every commit with traceoptions, without removing the
> prior one (the old TraceWriter is `Close()`d, so its callback now
> writes to a closed writer). This is the same class of bug. It is
> **out of scope** for #2075 (tracked separately if desired) — but
> our flowexport design must NOT add a second instance of it.

### Design: register the callback ONCE, swap the exporter behind a pointer

Register a single, stable indirection callback per exporter family at
the point the EventReader is created (boot), reading the *current*
exporter + its *current* resolved `ExportConfig` from daemon fields
guarded by a mutex. Reconcile then swaps those fields atomically —
the registered callback never changes, so nothing is ever appended or
leaked on commit.

```go
// daemon.go fields (replace the bare *Exporter / cancel / wg with a
// small holder, or keep fields + add a mutex). Concretely add:
flowMu        sync.Mutex      // guards flowExporter + flowEC + flowCancel
flowEC        *flowexport.ExportConfig // live resolved config (for ShouldExport)
flowHash      [32]byte        // config-hash gate
flowCBOnce    sync.Once       // register the indirection callback once
// (mirror for ipfix*)
```

The stable callback:

```go
er.AddCallback(func(rec logging.EventRecord, raw []byte) {
    if rec.Type != "SESSION_CLOSE" {
        return
    }
    d.flowMu.Lock()
    exp, ec := d.flowExporter, d.flowEC
    d.flowMu.Unlock()
    if exp == nil || ec == nil || !ec.ShouldExport(rec.InZone, rec.OutZone) {
        return
    }
    sd := flowexport.SessionCloseData{ ... }   // unchanged extraction
    exp.ExportSessionClose(rec, sd)
})
```

### Reconcile entry point

```go
// reconcileFlowExporters runs on every apply; CONFIG-HASH-GATED so an
// unrelated commit never bounces a healthy exporter (and never drops
// the in-flight template-refresh / sampling counter state). Returns
// true when it actually (re)started or stopped an exporter.
func (d *Daemon) reconcileFlowExporters(cfg *config.Config) bool
```

Behavior:

1. If `d.eventReader == nil` → return false (no event plumbing yet;
   the boot path will start it). This matches the syslog step 14b
   guard `if d.eventReader != nil`.
2. Build the desired resolved config:
   `ec := BuildExportConfig(&cfg.Services, &cfg.ForwardingOptions)`;
   if non-nil, fill `ec.SamplingZones = BuildSamplingZones(...)`.
3. Compute a content hash over the resolved-config inputs. **Hash the
   config inputs, not the built `*ExportConfig`** — `ExportConfig`
   carries an unexported `atomic.Uint64 sampleCounter`, but
   `json.Marshal` ignores unexported fields, so a JSON hash over the
   resolved `ec` (Collectors, timeouts, SamplingZones, SamplingRate,
   V9TemplateOpts) is deterministic. Use the same `sha256(json)`
   helper shape as `rpmConfigHash`. A nil `ec` hashes to a distinct
   sentinel (so "configured → removed" is a real change).
4. If hash == stored hash → return false (gated; healthy exporter
   keeps running with its template-refresh + sampling state intact).
5. Otherwise: stop the old exporter (`d.flowCancel()` + `flowWg.Wait()`
   + `Close()` under the swap discipline), then if `ec != nil` start a
   new one and publish `(exp, ec)` under `flowMu`. Ensure the
   indirection callback is registered exactly once (`flowCBOnce`).
   Store the new hash.

The callback registration moves OUT of `startFlowExporter` and into a
once-guarded path so reconcile and boot share it. `startFlowExporter`
/ `startIPFIXExporter` become thin wrappers that call
`reconcileFlowExporters` (boot just calls reconcile), or are removed
in favor of a single reconcile call at boot. Either way the boot
call sites collapse to the reconcile.

### Stop/start ordering invariant

`stopFlowExporter` cancels the context, waits the WaitGroup, then
`Close()`s. The swap must publish `flowExporter=nil` BEFORE
`flowWg.Wait()` is NOT required — but we must not hold `flowMu` across
`flowWg.Wait()` (the running `exp.Run` goroutine does not take
`flowMu`, so there is no deadlock either way; still, take the cancel
funcs under the lock, release, then Wait, to keep the lock hold short).
The callback reads `(exp, ec)` under `flowMu`; during a swap a
session-close event sees either the old pair or the new pair, never a
torn read — both are valid exporters. A brief window where `exp` is the
old (cancelled-but-not-yet-Closed) exporter is harmless:
`ExportSessionClose` on a cancelled exporter just queues into a buffer
that will be drained/dropped on Close — no panic. (Verify: walk
`Exporter.ExportSessionClose` / `Close` for a post-Close send hazard;
if a channel send after Close can panic, publish `nil` first, then
Wait+Close.)

## 4. Call-site changes

- `daemon_apply.go`: add a step (near 16, after `updateFlowTrace`):
  `d.reconcileFlowExporters(cfg)`.
- `daemon_run.go`: replace the two boot start blocks (838-843 and the
  857-858 fallback) with a single `d.reconcileFlowExporters(cfg)`
  call in each location, OR keep `startFlowExporter`/`startIPFIXExporter`
  as wrappers that delegate to reconcile. Boot uses `d.daemonCtx`
  (set at daemon_run.go:178) the same way reconcile does — so the
  exporter goroutine is parented to the daemon context, not a
  per-commit context. (Today boot uses the `ctx` arg which IS
  `d.daemonCtx`.)

## 5. Public API preservation

- `flowexport.Exporter` / `IPFIXExporter` / `BuildExportConfig` /
  `BuildIPFIXExportConfig` / `ShouldExport` / `ExportSessionClose` —
  **unchanged**.
- `EventReader.AddCallback` / `ClearCallbacks` — **unchanged** (we add
  no removal API; the once-registered indirection avoids needing one).
- `stopFlowExporter` / `stopIPFIXExporter` shutdown semantics —
  **unchanged** (still called at shutdown).

## 6. Hidden invariants the change must preserve

- **No callback leak:** exactly one flow-export callback and one
  IPFIX callback ever registered on the EventReader, for the daemon's
  lifetime. Proven by `sync.Once` + a test asserting callback count.
- **Hash-gate:** an unrelated commit (no sampling/flow-monitoring
  change) must NOT bounce a running exporter (preserves template
  refresh + sampling counter). Mirrors RPM/IPMon gating.
- **Boot parity:** boot still starts the exporter when configured;
  behavior with flow export configured at boot is unchanged.
- **Add-after-boot:** flow export added in a later commit now starts
  (the headline fix).
- **Remove-after-boot:** flow export removed in a later commit now
  stops the exporter (was impossible before).
- **Shutdown:** `stopFlowExporter`/`stopIPFIXExporter` still drain at
  shutdown; reconcile's swap must leave `flowExporter`/`flowCancel`
  in a state where the shutdown stop is idempotent (nil-safe).
- **Concurrency:** `applyConfigLocked` runs under `applySem`; the
  session-close callback runs on the event-reader goroutine. `flowMu`
  serializes the swap vs. the callback read. No lock held across
  `flowWg.Wait()`.

## 7. Risk assessment

| Class | Level | Notes |
|-------|-------|-------|
| Behavioral regression | LOW | Gated; boot path semantics preserved; new behavior only on a flow-export config change. |
| Lifetime / goroutine | MED | Stop/start swap + WaitGroup ordering; mitigated by short lock hold + nil-publish-before-Close if post-Close send can panic. |
| Performance | LOW | Per-commit only (slow path); callback adds one mutex lock per SESSION_CLOSE event — events are already callback-dispatched and rate-bounded by session closes, not per-packet. |
| Architectural mismatch | LOW | Directly mirrors the established `reconcileRPM`/`reconcileIPMon` pattern in the same file. |

## 8. Test plan (control-plane — NO dataplane smoke)

Per the campaign triage: this is a control-plane fix; cover with Go
unit tests in `pkg/daemon`. Tests must FAIL if the reconcile call is
removed (non-tautological). Gates:

- `go build ./...` clean.
- New `pkg/daemon/daemon_flowexport_reconcile_test.go`:
  1. **Add-after-boot:** Daemon with a non-nil EventReader and no
     flow export configured; `reconcileFlowExporters(cfgWithSampling)`
     returns true and `d.flowExporter != nil`.
  2. **Remove-after-boot:** from configured → empty config; reconcile
     returns true and `d.flowExporter == nil` (and the exporter
     goroutine drained).
  3. **Hash-gate:** identical config twice → second returns false; a
     semantically-equal freshly-built config also gated (content
     hash).
  4. **Change re-applies:** changing collector address/port/rate →
     reconcile returns true.
  5. **No callback leak:** after N reconciles the EventReader has
     exactly one flow callback (+ one ipfix callback) — assert via a
     test accessor on EventReader callback count, or a recorder seam.
  6. **Removal-of-the-reconcile-call regression guard:** a test that
     drives `applyConfigLocked` (or a thin seam it calls) and asserts
     the exporter started — so deleting the step-16.x line fails a
     test. If wiring full `applyConfigLocked` is too heavy, assert at
     minimum that `reconcileFlowExporters` is invoked by the apply
     path via a recorder/seam.
- 5x flake check on the most timing-sensitive new test (goroutine
  start/stop).
- Full `go test ./...` (30 Go packages) green.
- `pkg/flowexport` existing tests still pass.

No iperf / CoS / cluster smoke — the issue explicitly states
control-plane, no dataplane path touched.

## 9. Out of scope (explicitly)

- The `updateFlowTrace` latent callback leak (same class, different
  subsystem) — note it, do not fix it here.
- Adding a per-callback removal API to EventReader — the once-guarded
  indirection makes it unnecessary.
- Any change to NetFlow/IPFIX wire encoding or sampling math.
- HA / session-sync interaction (exporters are node-local).

## 10. Open questions for adversarial review (any may justify PLAN-KILL)

1. Is the **once-registered indirection callback** the right design,
   or should we instead add a real `RemoveCallback`/handle API to
   EventReader and re-register per reconcile? (Indirection avoids API
   churn + the clear-all hazard; is there a correctness reason to
   prefer explicit removal?)
2. Is hashing the **resolved `*ExportConfig` JSON** safe given the
   unexported `atomic.Uint64 sampleCounter` (ignored by
   `json.Marshal`)? Should we instead hash the raw config inputs
   (`cfg.Services.FlowMonitoring` + `cfg.ForwardingOptions.Sampling` +
   the zone-ID map)? Which is less fragile to future field additions?
3. **Post-Close send hazard:** RESOLVED by source walk —
   `Exporter.ExportSessionClose` calls only `e.batch.add(fr)`
   (transport.go:102, a mutex-guarded slice append; NOT a channel),
   and `Close()` only closes UDP connections (`conns.close()`). A
   post-Close `ExportSessionClose` therefore just appends to an
   in-memory batch that is never flushed — harmless, no panic. The
   swap ordering is forgiving. We still publish `(exp, ec)`
   atomically under `flowMu` for a clean read; nil-before-Close is
   not required for safety. (Reviewers: confirm IPFIX
   `ExportSessionClose` has the same shape — it does per
   ipfix.go:341.)
4. Should `reconcileFlowExporters` be **one** function handling both
   v9 and IPFIX, or two parallel functions? (RPM has one; the two
   exporters share zone-ID building and the callback shape.)
5. Is the **lock-ordering** (`flowMu` short hold, never across
   `flowWg.Wait()`) actually deadlock-free given `Exporter.Run`
   does not take `flowMu`? Any path where the event-reader goroutine
   blocks on a full channel while reconcile holds `flowMu` and waits
   on that goroutine?
6. Does running reconcile under `applySem` while the session-close
   callback fires on the event-reader goroutine introduce any
   ordering hazard with `applySyslogConfig` (which mutates the same
   EventReader's zone/policy/if-name maps under their own RW locks)?
