# #2075 — Reconcile NetFlow v9 / IPFIX exporters on config commit

**Status:** v2 — both hostile reviewers PLAN-NEEDS-MINOR (no kill); all
findings folded in below. Ready to implement.

### Review-fold changelog (v1 → v2)

- **[MAJOR, both reviewers]** Boot start is load-bearing in the
  post-EventReader block, NOT the apply-path step. Boot's
  `applyConfig` runs at `daemon_run.go:671`, BEFORE the EventReader is
  created (`778` native / `853` userspace fallback). The apply-path
  `reconcileFlowExporters` therefore no-ops at boot (`eventReader ==
  nil` guard). The post-EventReader reconcile call (replacing the
  `daemon_run.go:836-862` start blocks) is what starts the exporter at
  boot; the apply-path step is **additive** for later commits. Do NOT
  delete the post-EventReader block. (§4 rewritten.)
- **[MAJOR-1, reviewer B]** v1's claim "boot `ctx` IS `d.daemonCtx`" is
  FALSE. `daemon_run.go:178` sets `d.daemonCtx = ctx`, but `697-700`
  REASSIGNS the local `ctx` to `signal.NotifyContext(...)`. So today's
  boot exporter goroutine is cancelled by `stop()` (signal child) at
  `1471`, before the explicit `stopFlowExporter` at `1475`. Reconcile
  derives the exporter's cancel from `d.daemonCtx` (mirroring
  `reconcileRPM`), so after this change the goroutine dies ONLY via the
  explicit `flowCancel()` in `stopFlowExporter`/swap — which still runs
  at shutdown. Authoritative-stop invariant: `flowCancel =
  WithCancel(d.daemonCtx)` and shutdown's `stopFlowExporter` remains
  the stop path. (§3, §4 updated.)
- **[MAJOR-2 / criterion 6, both]** Drop the recorder/seam fallback for
  the apply-wiring test. Mandate a test that drives the REAL
  `applyConfigLocked` and asserts `d.flowExporter != nil` — fails iff
  the apply-path call is deleted. Template: `daemon_snmp_reconcile_test.go`
  (already drives real `applyConfigLocked` with
  `applySem: semaphore.NewWeighted(1)`, a runtime-only test DP, and a
  config store). (§8 rewritten.)
- **[MINOR, both]** Hash contradiction resolved: hash the **resolved
  `*ExportConfig`** (after `SamplingZones` is filled), JSON+sha256,
  **two separate hashes** (v9 + IPFIX) so a single-family change never
  cross-bounces the other. `sampleCounter` (unexported `atomic.Uint64`)
  is invisible to `json.Marshal`; `map[uint16]SamplingDir` marshals with
  numerically-sorted keys → deterministic. (§3 step 3 updated.)
- **[MINOR, B] sampleCounter ownership clarified:** the exporter never
  calls `ShouldExport` (only the daemon callback does, daemon_flow.go:
  168/230). So the exporter's by-value `cfg.sampleCounter` copy is dead;
  the daemon-held `*ExportConfig` is the SOLE 1-in-N counter owner.
  Therefore `flowEC` MUST be a `*ExportConfig` (pointer) — a value
  field would copy the atomic and split the counter. (§3 updated.)
- **[MINOR, B] copylocks:** `go vet ./pkg/flowexport ./pkg/daemon`
  ALREADY reports pre-existing copylocks on `NewExporter(cfg
  ExportConfig)` / `NewExporter(*ec)` (atomic.Uint64 by value). The swap
  introduces NO NEW vet class. We do not add extra by-value
  `ExportConfig` copies beyond the unavoidable `NewExporter(*ec)` already
  present. Changing `NewExporter` to take `*ExportConfig` is out of
  scope. (§9.)
- **[MINOR-3, B → ADOPTED] Replace the per-event mutex with
  `atomic.Pointer[exporterBundle]`.** The callback must read `(exp, ec)`
  as a consistent pair; an `atomic.Pointer` to an immutable
  `{exp *Exporter; ec *ExportConfig}` bundle makes the read lock-free and
  eliminates the "never hold a mutex across `flowWg.Wait()`" footgun
  entirely. Reconcile builds a new bundle and `Store`s it; a stale read
  during a swap sees either the old or new bundle — both valid. (§3.)
- **[MINOR, B] abort-side placement:** the reconcile step lands AFTER
  `updateFlowTrace` (step ~16), i.e. below the `compileErrorMustAbortApply`
  early-return at `daemon_apply.go:693-696`. Consistent with
  reconcileRPM/IPMon/syslog: an aborting commit defers the exporter
  change to the next clean commit. Stated as a deliberate choice. (§4.)
- **[MINOR, both] shutdown idempotency:** reconcile sets the bundle to a
  nil-exporter bundle (and clears `flowCancel`) after a stop, so the
  shutdown `stopFlowExporter` is nil-safe and `flowCancel()` double-call
  is harmless (stdlib CancelFunc is idempotent). (§6.)


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

### Design: register the callback ONCE, swap an immutable bundle via atomic.Pointer

Register a single, stable indirection callback per exporter family at
the point the EventReader is created (boot), reading the *current*
exporter + its *current* resolved `*ExportConfig` from an
`atomic.Pointer` to an immutable bundle. Reconcile builds a new bundle
and `Store`s it — the registered callback never changes, so nothing is
ever appended or leaked on commit, and the read is lock-free.

```go
// flowexport bundle: immutable once built; swapped atomically.
type exporterBundle struct {
    exp *flowexport.Exporter
    ec  *flowexport.ExportConfig // pointer — SOLE 1-in-N counter owner
}
type ipfixBundle struct {
    exp *flowexport.IPFIXExporter
    ec  *flowexport.ExportConfig
}

// daemon.go fields (keep flowExporter/flowCancel/flowWg for shutdown
// stop; ADD):
flowBundle    atomic.Pointer[exporterBundle] // live (exp, ec) for the callback
flowHash      [32]byte                        // v9 config-hash gate
flowCBOnce    sync.Once                        // register the v9 callback once
flowReconMu   sync.Mutex                       // serialize swap vs. shutdown stop
ipfixBundlePtr atomic.Pointer[ipfixBundle]
ipfixHash     [32]byte
ipfixCBOnce   sync.Once
ipfixReconMu  sync.Mutex
```

The stable callback (read is lock-free; no mutex per session-close):

```go
er.AddCallback(func(rec logging.EventRecord, raw []byte) {
    if rec.Type != "SESSION_CLOSE" {
        return
    }
    b := d.flowBundle.Load()
    if b == nil || b.exp == nil || b.ec == nil ||
        !b.ec.ShouldExport(rec.InZone, rec.OutZone) {
        return
    }
    sd := flowexport.SessionCloseData{ ... }   // unchanged extraction
    b.exp.ExportSessionClose(rec, sd)
})
```

`flowReconMu` serializes the reconcile swap against the shutdown
`stopFlowExporter` (both touch `flowCancel`/`flowWg`); it is NOT held
across the lock-free callback read. `b.ec` is a `*ExportConfig` because
the exporter never reads `sampleCounter` (only the callback's
`ShouldExport` does) — the daemon-held `ec` is the sole 1-in-N counter
owner. The exporter's cancel is derived from `d.daemonCtx`
(`flowCancel = WithCancel(d.daemonCtx)`), mirroring `reconcileRPM`; the
goroutine dies only via the explicit `flowCancel()` in the swap /
shutdown stop.

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
3. Compute a content hash over the **resolved `*ExportConfig`** (AFTER
   `SamplingZones` is filled, so a zone-only change is detected). JSON +
   sha256, same helper shape as `rpmConfigHash`. `ExportConfig`'s
   unexported `atomic.Uint64 sampleCounter` is ignored by
   `json.Marshal`; `map[uint16]SamplingDir` marshals with
   numerically-sorted keys → deterministic. A nil `ec` hashes to a
   distinct sentinel (so "configured → removed" is a real change).
   **Two separate hashes** — `flowHash` (v9) and `ipfixHash` — so a
   single-family change never cross-bounces the other family.
4. If hash == stored hash → return false (gated; healthy exporter
   keeps running with its template-refresh + sampling-counter state
   intact — the headline reason for gating).
5. Otherwise: stop the old exporter under `flowReconMu`
   (`flowCancel()` + `flowWg.Wait()` + `Close()`), then if `ec != nil`
   build a fresh exporter (`flowCancel = WithCancel(d.daemonCtx)`,
   start its `Run` goroutine on `flowWg`) and `flowBundle.Store(&{exp,
   ec})`; if `ec == nil`, `flowBundle.Store(&{nil, nil})` and clear
   `flowCancel`. Register the indirection callback exactly once
   (`flowCBOnce`). Store the new hash. `flowReconMu` is released before
   any lock-free callback read can observe a torn pair — the bundle is
   swapped as one atomic pointer.

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

- `daemon_apply.go`: add a step AFTER `updateFlowTrace` (step ~16),
  i.e. BELOW the `compileErrorMustAbortApply` early-return
  (`daemon_apply.go:693-696`): `d.reconcileFlowExporters(cfg)`.
  Deliberate abort-side placement, consistent with reconcileRPM /
  reconcileIPMon / applySyslogConfig: an aborting commit defers the
  exporter change to the next clean commit. (SNMP was deliberately
  placed ABOVE the abort; flowexport is observability and follows the
  RPM/IPMon side — stated as a choice.)
- `daemon_run.go`: the two boot start blocks
  (`836-844` native, `857-858` userspace fallback) each become a single
  `d.reconcileFlowExporters(cfg)` call. **These post-EventReader
  blocks are LOAD-BEARING** — they are what start the exporter at boot,
  because the earlier boot `applyConfig` at `daemon_run.go:671` runs
  while `d.eventReader == nil` (the EventReader is created at `778` /
  `853`), so the apply-path step no-ops at boot. Do NOT delete these.
- **Context:** the exporter goroutine is parented to `d.daemonCtx`
  (set at `daemon_run.go:178`), mirroring `reconcileRPM`. NOTE the
  correction from v1: boot's local `ctx` is the signal child
  (`signal.NotifyContext` at `697-700`), NOT `d.daemonCtx`. After this
  change the goroutine is no longer cancelled by `stop()` at `1471`;
  it dies via the explicit `flowCancel()` in `stopFlowExporter` (still
  called at shutdown, `1475`). `flowCancel = WithCancel(d.daemonCtx)`
  keeps shutdown authoritative.
- `startFlowExporter` / `startIPFIXExporter` are folded into
  `reconcileFlowExporters` (the callback registration moves into the
  `flowCBOnce`/`ipfixCBOnce` path). The shutdown `stopFlowExporter` /
  `stopIPFIXExporter` remain unchanged (still called at shutdown,
  nil-safe).

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
     returns true and `d.flowBundle.Load().exp != nil`.
  2. **Remove-after-boot:** from configured → empty config; reconcile
     returns true and the bundle's exporter is nil (goroutine drained
     — assert via `flowWg.Wait()` returning / a closed exporter).
  3. **Hash-gate (counter-preserving):** identical config twice →
     second returns false; a semantically-equal freshly-built config
     also gated (content hash). Assert the SAME exporter instance is
     still live after the gated call (the counter/template state is
     not reset).
  4. **Change re-applies:** changing collector address/port/rate →
     reconcile returns true and swaps to a new exporter instance.
  5. **No callback leak:** after N reconciles the EventReader has
     exactly one flow callback (+ one ipfix callback). Add a tiny
     test-only accessor `EventReader.CallbackCount()` (under
     `callbackMu.RLock`) in `pkg/logging` — used only by the test;
     mirrors existing test accessors. (The `sync.Once` guarantees this,
     but the test makes the leak class regress-detectable.)
  6. **Apply-wiring regression guard (NON-tautological — MANDATORY):**
     drive the REAL `applyConfigLocked` with a config that enables
     sampling and assert the exporter started. Template:
     `daemon_snmp_reconcile_test.go` — construct
     `&Daemon{applySem: semaphore.NewWeighted(1), dp:
     <runtimeOnlyApplyTestDP>, store: <configStore>, eventReader:
     <non-nil>, daemonCtx: ctx, opts: {NoDataplane:true}}`, call
     `applyConfigLocked(cfgWithSampling)`, assert
     `d.flowBundle.Load().exp != nil`. This FAILS iff the
     `reconcileFlowExporters` call is deleted from `applyConfigLocked`.
     No recorder/seam fallback.
  7. **v9/IPFIX independence:** v9 configured, IPFIX added in a later
     commit → IPFIX starts, the v9 exporter instance is untouched
     (same pointer).
- 5x flake check on the most timing-sensitive new test (goroutine
  start/stop — test 2 or 4).
- `go vet ./pkg/daemon/...` shows NO NEW copylocks beyond the
  pre-existing `NewExporter(*ec)` noise (documented in §9).
- Full `go test ./...` (30 Go packages) green.
- `pkg/flowexport` existing tests still pass.

The exporters bind UDP collector sockets in `NewExporter`
(`dialCollectors`). Tests use a loopback/`127.0.0.1:<port>` collector
(or `:0`) so `NewExporter` succeeds without external dependencies —
verify `dialCollectors` accepts an unreachable UDP collector (UDP
connect does not require a listener). If it requires a resolvable
address, the test config uses `127.0.0.1:9995`.

No iperf / CoS / cluster smoke — the issue explicitly states
control-plane, no dataplane path touched.

## 9. Out of scope (explicitly)

- The `updateFlowTrace` latent callback leak (same class, different
  subsystem) — note it, do not fix it here.
- Adding a per-callback removal API to EventReader — the once-guarded
  indirection makes it unnecessary.
- Any change to NetFlow/IPFIX wire encoding or sampling math.
- HA / session-sync interaction (exporters are node-local).
- **Pre-existing copylocks:** `go vet ./pkg/flowexport ./pkg/daemon`
  already reports copylocks on `NewExporter(cfg ExportConfig)` /
  `NewExporter(*ec)` (ExportConfig embeds `atomic.Uint64`). There is no
  `go vet` CI gate, so these are latent. Changing
  `NewExporter`/`NewIPFIXExporter` to take `*ExportConfig` would fix the
  root cause but is a separate refactor. This PR adds NO new by-value
  `ExportConfig` copy beyond the existing `NewExporter(*ec)`.

## 10. Open questions — RESOLVED by adversarial review

1. **Once-registered indirection vs RemoveCallback API:** indirection
   chosen. Both reviewers confirmed `applySyslogConfig` does NOT touch
   `er.callbacks` / `ClearCallbacks`, so the once-indirection is safe
   and avoids API churn. RESOLVED.
2. Is hashing the **resolved `*ExportConfig` JSON** safe given the
   unexported `atomic.Uint64 sampleCounter` (ignored by
   `json.Marshal`)? RESOLVED — both reviewers verified `json.Marshal`
   ignores `sampleCounter` and sorts the `map[uint16]` keys; hash the
   resolved `ec` (after zones filled), two separate hashes.
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
