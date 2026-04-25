# PR: #846 applyConfig serialization with daemon-level mutex

## Goal

Eliminate the cross-step interleaving race in `applyConfig` by holding
a single `applyMu sync.Mutex` for the entire call. Two concurrent
callers no longer overlap across VRF / tunnel / FRR-reload steps.

## Context

`applyConfig` (`pkg/daemon/daemon.go:1569`) is invoked from at least
9 distinct entry points (HTTP / gRPC commits, cluster sync recv,
DHCP callbacks, config-poll, dynamic-feed callbacks, event-engine,
in-process CLI commits, CLI auto-rollback). All of them call
`d.applyConfig(cfg)` directly, with no synchronization.

#844 added `d.vrfsMu` covering only the VRF reconcile phase.
That's a strict subset. This PR adds the broader lock.

## Approach

### Scope

Add a single `applyMu sync.Mutex` to the `Daemon` struct. The lock is
acquired at the top of `applyConfig` and held until the function
returns. All entry points call `applyConfig` unchanged; the mutex is
internal.

### Implementation

(Codex round-1 BLOCKER 8: plain `Lock()` ignores caller context. An
HTTP client that times out still queues an apply forever. Use a
context-aware acquire pattern with explicit upstream propagation.)

The cleanest pattern: keep `applyConfig(cfg)` as the synchronous
entry signature for compatibility (DHCP / cluster sync goroutines
don't have a request context), but add a context-aware sibling
`applyConfigCtx(ctx, cfg)` that the HTTP and gRPC handlers use:

```go
type Daemon struct {
    // ... existing fields ...
    applyMu sync.Mutex
}

// applyConfig — backwards-compatible synchronous entry. Callers
// without a request context (DHCP, cluster sync goroutine, event
// engine, CLI auto-rollback) use this. They block until the lock
// is released.
func (d *Daemon) applyConfig(cfg *config.Config) {
    d.applyMu.Lock()
    defer d.applyMu.Unlock()
    d.applyConfigLocked(cfg)
}

// applyConfigCtx — context-aware entry for HTTP/gRPC commit
// handlers. If the caller's context is canceled before we can
// acquire the lock, returns ErrApplyCanceled without queuing the
// apply. Body is identical otherwise.
func (d *Daemon) applyConfigCtx(ctx context.Context, cfg *config.Config) error {
    if !d.tryLockCtx(ctx, &d.applyMu) {
        return ErrApplyCanceled
    }
    defer d.applyMu.Unlock()
    d.applyConfigLocked(cfg)
    return nil
}

func (d *Daemon) tryLockCtx(ctx context.Context, mu *sync.Mutex) bool {
    acquired := make(chan struct{})
    go func() {
        mu.Lock()
        close(acquired)
    }()
    select {
    case <-acquired:
        return true
    case <-ctx.Done():
        // Lock is being acquired in a goroutine; it'll release
        // when applyConfig finishes. Caller bails out.
        go func() {
            <-acquired
            mu.Unlock()
        }()
        return false
    }
}

// applyConfigLocked — the existing applyConfig body, unchanged.
// Only callable with d.applyMu held.
func (d *Daemon) applyConfigLocked(cfg *config.Config) {
    // ... existing body of applyConfig() moves here ...
}
```

HTTP and gRPC handlers switch from `d.applyConfig(cfg)` to
`d.applyConfigCtx(ctx, cfg)`, propagating their request context.
Other callers (DHCP, cluster sync goroutine, event engine, CLI
auto-rollback) continue using `applyConfig(cfg)` — they're not
context-bound.

The `tryLockCtx` helper spawns a goroutine that will eventually
acquire the lock if the caller cancels — but that goroutine does NOT
run the apply body. It only acquires-then-releases the lock to keep
the mutex's invariant balanced. The canceled caller's apply is
DROPPED ON THE FLOOR. See the explicit "tryLockCtx semantics"
section below for the full contract.

### Why this is safe

- `applyConfig` is already low-frequency: config commits, DHCP
  events, peer config sync, feed callbacks, etc. — none are hot
  paths. Lock contention is negligible.
- Lock-held duration: a typical apply is ~50–500 ms (FRR reload is
  the dominant cost). Two concurrent commits queue rather than
  interleave; the operator-visible effect is "second commit waits"
  instead of "second commit corrupts kernel state."
- No callbacks INSIDE applyConfig re-enter applyConfig:
  - DHCP callbacks call applyConfig from goroutines, never from
    inside applyConfig. Verify by reading the call sites.
  - Cluster-sync receive runs in a separate goroutine.
  - Event engine triggers from a goroutine.
  Verify by grep: any function that holds applyMu must not call
  back into applyConfig synchronously. If found, the inner caller
  must drop the lock.

### Reentrancy verification

Search before coding:

```bash
grep -rn "applyConfig\|d\.applyMu" pkg/daemon/ pkg/cli/ pkg/api/ pkg/grpcapi/ pkg/cluster/ pkg/eventengine/
```

Walk every callsite and confirm none calls `applyConfig` from inside
the lock-held region. If a re-entry is found, the plan adjusts (e.g.
release lock around the inner call, or change the caller to async).

The issue body lists 9 entry points; expect them all to be top-level.

### Files touched

(Codex round-2 fix: full handler + wiring chain enumerated.)

| File | Change |
|---|---|
| `pkg/daemon/daemon.go` | Add `applyMu sync.Mutex`. Split `applyConfig(cfg)` into `applyConfig(cfg)` (sync wrapper) + `applyConfigCtx(ctx, cfg) error` (context-aware) + `applyConfigLocked(cfg)` (the existing body). New `tryLockCtx` helper. New `ErrApplyCanceled`. |
| `pkg/daemon/daemon_ha_sync.go` | Cluster sync receive uses sync `applyConfig` (no caller context). No change beyond verification. |
| `pkg/grpcapi/server.go` | `Config.ApplyFn` signature changes to `func(context.Context, *config.Config) error`. Daemon wires `applyConfigCtx` here. |
| `pkg/grpcapi/server_config.go` | Commit handler propagates the request `ctx` to ApplyFn; on `ErrApplyCanceled`, return gRPC `codes.Canceled` (or `codes.DeadlineExceeded` if `ctx.Err() == DeadlineExceeded`) so the client sees a clean reject rather than a hang. |
| `pkg/api/server.go` | Same Config-level signature change. |
| `pkg/api/handlers.go` | Commit handler propagates `r.Context()` to ApplyFn; on `ErrApplyCanceled`, return HTTP 503 (or 408 on deadline). |
| `pkg/cli/cli.go` | In-process CLI uses `d.applyConfig(cfg)` — no context, no behavior change. |
| `pkg/eventengine/engine.go` | Event engine fires from a goroutine — uses sync `applyConfig`. No context, no change. |

### tryLockCtx semantics — explicit

(Codex round-2 fix: clarify the "what happens on cancel" path.)

When `applyConfigCtx(ctx, cfg)` returns `ErrApplyCanceled`, the
canceled caller's apply **never runs**. The body of `applyConfig`
is NOT executed for that caller. Only the apply that already held
the lock at cancel time continues to completion (it cannot be
cancelled mid-stride because the body of applyConfig is not
cancellation-safe — kernel route writes, FRR reload, etc.).

The `tryLockCtx` goroutine that "eventually acquires and releases
the lock" only does so to keep the mutex's invariant (lock count
matched). It does NOT run the apply body. The cancel goroutine
just acquires-then-releases to give back the slot:

```go
case <-ctx.Done():
    go func() {
        <-acquired
        mu.Unlock()  // release the slot we caused to be held
    }()
    return false
```

Net effect: a context-cancelled commit is observably equivalent to
"the commit never happened" — the canceled config is dropped on the
floor. The operator sees an explicit error and knows to re-issue.

### Test strategy

(Codex round-1 BLOCKER 5: instrumenting `applyConfigLocked` directly
doesn't catch caller-driven deadlocks. Add a real-caller-driven test
in addition to the sentinel.)

1. **Sentinel test (mutex correctness)**: instrument
   `applyConfigLocked` body with an atomic in-progress counter.
   Run with `-race`. Assert max-concurrent observed == 1.
2. **Real-caller deadlock test**: spin up an in-process daemon test
   harness that exposes both the HTTP and gRPC commit handlers.
   Fire 5 concurrent commits via the HTTP handler + 5 via the gRPC
   handler with subtly different configs. Assert each returns
   within 30s (no deadlock), each completes either successfully or
   with `ErrApplyCanceled`, and the post-commit state matches the
   last successful caller's config.
3. **Context-cancel test**: HTTP caller posts a commit with a
   context canceled after 100ms while another commit is in
   progress (5s applyConfig blocked on FRR reload). Assert the
   second caller gets `ErrApplyCanceled` quickly and the in-flight
   first apply still completes.
4. **Existing test suite**: `make test` — no regressions.
5. **Failover-during-commit**: `make test-failover` (cluster) +
   trigger a CLI commit during the failover window — peer-config-
   sync receive should queue behind any in-progress local apply.

### Forwarding validation

(Codex round-1 BLOCKER 7: applyConfig recompiles dataplane, RETH
state, FRR rules, ip rules. Forwarding IS at risk during the lock
window.)

- **Pre/post commit**: deploy on `bpfrx-fw` (standalone), run a
  benign commit (whitespace-only config change), verify ping and
  iperf3 (`-t 5`, ≥18 Gbps) still pass post-commit.
- **Concurrent apply + iperf3**: start a 30s iperf3, mid-stream
  trigger 3 concurrent CLI commits. Verify iperf3 completes
  without TCP retransmits going crazy (acceptable: a few hundred
  retransmits during the apply window; unacceptable: TCP flows
  collapse).
- **FRR reload tail**: a long apply (FRR reload up to 15s) holds
  the mutex. Verify forwarding sessions remain stable across the
  whole window.

### Race-test design

```go
func TestApplyConfigSerialized(t *testing.T) {
    d := newTestDaemon(t)
    var wg sync.WaitGroup
    var concurrent int32
    var maxConcurrent int32
    for i := 0; i < 10; i++ {
        wg.Add(1)
        go func(i int) {
            defer wg.Done()
            // Hijack one step of applyConfig to assert no overlap.
            // Easier: instrument applyConfig with a sentinel that
            // increments on enter, decrements on exit, atomically
            // tracks max concurrent. After the test, max must be 1.
            d.applyConfig(testConfigVariant(i))
        }(i)
    }
    wg.Wait()
    if atomic.LoadInt32(&maxConcurrent) > 1 {
        t.Errorf("applyConfig was reentered: max concurrent = %d", maxConcurrent)
    }
}
```

Implementation note: the sentinel goes in a test-only build-tag-gated
file or behind a debug counter that's exposed only in tests.

## Alternatives considered

1. **Worker goroutine + channel**: serialize via a queue rather than
   a mutex. More invasive (changes the call shape from sync to
   request-then-wait). Rejected unless the simple mutex turns out to
   create deadlocks during reentrancy review.
2. **Per-step locks (vrfMu, frrMu, ipsecMu, etc.)**: finer-grained
   but doesn't fix the cross-step interleave the issue describes.
   Rejected.
3. **Defer lock until inner critical sections**: doesn't prevent
   interleave; rejected.

## Refs

Closes #846. Identified during #844/#845 (`vrfsMu`) review.
