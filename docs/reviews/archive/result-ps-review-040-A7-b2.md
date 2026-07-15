# Triage Result: ps-review-040-A7-b2

- **Subsystem**: Area A7 batch 2 — daemon host-tunables / linksetup / VRRP-self-recover
  / FRR render+status / IPsec crypto+IKE / networkd / routing (interfaces, routes,
  rules, tunnels/keepalive). 15 modules; only Module 1 produced a finding.
- **Base == master?** NO. Review base `0ebdb74b` is **397 commits behind**
  `origin/master`. Re-verified every cited symbol against current master.
- **Master SHA**: `95b33d49634d56086269a62a92e213dae7926f88`
- **Repo**: real bpfrx (`/home/ps/git/bpfrx`, github psaab/xpf). No avacado-fork
  path references.
- **Outcome counts**: 1 finding total → **1 GENUINE-RESIDUAL (downgraded to LOW;
  finding rated Medium)**, 0 already-fixed, 0 confabulated, 0 dup. (14 modules
  were negative/"sound" sweeps — no claims to triage.)

---

## Finding 1 — Data race on `priorHostTunables` maps: shutdown-restore vs a concurrent apply

**Disposition: GENUINE-RESIDUAL, but LOW (finding overstated at Medium; its primary
trace is disproven).** Lane: go.

### Symbol check (not confabulated)
`pkg/daemon/host_tunables_daemon.go` exists on master and is **unchanged since the
#801/#1636 work** (`b9698401a`, `f277f60d7`, `fc3ffe3ca`) — NOT touched by the
#4517–#4685 hardening range. Cited lines match:
- `applyStep0TunablesWith`: `priorTunablesMu.Lock()`@96 / `Unlock()`@99, then it
  mutates/reads `prior.mlx5Adaptive` + `prior.neighRetrans` **outside** the lock
  (via `applyCoalescence`/`applyNeighRetransTime`).
- `restoreStep0TunablesOnShutdown`@195: `Lock()`@196, reads `prior`, sets
  `d.priorTunables=nil`, `Unlock()`@201, then reads `len(prior.mlx5Adaptive)`,
  `len(prior.neighRetrans)`, and iterates `prior.mlx5Adaptive` **outside** the lock.

The structural claim is **factually correct**: the mutex protects only the pointer
swap, not the map contents; both functions can hold the same `*priorHostTunables`
pointer and touch its maps without mutual exclusion. `newPriorHostTunables` uses
plain `map[string]...` (not concurrent-safe). Restore does NOT take `applySem`.

### Why the finding's PRIMARY trace is DISPROVEN (config commit cannot race restore)
The finding's headline trigger is "a config commit executing `applyStep0TunablesWith`"
racing shutdown restore. On current master that path is **drained before restore
runs**. `restoreStep0TunablesOnShutdown` is the LAST teardown step
(`daemon_run.go:1855`), and every commit/apply source is stopped before it:
- **gRPC commits**: handler runs in the wg-tracked server goroutine
  (`daemon_run.go:1542`); on ctx cancel `grpcSrv.Run` calls `srv.GracefulStop()`
  (`grpcapi/server.go:257`), which blocks until in-flight RPCs finish. Joined by
  `wg.Wait()` at `daemon_run.go:1710` — long before :1855.
- **HTTP commits**: wg-tracked (`daemon_run.go:1411`); `http.Server.Shutdown`
  (`api/server.go:574-576`) drains in-flight requests; same `wg.Wait()` join.
- **Cluster peer SyncApply**: `d.sessionSync.Stop()` @1829, before restore.
- **Dynamic feeds apply**: `d.feeds.StopAll()` @1725; **event engine** apply:
  `d.eventEngine.Close()` (drains in-flight, #2157) @~1740; **ip-monitoring**:
  `d.ipmon.Stop()` @1748 — all before restore.
- **In-process CLI commit / auto-rollback**: run in the main goroutine, which has
  already left the shutdown `select` at the top of the teardown.
- Additionally `d.applyCancel()` @1705 aborts any abortable in-flight apply at its
  coarse boundaries.

So NO gRPC/HTTP/cluster/feed/event/CLI commit can be mid-`applyStep0TunablesWith`
when restore runs. The finding's refutation section ("gRPC handlers / telemetry
queries / event callbacks might still run") does not survive the actual teardown
ordering — telemetry/status RPCs never touch `priorTunables`, and the callback/RPC
goroutines are all joined or Stop()'d first.

### Why a residual STILL exists (the one un-drained apply source)
There is exactly one apply source the shutdown sequence does **not** drain: the
**DHCP client callback**. `onDHCPAddressChange` (`daemon_dhcp.go:76`) calls
`d.applyConfig(activeCfg)` @90 on the dataplane-relevant branch, which runs
`applyConfigLocked` → `applyTailReconciles` → `applyStep0Tunables`. The DHCP
renewal goroutines run on `context.WithCancel(context.Background())`
(`dhcp.go:332`) — **not** the daemon `ctx`, **not** wg-tracked — and there is **no
`d.dhcp.StopAll()` anywhere in the shutdown sequence** (grep confirms only
`feeds`/`rpm` StopAll exist in pkg/daemon). `d.applyConfig` also uses
`context.Background()` for both the semaphore and `applyConfigLocked`
(`daemon_apply.go:109,115`), so `applyCancel()` does NOT abort it. A DHCP lease
change that lands during the shutdown window can therefore run `applyStep0Tunables`
concurrently with `restoreStep0TunablesOnShutdown`.

### Why it is LOW, not Medium (materiality bounding)
The race only becomes a **fatal Go map read/write throw** when the shutdown-window
apply performs a map **WRITE**. All the capture helpers are first-apply-wins
(`captureMlx5Coalesce`/`captureNeighRetrans` — no-op if the key is already present;
`coalescence.go` MIN1 drift check only READS the map). In steady state every key
was captured at the startup apply, so a routine DHCP-renewal apply only READS the
maps — and a concurrent map **read vs read** (restore's `len`/range) is safe in Go.
A genuine write during the window requires a **newly-appearing interface / neigh
table** (interface churn creating an uncaptured key) coinciding with the sub-second
teardown window. Preconditions stack: (a) a DHCP-configured **dataplane** interface
(mgmt-only fxp0 takes the non-`applyConfig` branch), (b) a lease **address change**,
(c) `dhcpLeaseChangeRequiresRecompile` true, (d) a new capture key at that apply,
(e) timing overlap with restore's map read after it nil'd `d.priorTunables`.
The field-reassignment branches (`prior.governors=...`, `prior.neighRetrans=...`)
that would race on the map-pointer word are `claim-host-tunables` toggle / non-
userspace-DP edges, not the default DHCP path. Impact when it does fire: a panic
during an **already-terminating** process (restore is the final step, after
`dp.Teardown`) plus a skipped pre-xpf tunables restore (coalescence/neigh-retrans
left as xpf set them). Not attacker-reachable, no persistent-state corruption.

### Fix direction (cheap)
Simplest correct fix: have `restoreStep0TunablesOnShutdown` acquire `d.applySem`
(capacity-1) before touching the snapshot, so it serializes against every apply
source including the un-drained DHCP path — matching the lock discipline the rest
of the apply path already uses. Alternatively hold `priorTunablesMu` across the
map operations in both functions, or call `d.dhcp.StopAll()` in the shutdown
sequence before restore. Filing as LOW is appropriate.

### Dedup
Novel; not present in the #4517–#4685 range (file untouched there) and no matching
prior issue found. Reported as the single genuine residual.
