# Fabric Cross-Chassis Forwarding — Design & Bug Report

## Problem Statement

When fw0 reboots and preempts back to MASTER, a **2.1-second asymmetric routing
window** exists where fw0 is WAN MASTER but not yet LAN MASTER. During this gap:

1. WAN return traffic arrives at fw0 (it owns the WAN RETH VIP)
2. `bpf_fib_lookup` fails for LAN destinations (fw0 doesn't have the LAN route yet)
3. `META_FLAG_KERNEL_ROUTE` fallback hands post-NAT packets to the kernel
4. Kernel drops the packet (no route to the original LAN destination)
5. If a TCP RST traverses this path, BPF conntrack transitions the session to
   `SESS_STATE_CLOSED` — **permanently poisoning it**

**Timeline from fw0 logs (pre-fix):**
```
15:11:54.344 - vrrp: MASTER ge-0-0-1.50 group=101 (WAN)
15:11:56.485 - vrrp: MASTER ge-0-0-0 group=102 (LAN)   ← 2.1s gap
15:11:57.013 - SESSION_CLOSE src=172.16.50.6:1027 action=deny
```

## Solution — Three-Layer Fix

### Fix 1: BPF Fabric Cross-Chassis Redirect (Primary)

**Concept:** When `bpf_fib_lookup` returns `NO_NEIGH` or `NOT_FWDED` for an
existing session, redirect the **original (pre-NAT) packet** to the peer via the
fabric link instead of falling back to kernel routing.

**Why original (pre-NAT) packet?** At the xdp_zone stage, only meta fields have
been modified by dnat_table pre-routing — actual packet bytes are untouched.
Redirecting the raw packet lets the peer process it through its full pipeline
(dnat_table → session → FIB → NAT → forward) without double-NAT issues.

**Why this works on the peer:** Established sessions skip policy evaluation
(conntrack fast-path), so the zone mismatch (arriving on control zone fab0
instead of wan/lan) doesn't matter.

**Components:**

| File | Change |
|------|--------|
| `bpf/headers/xpf_maps.h` | `fabric_fwd_info` struct + `fabric_fwd` ARRAY map (1 entry) |
| `bpf/headers/xpf_helpers.h` | `try_fabric_redirect()` inline helper |
| `bpf/headers/xpf_common.h` | `GLOBAL_CTR_FABRIC_REDIRECT = 26` |
| `bpf/xdp/xdp_zone.c` | Call `try_fabric_redirect()` in NO_NEIGH + NOT_FWDED paths |
| `pkg/dataplane/types.go` | Go `FabricFwdInfo` struct matching C layout |
| `pkg/dataplane/maps.go` | `UpdateFabricFwd()` method on eBPF Manager |
| `pkg/dataplane/loader_ebpf.go` | Register `fabric_fwd` map from zoneObjs |
| `pkg/dataplane/dataplane.go` | `UpdateFabricFwd()` in DataPlane interface |
| `pkg/daemon/daemon.go` | `populateFabricFwd()` goroutine in `startClusterComms()` |

**Anti-loop protection:** `try_fabric_redirect()` checks
`ctx->ingress_ifindex == ff->ifindex` — packets arriving on the fabric interface
are never redirected back, preventing infinite loops.

**Map population:** `populateFabricFwd()` runs as a goroutine, resolving:
- Fabric interface ifindex + local MAC via `netlink.LinkByName()`
- Peer MAC from ARP table via `netlink.NeighList()` (retries up to 30x at 2s intervals)

**Event-driven refresh (`monitorFabricState`, #124):** a sibling goroutine
subscribes to netlink link + neighbor updates and calls `triggerFabricRefresh()`
when a fabric interface or the fabric peer's neighbor entry changes, so the
`fabric_fwd` map is re-resolved sub-second instead of waiting for the 30s
`populateFabricFwd` ticker. This monitor is resilient to netlink receive-buffer
overflow (ENOBUFS): a recoverable close of EITHER the link or neighbor update
channel resubscribes (via `runFabricStateSubscription`) after a 2s backoff and
re-syncs the fabric state, rather than dying permanently, and it closes BOTH
netlink sockets on every path so neither fd leaks (#4031). It exits only on
context cancellation.

**Per-fabric refresh channels (dual-fabric, #4038):** in a redundant
`fabric-link` + `fabric-link-1` cluster the fab0 loop (`populateFabricFwd`)
and the fab1 loop (`populateFabricFwd1`) each own a refresh channel
(`fabricRefreshCh` / `fabricRefreshCh1`). `monitorFabricState` does not tag
events per fabric, so `triggerFabricRefresh()` signals BOTH channels (non-
blocking, capacity 1) and every configured fabric re-resolves on any event —
matching the synchronous `RefreshFabricFwd()`, which already refreshes both
entries. A single shared channel was wrong: a Go send is received by exactly
one waiting goroutine, so one trigger woke only fab0 OR fab1 (whichever won
the receive) and the other fabric's link/neighbor event was dropped until its
30s safety-net tick — degrading the second fabric's sub-second convergence.
A single-fabric cluster leaves `fabricRefreshCh1` nil; the non-blocking send
falls through its `default` arm, so `triggerFabricRefresh()` is a no-op for
the absent fabric.

### Fix 2: VRRP Coordinated Preemption (Defense-in-depth)

**Concept:** All VRRP instances preempt simultaneously when `ReleaseSyncHold()`
fires after bulk session sync completes, minimizing the asymmetric window from
seconds to milliseconds.

| File | Change |
|------|--------|
| `pkg/vrrp/instance.go` | `preemptNowCh` channel + `triggerPreemptNow()` + select case in `run()` |
| `pkg/vrrp/manager.go` | Call `triggerPreemptNow()` in `ReleaseSyncHold()` |
| `pkg/vrrp/vrrp_test.go` | 3 new tests for coordinated preemption |

### Fix 3: BPF RST State Protection (Defense-in-depth)

**Concept:** In `handle_ct_hit_v4/v6`, when `META_FLAG_KERNEL_ROUTE` is set, skip
the RST→CLOSED state transition. The kernel may drop the packet (no route), so
the RST never reaches the peer — don't poison session state based on a packet
that won't be delivered.

| File | Change |
|------|--------|
| `bpf/xdp/xdp_conntrack.c` | Skip state→CLOSED when `meta->meta_flags & META_FLAG_KERNEL_ROUTE` |

## Bugs Found and Resolved

### Bug 1: `fabric_fwd` map not registered in Go loader

**Symptom:** `cluster: failed to update fabric_fwd map: fabric_fwd map not found`
repeated every 2 seconds on both nodes.

**Root cause:** The `fabric_fwd` ARRAY map is defined in `bpf/headers/xpf_maps.h`
and compiled into the xdp_zone ELF object. The bpf2go codegen creates
`zoneObjs.FabricFwd`, but `loader_ebpf.go` did not register it in `m.maps[]`
or add it to `MapReplacements`.

**Fix:** Added two lines to `loadAllObjects()`:
```go
m.maps["fabric_fwd"] = zoneObjs.FabricFwd
replaceOpts.MapReplacements["fabric_fwd"] = zoneObjs.FabricFwd
```

**Commit:** `5044ec1`

### Bug 2: (Pre-existing) WAN gateway unreachable in test environment

**Symptom:** `ping 1.1.1.1` and `ping 172.16.50.1` fail from fw0 and
cluster-lan-host.

**Status:** Pre-existing test environment issue — the upstream router at
172.16.50.1 is not present in the Incus bridge setup. Not related to the fabric
forwarding changes. LAN connectivity (ping 10.0.60.1) works correctly.

## Verification Results

| Check | Result |
|-------|--------|
| `make generate` | 14 BPF programs compiled (9 XDP + 5 TC) |
| `make test` | All tests pass (including 3 new VRRP tests) |
| `make build` + `make build-ctl` | Clean build |
| `make cluster-deploy` | Deployed to both nodes |
| Cluster status | fw0 primary, fw1 secondary, all RGs healthy |
| `fabric_fwd` map | Populated on both nodes (`fabric cross-chassis redirect enabled`) |
| LAN connectivity | Working (cluster-lan-host → 10.0.60.1) |
| WAN connectivity | Pre-existing test env limitation (no upstream router) |

## Commits

1. `dae87cb` — Fix TCP session death on VRRP failback: fabric cross-chassis redirect
   (46 files, 459 insertions, 29 deletions)
2. `5044ec1` — Register fabric_fwd BPF map in loader to fix map-not-found error
   (1 file, 2 insertions)

## Architecture Reference

```
                    ┌─────────────────┐
                    │   WAN Router    │
                    │  172.16.50.1    │
                    └────────┬────────┘
                             │
              ┌──────────────┴──────────────┐
              │                             │
    ┌─────────┴─────────┐       ┌───────────┴───────────┐
    │      fw0          │       │        fw1            │
    │  ge-0-0-1.50      │       │  ge-7-0-1.50          │
    │  (WAN MASTER)     │       │  (WAN BACKUP)         │
    │                   │ fab0  │                       │
    │  ──────────────── ├───────┤ ──────────────────    │
    │                   │       │                       │
    │  ge-0-0-0         │       │  ge-7-0-0             │
    │  (LAN BACKUP*)    │       │  (LAN MASTER*)        │
    └─────────┬─────────┘       └───────────┬───────────┘
              │                             │
              └──────────────┬──────────────┘
                             │
                    ┌────────┴────────┐
                    │  LAN Hosts      │
                    │  10.0.60.0/24   │
                    └─────────────────┘

    * During the 2.1s failback window

    Normal path:   WAN → fw0 → FIB → LAN
    Failback path: WAN → fw0 → FIB FAIL → fabric → fw1 → FIB → LAN
```

## Userspace dataplane: FabricRedirect unsendable fail-closed (#1946)

The Rust AF_XDP helper resolves a `FabricRedirect` disposition
(`resolve_fabric_redirect`, `userspace-dp/src/afxdp/forwarding/mod.rs`)
into an L2 redirect: re-header the original packet with the fabric
peer/local MACs and TX it out the fabric parent so the **peer** runs it
through its full pipeline. A FabricRedirect frame is therefore a
cross-chassis L2 redirect — it is **never** a packet for the local kernel
FIB.

There are two rare conditions where the helper cannot TX a FabricRedirect
to the peer, across both the desc-frame path and the Prebuilt fast path
(an embedded-ICMP NAT-reversed error whose resolution turned into a
fabric redirect via `finalize_embedded_icmp_resolution`):

1. **No XSK binding on the fabric parent** — the bind is not yet ready or
   `bind()` failed (`tx/dispatch/mod.rs`, the
   `resolve_pending_forward_target_binding` `None` arm — both the
   desc-frame fallback and the Prebuilt fast path).
2. **Build/enqueue failure** — the fabric parent binding exists but the
   forward-frame build or TX-ring enqueue failed
   (`handle_forward_build_failure`, `tx/dispatch/slow_path.rs`, for the
   desc-frame path; the Prebuilt local-enqueue failure arm in
   `tx/dispatch/mod.rs`).

In all of these the frame is **dropped fail-closed** and counted on the
per-binding `fabric_redirect_unsendable_drops` counter (surfaced on
`BindingStatus`; Go `FabricRedirectUnsendableDrops`), with a distinct
exception reason (`fabric_redirect_no_binding` vs
`fabric_redirect_build_failed`) for path observability. It is **not**
reinjected to the local kernel slow path.

Reinjecting a FabricRedirect locally would re-introduce exactly the
wrong-path / session-poisoning hazard this whole mechanism exists to
avoid (the kernel-route fallback in the asymmetric-routing window), plus
the slow-path reinject primitive strips L2 and applies NAT — wrong for a
fabric redirect that wants the original L2 frame, pre-NAT. This is the
same class of fail-closed gate as the #1873 R-C
`tunnel_encap_unresolved_drops` tunnel-reinject guard.

Before #1946 this was asymmetric: an `Owned` (GRE-decapped copy) no-
binding frame was raw-reinjected while a `Live` (raw in-UMEM) one was
silently dropped by the filtered `maybe_reinject_slow_path` wrapper
(`FabricRedirect` is excluded by `is_slow_path_eligible`), and the
build-failure path raw-reinjected both. #1946 makes all of them drop
fail-closed + count.

## Standby session retention on the userspace wheel (#2120)

Fabric cross-chassis forwarding keeps a flow alive across a VRRP
failback, but it only helps if the new primary still HAS the synced
session to redirect for. The standby must therefore RETAIN its synced
sessions until it is promoted.

In the eBPF era the Go conntrack GC's `IsLocalPrimary` gate kept the
standby from aging synced sessions. After the eBPF retirement
(#1373/#1476) the Go GC is `SkipSweep`'d in userspace mode (its
`IsLocalPrimary` gate is dead code) and expiry moved to the Rust
per-worker timer wheel, which had NO standby gate — so the standby
silently reaped long-lived peer-synced sessions at ~300 s (TCP idle) with
no local refresh, and the newly-promoted primary then dropped their return
traffic as a brand-new connection (#131 reintroduced).

#2120 restores the contract as a **per-RG standby retention gate in the
wheel** (`userspace-dp/src/session/expire.rs`): the standby HOLDS a
peer-synced session for an RG it does not currently FORWARD
(`HAGroupRuntime::is_forwarding_active`, the same lease-backed predicate
the fabric-redirect path trusts), self-heals it on promotion via the
`rg_epochs` edge (including the node-level `rg_epochs[0]` for
`owner_rg_id == 0` fabric/reverse entries), and reaps it at a bounded
`min(3 × timeout, ~7 d)` ceiling if a primary delete is lost. The epoch
bump moved BEFORE `rg_runtime.store` in `afxdp/ha.rs::update_ha_state` so
a worker that sees the active RG always sees the bumped epoch (airtight
self-heal). The control-plane sync sweep is unchanged — retention is the
wheel's job, not the sweep's (see `pkg/cluster/README.md` and
`userspace-dp/src/session/README.md` "Standby retention"). This keeps
#270's empty-sweep back-off and avoids the >1/s control-socket contention
CLAUDE.md warns against.

## Fabric-link build/refresh observability + persistence (#3773)

A fabric redirect can only fire if a `FabricLink` was actually built for
the parent interface. Two resolution passes build them:

- **snapshot build** — `populate_fabrics`
  (`userspace-dp/src/afxdp/forwarding_build/fib.rs`), run for every
  `build_forwarding_state` (config apply + route-churn `bump_fib`).
- **runtime refresh** — `resolve_fabric_links_from_snapshots`
  (`userspace-dp/src/afxdp/forwarding/mod.rs`), driven by the Go daemon's
  `SyncFabricState`/`refreshFabricFwd` (`update_fabrics` control verb) once
  ARP/NDP resolves the peer MAC that was unresolved at initial build.

### M13 — skipped fabric links are counted + named (was a silent `continue`)

Before #3773 each pass dropped a fabric link on a bare `continue` when
`parent_ifindex <= 0`, the `peer_address` was unparseable, the `local_mac`
was unresolvable, or the `peer_mac` was unresolvable — **no counter, log,
or status**. An HA cross-chassis fabric link that silently failed to
install (and therefore silently did not forward) was invisible; the
operator had no way to see an unresolved fabric.

Both passes now route the skip-vs-install decision through the shared
`build_fabric_link_or_skip` classifier, which partitions skips into two
cumulative diagnostic atomics (`forwarding/mod.rs`):

- **`FABRIC_LINK_SKIPPED_MALFORMED`** — an invalid parent ifindex, an
  unparseable peer address, or a **non-empty** local/peer MAC string that
  failed to parse. A config/environment fault that will not self-heal.
  Surfaced as `xpf_userspace_fabric_link_skipped_malformed_total`.
- **`FABRIC_LINK_UNRESOLVED_PEER`** — an **empty** peer/local MAC field
  still awaiting neighbor/interface resolution: the expected transient of
  the late-resolution `SyncFabricState` path (peer MAC empty until ARP/NDP
  resolves). Briefly non-zero at startup is normal; a persistently
  climbing value means a fabric peer is not resolving. Surfaced as
  `xpf_userspace_fabric_link_unresolved_peer_total`.

Fabric is an HA *optimization*, not enforcement, so a malformed link is
**skipped-with-visibility, not fail-closed-whole-snapshot** — the rest of
the forwarding state still applies (a single bad fabric stanza must not
blackhole the whole dataplane). This mirrors the #3771 M12
`NEIGHBOR_UNKNOWN_STATE_SKIPPED` diagnostic-atomic pattern.

The counters quantify; a named journal line qualifies. Each build/refresh
records its skips (by fabric name + reason) in
`ForwardingState.fabric_skips`, and `log_fabric_skip_transition`
(`coordinator/mod.rs`, mirroring `log_wg_endpoint_set_transition`) emits
`fabric skip set changed (<path>): [...] => [...]` **only when the set
changes** — so a persistently unresolved/malformed fabric logs ONCE when
it first appears (or changes reason), not on every 30s `SyncFabricState`
tick or route-churn `bump_fib`. The `snapshot-refresh` path prunes a skip
whose parent was re-added by the preserved-fabric merge (a link kept from
the prior resolved set is not reported as skipped).

### L4 — the `update_fabrics` refresh is now persisted

`update_fabrics` (`server/handlers/mod.rs`) was the only mutating control
verb that neither updated the stored snapshot nor set `persist_state`, so
a late-resolved peer/local MAC lived **only** in the coordinator's
in-memory forwarding state. The published state file (read by the Go
control plane's `show` surface, and the last record a consumer sees) kept
the stale apply-time (unresolved) fabric MACs.

The handler now folds the freshly-resolved `FabricSnapshot`s into the
stored snapshot and flags a write **only when the set actually changed**
— so the 30s periodic refresh does not rewrite the state file on every
unchanged tick.

**Restart continuity is explicit and is provided by the Go control plane,
not this file.** The helper starts with `snapshot: None`
(`server/lifecycle.rs`) and never self-restores from the state file; on
restart the daemon re-applies the full snapshot and re-runs
`populateFabricFwd` (500 ms fast retries → 30 s periodic), which
re-resolves and re-syncs the fabric MACs within seconds. The persisted
fabric set is therefore the **observability snapshot** (so `show` reflects
the resolved truth), not the restore source.

## Rate-based flood screens are not re-counted on fabric-redirected traffic (#4155)

A packet that ingresses the **non-owner** node for a session the RG **owner**
owns is screened on the ingress node and then fabric-redirected to the owner
(the Fix 1 path above). Before #4155 the owner **re-ran** the full screen stage
on that redirected packet, so the **rate-based flood counters** (`icmp-flood`,
`udp-flood`, `syn-flood`) counted the **same packet twice** against the
per-zone / per-destination flood thresholds. A legitimate high-pps synced
session could then false-trip a flood `Drop` on the owner — dropping exactly the
traffic fabric forwarding exists to keep alive during failback /
asymmetric-routing windows. This also diverges from vSRX, which does not
re-apply screens to fabric-forwarded traffic.

**Fix.** Stage 9 (`stage_classify_fabric_ingress`, `afxdp/poll_stages.rs`)
already sets `FABRIC_INGRESS_FLAG` on `meta.meta_flags` for a fabric-redirected
packet. Stage 10 (`stage_screen_check`) now derives
`skip_rate_flood = (meta.meta_flags & FABRIC_INGRESS_FLAG) != 0` and threads it
into `ScreenState::check_packet_with_zone_id_opts` /
`check_flowless_screens_opts` (`screen/mod.rs`). When set, the screen runtime
runs the **stateless** per-packet screens (land, ping-of-death, teardrop,
icmp-fragment, source-route — idempotent, so re-running them on the owner is
correct) and then returns before the **rate-based** flood counters, so the
owner never re-counts the packet. The per-destination flood sketches (#4132) are
left intact — the fix skips the re-count, it does not disable the screen. The
per-`(zone, src)` **scan/sweep** new-flow counter is skipped the same way at the
session-miss decision in `poll_descriptor/mod.rs` (gated on
`packet_fabric_ingress`), for the sync-race window in which a fabric-redirected
packet arrives before its synced session installs; the per-IP session-limit
check there still runs because it guards the owner's own `SessionTable`, which
the ingress node did not populate.

The flood screen therefore fires **once**, on the true cluster-ingress node.
RED-on-revert coverage: `screen/tests.rs`
(`fabric_skip_does_not_count_{icmp,udp,syn}_flood_4155`,
`fabric_skip_leaves_direct_ingress_counting_intact_4155`, plus the stateless
scope guards) and `afxdp/poll_stages.rs`
(`fabric_ingress_skips_rate_flood_direct_still_counts_4155`, driving the live
`stage_screen_check`).
