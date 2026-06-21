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
