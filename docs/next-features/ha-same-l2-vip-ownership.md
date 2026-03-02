# HA Same-L2 Strict VIP Ownership (#104)

## Problem

In same-L2 HA deployments where both cluster nodes share the same broadcast domain, VRRP failover creates a window where **both nodes** emit GARP/NA for the same VIPs simultaneously. This happens because:

1. The default activation rule is `rg_active = clusterPri || anyVrrpMaster`
2. When the cluster heartbeat elects a new primary, that node activates immediately via `clusterPri=true`, even before VRRP MASTER state settles
3. The old primary may still be VRRP MASTER for a brief window during transition
4. Both nodes call `becomeMaster()` → both send GARP bursts
5. Upstream switches/routers see MAC table thrashing for the VIP addresses

This dual-active window is normally benign (a few milliseconds), but in same-L2 deployments it causes:
- **Duplicate GARP/NA storms** flooding the broadcast domain
- **ARP/ND table instability** on routers and switches
- Potential for **asymmetric forwarding** during the overlap

## Solution: `strict-vip-ownership` knob

A per-redundancy-group configuration knob that enforces single-owner VIP semantics.

### Configuration

```junos
set chassis cluster redundancy-group 1 strict-vip-ownership
```

This is a boolean knob — no value, just presence enables it.

### Behavioral Changes When Enabled

| Aspect | Default Mode | Strict VIP Ownership |
|--------|-------------|---------------------|
| **RG activation rule** | `clusterPri \|\| anyVrrpMaster` | `anyVrrpMaster` only |
| **GARP on secondary** | Always sent when VRRP transitions | Suppressed |
| **Dual-active window** | Brief overlap possible | Eliminated |
| **GARP dedup** | None | Epoch-based + 500ms dampening |

#### 1. VRRP-Only Activation

The `rgStateMachine.reconcileLocked()` changes the activation formula:

```
// Default:
desired = clusterPri || anyVrrpMaster

// Strict VIP ownership:
desired = anyVrrpMaster
```

This means the cluster heartbeat primary status alone no longer activates the RG. Only VRRP MASTER state (which is authoritative for VIP ownership) triggers `rg_active=true` in the BPF dataplane.

#### 2. GARP Suppression on Secondary

When the cluster event handler detects a role change, it toggles GARP suppression:

```go
if s.IsStrictVIPOwnership() {
    d.vrrpMgr.SetGARPSuppression(ev.GroupID, !isPrimary)
}
```

- **Primary node**: GARP allowed (normal behavior)
- **Secondary node**: GARP suppressed — `becomeMaster()` skips the `go vi.sendGARP()` call

This prevents the secondary from emitting GARP even if it briefly transitions to VRRP MASTER during a failover window.

#### 3. GARP Epoch Dedup

Each `becomeMaster()` call increments a per-instance `garpEpoch` counter. The `sendGARP()` function checks:

```go
if vi.lastGARPEpoch.Load() == epoch && epoch > 0 {
    return // already sent for this transition
}
```

This prevents `ReconcileVIPs()` from triggering duplicate GARP bursts for the same BACKUP→MASTER transition.

#### 4. 500ms GARP Dampening

A minimum interval between GARP bursts prevents storms during rapid VRRP flaps:

```go
const minGARPInterval = 500 * time.Millisecond
if time.Since(time.Unix(0, vi.lastGARPTime.Load())) < minGARPInterval {
    return // too soon
}
```

## Implementation Details

### Files Changed

| File | Changes |
|------|---------|
| `pkg/config/types.go` | `StrictVIPOwnership bool` field on `RedundancyGroup` |
| `pkg/config/compiler.go` | Parse `strict-vip-ownership` keyword |
| `pkg/vrrp/instance.go` | `suppressGARP`, `garpEpoch`, `lastGARPEpoch`, `lastGARPTime` atomics; epoch dedup + dampening in `sendGARP()` |
| `pkg/vrrp/manager.go` | `SetGARPSuppression(rgID, suppress)` method; `ReconcileVIPs()` respects suppression |
| `pkg/daemon/rg_state.go` | `strictVIPOwnership` field, `SetStrictVIPOwnership()`/`IsStrictVIPOwnership()` methods, modified `reconcileLocked()` |
| `pkg/daemon/daemon.go` | `startClusterComms()` propagates config; `watchClusterEvents()` toggles GARP suppression |

### Design Decisions

1. **Per-RG granularity**: Different RGs can have different activation semantics. RG 0 (control plane) might use default mode while RG 1 (data plane) uses strict mode.

2. **Atomic fields for lockless hot path**: All GARP control fields (`suppressGARP`, `garpEpoch`, `lastGARPTime`) are Go atomics, keeping the VRRP state machine's hot path lock-free.

3. **Suppression controlled by cluster role, not VRRP state**: The cluster heartbeat event handler controls GARP suppression based on cluster primary/secondary role. VRRP state independently controls RG activation. This clean decoupling prevents circular dependencies between the two state machines.

4. **Two-layer GARP dedup**: Epoch handles same-transition duplicates (e.g., `ReconcileVIPs()` after `becomeMaster()`). Dampening handles cross-transition storms (e.g., rapid MASTER→BACKUP→MASTER flaps).

### When to Use

Enable `strict-vip-ownership` when:
- Both HA nodes are on the **same Layer 2 broadcast domain**
- Upstream network equipment is sensitive to duplicate GARP/NA
- You want to eliminate the brief dual-active window during failover

Do **not** enable when:
- Nodes are on separate L2 domains (the default dual-active overlap is harmless)
- You need the faster activation that `clusterPri` provides (the VRRP-only path may add ~30ms to activation)
