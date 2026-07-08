# Deterministic NAT (CGNAT) Support

## Overview

Carrier-grade NAT with deterministic port block allocation. Each subscriber from
a configured host range gets a fixed, algorithmically-computed block of ports on
a public IP address. The mapping is purely mathematical -- no per-session state
is needed for reverse lookup, enabling ISP compliance logging without per-session
overhead.

**Commits:** `74e1d17` (IPv4 CGNAT), `439cd3f` (IPv6/NAPT64 extension)

## Runtime status (userspace dataplane)

> The original block allocator (`74e1d17`, `439cd3f`) lived only in the eBPF
> plane, which was retired in #1373/#1476. After #1476 a deterministic pool
> committed clean but SILENTLY round-robined on the userspace dataplane (the
> only runtime). #4560 added a commit-time advisory; **#4559 ports the IPv4
> (mode 1) block allocator to `userspace-dp`.**

| Path | Status |
|------|--------|
| **IPv4 subscriber (mode 1)** | **ENFORCED** on the userspace dataplane (#4559). The Go builder carries the block/host params; the Rust allocator maps each in-range subscriber IPv4 to a fixed external pool address + port block, reversible from `(external IP, port)` with no per-flow state. |
| **IPv6 subscriber / NAPT64 (mode 2)** | **Deferred.** Config-accepted + validated, but the userspace allocator does not yet implement it — the pool round-robins for IPv6 subscribers and the commit-time advisory (`ValidateConfig`, #4559) surfaces the gap. |

See "Userspace Dataplane Implementation (#4559)" below. The "BPF
Implementation" section is retained for historical reference only — that source
was deleted in #1476.

## Configuration

### IPv4 Subscribers (Deterministic Mode 1)

```
set security nat source pool CGNAT-POOL address 203.0.113.1/32 to 203.0.113.4/32
set security nat source pool CGNAT-POOL port deterministic block-size 2016
set security nat source pool CGNAT-POOL port deterministic host address 100.64.0.0/25
set security nat source pool CGNAT-POOL port range low 1024 high 65535
```

This allocates:
- 4 public IPs (203.0.113.1 through 203.0.113.4)
- Port range 1024-65535 = 64512 ports per IP
- Block size 2016 = 32 blocks per IP
- 4 IPs x 32 blocks = 128 subscriber slots
- 100.64.0.0/25 = 128 hosts (must fit within the 128 blocks -- validated at
  compile: `totalBlocks >= subscriberCount`). A larger prefix such as
  `/22` (1024 hosts) is rejected `insufficient capacity (128 blocks) for
  1024 subscribers` -- widen the pool (more public IPs) or shrink the
  block-size to add blocks.

The four `set` lines above are entered in flat-set order; `block-size` and
`host address` are SEPARATE `set` lines under the same `port deterministic`
sub-stanza and GROUP onto one pool (#3864). The equivalent hierarchical
block form also compiles:

```
security {
    nat {
        source {
            pool CGNAT-POOL {
                address 203.0.113.1/32 to 203.0.113.4/32;
                port {
                    range low 1024 high 65535;
                    deterministic {
                        block-size 2016;
                        host address 100.64.0.0/25;
                    }
                }
            }
        }
    }
}
```

### IPv6 Subscribers / NAPT64 (Deterministic Mode 2)

```
set security nat source pool CGNAT64-POOL address 203.0.113.1/32 to 203.0.113.8/32
set security nat source pool CGNAT64-POOL port deterministic block-size 2016
set security nat source pool CGNAT64-POOL port deterministic host address 2001:db8::/32
```

IPv6 subscribers get deterministic IPv4 SNAT allocation based on their IPv6
source address prefix. The subscriber index is derived from the 32-bit word
after the configured prefix:
- `/32` prefix: word[1] (bytes 4-7 of IPv6 address)
- `/64` prefix: word[2] (bytes 8-11 of IPv6 address)

Only `/32` and `/64` prefix lengths are supported for IPv6 host addresses.

### Pool Utilization Alarm (#2079)

```
set security nat source pool-utilization-alarm raise-threshold 80
set security nat source pool-utilization-alarm clear-threshold 70
```

This is a single GLOBAL raise/clear pair (matching Junos `set security nat
source pool-utilization-alarm` scope); the same thresholds apply to every
source pool. `clear-threshold` is OPTIONAL (#4077, Junos-faithful): a raise-only
config —

```
set security nat source pool-utilization-alarm raise-threshold 90
```

— commits, with `clear-threshold` defaulted at parse time to a 10-point
hysteresis margin below raise (`defaultPoolAlarmClearThreshold`, floored at 1),
so raise 90 → clear 80, raise 50 → clear 40, raise 5 → clear 1. The default
always lands inside `0 < clear < raise`, so the runtime monitor arms the alarm
(it treats `clear <= 0` as disabled).

When BOTH are set, validation requires `0 < clear-threshold < raise-threshold
<= 100` with the standard strict-vs-lenient split (`validatePoolUtilizationAlarm`,
`compiler_nat.go`): a bare `pool-utilization-alarm;` (raise=0/clear=0) and
inverted/equal thresholds — and an EXPLICIT `clear-threshold 0` — are hard
`commit`/`commit check` errors, but the tolerant load / HA peer-sync path
downgrades them to a warning so a node that committed a legacy config before
this gate existed still boots (the runtime monitor treats raise<=0 as disabled,
so a leniently-loaded bad config is inert).

Runtime behaviour (vSRX-faithful) is driven by a slow (10s) daemon-resident
monitor (`pkg/natpoolalarm`) over the helper's LAST-APPLIED NAT pool snapshot
(`dp.AppliedNATView()` — config + same-generation pool counters; no Rust /
wire change, no extra control-socket traffic — it reuses the cached 1 Hz
status poll). For each rule-referenced, non-deterministic source pool the
monitor computes port utilization
`UsedPorts * 100 / (AddressCount * (PortHigh - PortLow + 1))` and applies
hysteresis: it RAISES when utilization `>= raise-threshold` and CLEARS when it
drops `< clear-threshold` (strict). On each raise/clear transition (and only
on a transition — never per tick) it:

- updates `show security alarms` (Class NAT, Severity Minor), visible at both
  the gRPC and local-CLI render sites; and
- emits one structured `RT_NAT NAT_POOL_UTILIZATION_ALARM_RAISED` /
  `..._CLEARED` syslog line through the configured syslog streams / local
  writers.

An alarm is also cleared when its last referencing source-NAT rule is removed,
the pool is removed from config, the pool is converted to deterministic, or the
alarm feature is disabled. The monitor HOLDs (makes no decision, neither raise
nor clear) when the dataplane view is unavailable (helper down / no reconciled
apply yet — including just after a helper restart) or mid-apply (status
generation != applied generation), during a RETH-MAC bring-up `DeferWorkers`
window (the helper has accepted the new generation but not yet reconciled its
forwarding state, so the NAT counters are still the old generation — the applied
snapshot is recorded only after the post-`NotifyLinkCycle` rebind reconcile),
and for transiently uncomputable samples (`AddressCount==0` / `PortHigh<PortLow`
/ capacity 0). Deterministic pools are SKIPPED in this release — `UsedPorts` is
not the right numerator for block-based allocation; block-based utilization is a
follow-up.

NOTE: the legacy eBPF `nat_port_counters` map (read by `metrics_nat.go` and
the CLI `show security nat source pool` "Utilization %") is never incremented
post eBPF-retirement and reports a random seed value in userspace mode — the
alarm deliberately uses the allocator snapshot (`SourceNATPoolStatus.UsedPorts`),
not that dead path. Fixing those two legacy surfaces is tracked separately.

## Algorithm

For a subscriber with source IP `src`:

```
sub_idx = ntohl(src) - ntohl(host_base)       # subscriber index in host range

ip_idx    = sub_idx / blocks_per_ip            # which public IP
block_idx = sub_idx % blocks_per_ip            # which port block on that IP

port_start = port_low + block_idx * block_size
port       = port_start + (counter++ % block_size)   # round-robin within block
```

The reverse mapping (given public IP + port, find subscriber) is equally simple:

```
ip_idx    = lookup(public_ip)                  # which pool IP index
block_idx = (port - port_low) / block_size     # which block
sub_idx   = ip_idx * blocks_per_ip + block_idx # subscriber index
subscriber = ntohl(host_base) + sub_idx        # subscriber IP
```

This allows ISP logging of just `(public_ip, port_range, subscriber)` tuples
at pool configuration time, instead of per-session SNAT logs.

## Userspace Dataplane Implementation (#4559)

The IPv4 (mode 1) path is implemented in the Rust AF_XDP dataplane. The
external-IP + port-block assignment is byte-for-byte the same deterministic,
reversible mapping the eBPF plane used (Algorithm above); the userspace version
additionally tracks live flows so a port is not reused while a session is alive.

| Component | Change |
|-----------|--------|
| `pkg/dataplane/userspace/nat_source.go` | `deterministicSourceNATFields()` precomputes `mode`/`block_size`/`blocks_per_ip`/`host_base` (host-order u32)/`host_count` from the pool + the defaulted port range, and stamps them on `SourceNATRuleSnapshot`. IPv4 host → mode 1; IPv6 host → mode 0 (deferred). |
| `pkg/dataplane/userspace/protocol.go` | `SourceNATRuleSnapshot` gains the five additive `deterministic_*` wire fields (omitempty, #1961 skew-safe). |
| `userspace-dp/src/protocol/nat.rs` | Rust mirror of the wire fields (`#[serde(default)]` — an old control plane omits them → round-robin). |
| `userspace-dp/src/nat/allocator.rs` | `DeterministicV4` params; `deterministic_indices_v4()` (subscriber IPv4 → `(ip_idx, block_idx)`); `allocate_deterministic_v4()` (claims the first free port in the subscriber's block against the live owner map, collision-free); `reverse_deterministic_v4()` (`(external IP, port)` → subscriber IPv4, no per-flow state). A deterministic allocation is NOT recycled on release (its block is re-scanned directly), so a deterministic-only pool never grows the recycle queue. |
| `userspace-dp/src/nat/source.rs` | Builds `SourceNatRule.deterministic_v4` from the snapshot (mode 1 only) and routes a deterministic-pool match through `allocate_deterministic_v4` instead of the round-robin allocator. An out-of-range subscriber fails CLOSED (`DeterministicSubscriberOutOfRange`) rather than silently round-robining. |
| `pkg/config/compiler_validate_warn.go` | The #4560 advisory is narrowed to IPv6-host (mode 2) pools only — an IPv4-host deterministic pool is now enforced and does not warn. |

**Difference from the retired eBPF version:** the eBPF allocator picked the
port within a block with a single per-pool `counter++ % block_size` and kept no
per-flow state. The userspace allocator instead claims the first *free* port in
the block (checked against the shared live-owner map) and records the flow, so
two concurrent sessions from one subscriber never collide on a translated tuple
and a flow re-allocates its own tuple on retransmit. The subscriber→block→IP
assignment (the part that must be deterministic and reversible for compliance
logging) is identical.

**Deferred (still tracked in #4559):**
- IPv6 subscriber / NAPT64 (mode 2) block allocation.
- Block-based pool-utilization for deterministic pools (the #2079 alarm still
  skips them — `UsedPorts` is not the right numerator for block allocation).

## BPF Implementation

> Historical: this source was deleted in #1476 (eBPF dataplane retirement). It
> is retained here as the reference the userspace port (#4559) reproduces. The
> live implementation is "Userspace Dataplane Implementation (#4559)" above.

### C Struct Extension

`nat_pool_config` was extended from 8 bytes to 40 bytes:

| Field | Type | Mode | Description |
|-------|------|------|-------------|
| `num_ips` | u16 | all | Number of IPv4 IPs in pool |
| `pool_id` | u8 | all | Pool identifier |
| `port_low` | u16 | all | Port range start (default 1024) |
| `port_high` | u16 | all | Port range end (default 65535) |
| `addr_persistent` | u8 | 0 | Same src always maps to same pool IP |
| `deterministic` | u8 | 1,2 | 0=off, 1=IPv4 host, 2=IPv6 host |
| `block_size` | u16 | 1,2 | Ports per subscriber |
| `host_base` | be32 | 1 | IPv4 subscriber range base |
| `host_count` | u32 | 1,2 | Number of subscriber IPs/prefixes |
| `blocks_per_ip` | u16 | 1,2 | Precomputed port_range / block_size |
| `host_prefix_len` | u8 | 2 | IPv6 prefix length (32 or 64) |
| `host_base_v6` | be32[4] | 2 | IPv6 subscriber base address |

### BPF Functions

| Function | File | Purpose |
|----------|------|---------|
| `nat_pool_alloc_deterministic_v4` | xdp_policy.c | IPv4 deterministic allocation |
| `nat_pool_alloc_deterministic_v6` | xdp_policy.c | IPv6/NAT64 deterministic allocation |

Both are `__noinline` to stay within the BPF stack budget. Dispatch is via
`cfg->deterministic`: the policy program checks this flag before calling the
regular `nat_pool_alloc_v4()`.

### Map Changes

`MAX_NAT_POOL_IPS_PER_POOL` increased from 8 to 256 (CGNAT pools need 125+
public IPs). `MAX_NAT_POOL_IPS` correspondingly increased to 8192.

## Go Implementation

| Component | Change |
|-----------|--------|
| `pkg/config/types.go` | `DeterministicNATConfig` struct, `PoolUtilizationAlarmConfig` |
| `pkg/config/compiler_nat.go` | Parse deterministic port config (hierarchical + flat set, accumulated across both AST shapes, #3864), address ranges (`addr1/32 to addr2/32`), capacity validation |
| `pkg/config/schema_security.go` | Models `port deterministic { block-size; host address }` so the flat-set sub-stanza GROUPS + tab-completes (#3864) |
| `pkg/dataplane/compiler.go` | Compile deterministic fields to `NATPoolConfig`, mode 1 vs mode 2 dispatch |
| `pkg/dataplane/types.go` | `NATPoolConfig` extended with deterministic fields |
| `pkg/api/metrics.go` | `xpf_nat_pool_deterministic_info` Prometheus gauge |
| `pkg/cmdtree/tree.go` | `deterministic-nat nat-table` show command |

### Validation Rules

The compiler enforces these at commit time:

1. `block_size` must be > 0
2. `host_address` CIDR must be valid
3. IPv6 host prefix must be `/32` or `/64`
4. Total blocks (pool_ips * blocks_per_ip) must accommodate all subscribers
5. Deterministic NAT is mutually exclusive with `persistent-nat`
6. Deterministic NAT is mutually exclusive with `address-persistent`

### Address Range Expansion

The `expandAddressRange()` function handles `addr1/32 to addr2/32` syntax,
expanding into individual IP strings. Maximum 256 IPs per range.

## DPDK Parity

DPDK retired (#1525). The historical parity work mirrored deterministic
NAT struct and constant changes in `dpdk_worker/` (`shared_mem.h`
`nat_pool_config`, `tables.h` `MAX_NAT_POOL_IPS_PER_POOL=256`,
`policy.c` inline v4 SNAT, `nat64.c` inline v6 NAT64). The DPDK
backend is removed in #1527/#1528; no further DPDK parity work
applies.

## Prometheus Metrics

```
xpf_nat_pool_deterministic_info{pool="CGNAT-POOL", block_size="2016", host_count="1024"} 1
```

A gauge metric exposing the deterministic configuration for each pool.

## CLI

```
show security nat source deterministic-nat nat-table
```

Displays the deterministic mapping table showing subscriber-to-public-IP/port-block
assignments.

## Limitations

- Maximum 256 public IPs per pool (`MAX_NAT_POOL_IPS_PER_POOL`)
- Maximum 32 pools total (`MAX_NAT_POOLS`)
- IPv6 subscriber index limited to 32-bit word extraction (prefix must be /32 or /64)
- No per-subscriber session counting (by design -- the whole point is to avoid per-session state)
