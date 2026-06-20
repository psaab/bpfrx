# Deterministic NAT (CGNAT) Support

## Overview

Carrier-grade NAT with deterministic port block allocation. Each subscriber from
a configured host range gets a fixed, algorithmically-computed block of ports on
a public IP address. The mapping is purely mathematical -- no per-session state
is needed for reverse lookup, enabling ISP compliance logging without per-session
overhead.

**Commits:** `74e1d17` (IPv4 CGNAT), `439cd3f` (IPv6/NAPT64 extension)

## Configuration

### IPv4 Subscribers (Deterministic Mode 1)

```
set security nat source pool CGNAT-POOL address 203.0.113.1/32 to 203.0.113.4/32
set security nat source pool CGNAT-POOL port deterministic block-size 2016
set security nat source pool CGNAT-POOL port deterministic host address 100.64.0.0/22
set security nat source pool CGNAT-POOL port range low 1024 high 65535
```

This allocates:
- 4 public IPs (203.0.113.1 through 203.0.113.4)
- Port range 1024-65535 = 64512 ports per IP
- Block size 2016 = 32 blocks per IP
- 4 IPs x 32 blocks = 128 subscriber slots
- 100.64.0.0/22 = 1024 hosts (must fit within 128 blocks -- validated at compile)

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
source pool. Commit-time validation requires `0 < clear-threshold <
raise-threshold <= 100` — a bare `pool-utilization-alarm;` (raise=0/clear=0)
and inverted/equal thresholds are hard commit errors (`compiler_nat.go`).

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
nor clear) when the dataplane view is unavailable (helper down) or mid-apply
(status generation != applied generation), and for transiently uncomputable
samples (`AddressCount==0` / `PortHigh<PortLow` / capacity 0). Deterministic
pools are SKIPPED in this release — `UsedPorts` is not the right numerator for
block-based allocation; block-based utilization is a follow-up.

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

## BPF Implementation

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
| `pkg/config/compiler.go` | Parse deterministic port config (hierarchical + flat set), address ranges (`addr1/32 to addr2/32`), validation |
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
