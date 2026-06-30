# SYN Cookie Flood Protection

## Overview

When `security flow syn-flood-protection-mode syn-cookie` is configured, SYN
floods trigger cookie-based source validation in XDP instead of dropping all SYNs
indiscriminately. Legitimate sources pass after a single extra round-trip;
spoofed sources fail validation. Once validated, a source has zero per-packet
overhead for subsequent connections during the flood.

**Commit:** `8cbf31a`

## Configuration

```
set security flow syn-flood-protection-mode syn-cookie
set security screen ids-option SCREEN tcp syn-flood alarm-threshold 512 attack-threshold 1024
set security zones security-zone untrust screen SCREEN
```

The `syn-flood-protection-mode` is a global flow setting. The per-zone screen
`syn-flood` thresholds control when the mode activates. When the threshold is
exceeded:

- **Without syn-cookie mode:** SYNs are dropped (existing behavior)
- **With syn-cookie mode:** SYNs trigger the cookie challenge instead of being dropped

### Default attack-threshold (#3024)

Matching Junos SRX, a `tcp syn-flood` screen that is enabled WITHOUT an
explicit `attack-threshold` arms at the default of **200 SYN segments/second**.
Configuring syn-flood with only `destination-threshold`, `source-threshold`,
`alarm-threshold`, or `timeout` (no `attack-threshold`) still enables the
screen — and the nested syn-cookie challenge — at that default rate. The
config compiler seeds the default at parse time
(`defaultSynFloodAttackThreshold` in `pkg/config/compiler_security.go`); the
dataplane gate in `pkg/dataplane/compiler_iface.go` (`buildScreenConfig`)
applies the same default defensively. Previously the dataplane gate required
`AttackThreshold > 0`, so an unset attack-threshold silently left SYN-flood
protection disabled even when configured.

### Default thresholds for the other rate/scan screens (#3230)

The Rust screen engine (`userspace-dp/src/screen/mod.rs`, `scan.rs`) gates
icmp-flood, udp-flood, tcp port-scan, and ip ip-sweep on `threshold > 0`. Like
syn-flood before #3024, these checks had NO default: enabling one without an
explicit threshold compiled to 0 and the check was silently skipped. The config
compiler now seeds a Junos-aligned default at parse time
(`pkg/config/compiler_security.go`) for each ENABLED-but-unset check. An
explicit threshold is always preserved, and a check that is not configured stays
off (threshold 0).

| Screen check        | Default | Junos basis |
|---------------------|---------|-------------|
| `icmp flood`        | 1000    | Junos `icmp flood threshold` default of 1000 pps |
| `udp flood`         | 1000    | Junos `udp flood threshold` default of 1000 pps |
| `tcp port-scan`     | 10      | Junos flags a port scan at 10 distinct destination ports |
| `ip ip-sweep`       | 10      | Junos flags an address sweep at 10 distinct destination addresses |

Note on the scan/sweep defaults: Junos expresses the port-scan / ip-sweep
`threshold` as a time window (default 5000 microseconds) within which 10 distinct
ports / addresses trigger detection. This engine instead interprets the
threshold as a DISTINCT-DESTINATION COUNT over a fixed 10-second window
(`WINDOW_SECS` in `scan.rs`, comparison `len() > threshold`), so the default
uses Junos's distinct-destination detection count (10) rather than its 5000-
microsecond time-window value. Feeding 5000 here would be read as a count and
clamped to the dataplane cap (1023, `maxScanSweepThreshold`) — effectively never
firing.

### SYN-flood sub-thresholds: source / destination / alarm / timeout (#3315)

The Go compiler parses the full Junos `tcp syn-flood` shape (alarm/attack/
source/destination/timeout) into `config.SynFloodConfig`, but before #3315 only
`attack-threshold` crossed the userspace-dp wire — the four sub-thresholds
committed cleanly yet were operationally inert (the dataplane enforced only the
aggregate per-zone SYN counter). A config that appeared to cap per-source or
per-destination SYNs did nothing.

#3315 wires three of them across the boundary and enforces them in the Rust
screen runtime:

- **`destination-threshold`** — per-destination-IP SYN/s cap. PRIMARY,
  spoof-resistant: every SYN to a victim lands in the same sketch cells, so a
  hot destination trips regardless of how the sources are spread (or spoofed).
  It runs even when the zone is SYN-cookie active (a cookie-completing
  distributed flood must not evade `destination-threshold`).
- **`source-threshold`** — per-source-IP SYN/s cap. SECONDARY/best-effort.
  Skipped while the zone is SYN-cookie active (the cookie governs the
  high-cardinality spoofed-flood regime, where per-source is spoof-defeated and
  the sketch would over-throttle); confined this way to the sub-aggregate regime
  where source cardinality is bounded and the sketch is accurate.
- **`alarm-threshold`** — log-only rate below `attack-threshold`. Crossing it
  raises an out-of-band, ≤1/sec/zone screen ALARM event (RT_FLOW PERMIT, NOTICE
  severity, reason `syn-flood-alarm`) WITHOUT dropping the packet, like the
  scan-table-pressure alarm.
- **`timeout`** — ENFORCED (#3527; the #3315 tracked follow-up). It is NOT a
  screen-rate control: it maps to the per-zone half-open TCP session window
  (`SessionTimeouts.tcp_opening_ns`, 20 s default — the Junos
  half-completed-connection queue). `timeout N` now crosses the wire
  (`ScreenProfileSnapshot.syn_flood_timeout`, seconds) and the forwarding
  builder turns it into a per-ingress-zone override of `tcp_opening_ns`
  (`ForwardingState.session_opening_overrides` →
  `SessionTable::set_opening_overrides`). A bare-SYN (OPENING / half-open)
  session in a screened zone is then reaped on `N` seconds instead of the
  global 20 s default — so a flood that stops is forgotten on the operator's
  window, and a half-open never lingers longer than the configured queue
  bound. `session_timeout_ns` consults the override ONLY on the OPENING branch
  (never the established / closing / RST windows). HA composition (#3315 plan
  §11.1): the override is config-derived and re-derived per node from the
  snapshot — it does NOT travel on the session-sync wire. A peer-synced session
  is imported ESTABLISHED, so its OPENING branch is never taken, and identical
  config on both nodes yields the same map independently. The #3315 commit-time
  "accepted but NOT yet enforced" WARNING is removed now that the leaf is
  effective.

Enforcement order (`screen/mod.rs`, inside the initial-SYN gate, after the
validated-cookie bypass): (1) the aggregate `attack-threshold` (+
`alarm-threshold`) ALWAYS counts via a single `RateCounter::increment_and_classify`
so its cookie-activation side-effect can never be skipped — `attack` keeps the
existing cookie-mint / Drop behaviour; (2) per-destination cap; (3) per-source
cap (gated). The aggregate is authoritative — a per-IP cap only ADDS drops for
IPs under the aggregate radar. A per-IP trip hard-drops with the existing
`syn-flood` reason id (no Go gRPC/CLI change); per-source vs per-destination is
distinguished by separate per-worker counters.

Substrate (`userspace-dp/src/screen/syn_rate.rs`): a per-zone **count-min sketch
of `RateCounter`s** — `ROWS=4` independent seeded-hash rows × `DST_COLS=1024` /
`SRC_COLS=2048` columns — with **no eviction**. A key always counts in its
`ROWS` cells and trips ⟺ ALL cells are over threshold (the CMS `min` read,
implemented as the AND of the per-row results, never OR/MAX). No eviction means
no Hot-Set-Lockout / Cold-Start-Eviction-Race starvation (a victim is always
tracked and its cells only increase within the sliding window). Collisions can
only OVER-count (fail-closed: never a false-negative; the only error is a
false-positive bounded by `~(load)^ROWS`). Each sketch is allocated PER
THRESHOLD, not per zone: the per-destination sketch only when
`destination-threshold > 0`, the per-source sketch only when
`source-threshold > 0` (`update_profiles`, `screen/mod.rs` ~333/345), and each
is freed when its threshold is removed. An **alarm-only** profile
(`alarm-threshold` set, no source/destination cap) allocates NEITHER sketch —
only the tiny per-zone `syn_alarm_last_emit_sec` cadence timestamp (~350).

Memory (per worker): `RateCounter` ≈ 16 B. The per-destination sketch costs
`ROWS*DST_COLS*16 = 64 KiB` and is allocated only when `destination-threshold`
is set; the per-source sketch costs `ROWS*SRC_COLS*16 = 128 KiB` and is
allocated only when `source-threshold` is set. A zone that configures BOTH caps
costs the **192 KiB/zone** worst case × num_workers; a zone with only one cap
costs just that cap's table; an alarm-only zone costs neither (a single `u64`).
The Go compiler emits a commit-time advisory when `attack-threshold /
source-threshold` exceeds ~1000 (the only regime where the per-source sketch can
false-throttle legitimate sources under a sub-aggregate spoofed spread).

Wire: `ScreenProfileSnapshot` gains `syn_flood_alarm_threshold`,
`syn_flood_dst_threshold`, `syn_flood_src_threshold` (Go
`pkg/dataplane/userspace/protocol.go`; Rust `userspace-dp/src/protocol/
security.rs`). All three are additive with `omitempty` (Go) / `#[serde(default)]`
(Rust), so a control plane / helper missing them decodes 0 (disabled) and version
skew degrades safely (#1961). `timeout` is intentionally NOT serialized. The
`protocol_wire_v1.json` fixture was regenerated (`XPF_PROTOCOL_WIRE_REGEN=1`,
additive-only — three new fields, zero drift on existing).

## Algorithm

```
SYN flood detected (rate > threshold)
  → Zone enters synproxy_active mode
  → Unvalidated SYN arrives
    → Check validated_clients LRU map
      → Hit: bypass cookie challenge (SCREEN_SYN_COOKIE counter incremented)
      → Miss:
        1. Generate SYN-ACK with cookie seq via bpf_tcp_raw_gen_syncookie_ipv4/v6
        2. XDP_TX the SYN-ACK back to sender
        3. Legitimate client responds with ACK containing cookie
        4. validate_syncookie checks ACK via bpf_tcp_raw_check_syncookie_ipv4/v6
        5. On success: add source to validated_clients LRU, send RST
        6. Client retransmits SYN → passes as validated → normal session creation

SYN rate drops below threshold/2 in a new window
  → synproxy_active deactivated
  → All SYNs pass through normally again
```

## BPF Implementation

### Kernel Helpers Used

| Helper | ID | Since | Purpose |
|--------|----|-------|---------|
| `bpf_tcp_raw_gen_syncookie_ipv4` | 204 | 5.19 | Generate IPv4 SYN cookie |
| `bpf_tcp_raw_gen_syncookie_ipv6` | 205 | 5.19 | Generate IPv6 SYN cookie |
| `bpf_tcp_raw_check_syncookie_ipv4` | 206 | 5.19 | Validate IPv4 SYN cookie |
| `bpf_tcp_raw_check_syncookie_ipv6` | 207 | 5.19 | Validate IPv6 SYN cookie |

### BPF Maps

| Map | Type | Size | Purpose |
|-----|------|------|---------|
| `validated_clients` | LRU_HASH | 65536 | Tracks sources that passed cookie validation |
| `flood_counters` | (existing) | per-zone | Extended with `synproxy_active` field |

### BPF Functions (all `__noinline` for stack budget)

| Function | File | Purpose |
|----------|------|---------|
| `send_syncookie_synack_v4` | xdp_screen.c | Build and TX SYN-ACK with cookie (58 bytes) |
| `send_syncookie_synack_v6` | xdp_screen.c | Build and TX SYN-ACK with cookie (78 bytes) |
| `validate_syncookie_v4` | xdp_screen.c | Validate ACK, whitelist source, send RST (54 bytes) |
| `validate_syncookie_v6` | xdp_screen.c | Validate ACK, whitelist source, send RST (74 bytes) |

### Global Counters

| Counter | ID | Description |
|---------|----|-------------|
| `GLOBAL_CTR_SYNCOOKIE_SENT` | 27 | SYN-ACK cookies generated and sent |
| `GLOBAL_CTR_SYNCOOKIE_VALID` | 28 | ACKs with valid cookies (source whitelisted) |
| `GLOBAL_CTR_SYNCOOKIE_INVALID` | 29 | ACKs with invalid cookies (not a cookie response) |
| `GLOBAL_CTR_SYNCOOKIE_BYPASS` | 30 | SYNs that bypassed challenge (already validated) |

### Screen Flag

`SCREEN_SYN_COOKIE` (1<<14) is set in the zone's `screen_config.flags` when
syn-cookie mode is configured. The `check_flood()` function in xdp_screen.c
checks this flag to decide between drop mode and cookie mode.

## Go Implementation

| Component | Change |
|-----------|--------|
| `pkg/config/types.go` | `FlowConfig.SynFloodProtectionMode` field |
| `pkg/config/compiler.go` | Parses `syn-flood-protection-mode syn-cookie` |
| `pkg/dataplane/compiler.go` | Sets `ScreenSynCookie` flag on screen config |
| `pkg/dataplane/types.go` | `ScreenSynCookie` constant |
| `pkg/api/metrics.go` | 4 Prometheus metrics (`xpf_screen_syncookie_total`) |
| `pkg/dataplane/userspace/protocol.go` | Userspace `BindingStatus` SYN-cookie counters |
| `pkg/cli/cli_show_security.go`, `pkg/grpcapi/server_show.go` | Userspace counters in screen statistics display |

## Userspace Dataplane Status and HA Propagation

The userspace dataplane reports per-binding SYN-cookie counters in
`BindingStatus`:

| JSON key | Meaning |
|----------|---------|
| `syn_cookie_challenges` | SYNs that entered the userspace challenge path |
| `syn_cookie_secret_unavailable` | Challenge attempts that failed closed because no SYN-cookie secret was published |
| `syn_cookie_syn_ack_sent` | SYN-cookie SYN-ACK replies admitted to the bounded local TX queue |
| `syn_cookie_ack_rst_sent` | RST replies admitted after a returning ACK validates |
| `syn_cookie_reply_budget_drops` | Cookie replies dropped to preserve forwarding TX headroom |
| `syn_cookie_ack_valid` | Session-miss ACKs that validated against a minted cookie |
| `syn_cookie_ack_invalid` | Session-miss ACKs that did not validate |
| `syn_cookie_bypass` | SYNs admitted from the local validated-client cache |

`syn_cookie_syn_ack_sent`, `syn_cookie_ack_valid`,
`syn_cookie_ack_invalid`, and `syn_cookie_bypass` are propagated as deltas into
the daemon's BPF-compatible global counters. Secret-unavailable and
reply-budget drops remain userspace-local diagnostics because they describe
helper-local fail-closed and backpressure conditions. The validated-client cache
is local, but the snapshot-published key is derived from cluster-synced root
encrypted-password material so peers with the same committed config can
validate cookies minted by the former active node inside the current,
previous, or next Unix wall-clock epoch overlap. The next-epoch candidate keeps
failover stable when peer clocks straddle a 64-second boundary. The epoch input
MUST be Unix wall-clock seconds (not `CLOCK_MONOTONIC`), since peers share only
the NTP-synced wall clock — their monotonic bases are unrelated. To avoid an OS
clock read on every minted/validated cookie under a flood (#3032), the helper
reads `SystemTime::now()` at most once per monotonic second
(`ScreenState::current_syn_cookie_full_epoch`, gated by the batch-cached
monotonic second already threaded into the screen check) and caches the derived
wall-clock seconds; every cookie in the same second reuses the cached value
because they all map to the same 64-second epoch. The epoch leaf
(`SynCookieCodec::current_full_epoch`) is a pure function of the supplied
seconds and never touches the clock. A standby peer
accepts a valid cookie ACK even when it has not locally observed the flood
threshold; ACKs outside the transmitted-epoch window are prefiltered before
SipHash, and plausible standby ACKs are rate-limited per zone over a sliding
1-second window. The limiter (`screen/rate.rs`) is a two-bucket sliding-window
counter rather than a fixed wall-second window: the immediately preceding
second's tally still contributes for the whole of the current second, so an
attacker cannot double the plausible-ACK validation budget by straddling a
wall-second boundary (#2937). The same counter type gates the ICMP/UDP/SYN
flood screens.
Invalid ACKs outside a local active flood window remain ordinary session-miss
traffic instead of being counted as cookie failures.

The validated-client cache is keyed by `(zone_id, profile_generation, 4-tuple)`
(#2446). Each zone carries a SYN-cookie profile generation that is bumped
whenever a SYN-cookie-relevant profile field changes — the `syn-cookie`
enable/disable toggle or the `syn-flood` threshold, plus the zone gaining or
losing a profile (how a zone→profile rebinding manifests). The current
generation is stamped into an entry on insert and compared on consume: an entry
from an older generation is treated as a cache miss and the connection is
re-validated under the new profile, so the new profile's SYN-flood counter sees
it. This closes the window where a master-key-stable profile edit let a tuple
validated under the old profile bypass the new profile's flood gate until the
cache TTL expired. The master-key-rotation clear (`set_hash_keys`) remains as
defense in depth, and unrelated profile edits (e.g. stateless screens,
scan/sweep thresholds) do NOT bump the generation, so they cause no
re-validation churn.

If that secret material is
absent, userspace
omits the key and fails closed instead of minting predictable cookies; config
validation also warns and userspace capability admission refuses active
SYN-cookie screen profiles until the secret exists.

Cookie replies are host-generated flood-control frames. They intentionally
bypass output filters, CoS classification, DSCP rewrite, and mirroring, matching
the legacy eBPF `XDP_TX` behavior instead of treating replies as forwarded
transit packets.

## Prometheus Metrics

```
xpf_screen_syncookie_total{type="sent"}     # SYN-ACK cookies generated
xpf_screen_syncookie_total{type="valid"}     # Valid cookie ACKs received
xpf_screen_syncookie_total{type="invalid"}   # Invalid cookie ACKs
xpf_screen_syncookie_total{type="bypass"}    # Validated sources bypassing challenge
```

## Verifier Gotchas

1. **Variable TCP header length:** `tcph->doff * 4` gives wide `var_off` (up to
   60). The BPF helper call must use constant `sizeof(struct tcphdr)` instead.

2. **MAC read ordering:** The compiler may reorder MAC reads past the
   `bpf_tcp_raw_gen_syncookie` call. Reading MACs from the packet is safe because
   `bpf_xdp_adjust_tail` does not modify the beginning of the packet.

3. **Meta offset masking:** `meta->l3_offset` and `meta->l4_offset` are masked
   with `& 0x3F` / `& 0x7F` to narrow `var_off` for the verifier.

## Limitations

- **syn-proxy mode** (stateful proxying with full TCP handshake completion) is not
  implemented. Only syn-cookie mode is supported.
- The `validated_clients` LRU map has a fixed size of 65536 entries. Under
  extremely high cardinality attacks, legitimate entries may be evicted.
- IPv6 SYN-ACK MSS is 1440 (vs 1460 for IPv4) to account for the larger header.
- Userspace SYN-cookie challenge, secret-unavailable, SYN-ACK, ACK-RST, budget,
  valid, invalid, and bypass counters are visible in helper status. Live
  HA/flood evidence is still required before BPF source removal.
