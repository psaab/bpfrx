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
validate cookies minted by the former active node inside the current/previous
Unix wall-clock epoch overlap. If that secret material is absent, userspace
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
