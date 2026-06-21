# userspace-dp/src/ — feature modules

The single-file feature modules sit at the crate root and are
consumed by the per-worker hot path in `afxdp/`. They're intentionally
flat: each owns one feature's lookup tables and decision logic, with
no internal sub-modules. Test layout is mixed: most feature modules
have a sibling `<feature>_tests.rs` (`nat`, `nat64`, `nptv6`,
`policy`, `screen`, `prefix_set`); some keep their tests
inline (`fairness`, `slowpath`, `protocol`, `prefix`); and a few have
neither (`state_writer`, `xsk_ffi`).

## Stages mirroring the BPF pipeline

These mirror the BPF-side stage modules in `bpf/xdp/` and `bpf/tc/`.
The table is a simplified map of feature areas — the actual order
the worker hot path runs them in is interleaved across the
session-hit and session-miss branches in
`afxdp/poll_descriptor.rs`. Read that file for the authoritative
ordering.

| File | Stage | What it does |
|------|-------|--------------|
| `screen.rs` | screen | Pre-session attack-protection checks (land, TCP SYN+FIN, no-flag, FIN-without-ACK, ICMP frag, plus rate-limits). Mirrors `bpf/xdp/xdp_screen.c`. Also contains the #1374 userspace SYN-cookie runtime: deterministic cookie mint/validate, fixed-size validated-client admission table, session-miss ACK validation with current/previous/next wall-clock epoch tolerance and standby prefilter/rate-limiting, bounded SYN-ACK/RST reply enqueue, snapshot-published key derived from cluster-synced root encrypted-password material, and per-binding sent/valid/invalid/bypass/budget counters. The Go `syn-cookie` capability gate admits active SYN-cookie screen profiles only after secret material exists; missing secret material fails closed and remaining #1374 work is live HA/flood evidence before BPF source removal. |
| `policy.rs` | policy | Zone-pair → permit/deny + forwarding-class + DSCP-rewrite + filter chaining. `ZonePairKey` is a `u32` (`from_id << 16 \| to_id`); `JUNOS_GLOBAL_ZONE_ID = u16::MAX` is the sentinel for the global zone. |
| `nat.rs` | NAT44 | Source / destination / static NAT decisions. `NatDecision` carries `rewrite_src` and `rewrite_dst` Options the TX path consumes. |
| `nat64.rs` | NAT64 | RFC 6052/7915 IPv4↔IPv6 translation. `Nat64Prefix` is the 96-bit + IPv4-pool config; `Nat64ReverseInfo` carries the original IPv6 tuple for reverse translation. **No per-packet heap alloc on the transit path (#2211):** `write_v6_to_v4_into`/`write_v4_to_v6_into` translate directly into a caller buffer with a streamed pseudo-header checksum; the frame builders make exactly one output allocation (`TxRequest.bytes`). **Fail-closed config parse (#2212):** `try_from_snapshots` rejects the snapshot (`SnapshotIntegrityError::Nat64UnparseableRule`) on a bad prefix or a non-host pool address rather than silently dropping it (helper-boundary backstop to the Go #2173 commit-time gate). |
| `nptv6.rs` | NPTv6 | RFC 6296 stateless IPv6-to-IPv6 prefix translation. Each rule maps an internal /48 or /64 to an external prefix; a precomputed adjustment value keeps the L4 checksum neutral so no checksum update is needed after rewrite. **Fail-closed config parse (#2240):** `try_from_snapshots` rejects the whole snapshot (`SnapshotIntegrityError::Nptv6UnparseableRule`) on an unparseable / unsupported / mismatched-length prefix rather than silently `continue`-ing past the bad rule (the pre-fix skip let the Go compiler's `DeleteStaleNPTv6` tear down a working translation on a typo — a fail-open in a retired-eBPF world); helper-boundary backstop to the Go #2240 commit-time gate (`pkg/config/compiler_nat.go`). |

## Cross-cutting helpers

| File | What it does |
|------|--------------|
| `slowpath.rs` | TUN device injection for firewall-local packets (TCP retransmits, ICMP errors). Built on `io_uring` for batched submit. Rate-limited with `DEFAULT_RATE_LIMIT_PACKETS_PER_SEC = 1_000_000` and `DEFAULT_RATE_LIMIT_BYTES_PER_SEC = 4 * 1024 * 1024 * 1024` (4 GiB). |
| `fairness.rs` | Pure functions for the fairness-regimes contract (`compute_cstruct`, `compute_observed_cov`, `starved_flow_count`). Consumed by the `fairness-eval` binary and by the contract's pinned worked-example tests. See `docs/fairness-regimes.md` and `docs/per-5-tuple/state.md`. |

## Lookup-structure helpers

| File | What it does |
|------|--------------|
| `prefix.rs` | `PrefixV4` / `PrefixV6` — the canonical IP-prefix value type. |
| `prefix_set.rs` | `PrefixSetV4` / `PrefixSetV6` — adaptive 3-variant enum (#923): `MatchAny`, linear scan, and trie variants. The compiler picks based on the input prefix list. |

## Wire / transport / state

| File | What it does |
|------|--------------|
| `protocol.rs` | Control request / response and snapshot schema types shared between the control socket server (`server/`) and the AF_XDP coordinator. The JSON tags ARE the wire contract — changing them without updating the Go side (`pkg/dataplane/userspace/protocol.go`) breaks the helper. |
| `state_writer.rs` | Crash-safe writer for the daemon's state snapshot file. Both the `io_uring` transport and the sync fallback route through one durable finalizer (`finalize_durably`): fsync temp file → atomic rename → fsync parent dir (#2147). |
| `xsk_ffi.rs` | Drop-in replacement for `xdpilone` using libxdp's XSK helpers via a C bridge. Provides the same type names (`Umem`, `UmemConfig`, `UmemChunk`, `IfInfo`, `Socket`, `DeviceQueue`, `RingRx`, `RingTx`, `ReadRx`, `WriteTx`, `WriteFill`, `ReadComplete`, `XdpDesc`) so the rest of the crate compiles unchanged. |
| `test_zone_ids.rs` | Test-only zone-id constants used across `_tests.rs` files. |
| `main.rs` / `main_tests.rs` | Crate `main()` — argv handling and dispatch into `server::lifecycle::run()`. Tests live next door. |

## Where these are called from

The worker poll loop drives the per-packet stages from
`afxdp/worker/lifecycle.rs::poll_binding` and the per-descriptor
dispatch in `afxdp/poll_descriptor.rs`. The stages above approximate
the "session-hit" fast path; the real session-miss order interleaves
DNAT, NPTv6 inbound, NAT64, FIB / forwarding resolution, policy, and
SNAT decisions across multiple branches in `poll_descriptor.rs`. Read
that file for the authoritative order — the tabular pipeline above is
intentionally simplified.

`fairness` is an auxiliary surface consumed by the `fairness-eval`
binary. (Flow export — NetFlow v9 / IPFIX — is NOT a dataplane module:
it is owned entirely by the Go control plane `pkg/flowexport`, driven by
SESSION_CLOSE events. The dead Rust `flowexport.rs` exporter was removed
in #2130; the dataplane emits no flow records.)
