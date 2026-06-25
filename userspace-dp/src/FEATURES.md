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
| `screen.rs` | screen | Pre-session attack-protection checks (land, TCP SYN+FIN, no-flag, FIN-without-ACK, WinNuke, syn-frag, ping-of-death, teardrop, ICMP frag, IP source-route, plus rate-limits). Mirrors `bpf/xdp/xdp_screen.c`. **#2215 parity fixes:** `ping-of-death` now ports the #893 IPv4 fragment-reassembly formula — any IPv4 fragment where `((frag_off & 0x1FFF) << 3) + ip_total_len > 65535` drops (the prior userspace port was an ICMP-only `pkt_len > 65535` predicate that is structurally unsatisfiable on a `u16`, so fragment ping-of-death went undetected); `land` now drops on `src_ip == dst_ip` alone for IPv4/IPv6 (the prior port additionally required `src_port == dst_port`, admitting same-IP different-port spoofed frames the BPF screen dropped). Also contains the #1374 userspace SYN-cookie runtime: deterministic cookie mint/validate, fixed-size validated-client admission table, session-miss ACK validation with current/previous/next wall-clock epoch tolerance and standby prefilter/rate-limiting, bounded SYN-ACK/RST reply enqueue, snapshot-published key derived from cluster-synced root encrypted-password material, and per-binding sent/valid/invalid/bypass/budget counters. The Go `syn-cookie` capability gate admits active SYN-cookie screen profiles only after secret material exists; missing secret material fails closed and remaining #1374 work is live HA/flood evidence before BPF source removal. |
| `policy.rs` | policy | Zone-pair → permit/deny + forwarding-class + DSCP-rewrite + filter chaining. `ZonePairKey` is a `u32` (`from_id << 16 \| to_id`); `JUNOS_GLOBAL_ZONE_ID = u16::MAX` is the sentinel for the global zone. Zone ids are carried on the event-stream wire as **u8** (max usable id 255 — see `MaxUsableZoneID` / `validateZoneCountStrict` in the Go compiler, #2391); `SnapshotIntegrityError::InterfaceUnknownZone` fails the snapshot CLOSED when an interface names a zone absent from the zone table instead of collapsing it to zone 0. **#2410 (validated narrowing newtypes):** the forwarding-build conversion (`afxdp/forwarding_build/validated.rs` — `VlanId`/`TunnelTtl`/`QueueId`, decoded ONCE with a checked `try_from_snapshot`) fails the snapshot CLOSED on an out-of-range integer at the second trust boundary instead of narrowing it with an unchecked `as` cast: a VLAN id > 65535 (`InterfaceVlanOutOfRange`) no longer wraps to a different L2 domain, a tunnel TTL > 255 (`TunnelTtlOutOfRange`) no longer wraps 256→0 (blackhole), and a CoS forwarding-class queue id outside 0..=255 (`CosQueueIdOutOfRange`) is no longer silently dropped from `class_to_queue`. **#2409 (fail-silent drop):** an interface address that fails `IpNet` parse (`InterfaceAddressUnparseable`) and a CoS scheduler-map entry referencing a forwarding-class absent from the class-to-queue table (`SchedulerMapUnknownClass`) now fail the snapshot CLOSED instead of `continue`-ing — the pre-fix skips lost connected-route material or partially installed a scheduler while the apply still succeeded. All five are helper-boundary backstops to the Go commit-time gates, consistent with the #2173/#2212/#2240/#2391 fail-closed family; the apply preflight catches the Err and keeps the previous live forwarding state. |
| `nat.rs` | NAT44 | Source / destination / static NAT decisions. `NatDecision` carries `rewrite_src` and `rewrite_dst` Options the TX path consumes. **#2394:** the DNAT table (`nat/destination.rs`) matches a rule on `(protocol, dst_ip, dst_port)` AND its `match source-address` constraint — a source-scoped DNAT (`DnatEntry.source_v4/source_v6`, CIDR or bare-host /32 /128) fires only for packets whose source IP falls in a configured prefix. `DnatEntry.source_constrained` distinguishes an UNSCOPED rule (no `source-address` -> match any source, unchanged behavior) from a SCOPED rule whose entries all failed to parse (-> match NOTHING, fail closed — never match-any). Before #2394 the source constraint was dropped at the Go->Rust snapshot boundary, so a source-scoped DNAT became destination-only and published the internal service to every source (fail-open). **#2398 (SNAT sibling):** the SNAT match logic (`nat/source.rs`) gets the same fail-closed treatment for BOTH its source AND destination match sets. `SourceNatRule.source_constrained`/`destination_constrained` (derived at decode from the snapshot match list being non-empty — no wire field) drive `nets_match_v4`/`nets_match_v6`: no match set -> match any (unscoped, unchanged); a non-empty match set whose prefixes ALL fail to parse -> match NOTHING (fail closed). Match prefixes also parse a bare host IP -> /32 (v4) or /128 (v6). Before #2398 an empty parsed list collapsed to match-any, so a SNAT rule whose match prefixes were all typo'd silently translated all traffic in the zone pair (fail-open broadening). |
| `nat64.rs` | NAT64 | RFC 6052/7915 IPv4↔IPv6 translation. `Nat64Prefix` is the 96-bit + IPv4-pool config; `Nat64ReverseInfo` carries the original IPv6 tuple for reverse translation. **No per-packet heap alloc on the transit path (#2211):** `write_v6_to_v4_into`/`write_v4_to_v6_into` translate directly into a caller buffer with a streamed pseudo-header checksum; the frame builders make exactly one output allocation (`TxRequest.bytes`). **Fail-closed config parse (#2212):** `try_from_snapshots` rejects the snapshot (`SnapshotIntegrityError::Nat64UnparseableRule`) on a bad prefix or a non-host pool address rather than silently dropping it (helper-boundary backstop to the Go #2173 commit-time gate). **RFC 7915 fragment translation (#2488):** v6→v4 derives the IPv4 MF/offset/Identification (low 16 bits of the 32-bit id) from the IPv6 Fragment Header when present (`ipv6_fragment_header`), falling back to the `no-v6-frag-header` atomic-datagram policy only when absent; v4→v6 inserts an 8-byte IPv6 Fragment Header (next-header 44) for a fragmented IPv4 input, copying offset/MF and zero-extending the 16-bit id. A first-fragment TCP/UDP checksum is adjusted incrementally for the v4↔v6 pseudo-header address delta (RFC 1624) since the full payload is absent; a v4 UDP fragment with a zero checksum is dropped (cannot synthesize the mandatory v6 checksum). Only first/atomic fragments translate — non-first fragments are dropped both directions (the round-robin SNAT pool + port-keyed sessions cannot consistently map a port-less fragment), so end-to-end fragmented NAT64 awaits a stateful fragment-id cache. |
| `nptv6.rs` | NPTv6 | RFC 6296 stateless IPv6-to-IPv6 prefix translation. Each rule maps an internal /48 or /64 to an external prefix; a precomputed adjustment value keeps the L4 checksum neutral so no checksum update is needed after rewrite. **Fail-closed config parse (#2240):** `try_from_snapshots` rejects the whole snapshot (`SnapshotIntegrityError::Nptv6UnparseableRule`) on an unparseable / unsupported / mismatched-length prefix rather than silently `continue`-ing past the bad rule (the pre-fix skip let the Go compiler's `DeleteStaleNPTv6` tear down a working translation on a typo — a fail-open in a retired-eBPF world); helper-boundary backstop to the Go #2240 commit-time gate (`pkg/config/compiler_nat.go`). **Overlap rejection (#2241):** because the runtime resolves a match by FIRST hit in insertion order with no longest-prefix-match, `try_from_snapshots` also rejects the whole snapshot (`SnapshotIntegrityError::Nptv6OverlappingPrefix`, carrying the two rule names + the offending `direction`) when two rules have overlapping prefixes in the same direction — internal/outbound or external/inbound, including a /48 that nests a /64 and identical prefixes. Without it a broad prefix configured before a more-specific one would shadow it and reordering the same rules would change the translation identity; rejecting keeps translation deterministic and order-independent. The Go commit-time gate (#2241, `validateNPTv6Strict` in `pkg/config/compiler_nat.go`) is primary; this is the helper-boundary backstop. The lenient load path (#1960 doctrine) downgrades both #2240 and #2241 violations to warnings so a pre-gate or peer-synced config still boots, and the helper preflight (not the validator) is what keeps the previous forwarding state until the rule is corrected. |

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
| `state_writer.rs` | Crash-safe writer for the daemon's state snapshot file. Each write goes to a PRIVATE temp path `<dest>.<pid>.<seq>.tmp` (pid + a process-global monotonic counter), created `O_EXCL`, so two writers — even overlapping helper processes during a restart/upgrade handover — can never open/truncate/write the SAME temp and publish crossed bytes under a successful rename (#2705). Both the `io_uring` transport and the sync fallback route through one durable finalizer (`finalize_durably`): fsync temp file → atomic rename → fsync parent dir (#2147); a failed write removes its unique temp so nothing leaks. |
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
