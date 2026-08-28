use super::*;

pub(super) fn uses_kernel_local_session_map_entry(
    decision: SessionDecision,
    metadata: &SessionMetadata,
    origin: SessionOrigin,
) -> bool {
    origin.is_peer_synced()
        && !metadata.is_reverse
        && decision.resolution.disposition == ForwardingDisposition::LocalDelivery
        && decision.resolution.tunnel_endpoint_id == 0
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct UserspaceSessionMapKey {
    addr_family: u8,
    protocol: u8,
    pad: u16,
    src_port: u16,
    dst_port: u16,
    src_addr: [u8; 16],
    dst_addr: [u8; 16],
}

pub(super) fn session_map_key(key: &SessionKey) -> UserspaceSessionMapKey {
    fn encode_ip(ip: &IpAddr) -> [u8; 16] {
        match ip {
            IpAddr::V4(v4) => {
                let mut out = [0u8; 16];
                out[..4].copy_from_slice(&v4.octets());
                out
            }
            IpAddr::V6(v6) => v6.octets(),
        }
    }
    UserspaceSessionMapKey {
        addr_family: key.addr_family,
        protocol: key.protocol,
        pad: 0,
        src_port: key.src_port,
        dst_port: key.dst_port,
        src_addr: encode_ip(&key.src_ip),
        dst_addr: encode_ip(&key.dst_ip),
    }
}

pub(super) fn publish_session_map_key(
    map_fd: c_int,
    key: &SessionKey,
    value: u8,
) -> io::Result<()> {
    let map_key = session_map_key(key);
    let rc = unsafe {
        libbpf_sys::bpf_map_update_elem(
            map_fd,
            (&map_key as *const UserspaceSessionMapKey).cast::<c_void>(),
            (&value as *const u8).cast::<c_void>(),
            libbpf_sys::BPF_ANY as u64,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(super) fn publish_live_session_key(map_fd: c_int, key: &SessionKey) -> io::Result<()> {
    publish_session_map_key(map_fd, key, USERSPACE_SESSION_ACTION_REDIRECT)
}

pub(super) fn publish_kernel_local_session_key(map_fd: c_int, key: &SessionKey) -> io::Result<()> {
    publish_session_map_key(map_fd, key, USERSPACE_SESSION_ACTION_PASS_TO_KERNEL)
}

pub(super) fn publish_live_session_entry(
    map_fd: c_int,
    key: &SessionKey,
    nat: NatDecision,
    is_reverse: bool,
) -> io::Result<()> {
    publish_live_session_key(map_fd, key)?;
    if !is_reverse {
        let wire_key = forward_wire_key(key, nat);
        if wire_key != *key {
            publish_live_session_key(map_fd, &wire_key)?;
        }
        let reverse_wire = reverse_session_key(key, nat);
        if reverse_wire != *key {
            publish_live_session_key(map_fd, &reverse_wire)?;
        }
        let reverse_canonical = reverse_canonical_key(key, nat);
        if reverse_canonical != *key && reverse_canonical != reverse_wire {
            publish_live_session_key(map_fd, &reverse_canonical)?;
        }
    }
    Ok(())
}

// ── BPF conntrack context ──

/// Optional context for mirroring sessions into the BPF conntrack maps.
/// When present, `publish_session_map_entry_for_session` and
/// `delete_session_map_entry_for_removed_session` also write/delete from
/// the kernel-visible `sessions`/`sessions_v6` maps so `show security
/// flow session` displays correct zone and interface information.
#[derive(Clone, Copy)]
pub(super) struct ConntrackCtx<'a> {
    pub(super) v4_fd: c_int,
    pub(super) v6_fd: c_int,
    pub(super) zone_name_to_id: &'a FastMap<String, u16>,
    /// `security alg <proto> disable` bitfield (#2008 H3/H4), carried from
    /// ForwardingState so the mirrored conntrack entry's alg_type honours
    /// the operator's disable knobs.
    pub(super) alg_disable_flags: u8,
    /// Resolved application-identification id (#2008 M5) for the session, 0 =
    /// unknown. Carried so a mirrored conntrack entry stamps app_id. NOTE: in
    /// the current code base every production conntrack mirror is the live
    /// session-create path in poll_descriptor, which calls
    /// `publish_bpf_conntrack_entry` directly (not via this ctx); this field
    /// keeps the ctx contract complete for any future `Some(ctx)` caller.
    pub(super) app_id: u16,
    /// #5213: the stable dataplane session id for the mirrored session (see
    /// `publish_bpf_conntrack_entry`). Like `app_id`, carried for contract
    /// completeness — the production conntrack mirror is the direct
    /// poll_descriptor call, which resolves the id from the session table.
    pub(super) session_id: u64,
}

// ── BPF conntrack map structs (mirrors C struct session_key / session_value) ──

/// Mirrors C `struct session_key` — 16 bytes, packed.
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct BpfSessionKeyV4 {
    src_ip: [u8; 4], // __be32, network byte order
    dst_ip: [u8; 4], // __be32, network byte order
    src_port: u16,   // __be16, network byte order
    dst_port: u16,   // __be16, network byte order
    protocol: u8,
    pad: [u8; 3],
}

/// Mirrors C `struct session_value` — full connection state.
#[repr(C)]
#[derive(Clone, Copy)]
struct BpfSessionValueV4 {
    state: u8,
    // __u16 to fit SESS_FLAG_NPTV6 (bit 8, 0x100), which overflows a u8 (#5460).
    // The compiler inserts one pad byte after `state` and two before
    // `app_timeout`; the layout matches C `struct session_value` and the Go
    // `bpfSessionValue` mirror (size-asserted at 144 in bpf_map_tests.rs --
    // 136 before #4983 added the ingress-identity pair below).
    flags: u16,
    tcp_state: u8,
    is_reverse: u8,
    app_timeout: u32,
    session_id: u64,
    created: u64,
    last_seen: u64,
    timeout: u32,
    policy_id: u32,
    ingress_zone: u16,
    egress_zone: u16,
    nat_src_ip: u32,   // __be32, native endian for BPF
    nat_dst_ip: u32,   // __be32, native endian for BPF
    nat_src_port: u16, // __be16, network byte order
    nat_dst_port: u16, // __be16, network byte order
    fwd_packets: u64,
    fwd_bytes: u64,
    rev_packets: u64,
    rev_bytes: u64,
    reverse_key: BpfSessionKeyV4,
    alg_type: u8,
    log_flags: u8,
    app_id: u16,
    fib_ifindex: u32,
    fib_vlan_id: u16,
    fib_dmac: [u8; 6],
    fib_smac: [u8; 6],
    fib_gen: u16,
    /// #4983: the ifindex of the binding the session's FIRST packet arrived
    /// on -- the session's TRUE ingress identity, stamped once at install from
    /// `SessionMetadata::ingress_ifindex` and never re-derived from the zone.
    /// Distinct from `fib_ifindex` above, which is the resolved EGRESS. `0`
    /// means "no ingress identity carried" (reverse companion / peer-synced /
    /// host-outbound GRE, which has no ingress binding to record) and is never
    /// a valid ifindex; the Go consumer falls back to the zone approximation
    /// for it. #6928: this parenthetical listed a "pre-#4983 entry" as a fourth
    /// case; there is no such population, because a `ValueSize` mismatch
    /// against the live pin is a hard refusal in the shim ABI pre-flight
    /// (`validateUserspaceShimLivePins`) — see `session/entry.rs`. Appending this u32 on the
    /// existing 8-byte boundary + the compiler's 4-byte tail pad grows the
    /// struct 136 -> 144 (v4) / 184 -> 192 (v6) -- `ingress_vlan_id` below
    /// lands inside that same tail pad, so it costs nothing further.
    ingress_ifindex: u32,
    /// #4983: the 802.1Q VLAN id the session's first packet arrived with. 0 is
    /// BOTH untagged and 802.1p priority-tagged (a real tag with VID 0 and
    /// PCP/DEI set); this bare VID does not distinguish them, though the TX
    /// side does via `TxVlanTag` on tag PRESENCE (#2149, afxdp/README.md).
    /// Paired with `ingress_ifindex` it names the LOGICAL ingress
    /// unit using the very same `{parent ifindex, vlan}` identity the Go side
    /// already resolves the EGRESS interface name by, so two VLAN units of one
    /// trunk NIC are distinguishable rather than aliased onto the NIC.
    ingress_vlan_id: u16,
}

/// Mirrors C `struct session_key_v6` — 40 bytes, packed.
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct BpfSessionKeyV6 {
    src_ip: [u8; 16],
    dst_ip: [u8; 16],
    src_port: u16, // __be16, network byte order
    dst_port: u16, // __be16, network byte order
    protocol: u8,
    pad: [u8; 3],
}

/// Build the v4 conntrack map key.
///
/// SINGLE SOURCE (#7743). The conntrack map is written by three separate
/// operations — publish (`publish_conntrack`), refresh (the lookup+`BPF_EXIST`
/// update in `refresh_bpf_conntrack_entry`), and delete
/// (`delete_bpf_conntrack_entry`). A BPF hash map is keyed on the raw key
/// BYTES, so all three must produce a byte-identical key or the operations
/// stop addressing the same row: a publish that encodes ports differently from
/// the delete writes an entry the delete can never remove, leaking a conntrack
/// row for the life of the map. Before #7743 each of the eight sites
/// hand-rolled this literal, so the `to_be()` and the zeroed `pad` were
/// repeated assumptions rather than one enforced encoding.
#[inline]
fn bpf_session_key_v4(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    protocol: u8,
) -> BpfSessionKeyV4 {
    BpfSessionKeyV4 {
        src_ip,
        dst_ip,
        // __be16 on the wire; SessionKey holds host order.
        src_port: src_port.to_be(),
        dst_port: dst_port.to_be(),
        protocol,
        pad: [0; 3],
    }
}

/// Build the v6 conntrack map key. See [`bpf_session_key_v4`] for why this is
/// single-sourced.
#[inline]
fn bpf_session_key_v6(
    src_ip: [u8; 16],
    dst_ip: [u8; 16],
    src_port: u16,
    dst_port: u16,
    protocol: u8,
) -> BpfSessionKeyV6 {
    BpfSessionKeyV6 {
        src_ip,
        dst_ip,
        src_port: src_port.to_be(),
        dst_port: dst_port.to_be(),
        protocol,
        pad: [0; 3],
    }
}

/// Mirrors C `struct session_value_v6` — full connection state with 128-bit IPs.
#[repr(C)]
#[derive(Clone, Copy)]
struct BpfSessionValueV6 {
    state: u8,
    // __u16 to fit SESS_FLAG_NPTV6 (bit 8), see BpfSessionValueV4::flags (#5460).
    // Layout matches C `struct session_value_v6` (size-asserted at 192 -- 184
    // before #4983 added the ingress-identity pair below).
    flags: u16,
    tcp_state: u8,
    is_reverse: u8,
    app_timeout: u32,
    session_id: u64,
    created: u64,
    last_seen: u64,
    timeout: u32,
    policy_id: u32,
    ingress_zone: u16,
    egress_zone: u16,
    nat_src_ip: [u8; 16],
    nat_dst_ip: [u8; 16],
    nat_src_port: u16, // __be16, network byte order
    nat_dst_port: u16, // __be16, network byte order
    fwd_packets: u64,
    fwd_bytes: u64,
    rev_packets: u64,
    rev_bytes: u64,
    reverse_key: BpfSessionKeyV6,
    alg_type: u8,
    log_flags: u8,
    app_id: u16,
    fib_ifindex: u32,
    fib_vlan_id: u16,
    fib_dmac: [u8; 6],
    fib_smac: [u8; 6],
    fib_gen: u16,
    /// #4983: the ifindex of the binding the session's FIRST packet arrived
    /// on -- the session's TRUE ingress identity, stamped once at install from
    /// `SessionMetadata::ingress_ifindex` and never re-derived from the zone.
    /// Distinct from `fib_ifindex` above, which is the resolved EGRESS. `0`
    /// means "no ingress identity carried" (reverse companion / peer-synced /
    /// host-outbound GRE, which has no ingress binding to record) and is never
    /// a valid ifindex; the Go consumer falls back to the zone approximation
    /// for it. #6928: this parenthetical listed a "pre-#4983 entry" as a fourth
    /// case; there is no such population, because a `ValueSize` mismatch
    /// against the live pin is a hard refusal in the shim ABI pre-flight
    /// (`validateUserspaceShimLivePins`) — see `session/entry.rs`. Appending this u32 on the
    /// existing 8-byte boundary + the compiler's 4-byte tail pad grows the
    /// struct 136 -> 144 (v4) / 184 -> 192 (v6) -- `ingress_vlan_id` below
    /// lands inside that same tail pad, so it costs nothing further.
    ingress_ifindex: u32,
    /// #4983: the 802.1Q VLAN id the session's first packet arrived with. 0 is
    /// BOTH untagged and 802.1p priority-tagged (a real tag with VID 0 and
    /// PCP/DEI set); this bare VID does not distinguish them, though the TX
    /// side does via `TxVlanTag` on tag PRESENCE (#2149, afxdp/README.md).
    /// Paired with `ingress_ifindex` it names the LOGICAL ingress
    /// unit using the very same `{parent ifindex, vlan}` identity the Go side
    /// already resolves the EGRESS interface name by, so two VLAN units of one
    /// trunk NIC are distinguishable rather than aliased onto the NIC.
    ingress_vlan_id: u16,
}

// #4983: WHERE the ingress-identity pair sits, not just how big the struct is.
//
// `bpf_conntrack_struct_sizes_match_c` cannot see a REORDER. Swapping the two
// fields in both structs puts the u16 at 136/184 and the u32 at 140/188, and
// `size_of` stays 144/192 — so the size test passes and the whole crate suite
// passes. That was measured, not reasoned: the transposed tree ran the full
// suite green. Nothing else catches it either — the
// `build_conntrack_value_stamps_ingress_identity_*` tests compare struct
// FIELDS, so they are transposition-blind by construction, and the C header
// has no compiled consumer on this side.
//
// What a transposition costs at runtime: this helper writes the VLAN id where
// Go reads the ifindex. A host-inbound session on {parent ifindex 24, VLAN 80}
// goes onto the map as ifindex=80/vlan=24, Go lifts it as
// IngressIfindex=80/IngressVlanID=24, `ifaceNamesByKey[{80,24}]` misses, and
// every row silently degrades to the zone approximation — and on a box that
// really does have an ifindex 80, the CLI names the WRONG NIC instead. Both
// numbers are plausible, so nothing surfaces as an error.
//
// These are compile-time, so a transposition is a BUILD failure rather than a
// test failure. The offsets are the ones C writes
// (`bpf/headers/xpf_conntrack.h`), and they are the same four the Go mirror
// pins in `TestBPFSessionValueIngressIdentityOffsets`
// (`pkg/dataplane/bpf_session_value_test.go`) — three sides, one set of
// numbers. Same idiom as `UserspaceDpMeta` in `afxdp/types/mod.rs`.
const _: [(); 136] = [(); std::mem::offset_of!(BpfSessionValueV4, ingress_ifindex)];
const _: [(); 140] = [(); std::mem::offset_of!(BpfSessionValueV4, ingress_vlan_id)];
const _: [(); 184] = [(); std::mem::offset_of!(BpfSessionValueV6, ingress_ifindex)];
const _: [(); 188] = [(); std::mem::offset_of!(BpfSessionValueV6, ingress_vlan_id)];

/// Session flag constants matching C SESS_FLAG_* defines. `u16` because the
/// `session_value.flags` field is `__u16` (SESS_FLAG_NPTV6 is bit 8, #5460).
const SESS_FLAG_SNAT: u16 = 1 << 0;
const SESS_FLAG_DNAT: u16 = 1 << 1;
/// Session state constants matching C SESS_STATE_* defines.
const SESS_STATE_ESTABLISHED: u8 = 4;

/// Write a session entry to the BPF conntrack map so `show security flow session`
/// displays correct zone and interface information for helper-managed sessions.
///
/// `conntrack_v4_fd` / `conntrack_v6_fd`: FDs for the pinned `sessions` / `sessions_v6`
/// BPF HASH maps. Pass -1 if unavailable (will be a no-op).
/// #6965 fail-on-revert instrumentation: every `publish_bpf_conntrack_entry`
/// call, recorded with enough of its arguments to say WHICH population it came
/// from.
///
/// A bare counter would not do the job here. The test driver
/// (`tests_support::txn_run_descriptor`) passes `-1` for both conntrack fds, so
/// no row is ever written in a unit test and there is nothing in a map to read
/// back. What the #6965 defect actually IS, though, is a MISSING CALL SITE —
/// the transit forward install never called this function at all — so the
/// property to bind is the call and its arguments, not the map write. The value
/// SHAPE this function produces from those arguments is a different property
/// and is already owned by `bpf_map_tests.rs`
/// (`build_conntrack_value_v4`/`_v6`); this recorder deliberately does not
/// restate it.
///
/// Recording the ingress identity and `is_reverse` rather than counting is what
/// makes the transit assertion non-vacuous: a count of 1 is also what you get
/// from a publish of the WRONG row, and the three pre-existing call sites all
/// publish rows this fixture must not be satisfied by.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ConntrackPublishRecord {
    pub(super) is_reverse: bool,
    pub(super) ingress_ifindex: u32,
    pub(super) ingress_vlan_id: u16,
    pub(super) ingress_zone: u16,
    pub(super) egress_zone: u16,
    pub(super) app_id: u16,
    pub(super) session_id: u64,
}

#[cfg(test)]
pub(super) static CONNTRACK_PUBLISHES: std::sync::Mutex<Vec<ConntrackPublishRecord>> =
    std::sync::Mutex::new(Vec::new());

/// #6965: the ONE mutex that serializes tests SAMPLING `CONNTRACK_PUBLISHES`.
///
/// Module scope for the same reason as `checksum::DNAT_COUNTER_GUARD` (#6872):
/// a `static` declared inside a test function body is unnameable from any other
/// function, so two tests each declaring one lock private mutexes and exclude
/// nobody. This does NOT mutually exclude the writer below — that is production
/// code on the install path and must not take a lock — it serializes the
/// samplers against each other, which is the shape that breaks.
#[cfg(test)]
pub(super) static CONNTRACK_PUBLISH_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// #6965: clear the recorder and return the guard, so a sampling test cannot
/// forget either half.
#[cfg(test)]
pub(super) fn take_conntrack_publish_guard() -> std::sync::MutexGuard<'static, ()> {
    let guard = CONNTRACK_PUBLISH_GUARD
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    CONNTRACK_PUBLISHES
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clear();
    guard
}

#[cfg(test)]
pub(super) fn conntrack_publishes() -> Vec<ConntrackPublishRecord> {
    CONNTRACK_PUBLISHES
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

pub(super) fn publish_bpf_conntrack_entry(
    conntrack_v4_fd: c_int,
    conntrack_v6_fd: c_int,
    key: &SessionKey,
    decision: SessionDecision,
    metadata: &SessionMetadata,
    _zone_name_to_id: &FastMap<String, u16>,
    // `security alg <proto> disable` bitfield (#2008 H3/H4). Carried from
    // ForwardingState so the session's alg_type honours the operator's
    // disable knobs instead of being hardcoded to 0.
    alg_disable_flags: u8,
    // Resolved application-identification id (#2008 M5). 0 = unknown (the
    // existing default). Computed by the caller from
    // ForwardingState.app_catalog so both the v4 and v6 publish stamp the
    // session's app_id, letting `show security flow session` report a name.
    app_id: u16,
    // #5213: the STABLE dataplane session id (`SessionEntry.session_id`, #4915)
    // for this session, resolved by the caller from the session table
    // (`SessionTable::session_id_for`). Stamped into the conntrack value so
    // `show security flow session` reports the SAME id RT_FLOW emits. `0` =
    // unknown (no live entry) — the Go render then keeps the legacy ordinal.
    session_id: u64,
) {
    // #6965: record the call BEFORE the `fd >= 0` gate below. The gate is what
    // makes this a no-op under a unit test's `-1` fds, and the property the
    // #6965 tests bind is that the call SITE exists on the transit install
    // path — which is fd-independent.
    #[cfg(test)]
    {
        CONNTRACK_PUBLISHES
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(ConntrackPublishRecord {
                is_reverse: metadata.is_reverse,
                ingress_ifindex: metadata.ingress_ifindex,
                ingress_vlan_id: metadata.ingress_vlan_id,
                ingress_zone: metadata.ingress_zone,
                egress_zone: metadata.egress_zone,
                app_id,
                session_id,
            });
    }
    // #919: zones are now u16 in SessionMetadata; the round-trip
    // name→id lookup the old code did is gone.
    let ingress_zone_id = metadata.ingress_zone;
    let egress_zone_id = metadata.egress_zone;

    let now_secs = monotonic_nanos() / 1_000_000_000;

    let mut flags: u16 = 0;
    if decision.nat.rewrite_src.is_some() {
        flags |= SESS_FLAG_SNAT;
    }
    if decision.nat.rewrite_dst.is_some() {
        flags |= SESS_FLAG_DNAT;
    }

    match (key.addr_family as i32, &key.src_ip, &key.dst_ip) {
        (libc::AF_INET, IpAddr::V4(src), IpAddr::V4(dst)) if conntrack_v4_fd >= 0 => {
            publish_conntrack::publish_v4_session(
                conntrack_v4_fd,
                key,
                *src,
                *dst,
                decision,
                metadata,
                flags,
                ingress_zone_id,
                egress_zone_id,
                now_secs,
                alg_disable_flags,
                app_id,
                session_id,
            );
        }
        (libc::AF_INET6, IpAddr::V6(src), IpAddr::V6(dst)) if conntrack_v6_fd >= 0 => {
            publish_conntrack::publish_v6_session(
                conntrack_v6_fd,
                key,
                *src,
                *dst,
                decision,
                metadata,
                flags,
                ingress_zone_id,
                egress_zone_id,
                now_secs,
                alg_disable_flags,
                app_id,
                session_id,
            );
        }
        _ => {}
    }
}

/// Delete a session entry from the BPF conntrack map.
pub(super) fn delete_bpf_conntrack_entry(
    conntrack_v4_fd: c_int,
    conntrack_v6_fd: c_int,
    key: &SessionKey,
) {
    match (key.addr_family as i32, &key.src_ip, &key.dst_ip) {
        (libc::AF_INET, IpAddr::V4(src), IpAddr::V4(dst)) if conntrack_v4_fd >= 0 => {
            let bpf_key = bpf_session_key_v4(src.octets(), dst.octets(), key.src_port, key.dst_port, key.protocol);
            let _ = unsafe {
                libbpf_sys::bpf_map_delete_elem(
                    conntrack_v4_fd,
                    (&bpf_key as *const BpfSessionKeyV4).cast::<c_void>(),
                )
            };
        }
        (libc::AF_INET6, IpAddr::V6(src), IpAddr::V6(dst)) if conntrack_v6_fd >= 0 => {
            let bpf_key = bpf_session_key_v6(src.octets(), dst.octets(), key.src_port, key.dst_port, key.protocol);
            let _ = unsafe {
                libbpf_sys::bpf_map_delete_elem(
                    conntrack_v6_fd,
                    (&bpf_key as *const BpfSessionKeyV6).cast::<c_void>(),
                )
            };
        }
        _ => {}
    }
}

/// Update `last_seen` in BPF conntrack entries for active userspace sessions.
///
/// The userspace helper owns session lifetime in its own SessionTable, but
/// `publish_bpf_conntrack_entry` only writes `last_seen` at creation time.
/// Without periodic refresh, Go callers of `IterateSessions` (CLI session
/// display, Prometheus metrics, ARP warmup, HA sync) see stale idle times.
///
/// The Go GC has `SkipSweep` set when the userspace DP is active, so stale
/// `last_seen` will NOT cause premature expiry. This refresh is purely for
/// diagnostic accuracy.
///
/// #5287: this is an INCREMENTAL, budgeted slice — NOT a full-table pass. It
/// refreshes at most `budget` slab slots starting at `cursor` and returns the
/// next cursor for the following slice (0 once a full-table cycle completes).
/// The worker loop drives one slice per ~100ms and paces successive cycles to
/// the ~10s freshness window, so the whole table still gets refreshed within
/// that window but the per-tick cost is hard-bounded instead of the old
/// tens-of-thousands-of-syscalls single burst that stalled the low-latency
/// core. See `SessionTable::iter_with_idle_budgeted` and the worker loop.
///
/// #3395: `policy` is the CURRENT snapshot's `PolicyState`. For every refreshed
/// forward entry the live-row `policy_id` is RE-RESOLVED from the session's
/// bound rule handle (`SessionMetadata::policy_counter`, #3322) against the
/// current rule table, so `show security flow session` (and the REST/gRPC
/// surfaces that read `val.PolicyID`) attribute an established session to its
/// admitting rule's CURRENT positional id after a live mid-list policy
/// insert/delete — instead of the frozen-at-install stale index. A session whose
/// admitting rule was deleted re-resolves to the unattributed default-policy
/// sentinel; an unbound (non-policy / peer-synced) session keeps its frozen id.
/// See `PolicyState::reresolve_session_policy_id`.
pub(super) fn refresh_bpf_conntrack_last_seen(
    conntrack_v4_fd: c_int,
    conntrack_v6_fd: c_int,
    sessions: &crate::session::SessionTable,
    policy: &crate::policy::PolicyState,
    now_ns: u64,
    cursor: usize,
    budget: usize,
) -> usize {
    let now_secs = now_ns / 1_000_000_000;

    sessions.iter_with_idle_budgeted(cursor, budget, now_ns, |key, _decision, metadata, idle_ns, counters| {
        // Only refresh forward entries — reverse entries mirror the forward.
        // #2501: the forward SessionEntry carries BOTH directions' counters
        // (the reverse entry shares them via the canonical forward key the
        // hot path accounts under), so the forward-only mirror surfaces the
        // full fwd+rev volume.
        if metadata.is_reverse {
            return;
        }
        // #3395: re-resolve the live-row policy_id from the bound rule handle
        // against the current rule table (frozen-at-install id would mis-map
        // after a live policy reorder).
        let reresolved_policy_id = policy
            .reresolve_session_policy_id(metadata.policy_counter.as_ref(), metadata.policy_id);
        match (key.addr_family as i32, &key.src_ip, &key.dst_ip) {
            (libc::AF_INET, IpAddr::V4(src), IpAddr::V4(dst)) if conntrack_v4_fd >= 0 => {
                let bpf_key = bpf_session_key_v4(src.octets(), dst.octets(), key.src_port, key.dst_port, key.protocol);
                let mut value: BpfSessionValueV4 = unsafe { std::mem::zeroed() };
                let rc = unsafe {
                    libbpf_sys::bpf_map_lookup_elem(
                        conntrack_v4_fd,
                        (&bpf_key as *const BpfSessionKeyV4).cast::<c_void>(),
                        (&mut value as *mut BpfSessionValueV4).cast::<c_void>(),
                    )
                };
                if rc == 0 {
                    // Compute last_seen from session's actual idle, not now.
                    let actual_last_seen = now_secs.saturating_sub(idle_ns / 1_000_000_000);
                    value.last_seen = actual_last_seen;
                    // #3395: re-stamp the re-resolved current positional policy_id
                    // so a live policy reorder no longer mis-attributes this
                    // established session's row.
                    value.policy_id = reresolved_policy_id;
                    // #2501: surface live per-session volume so `show security
                    // flow session` reports real byte/packet counts.
                    value.fwd_packets = counters.fwd_packets;
                    value.fwd_bytes = counters.fwd_bytes;
                    value.rev_packets = counters.rev_packets;
                    value.rev_bytes = counters.rev_bytes;
                    let _ = unsafe {
                        libbpf_sys::bpf_map_update_elem(
                            conntrack_v4_fd,
                            (&bpf_key as *const BpfSessionKeyV4).cast::<c_void>(),
                            (&value as *const BpfSessionValueV4).cast::<c_void>(),
                            libbpf_sys::BPF_EXIST as u64, // avoid recreating deleted entries
                        )
                    };
                }
            }
            (libc::AF_INET6, IpAddr::V6(src), IpAddr::V6(dst)) if conntrack_v6_fd >= 0 => {
                let bpf_key = bpf_session_key_v6(src.octets(), dst.octets(), key.src_port, key.dst_port, key.protocol);
                let mut value: BpfSessionValueV6 = unsafe { std::mem::zeroed() };
                let rc = unsafe {
                    libbpf_sys::bpf_map_lookup_elem(
                        conntrack_v6_fd,
                        (&bpf_key as *const BpfSessionKeyV6).cast::<c_void>(),
                        (&mut value as *mut BpfSessionValueV6).cast::<c_void>(),
                    )
                };
                if rc == 0 {
                    let actual_last_seen = now_secs.saturating_sub(idle_ns / 1_000_000_000);
                    value.last_seen = actual_last_seen;
                    // #3395: re-stamp the re-resolved current positional policy_id
                    // (see v4 arm).
                    value.policy_id = reresolved_policy_id;
                    // #2501: surface live per-session volume (see v4 arm).
                    value.fwd_packets = counters.fwd_packets;
                    value.fwd_bytes = counters.fwd_bytes;
                    value.rev_packets = counters.rev_packets;
                    value.rev_bytes = counters.rev_bytes;
                    let _ = unsafe {
                        libbpf_sys::bpf_map_update_elem(
                            conntrack_v6_fd,
                            (&bpf_key as *const BpfSessionKeyV6).cast::<c_void>(),
                            (&value as *const BpfSessionValueV6).cast::<c_void>(),
                            libbpf_sys::BPF_EXIST as u64,
                        )
                    };
                }
            }
            _ => {}
        }
    })
}

pub(super) fn publish_session_map_entry_for_session(
    map_fd: c_int,
    key: &SessionKey,
    decision: SessionDecision,
    metadata: &SessionMetadata,
) -> io::Result<()> {
    publish_session_map_entry_for_session_with_origin(
        map_fd,
        key,
        decision,
        metadata,
        SessionOrigin::ForwardFlow,
    )
}

pub(super) fn publish_session_map_entry_for_session_with_origin(
    map_fd: c_int,
    key: &SessionKey,
    decision: SessionDecision,
    metadata: &SessionMetadata,
    origin: SessionOrigin,
) -> io::Result<()> {
    publish_session_map_entry_for_session_with_conntrack(
        map_fd, key, decision, metadata, origin, None,
    )
}

pub(super) fn publish_session_map_entry_for_session_with_conntrack(
    map_fd: c_int,
    key: &SessionKey,
    decision: SessionDecision,
    metadata: &SessionMetadata,
    origin: SessionOrigin,
    ct: Option<ConntrackCtx<'_>>,
) -> io::Result<()> {
    if uses_kernel_local_session_map_entry(decision, metadata, origin) {
        publish_kernel_local_session_key(map_fd, key)?;
        // For SNATed local-delivery sessions (e.g., ICMP to an interface-NAT
        // address), the reply packet arrives with the SNAT address as
        // destination. Publish the reverse session key so the XDP shim
        // redirects reply packets to the helper for reverse-NAT processing
        // instead of passing them to the kernel where no NAT reversal exists.
        if decision.nat.rewrite_src.is_some() {
            let reverse_wire = reverse_session_key(key, decision.nat);
            if reverse_wire != *key {
                publish_live_session_key(map_fd, &reverse_wire)?;
            }
        }
        // Also mirror to conntrack for session display.
        if let Some(ctx) = ct {
            publish_bpf_conntrack_entry(
                ctx.v4_fd,
                ctx.v6_fd,
                key,
                decision,
                metadata,
                ctx.zone_name_to_id,
                ctx.alg_disable_flags,
                ctx.app_id,
                ctx.session_id,
            );
        }
        return Ok(());
    }
    let result = publish_live_session_entry(map_fd, key, decision.nat, metadata.is_reverse);
    // Mirror to conntrack for session display.
    if let Some(ctx) = ct {
        publish_bpf_conntrack_entry(
            ctx.v4_fd,
            ctx.v6_fd,
            key,
            decision,
            metadata,
            ctx.zone_name_to_id,
            ctx.alg_disable_flags,
            ctx.app_id,
            ctx.session_id,
        );
    }
    result
}

/// Verify a session key exists in the BPF map (read-back after publish).
pub(super) fn verify_session_key_in_bpf(map_fd: c_int, key: &SessionKey) -> bool {
    let map_key = session_map_key(key);
    let mut value = 0u8;
    let rc = unsafe {
        libbpf_sys::bpf_map_lookup_elem(
            map_fd,
            (&map_key as *const UserspaceSessionMapKey).cast::<c_void>(),
            (&mut value as *mut u8).cast::<c_void>(),
        )
    };
    rc == 0
}

pub(super) fn delete_live_session_key(map_fd: c_int, key: &SessionKey) {
    let map_key = session_map_key(key);
    let _ = unsafe {
        libbpf_sys::bpf_map_delete_elem(
            map_fd,
            (&map_key as *const UserspaceSessionMapKey).cast::<c_void>(),
        )
    };
}

pub(super) fn delete_live_session_entry(
    map_fd: c_int,
    key: &SessionKey,
    nat: NatDecision,
    is_reverse: bool,
) {
    delete_live_session_key(map_fd, key);
    if !is_reverse {
        let wire_key = forward_wire_key(key, nat);
        if wire_key != *key {
            delete_live_session_key(map_fd, &wire_key);
        }
        let reverse_wire = reverse_session_key(key, nat);
        if reverse_wire != *key {
            delete_live_session_key(map_fd, &reverse_wire);
        }
        let reverse_canonical = reverse_canonical_key(key, nat);
        if reverse_canonical != *key && reverse_canonical != reverse_wire {
            delete_live_session_key(map_fd, &reverse_canonical);
        }
    }
}

fn for_each_session_map_redirect_key<F>(
    key: &SessionKey,
    decision: SessionDecision,
    metadata: &SessionMetadata,
    _origin: SessionOrigin,
    mut f: F,
) where
    F: FnMut(SessionKey),
{
    f(key.clone());
    if !metadata.is_reverse {
        let wire_key = forward_wire_key(key, decision.nat);
        if wire_key != *key {
            f(wire_key);
        }
        let reverse_wire = reverse_session_key(key, decision.nat);
        if reverse_wire != *key {
            f(reverse_wire.clone());
        }
        let reverse_canonical = reverse_canonical_key(key, decision.nat);
        if reverse_canonical != *key && reverse_canonical != reverse_wire {
            f(reverse_canonical);
        }
    }
}

#[cfg(test)]
fn session_map_redirect_keys_for_session(
    key: &SessionKey,
    decision: SessionDecision,
    metadata: &SessionMetadata,
    origin: SessionOrigin,
) -> Vec<SessionKey> {
    let mut keys = Vec::with_capacity(4);
    for_each_session_map_redirect_key(key, decision, metadata, origin, |redirect_key| {
        keys.push(redirect_key);
    });
    keys
}

pub(super) fn delete_session_map_redirect_for_session(
    map_fd: c_int,
    key: &SessionKey,
    decision: SessionDecision,
    metadata: &SessionMetadata,
    origin: SessionOrigin,
) {
    for_each_session_map_redirect_key(key, decision, metadata, origin, |redirect_key| {
        delete_live_session_key(map_fd, &redirect_key);
    });
}

pub(super) fn delete_session_map_entry_for_removed_session(
    map_fd: c_int,
    key: &SessionKey,
    decision: SessionDecision,
    metadata: &SessionMetadata,
) {
    // Default to SyncImport for backwards-compatible callers where
    // the session being deleted is always from a sync path.
    delete_session_map_entry_for_removed_session_with_origin(
        map_fd,
        key,
        decision,
        metadata,
        SessionOrigin::SyncImport,
        -1,
        -1,
    );
}

pub(super) fn delete_session_map_entry_for_removed_session_with_origin(
    map_fd: c_int,
    key: &SessionKey,
    decision: SessionDecision,
    metadata: &SessionMetadata,
    origin: SessionOrigin,
    conntrack_v4_fd: c_int,
    conntrack_v6_fd: c_int,
) {
    // #7743: the conntrack mirror is deleted unconditionally. This was written
    // as an `if uses_kernel_local_session_map_entry(..) { delete; return } delete`
    // whose two arms called the SAME function with the SAME arguments, so the
    // branch never changed an outcome. It is collapsed rather than given a
    // second behaviour because the delete is already correct for both cases:
    // the kernel-local publish path writes its entry under `session_map_key`
    // (only the map VALUE differs — `USERSPACE_SESSION_ACTION_PASS_TO_KERNEL`),
    // and a BPF delete addresses the row by KEY, so the redirect walk below
    // removes the kernel-local row and the live row alike.
    delete_session_map_redirect_for_session(map_fd, key, decision, metadata, origin);
    delete_bpf_conntrack_entry(conntrack_v4_fd, conntrack_v6_fd, key);
}

#[cfg(test)]
#[path = "../bpf_map_tests.rs"]
mod tests;

mod publish_conntrack;

// #2003: behaviour-preserving code motion. Each submodule owns one
// cluster — `ha.rs` the HA liveness-slot writes (XSK + heartbeat map
// updates that gate active-binding state), `metrics.rs` the telemetry
// counters plus the raw-ring / session-map diagnostics, `pin.rs` the
// libbpf fd-pinning RAII wrapper and the pinned degraded-path stats
// reader. Items keep their original `pub(in crate::afxdp)` visibility and
// are re-exported so the parent `afxdp` glob (`use self::bpf_map::*`) and
// the relocated `bpf_map_tests.rs` (`use super::*`) resolve them by bare
// name exactly as before. Mirrors the `publish_conntrack.rs` precedent
// (#1356).
mod ha;
mod metrics;
mod pin;

pub(in crate::afxdp) use ha::*;
pub(in crate::afxdp) use metrics::*;
pub(in crate::afxdp) use pin::*;
