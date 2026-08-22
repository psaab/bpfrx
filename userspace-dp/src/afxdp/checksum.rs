use super::*;

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct DnatTableFds {
    pub(super) v4: Option<c_int>,
    #[allow(dead_code)] // reserved for DNAT v6 support
    pub(super) v6: Option<c_int>,
}

/// Compute IP header checksum delta from NAT IP rewrites.
/// Returns a 16-bit value that can be added to `!old_csum` along with
/// the TTL delta (`0x0100`) to produce the new checksum.
pub(super) fn compute_ip_csum_delta(flow: &SessionFlow, nat: &NatDecision) -> u16 {
    let mut sum: u32 = 0;
    if let Some(new_src) = nat.rewrite_src {
        if let (IpAddr::V4(old), IpAddr::V4(new)) = (flow.src_ip, new_src) {
            let old_w = ipv4_csum_words(old);
            let new_w = ipv4_csum_words(new);
            sum += (!old_w[0] as u32) & 0xffff;
            sum += (!old_w[1] as u32) & 0xffff;
            sum += new_w[0] as u32;
            sum += new_w[1] as u32;
        }
    }
    if let Some(new_dst) = nat.rewrite_dst {
        if let (IpAddr::V4(old), IpAddr::V4(new)) = (flow.dst_ip, new_dst) {
            let old_w = ipv4_csum_words(old);
            let new_w = ipv4_csum_words(new);
            sum += (!old_w[0] as u32) & 0xffff;
            sum += (!old_w[1] as u32) & 0xffff;
            sum += new_w[0] as u32;
            sum += new_w[1] as u32;
        }
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}

/// Compute L4 (TCP/UDP) pseudo-header checksum delta from NAT rewrites.
/// Includes both IP address and port changes. Handles IPv4 and IPv6.
pub(super) fn compute_l4_csum_delta(flow: &SessionFlow, nat: &NatDecision) -> u16 {
    let mut sum: u32 = 0;
    // #3121: a PURE NPTv6 translation (only one of src/dst rewritten, no
    // composed DNAT) is checksum-neutral by RFC 6296 -- the adjustment word
    // preserves the address's ones-complement sum -- so it contributes no L4
    // delta and we short-circuit. When NPTv6 COMPOSES with a destination
    // rewrite (DNAT), BOTH rewrite_src and rewrite_dst are set: the NPTv6 side
    // is still checksum-neutral (its word delta nets zero by construction,
    // regardless of whether it lands on src in the forward direction or dst in
    // the reverse), while the DNAT side is NOT neutral and MUST be folded in.
    // So in the compose case we fall through and compute both deltas; the
    // neutral NPTv6 term naturally sums to zero, leaving only the DNAT delta.
    if nat.nptv6 && !(nat.rewrite_src.is_some() && nat.rewrite_dst.is_some()) {
        return 0;
    }
    if let Some(new_src) = nat.rewrite_src {
        match (flow.src_ip, new_src) {
            (IpAddr::V4(old), IpAddr::V4(new)) => {
                let old_w = ipv4_csum_words(old);
                let new_w = ipv4_csum_words(new);
                sum += (!old_w[0] as u32) & 0xffff;
                sum += (!old_w[1] as u32) & 0xffff;
                sum += new_w[0] as u32;
                sum += new_w[1] as u32;
            }
            (IpAddr::V6(old), IpAddr::V6(new)) => {
                let old_o = old.octets();
                let new_o = new.octets();
                for i in (0..16).step_by(2) {
                    let old_w = u16::from_be_bytes([old_o[i], old_o[i + 1]]);
                    let new_w = u16::from_be_bytes([new_o[i], new_o[i + 1]]);
                    sum += (!old_w as u32) & 0xffff;
                    sum += new_w as u32;
                }
            }
            _ => {}
        }
    }
    if let Some(new_dst) = nat.rewrite_dst {
        match (flow.dst_ip, new_dst) {
            (IpAddr::V4(old), IpAddr::V4(new)) => {
                let old_w = ipv4_csum_words(old);
                let new_w = ipv4_csum_words(new);
                sum += (!old_w[0] as u32) & 0xffff;
                sum += (!old_w[1] as u32) & 0xffff;
                sum += new_w[0] as u32;
                sum += new_w[1] as u32;
            }
            (IpAddr::V6(old), IpAddr::V6(new)) => {
                let old_o = old.octets();
                let new_o = new.octets();
                for i in (0..16).step_by(2) {
                    let old_w = u16::from_be_bytes([old_o[i], old_o[i + 1]]);
                    let new_w = u16::from_be_bytes([new_o[i], new_o[i + 1]]);
                    sum += (!old_w as u32) & 0xffff;
                    sum += new_w as u32;
                }
            }
            _ => {}
        }
    }
    if let Some(new_port) = nat.rewrite_src_port {
        let old_port = flow.forward_key.src_port;
        sum += (!old_port as u32) & 0xffff;
        sum += new_port as u32;
    }
    if let Some(new_port) = nat.rewrite_dst_port {
        let old_port = flow.forward_key.dst_port;
        sum += (!old_port as u32) & 0xffff;
        sum += new_port as u32;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    // #3121: the checksum-neutral NPTv6 term in a compose folds to a
    // ones-complement zero (0x0000 or 0xFFFF) and is the additive identity for
    // the DNAT term, so a composed NPTv6+DNAT delta folds to the DNAT delta on
    // its own -- no special canonicalization is needed here. The apply path
    // already handles a 0xFFFF (ones-complement zero) delta correctly, which
    // the v6 zero-encoding parity tests pin, so leave the folded sum as-is.
    sum as u16
}

#[inline]
pub(super) fn ipv4_csum_words(ip: Ipv4Addr) -> [u16; 2] {
    let o = ip.octets();
    [
        u16::from_be_bytes([o[0], o[1]]),
        u16::from_be_bytes([o[2], o[3]]),
    ]
}

/// Write a reverse SNAT entry to the BPF dnat_table so the eBPF
/// embedded ICMP handler can find the original pre-NAT source.
///
/// Returns `true` when the entry was published (or when there was
/// nothing to publish for this flow — no SNAT rewrite, an unsupported
/// address family, or an absent table fd), and `false` ONLY when the
/// `bpf_map_update_elem` syscall actually failed (map at capacity,
/// EINVAL, kernel resource exhaustion). #2244: the caller bumps a
/// per-binding `dnat_publish_errors` counter on `false` so map-pressure
/// reverse-NAT loss is operator-visible instead of silent. The result
/// is `#[must_use]` to keep the syscall return from being discarded
/// again.
/// Encode an SNAT66-return reverse-NAT entry for `dnat_table_v6` (#2406).
///
/// Returns the (key, value) byte buffers matching `struct dnat_key_v6`
/// (24B: protocol, 3B pad, 16B dst_ip, dst_port, from_zone) and
/// `struct dnat_value_v6` (20B: 16B new_dst_ip, new_dst_port, flags, pad) in
/// bpf/headers/xpf_maps.h. The key's dst is the SNAT address + SNAT port
/// (what the inbound return packet carries); the value is the original
/// pre-NAT source the shim must steer back toward. Pure so the wire layout
/// is unit-testable without a real BPF map.
///
/// #2406 BYTE-ORDER: the KEY port MUST be HOST-ORDER numeric serialized
/// natively (`to_ne_bytes`), NOT network-order. The AF_XDP shim's dnat
/// reader builds its lookup key port via `u16::from_be_bytes(wire)` (which
/// yields the host-order numeric value, e.g. 443) and stores it natively
/// into the key struct — identical to the proven `session_map_key` writer.
/// `snat_port` is already a host-order numeric `u16` in the helper, so
/// `to_ne_bytes` matches. A network-order key (`to_be_bytes`) never matches
/// the reader -> the lookup misses and the inbound ICMP error is not steered
/// (the original v6 AND v4 bug). The shim never reads the VALUE (steering is
/// `.is_some()` only); the value port encoding is inert, kept network-order.
pub(super) fn dnat_v6_entry_bytes(
    protocol: u8,
    snat_v6: std::net::Ipv6Addr,
    snat_port: u16,
    orig_v6: std::net::Ipv6Addr,
    orig_port: u16,
) -> ([u8; 24], [u8; 20]) {
    let mut dk = [0u8; 24];
    dk[0] = protocol;
    // dk[1..4] pad; dk[4..20] dst_ip; dk[20..22] dst_port; dk[22..24] from_zone(0)
    dk[4..20].copy_from_slice(&snat_v6.octets());
    dk[20..22].copy_from_slice(&snat_port.to_ne_bytes());

    let mut dv = [0u8; 20];
    dv[0..16].copy_from_slice(&orig_v6.octets());
    dv[16..18].copy_from_slice(&orig_port.to_be_bytes());
    dv[18] = 0; // flags: 0 = dynamic/SNAT-return
    (dk, dv)
}

/// Build the `dnat_table` (v4) lookup KEY for an SNAT'd flow, matching the
/// shim reader's encoding (see `dnat_v6_entry_bytes` for the byte-order
/// rationale). Returns `None` when the flow has no v4 SNAT rewrite and so
/// published no `dnat_table` entry. #2979: the SINGLE source of the v4 key
/// so the close-handler delete (`delete_dnat_table_entry`) and the
/// install-path publish (`publish_dnat_table_entry`) cannot drift — a
/// mismatched delete key would leave the entry leaked.
pub(super) fn dnat_v4_key_bytes(
    key: &crate::session::SessionKey,
    nat: NatDecision,
) -> Option<[u8; 12]> {
    let snat_v4 = match (key.addr_family as i32, nat.rewrite_src?) {
        (libc::AF_INET, IpAddr::V4(snat_v4)) => snat_v4,
        _ => return None,
    };
    let snat_port = nat.rewrite_src_port.unwrap_or(key.src_port);
    let mut dk = [0u8; 12];
    dk[0] = key.protocol;
    dk[4..8].copy_from_slice(&snat_v4.octets());
    // #2406: KEY port is HOST-ORDER numeric serialized natively to
    // match the AF_XDP shim reader (from_be_bytes -> host order, stored
    // natively, like session_map_key). to_be_bytes (network order)
    // never matched the reader -> latent v4 reverse-NAT-over-GRE bug.
    dk[8..10].copy_from_slice(&snat_port.to_ne_bytes());
    Some(dk)
}

/// Build the `dnat_table_v6` lookup KEY for an SNAT66'd flow. Returns `None`
/// when the flow has no v6 SNAT rewrite. #2979: SSOT for the v6 key shared by
/// publish (install) and delete (close). The bytes mirror the KEY half of
/// `dnat_v6_entry_bytes` (the shim never reads the value).
pub(super) fn dnat_v6_key_bytes(
    key: &crate::session::SessionKey,
    nat: NatDecision,
) -> Option<[u8; 24]> {
    let snat_v6 = match (key.addr_family as i32, nat.rewrite_src?) {
        (libc::AF_INET6, IpAddr::V6(snat_v6)) => snat_v6,
        _ => return None,
    };
    let snat_port = nat.rewrite_src_port.unwrap_or(key.src_port);
    let mut dk = [0u8; 24];
    dk[0] = key.protocol;
    // dk[1..4] pad; dk[4..20] dst_ip; dk[20..22] dst_port; dk[22..24] from_zone(0)
    dk[4..20].copy_from_slice(&snat_v6.octets());
    dk[20..22].copy_from_slice(&snat_port.to_ne_bytes());
    Some(dk)
}

/// #6745: the sessions currently relying on each reverse-NAT steering row.
///
/// THE ROW IS SHARED AND THE CLOSE WAS NOT. `dnat_v4_key_bytes` /
/// `dnat_v6_key_bytes` build the key from `(protocol, SNAT source address,
/// SNAT source port)` and NOTHING ELSE — the remote endpoint is absent. Under
/// address-only SNAT (`port no-translation`) and plain static SNAT, two flows
/// from one internal source to DIFFERENT remotes therefore land on ONE row,
/// and the allocator admits both on purpose: `AddressOnlyReverseKey`
/// (`nat/allocator.rs`) enforces uniqueness on a key that DOES include
/// `dst_ip`/`dst_port`. A per-session close then deleted that row
/// unconditionally, so closing either flow removed the steering the other one
/// still needed.
///
/// WHY A READ-BEFORE-DELETE VALUE COMPARISON IS NOT THE FIX, since it is the
/// first thing anyone reaches for and it is a strict improvement for a
/// different case. The VALUE encodes the reverse-NAT target — the ORIGINAL
/// source ip/port. The two colliding flows above share one internal source, so
/// both publish an IDENTICAL value: a comparison cannot separate them, and the
/// closing session still deletes the row the survivor needs. It fixes only the
/// DISPLACED case (one session's publish overwrote another's differing value).
/// Holders are what the shared case needs.
///
/// WHY A PROCESS GLOBAL, and not a field threaded through the callers. The
/// `dnat_table` map is itself a single process-global object — `ha`'s import
/// path says so where it publishes ("The process-global `dnat_table` map is a
/// single shared object, so this once-per-synced-session publish (not per
/// worker) mirrors the primary"). Holder accounting has exactly that resource's
/// scope. Putting it in `DnatTableFds` would strip that struct's `Copy` and
/// churn every call site; keeping it here means the ONLY two functions that
/// touch a row are also the only two that account for it, so the accounting
/// cannot drift from the map — there is nowhere else to put it.
///
/// COST. One uncontended mutex acquisition on a path that already performs a
/// `bpf_map_update_elem` / `bpf_map_delete_elem` SYSCALL for the same row, and
/// only for sessions that carry a source rewrite. It is not on the per-packet
/// path; it is per NAT'd session install and close.
static DNAT_STEERING_HOLDERS: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<DnatSteeringKey, Vec<crate::session::SessionKey>>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

/// The identity of one reverse-NAT steering row, per family.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub(super) enum DnatSteeringKey {
    V4([u8; 12]),
    V6([u8; 24]),
}

/// The steering row `key`+`nat` would publish, or `None` when the flow has no
/// SNAT source rewrite and therefore publishes no row.
pub(super) fn dnat_steering_key(
    key: &crate::session::SessionKey,
    nat: NatDecision,
) -> Option<DnatSteeringKey> {
    match key.addr_family as i32 {
        libc::AF_INET => dnat_v4_key_bytes(key, nat).map(DnatSteeringKey::V4),
        libc::AF_INET6 => dnat_v6_key_bytes(key, nat).map(DnatSteeringKey::V6),
        _ => None,
    }
}

/// Record that `key` relies on its steering row. Idempotent: a re-publish of
/// the same session (re-sync, reconcile replay, a second worker seeing the
/// same flow) must not add a second holder, or the row would outlive its last
/// real user.
pub(super) fn add_dnat_steering_holder(key: &crate::session::SessionKey, nat: NatDecision) {
    let Some(sk) = dnat_steering_key(key, nat) else {
        return;
    };
    let mut holders = DNAT_STEERING_HOLDERS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let entry = holders.entry(sk).or_default();
    if !entry.iter().any(|held| held == key) {
        entry.push(key.clone());
    }
}

/// Drop `key`'s reliance on its steering row and report whether the ROW may now
/// be deleted.
///
/// Returns `true` when no other session holds it — including when nothing was
/// ever recorded, which is deliberately the PRE-#6745 answer: a row published
/// by a path that does not account (or by an older build across a restart) is
/// deleted exactly as before rather than leaked forever. The failure direction
/// of an accounting gap is therefore "unchanged", never "the map fills up".
pub(super) fn release_dnat_steering_holder(
    key: &crate::session::SessionKey,
    nat: NatDecision,
) -> bool {
    let Some(sk) = dnat_steering_key(key, nat) else {
        return true;
    };
    let mut holders = DNAT_STEERING_HOLDERS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let Some(entry) = holders.get_mut(&sk) else {
        return true;
    };
    entry.retain(|held| held != key);
    if entry.is_empty() {
        holders.remove(&sk);
        return true;
    }
    false
}

#[cfg(test)]
pub(super) fn dnat_steering_holder_count(
    key: &crate::session::SessionKey,
    nat: NatDecision,
) -> usize {
    let Some(sk) = dnat_steering_key(key, nat) else {
        return 0;
    };
    DNAT_STEERING_HOLDERS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(&sk)
        .map_or(0, |v| v.len())
}

#[cfg(test)]
pub(super) fn reset_dnat_steering_holders() {
    DNAT_STEERING_HOLDERS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clear();
}

/// #2979: delete the dynamic reverse-NAT `dnat_table` / `dnat_table_v6` entry
/// published by `publish_dnat_table_entry` when the SNAT'd session closes or
/// expires. The maps are `BPF_MAP_TYPE_HASH` (not LRU) with
/// `max_entries = MAX_SESSIONS` and `BPF_F_NO_PREALLOC`, so without this delete
/// every closed SNAT session leaks one entry until the map fills and new
/// reverse-NAT publishes start failing (the #2244 capacity error). The key is
/// derived from the SAME `dnat_v4_key_bytes` / `dnat_v6_key_bytes` helpers the
/// publish path uses, so it byte-matches the insert key exactly. A non-SNAT
/// session produces no key (`None`) and so is a no-op; an absent table fd is a
/// no-op; an absent-key delete (`ENOENT`) is benign (the entry was never
/// published, e.g. a publish that failed at capacity, or a non-DNAT flow).
pub(super) fn delete_dnat_table_entry(
    fds: &DnatTableFds,
    key: &crate::session::SessionKey,
    nat: NatDecision,
) {
    if nat.rewrite_src.is_none() {
        return;
    }
    // #6745: the steering row is SHARED — its key carries no remote endpoint,
    // so two sessions from one internal source to different remotes land on
    // one row and the allocator admits both deliberately. Release this
    // session's hold first and delete only when it was the last. A `false`
    // here means another live session still steers through this row; deleting
    // it would blackhole that session's return traffic until it re-published.
    // See DNAT_STEERING_HOLDERS for why a value comparison does not do this.
    if !release_dnat_steering_holder(key, nat) {
        return;
    }
    match key.addr_family as i32 {
        libc::AF_INET => {
            let (Some(fd), Some(dk)) = (fds.v4, dnat_v4_key_bytes(key, nat)) else {
                return;
            };
            // #2979: count the attempt so the close-handler wiring is testable
            // without a real BPF map (unprivileged_bpf_disabled blocks map
            // creation under `cargo test`). Production cost is one relaxed
            // increment under `#[cfg(test)]` only.
            #[cfg(test)]
            DNAT_DELETE_ATTEMPTS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            unsafe {
                libbpf_sys::bpf_map_delete_elem(fd, dk.as_ptr().cast::<libc::c_void>());
            }
        }
        libc::AF_INET6 => {
            let (Some(fd), Some(dk)) = (fds.v6, dnat_v6_key_bytes(key, nat)) else {
                return;
            };
            #[cfg(test)]
            DNAT_DELETE_ATTEMPTS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            unsafe {
                libbpf_sys::bpf_map_delete_elem(fd, dk.as_ptr().cast::<libc::c_void>());
            }
        }
        _ => {}
    }
}

// #2979 fail-on-revert instrumentation: counts `delete_dnat_table_entry`
// syscall attempts (an SNAT flow with a live table fd). Used by the
// close-handler wiring test in afxdp/tests.rs to prove a Close delta for an
// SNAT'd session reaches the dnat_table delete — RED if the delete call is
// removed from flush_session_deltas (the leak regresses). Test-only.
#[cfg(test)]
pub(super) static DNAT_DELETE_ATTEMPTS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

// #4393 fail-on-revert instrumentation: counts `publish_dnat_table_entry`
// syscall attempts (an SNAT flow with a live table fd). Used by the
// coordinator peer-synced-install wiring test in afxdp/ha_tests.rs to prove
// `upsert_synced_session` publishes the reverse-SNAT `dnat_table` entry for a
// synced SNAT session — RED if the publish call is removed from
// `upsert_synced_session` (the standby loses the embedded-ICMP steering entry
// and PMTUD blackholes after failover). Test-only; mirrors DNAT_DELETE_ATTEMPTS.
#[cfg(test)]
pub(super) static DNAT_PUBLISH_ATTEMPTS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

#[must_use]
pub(super) fn publish_dnat_table_entry(
    fds: &DnatTableFds,
    key: &crate::session::SessionKey,
    nat: NatDecision,
) -> bool {
    let Some(snat_ip) = nat.rewrite_src else {
        return true;
    };
    // #6745: record the hold BEFORE the map write, and unconditionally — not
    // only on the success path. A publish that fails still leaves this session
    // steering through that row conceptually, and more importantly the FAILURE
    // path must not make a concurrent sibling's close look like the last one.
    // Recording here also means every publisher accounts, including the HA
    // import path, which reaches this function and nothing else.
    add_dnat_steering_holder(key, nat);
    match (key.addr_family as i32, snat_ip) {
        (libc::AF_INET, IpAddr::V4(_snat_v4)) => {
            let Some(fd) = fds.v4 else { return true };
            let snat_port = nat.rewrite_src_port.unwrap_or(key.src_port);
            let IpAddr::V4(orig_v4) = key.src_ip else {
                return true;
            };
            // #2979: build the KEY via the shared helper so install and close
            // (delete_dnat_table_entry) cannot drift — the key bytes come from
            // the SSOT (dnat_v4_key_bytes), the value is built locally below.
            let Some(dk) = dnat_v4_key_bytes(key, nat) else {
                return true;
            };

            let mut dv = [0u8; 8];
            dv[0..4].copy_from_slice(&orig_v4.octets());
            // VALUE is never read by the shim (steering is .is_some() only);
            // encoding is inert, kept as-is.
            dv[4..6].copy_from_slice(&key.src_port.to_be_bytes());
            dv[6] = 0;

            // #4393: count the keyed publish attempt so the synced-install
            // wiring is testable without a real BPF map (test-only, no-op in
            // release). Mirrors DNAT_DELETE_ATTEMPTS on the delete side.
            #[cfg(test)]
            DNAT_PUBLISH_ATTEMPTS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let rc = unsafe {
                libbpf_sys::bpf_map_update_elem(
                    fd,
                    dk.as_ptr().cast::<libc::c_void>(),
                    dv.as_ptr().cast::<libc::c_void>(),
                    libbpf_sys::BPF_ANY as u64,
                )
            };
            if rc < 0 {
                // Error branch (map full / EINVAL / resource exhaustion).
                // The per-binding counter the caller bumps is the durable
                // signal. Both call sites are on the session-install path, so
                // under sustained dnat_table pressure every new SNAT'd session
                // would log — a journald storm. Gate the line to the first 32
                // failures (mirrors the first-N idiom at poll_descriptor's
                // ICMPV6_EMBED_LOGGED); after that the counter alone carries it.
                static DNAT_PUBLISH_LOG_COUNT: std::sync::atomic::AtomicU32 =
                    std::sync::atomic::AtomicU32::new(0);
                if DNAT_PUBLISH_LOG_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed) < 32 {
                    eprintln!(
                        "xpf: dnat_table reverse-NAT publish failed (proto={} snat_port={}): {} (further occurrences suppressed; see xpf_userspace_dnat_publish_errors_total)",
                        key.protocol,
                        snat_port,
                        std::io::Error::last_os_error()
                    );
                }
                return false;
            }
            true
        }
        (libc::AF_INET6, IpAddr::V6(snat_v6)) => {
            // SNAT66-return reverse mapping (#2406). Mirrors the v4 arm into
            // dnat_table_v6 (`struct dnat_key_v6` 24B / `struct dnat_value_v6`
            // 20B in bpf/headers/xpf_maps.h). The shim's GRE-inner v6 classify
            // (`dnat_lookup_v6`) reads this so an inbound ICMPv6 error whose
            // inner destination is the SNAT pool address is steered to the
            // helper for embedded-ICMP reverse-NAT.
            let Some(fd) = fds.v6 else { return true };
            let snat_port = nat.rewrite_src_port.unwrap_or(key.src_port);
            let IpAddr::V6(orig_v6) = key.src_ip else {
                return true;
            };
            let (dk, dv) = dnat_v6_entry_bytes(key.protocol, snat_v6, snat_port, orig_v6, key.src_port);

            // #4393: count the keyed publish attempt (test-only; see the v4 arm).
            #[cfg(test)]
            DNAT_PUBLISH_ATTEMPTS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let rc = unsafe {
                libbpf_sys::bpf_map_update_elem(
                    fd,
                    dk.as_ptr().cast::<libc::c_void>(),
                    dv.as_ptr().cast::<libc::c_void>(),
                    libbpf_sys::BPF_ANY as u64,
                )
            };
            if rc < 0 {
                static DNAT_PUBLISH_V6_LOG_COUNT: std::sync::atomic::AtomicU32 =
                    std::sync::atomic::AtomicU32::new(0);
                if DNAT_PUBLISH_V6_LOG_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed) < 32
                {
                    eprintln!(
                        "xpf: dnat_table_v6 reverse-NAT publish failed (proto={} snat_port={}): {} (further occurrences suppressed; see xpf_userspace_dnat_publish_errors_total)",
                        key.protocol,
                        snat_port,
                        std::io::Error::last_os_error()
                    );
                }
                return false;
            }
            true
        }
        _ => true,
    }
}
