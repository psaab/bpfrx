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
    if nat.nptv6 {
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
#[must_use]
pub(super) fn publish_dnat_table_entry(
    fds: &DnatTableFds,
    key: &crate::session::SessionKey,
    nat: NatDecision,
) -> bool {
    let Some(snat_ip) = nat.rewrite_src else {
        return true;
    };
    match (key.addr_family as i32, snat_ip) {
        (libc::AF_INET, IpAddr::V4(snat_v4)) => {
            let Some(fd) = fds.v4 else { return true };
            let snat_port = nat.rewrite_src_port.unwrap_or(key.src_port);
            let IpAddr::V4(orig_v4) = key.src_ip else {
                return true;
            };
            let mut dk = [0u8; 12];
            dk[0] = key.protocol;
            dk[4..8].copy_from_slice(&snat_v4.octets());
            dk[8..10].copy_from_slice(&snat_port.to_be_bytes());

            let mut dv = [0u8; 8];
            dv[0..4].copy_from_slice(&orig_v4.octets());
            dv[4..6].copy_from_slice(&key.src_port.to_be_bytes());
            dv[6] = 0;

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
        _ => true,
    }
}
