use super::*;

const GRE_FLAG_CHECKSUM: u16 = 0x8000;
const GRE_FLAG_ROUTING: u16 = 0x4000;
const GRE_FLAG_KEY: u16 = 0x2000;
const GRE_FLAG_SEQUENCE: u16 = 0x1000;
const GRE_VERSION_MASK: u16 = 0x0007;
const GRE_PROTO_IPV4: u16 = 0x0800;
const GRE_PROTO_IPV6: u16 = 0x86dd;

#[derive(Clone, Debug)]
pub(super) struct NativeGrePacket {
    pub(super) frame: Vec<u8>,
    pub(super) meta: UserspaceDpMeta,
}

fn parse_outer_addresses(frame: &[u8], meta: UserspaceDpMeta) -> Option<(IpAddr, IpAddr)> {
    let l3 = meta.l3_offset as usize;
    match meta.addr_family as i32 {
        libc::AF_INET => {
            let end = l3.checked_add(20)?;
            if end > frame.len() {
                return None;
            }
            Some((
                IpAddr::V4(Ipv4Addr::new(
                    frame[l3 + 12],
                    frame[l3 + 13],
                    frame[l3 + 14],
                    frame[l3 + 15],
                )),
                IpAddr::V4(Ipv4Addr::new(
                    frame[l3 + 16],
                    frame[l3 + 17],
                    frame[l3 + 18],
                    frame[l3 + 19],
                )),
            ))
        }
        libc::AF_INET6 => {
            let end = l3.checked_add(40)?;
            if end > frame.len() {
                return None;
            }
            Some((
                IpAddr::V6(Ipv6Addr::from(
                    <[u8; 16]>::try_from(&frame[l3 + 8..l3 + 24]).ok()?,
                )),
                IpAddr::V6(Ipv6Addr::from(
                    <[u8; 16]>::try_from(&frame[l3 + 24..l3 + 40]).ok()?,
                )),
            ))
        }
        _ => None,
    }
}

pub(in crate::afxdp) fn packet_trimmed_len(packet: &[u8], addr_family: u8) -> Option<usize> {
    match addr_family as i32 {
        libc::AF_INET => {
            if packet.len() < 20 {
                return None;
            }
            let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
            if total_len == 0 || total_len > packet.len() {
                return None;
            }
            Some(total_len)
        }
        libc::AF_INET6 => {
            if packet.len() < 40 {
                return None;
            }
            let payload_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
            let total_len = 40usize.checked_add(payload_len)?;
            if total_len > packet.len() {
                return None;
            }
            Some(total_len)
        }
        _ => None,
    }
}

/// #2315: count of GRE-decap frames DROPPED because the outer header
/// carried a CE mark over an inner packet that was Not-ECT — the
/// "illegal" RFC 6040 §4.2 combination (a congested router CE-marked a
/// packet whose endpoints never negotiated ECN). Surfaced via
/// `coordinator/status.rs` as
/// `xpf_userspace_gre_decap_ecn_illegal_drops_total`. A nonzero value
/// means a misbehaving/misconfigured tunnel ingress copied ECT onto the
/// outer for traffic the inner endpoints did not mark, then the path
/// congested. RFC 6040 mandates a drop here (the alternative — clearing
/// the bogus CE — would silently hide the protocol violation).
pub(in crate::afxdp) static GRE_DECAP_ECN_ILLEGAL_DROPS: AtomicU64 = AtomicU64::new(0);

/// #2317: count of WireGuard-decap inner packets DROPPED by the same
/// RFC 6040 §4.2 combine, for the WG path. Separate from the GRE
/// counter so the two tunnel families are independently observable.
/// Surfaced via `coordinator/status.rs` as
/// `xpf_userspace_wg_decap_ecn_illegal_drops_total`. The WG decap path
/// captures the outer ECN out-of-band (the kernel UDP socket strips the
/// outer IP header before userspace, so the bits arrive as `IP_RECVTOS`
/// / `IPV6_RECVTCLASS` ancillary data on `recvmsg` — see
/// `coordinator/wg_control.rs`) and feeds it into the SAME
/// `apply_decap_ecn_combine` below. A nonzero value means a misbehaving
/// WG ingress / congested path CE-marked the outer of a Not-ECT inner.
pub(in crate::afxdp) static WG_DECAP_ECN_ILLEGAL_DROPS: AtomicU64 = AtomicU64::new(0);

/// Read the inner IP packet's DSCP+ECN byte for outer-header
/// propagation on tunnel encap (#2303). Returns the full 8-bit
/// TOS / Traffic-Class value (DSCP in the high 6 bits, ECN in the
/// low 2 bits) so the encap site can copy it verbatim onto the
/// outer header:
///
///   - DSCP: uniform model (RFC 2983 §3) — the inner DSCP is mirrored
///     onto the outer so per-hop QoS classification survives the
///     tunnel.
///   - ECN: RFC 6040 normal-mode ingress — the inner ECN is COPIED to
///     the outer ECN field at ENCAP, so a CE mark applied by a
///     congested router on the OUTER path can later be combined back
///     into the inner ECN at DECAP (loss-free congestion signalling
///     instead of a fallback to loss-based control). The complementary
///     DECAP-side combine (outer ECN → inner ECN) is `decap_ecn_combine`
///     below, wired into `try_native_gre_decap_from_frame` (#2315). This
///     function is ENCAP-only — it just reads the byte to copy.
///
/// Reading the WHOLE byte (rather than masking to DSCP and re-shifting,
/// the `wg::dscp::tos_from_dscp` shape that clears ECN) is what makes
/// this RFC-6040-compliant: ECN must propagate, not be zeroed.
///
/// `packet` is the inner IP packet (L2 already stripped); `addr_family`
/// is the inner family. Returns `0` (the pre-#2303 behavior) when the
/// packet is too short to hold the byte, so a malformed inner never
/// produces an out-of-bounds read — it just falls back to a zero outer
/// TOS.
#[inline]
pub(in crate::afxdp) fn inner_tos_byte(packet: &[u8], addr_family: u8) -> u8 {
    match addr_family as i32 {
        libc::AF_INET => {
            // IPv4 TOS / DiffServ byte is octet 1.
            packet.get(1).copied().unwrap_or(0)
        }
        libc::AF_INET6 => {
            // IPv6 Traffic Class spans the low nibble of octet 0 and
            // the high nibble of octet 1: TC = (b0 << 4) | (b1 >> 4).
            match (packet.first(), packet.get(1)) {
                (Some(&b0), Some(&b1)) => (b0 << 4) | (b1 >> 4),
                _ => 0,
            }
        }
        _ => 0,
    }
}

/// Extract the 2-bit ECN field from an IP TOS / Traffic-Class byte.
/// ECN occupies the low 2 bits of the DiffServ octet:
///   00 = Not-ECT, 10 = ECT(0), 01 = ECT(1), 11 = CE.
#[inline]
fn ecn_of_tos(tos: u8) -> u8 {
    tos & 0x03
}

/// Read the OUTER IP header's 2-bit ECN field for the RFC 6040 §4.2
/// decap combine. `frame` is the full received frame; `meta.l3_offset`
/// is the outer IP header start; `meta.addr_family` is the OUTER family.
/// Returns `None` when the outer header is truncated (caller then skips
/// the combine — a malformed outer never mutates the inner).
#[inline]
fn outer_ecn_bits(frame: &[u8], meta: UserspaceDpMeta) -> Option<u8> {
    let l3 = meta.l3_offset as usize;
    match meta.addr_family as i32 {
        // IPv4: TOS/DiffServ is octet 1 of the outer header.
        libc::AF_INET => Some(ecn_of_tos(*frame.get(l3 + 1)?)),
        // IPv6: Traffic Class spans the low nibble of octet 0 and the
        // high nibble of octet 1; ECN is its low 2 bits — i.e. bits 2-3
        // of octet 1. TC = (b0 << 4) | (b1 >> 4); ECN = TC & 0x03 =
        // (b1 >> 4) & 0x03.
        libc::AF_INET6 => Some((*frame.get(l3 + 1)? >> 4) & 0x03),
        _ => None,
    }
}

/// Parse the inner IP packet's DESTINATION address (#1434 B1b). Used by
/// the WG transit-encap path to LPM-select the egress peer by inner-dst.
/// `packet` is the inner IP packet (L2 stripped); `addr_family` is the
/// inner family. Returns `None` when the packet is too short — a
/// malformed inner produces no peer selection and the frame is dropped.
#[inline]
pub(in crate::afxdp) fn inner_dst_ip(packet: &[u8], addr_family: u8) -> Option<IpAddr> {
    match addr_family as i32 {
        libc::AF_INET => {
            // IPv4 destination address is octets 16..20.
            let b: [u8; 4] = packet.get(16..20)?.try_into().ok()?;
            Some(IpAddr::V4(std::net::Ipv4Addr::from(b)))
        }
        libc::AF_INET6 => {
            // IPv6 destination address is octets 24..40.
            let b: [u8; 16] = packet.get(24..40)?.try_into().ok()?;
            Some(IpAddr::V6(std::net::Ipv6Addr::from(b)))
        }
        _ => None,
    }
}

/// RFC 6040 §4.2 decapsulation outcome for a single (inner, outer) ECN
/// pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::afxdp) enum DecapEcn {
    /// Leave the inner ECN field unchanged.
    Keep,
    /// Upgrade the inner ECN to CE (congestion experienced).
    SetCe,
    /// Illegal combination (outer CE over a Not-ECT inner) — drop the
    /// packet per RFC 6040 §4.2.
    Drop,
}

/// RFC 6040 §4.2 ECN combine. Given the ARRIVING inner ECN and the
/// ARRIVING outer ECN, decide how the inner ECN must change at decap.
///
/// Table (rows = inner, columns = outer):
///
/// | inner \ outer | Not-ECT(00) | ECT0(10) | ECT1(01) | CE(11) |
/// |---------------|-------------|----------|----------|--------|
/// | Not-ECT(00)   | Keep        | Keep     | Keep     | Drop   |
/// | ECT(0)(10)    | Keep        | Keep     | Keep*    | SetCe  |
/// | ECT(1)(01)    | Keep        | Keep     | Keep     | SetCe  |
/// | CE(11)        | Keep        | Keep     | Keep     | Keep   |
///
/// The only state change is: outer CE upgrades any ECN-capable, non-CE
/// inner to CE (the loss-free congestion signal this whole feature
/// exists for). The illegal outer=CE / inner=Not-ECT cell is a Drop.
/// Every other cell keeps the inner verbatim (so a Not-ECT or already-CE
/// inner is never touched, and the inner DSCP — which is authoritative
/// at decap — is never copied from the outer).
///
/// (* the §4.2 "MAY" cell — outer=ECT(1) over inner=ECT(0) — leaves the
/// receiver free to either keep the inner ECT(0) or upgrade it to
/// ECT(1); neither carries a congestion mark. We take the simpler
/// conformant choice and Keep the inner ECT(0). Linux's
/// `__INET_ECN_decapsulate` upgrades to ECT(1) instead; both are RFC
/// 6040 conformant.)
///
/// `inner_ecn` and `outer_ecn` are the 2-bit ECN values (low 2 bits).
#[inline]
pub(in crate::afxdp) fn decap_ecn_combine(inner_ecn: u8, outer_ecn: u8) -> DecapEcn {
    const NOT_ECT: u8 = 0b00;
    const ECT_1: u8 = 0b01;
    const ECT_0: u8 = 0b10;
    const CE: u8 = 0b11;
    match (inner_ecn & 0x03, outer_ecn & 0x03) {
        // Not-ECT inner: never carries a congestion mark. Outer CE is
        // the illegal combination — drop. Any other outer is ignored
        // (a Not-ECT endpoint cannot consume an ECN signal).
        (NOT_ECT, CE) => DecapEcn::Drop,
        (NOT_ECT, _) => DecapEcn::Keep,
        // CE inner already carries the strongest signal — nothing to do.
        (CE, _) => DecapEcn::Keep,
        // ECN-capable, non-CE inner: outer CE upgrades it to CE.
        (_, CE) => DecapEcn::SetCe,
        // §4.2 MAY: outer=ECT(1) over inner=ECT(0). RFC 6040 leaves this
        // cell a MAY — the receiver may keep the inner ECT(0) or upgrade
        // it to ECT(1); neither is a congestion mark. We take the simpler
        // conformant choice and Keep the inner ECT(0). (Linux's
        // `__INET_ECN_decapsulate` upgrades to ECT(1); both are
        // conformant. A codepoint upgrade would need a distinct SetEct1
        // outcome variant, which carries no congestion semantics and is
        // not worth the type complexity.)
        (ECT_0, ECT_1) => DecapEcn::Keep,
        // All remaining non-CE outer values leave an ECN-capable inner
        // unchanged.
        _ => DecapEcn::Keep,
    }
}

/// Apply the RFC 6040 §4.2 decap ECN combine IN PLACE to the inner IP
/// packet. `inner_packet` is the inner IP datagram (L2 already
/// stripped); `inner_family` is the inner family; `outer_ecn` is the
/// 2-bit outer ECN read from the (now-stripped) outer header.
///
/// Returns `true` to FORWARD (possibly after setting the inner CE bit)
/// and `false` to DROP (the illegal outer-CE / inner-Not-ECT combo, per
/// §4.2; the drop counter is bumped here).
///
/// When the inner ECN is upgraded to CE on an IPv4 inner, the IPv4
/// header checksum is recomputed (the TOS byte is covered by the IPv4
/// header checksum but NOT by the L4 checksum). IPv6 inners have no IP
/// header checksum, and the IPv6 Traffic Class is not covered by the L4
/// pseudo-header, so no checksum work is needed.
///
/// `illegal_drops` is the per-tunnel-family drop counter bumped on the
/// illegal §4.2 combination (GRE and WG keep independent counters,
/// #2315 / #2317), so this one body is shared by both decap paths.
#[inline]
pub(in crate::afxdp) fn apply_decap_ecn_combine(
    inner_packet: &mut [u8],
    inner_family: u8,
    outer_ecn: u8,
    illegal_drops: &AtomicU64,
) -> bool {
    match inner_family as i32 {
        libc::AF_INET => {
            // IPv4 TOS is octet 1; ECN is its low 2 bits.
            let Some(&tos) = inner_packet.get(1) else {
                // Too short to hold the byte — forward unchanged
                // (consistent with the encap-side short-packet fallback).
                return true;
            };
            match decap_ecn_combine(ecn_of_tos(tos), outer_ecn) {
                DecapEcn::Keep => true,
                DecapEcn::Drop => {
                    illegal_drops.fetch_add(1, Ordering::Relaxed);
                    false
                }
                DecapEcn::SetCe => {
                    // Set ECN = CE (low 2 bits) without disturbing DSCP.
                    inner_packet[1] = (tos & 0xFC) | 0x03;
                    recompute_ipv4_header_checksum(inner_packet);
                    true
                }
            }
        }
        libc::AF_INET6 => {
            // IPv6 ECN is bits 2-3 of octet 1 (low 2 bits of the
            // Traffic Class). Need octets 0 and 1 to read/write it.
            let Some(&b1) = inner_packet.get(1) else {
                return true;
            };
            let inner_ecn = (b1 >> 4) & 0x03;
            match decap_ecn_combine(inner_ecn, outer_ecn) {
                DecapEcn::Keep => true,
                DecapEcn::Drop => {
                    illegal_drops.fetch_add(1, Ordering::Relaxed);
                    false
                }
                DecapEcn::SetCe => {
                    // CE = 0b11 in the ECN slot = bits 2-3 of octet 1.
                    // Clear the existing ECN nibble-bits then set CE.
                    inner_packet[1] = (b1 & 0xCF) | (0x03 << 4);
                    // IPv6: no header checksum; TC not in the L4
                    // pseudo-header — nothing else to recompute.
                    true
                }
            }
        }
        _ => true,
    }
}

/// Recompute the IPv4 header checksum in place. `packet` starts at the
/// IPv4 header. The header length is taken from IHL (octet 0 low nibble,
/// in 32-bit words). A short or malformed header leaves the packet
/// unchanged. Used after the decap ECN combine mutates the TOS byte.
#[inline]
fn recompute_ipv4_header_checksum(packet: &mut [u8]) {
    let Some(&b0) = packet.first() else { return };
    let ihl = usize::from(b0 & 0x0f) * 4;
    if ihl < 20 || packet.len() < ihl {
        return;
    }
    // Zero the checksum field (octets 10-11) before recomputing.
    packet[10] = 0;
    packet[11] = 0;
    let cs = checksum16(&packet[..ihl]);
    packet[10..12].copy_from_slice(&cs.to_be_bytes());
}

fn gre_inner_family_and_proto(proto: u16) -> Option<(u8, u16)> {
    match proto {
        GRE_PROTO_IPV4 => Some((libc::AF_INET as u8, 0x0800)),
        GRE_PROTO_IPV6 => Some((libc::AF_INET6 as u8, 0x86dd)),
        _ => None,
    }
}

/// Match a received GRE (proto-47) outer tuple to a GRE-mode tunnel
/// endpoint.
///
/// #2327 (kind-segregation + O(N) fix): the lookup goes through
/// `gre_decap_index`, which only contains `mode == "gre"` / `"ip6gre"`
/// endpoints — so a GRE frame is NEVER decapped against a WireGuard or
/// any other non-GRE row even if the outer tuple/key happen to collide.
/// The index is keyed by the endpoint's own
/// `(outer_family, source, destination)`; a received frame mirrors it as
/// `(addr_family, outer_dst, outer_src)`. Each bucket is a small
/// candidate list so a duplicate outer tuple (a keyed and an unkeyed
/// endpoint, or distinct logical ifindexes) is disambiguated by the GRE
/// key here rather than resolved non-deterministically by a first-match
/// scan over the entire table. Defense-in-depth: each candidate's
/// `mode` is re-checked via `tunnel_mode_kind` so a future build-side
/// indexing bug can never surface a non-GRE row on this path.
fn match_tunnel_endpoint(
    forwarding: &ForwardingState,
    outer_family: i32,
    outer_src: IpAddr,
    outer_dst: IpAddr,
    key: u32,
    key_present: bool,
) -> Option<&TunnelEndpoint> {
    let candidates = forwarding
        .gre_decap_index
        .get(&(outer_family, outer_dst, outer_src))?;
    for id in candidates {
        let Some(endpoint) = forwarding.tunnel_endpoints.get(id) else {
            continue;
        };
        // Kind re-check (defense in depth): only GRE-mode rows decap as
        // GRE, regardless of what the index claims.
        if tunnel_mode_kind(&endpoint.mode) != TunnelKind::Gre {
            continue;
        }
        let key_ok = if endpoint.key == 0 {
            !key_present || key == 0
        } else {
            key_present && endpoint.key == key
        };
        if key_ok {
            return Some(endpoint);
        }
    }
    None
}

fn parse_inner_protocol_and_offsets(packet: &[u8], addr_family: u8) -> Option<(u8, u16, u16)> {
    match addr_family as i32 {
        libc::AF_INET => {
            if packet.len() < 20 {
                return None;
            }
            let ihl = usize::from(packet[0] & 0x0f) * 4;
            if ihl < 20 || packet.len() < ihl {
                return None;
            }
            let protocol = packet[9];
            let l4_offset = ihl as u16;
            let payload_offset = match protocol {
                PROTO_TCP => {
                    if packet.len() < ihl + 20 {
                        return None;
                    }
                    let tcp_len = usize::from(packet[ihl + 12] >> 4) * 4;
                    if tcp_len < 20 || packet.len() < ihl + tcp_len {
                        return None;
                    }
                    l4_offset + tcp_len as u16
                }
                PROTO_UDP => l4_offset + 8,
                PROTO_ICMP => l4_offset + 8,
                _ => l4_offset,
            };
            Some((protocol, l4_offset, payload_offset))
        }
        libc::AF_INET6 => {
            if packet.len() < 40 {
                return None;
            }
            // Use the extension-header-aware helper to get both the final L4
            // protocol and the correct offset. packet[6] may be an extension
            // header type, not the actual L4 protocol.
            //
            // #2292: `packet_rel_l4_offset_and_protocol` now fails CLOSED
            // (returns `None`) when the ext-header chain is still on an
            // extension header at the `MAX_IPV6_EXT_HEADERS` bound, so a
            // surrendered `protocol == 0` (unconsumed Hop-by-Hop) can no
            // longer reach this match. The `_` arm below additionally
            // DROPS any leftover ext-header / no-next-header sentinel
            // (Hop-by-Hop 0, Routing 43, AH 51, No-Next 59, Dest-Opts 60)
            // rather than forwarding it with the ext-header offset used as
            // a fake L4/payload offset — defense in depth so this caller
            // never forwards a packet whose L4 protocol it could not
            // resolve.
            let (l4_off, protocol) = packet_rel_l4_offset_and_protocol(packet, addr_family)?;
            let rel_l4 = l4_off as u16;
            let payload_offset = match protocol {
                PROTO_TCP => {
                    let l4 = rel_l4 as usize;
                    if packet.len() < l4 + 20 {
                        return None;
                    }
                    let tcp_len = usize::from(packet[l4 + 12] >> 4) * 4;
                    if tcp_len < 20 || packet.len() < l4 + tcp_len {
                        return None;
                    }
                    rel_l4 + tcp_len as u16
                }
                PROTO_UDP => rel_l4 + 8,
                PROTO_ICMPV6 => rel_l4 + 8,
                // #2292: an unresolved/extension-header protocol is a drop,
                // not a forward. 0/43/51/59/60 are IPv6 ext-header or
                // no-next-header sentinels, never a real inner L4.
                0 | 43 | 51 | 59 | 60 => return None,
                _ => rel_l4,
            };
            Some((protocol, rel_l4, payload_offset))
        }
        _ => None,
    }
}

fn packet_tcp_flags(packet: &[u8], _addr_family: u8, protocol: u8, rel_l4: u16) -> u8 {
    if protocol != PROTO_TCP {
        return 0;
    }
    let l4 = rel_l4 as usize;
    packet.get(l4 + 13).copied().unwrap_or_default()
}

pub(super) fn try_native_gre_decap_from_frame(
    frame: &[u8],
    meta: UserspaceDpMeta,
    forwarding: &ForwardingState,
) -> Option<NativeGrePacket> {
    if meta.protocol != PROTO_GRE {
        return None;
    }
    let gre_offset = meta.l4_offset as usize;
    let base = frame.get(gre_offset..gre_offset + 4)?;
    let flags_version = u16::from_be_bytes([base[0], base[1]]);
    if (flags_version & GRE_VERSION_MASK) != 0 {
        return None;
    }
    if (flags_version & (GRE_FLAG_CHECKSUM | GRE_FLAG_ROUTING)) != 0 {
        return None;
    }
    let key_present = (flags_version & GRE_FLAG_KEY) != 0;
    let sequence_present = (flags_version & GRE_FLAG_SEQUENCE) != 0;
    let gre_proto = u16::from_be_bytes([base[2], base[3]]);
    let (inner_family, inner_eth_proto) = gre_inner_family_and_proto(gre_proto)?;

    let mut inner_offset = gre_offset + 4;
    let mut key = 0u32;
    if key_present {
        key = u32::from_be_bytes(
            <[u8; 4]>::try_from(frame.get(inner_offset..inner_offset + 4)?).ok()?,
        );
        inner_offset += 4;
    }
    if sequence_present {
        frame.get(inner_offset..inner_offset + 4)?;
        inner_offset += 4;
    }
    let inner_packet = frame.get(inner_offset..)?;
    let inner_len = packet_trimmed_len(inner_packet, inner_family)?;
    let inner_packet = &inner_packet[..inner_len];

    let (outer_src, outer_dst) = parse_outer_addresses(frame, meta)?;
    let endpoint = match_tunnel_endpoint(
        forwarding,
        meta.addr_family as i32,
        outer_src,
        outer_dst,
        key,
        key_present,
    )?;
    let (protocol, rel_l4_offset, payload_offset) =
        parse_inner_protocol_and_offsets(inner_packet, inner_family)?;

    let mut synthetic = vec![0u8; 14 + inner_packet.len()];
    synthetic[12..14].copy_from_slice(&inner_eth_proto.to_be_bytes());
    synthetic[14..].copy_from_slice(inner_packet);

    // #2315: RFC 6040 §4.2 decap-side ECN combine. The outer ECN (read
    // from the still-present outer IP header in `frame` at
    // `meta.l3_offset`) is combined into the inner ECN: an outer CE
    // upgrades an ECN-capable inner to CE so a congestion mark applied
    // on the OUTER path is reflected to the inner endpoints; the illegal
    // outer-CE / inner-Not-ECT combination is dropped. Mutates the
    // synthetic inner in place (octet `14 + 1` for the inner TOS) and
    // recomputes the inner IPv4 header checksum when CE is set. Skipped
    // when the outer header is truncated (`outer_ecn_bits` → None).
    if let Some(outer_ecn) = outer_ecn_bits(frame, meta)
        && !apply_decap_ecn_combine(
            &mut synthetic[14..],
            inner_family,
            outer_ecn,
            &GRE_DECAP_ECN_ILLEGAL_DROPS,
        )
    {
        // Illegal RFC 6040 §4.2 combination — drop (counter bumped in
        // apply_decap_ecn_combine).
        return None;
    }

    let flow = parse_session_flow_from_frame(
        &synthetic,
        UserspaceDpMeta {
            addr_family: inner_family,
            protocol,
            ..UserspaceDpMeta::default()
        },
    );
    let mut flow_src_addr = [0u8; 16];
    let mut flow_dst_addr = [0u8; 16];
    let (src_port, dst_port) = flow
        .as_ref()
        .map(|flow| (flow.forward_key.src_port, flow.forward_key.dst_port))
        .unwrap_or_default();
    if let Some(flow) = flow.as_ref() {
        match flow.src_ip {
            IpAddr::V4(ip) => flow_src_addr[..4].copy_from_slice(&ip.octets()),
            IpAddr::V6(ip) => flow_src_addr.copy_from_slice(&ip.octets()),
        }
        match flow.dst_ip {
            IpAddr::V4(ip) => flow_dst_addr[..4].copy_from_slice(&ip.octets()),
            IpAddr::V6(ip) => flow_dst_addr.copy_from_slice(&ip.octets()),
        }
    }

    // #921: GRE decap fires from afxdp.rs (pre-flow-cache), so this
    // is the per-packet path on GRE-tunnel workloads. Direct ID
    // lookup — was a two-hop name round-trip.
    let ingress_zone = forwarding
        .ifindex_to_zone_id
        .get(&endpoint.logical_ifindex)
        .copied()
        .unwrap_or_default();
    let pkt_len = u16::try_from(inner_packet.len()).ok()?;
    let inner_meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: endpoint.logical_ifindex as u32,
        rx_queue_index: meta.rx_queue_index,
        ingress_vlan_id: 0,
        ingress_zone,
        l3_offset: 14,
        l4_offset: 14 + rel_l4_offset,
        payload_offset: 14 + payload_offset,
        pkt_len,
        addr_family: inner_family,
        protocol,
        tcp_flags: packet_tcp_flags(inner_packet, inner_family, protocol, rel_l4_offset),
        flow_src_port: src_port,
        flow_dst_port: dst_port,
        flow_src_addr,
        flow_dst_addr,
        config_generation: meta.config_generation,
        fib_generation: meta.fib_generation,
        ..UserspaceDpMeta::default()
    };

    Some(NativeGrePacket {
        frame: synthetic,
        meta: inner_meta,
    })
}

pub(super) fn encapsulate_native_gre_frame(
    inner_frame: &[u8],
    inner_meta: impl Into<ForwardPacketMeta>,
    decision: &SessionDecision,
    forwarding: &ForwardingState,
) -> Option<Vec<u8>> {
    let inner_meta = inner_meta.into();
    let endpoint = forwarding
        .tunnel_endpoints
        .get(&decision.resolution.tunnel_endpoint_id)?;
    // #1873 (Codex code r2): refuse to encapsulate when the id's
    // owning netdev differs from the one recorded in the session's
    // stored resolution (egress_ifindex = logical_ifindex at resolve
    // time) — a re-owned id must fail the build (R-C gate drops the
    // frame), never encapsulate into the new owner.
    if decision.resolution.egress_ifindex > 0
        && endpoint.logical_ifindex != decision.resolution.egress_ifindex
    {
        return None;
    }
    let dst_mac = decision.resolution.neighbor_mac?;
    let src_mac = decision.resolution.src_mac?;
    let vlan_id = decision.resolution.tx_vlan_id;
    let outer_eth_len = if vlan_id > 0 { 18 } else { 14 };
    let inner_l3 = match frame_l3_offset(inner_frame) {
        Some(offset) => offset,
        None => inner_meta.l3_offset as usize,
    };
    let inner_packet = inner_frame.get(inner_l3..)?.to_vec();
    let inner_len = packet_trimmed_len(&inner_packet, inner_meta.addr_family)?;
    let inner_packet = &inner_packet[..inner_len];
    // #2303: copy the inner DSCP+ECN onto the outer header (uniform
    // DSCP model + RFC 6040 ECN ingress copy) instead of hardcoding 0.
    let outer_tos = inner_tos_byte(inner_packet, inner_meta.addr_family);

    let key_words = if endpoint.key != 0 { 1 } else { 0 };
    let gre_len = 4 + key_words * 4;
    let outer_ip_len = match endpoint.outer_family {
        libc::AF_INET => 20,
        libc::AF_INET6 => 40,
        _ => return None,
    };
    let frame_len = outer_eth_len + outer_ip_len + gre_len + inner_packet.len();
    let mut out = vec![0u8; frame_len];
    write_eth_header_slice(
        out.get_mut(..outer_eth_len)?,
        dst_mac,
        src_mac,
        vlan_id,
        if endpoint.outer_family == libc::AF_INET {
            0x0800
        } else {
            0x86dd
        },
    )?;

    let outer_ip_start = outer_eth_len;
    let gre_start = outer_ip_start + outer_ip_len;
    let inner_start = gre_start + gre_len;
    out.get_mut(inner_start..)?
        .get_mut(..inner_packet.len())?
        .copy_from_slice(inner_packet);

    let gre_flags = if endpoint.key != 0 { GRE_FLAG_KEY } else { 0 };
    out[gre_start..gre_start + 2].copy_from_slice(&gre_flags.to_be_bytes());
    out[gre_start + 2..gre_start + 4].copy_from_slice(
        &(if inner_meta.addr_family as i32 == libc::AF_INET {
            GRE_PROTO_IPV4
        } else {
            GRE_PROTO_IPV6
        })
        .to_be_bytes(),
    );
    if endpoint.key != 0 {
        out[gre_start + 4..gre_start + 8].copy_from_slice(&endpoint.key.to_be_bytes());
    }

    match endpoint.outer_family {
        libc::AF_INET => {
            let src = match endpoint.source {
                IpAddr::V4(ip) => ip,
                _ => return None,
            };
            let dst = match endpoint.destination {
                IpAddr::V4(ip) => ip,
                _ => return None,
            };
            let total_len = u16::try_from(outer_ip_len + gre_len + inner_packet.len()).ok()?;
            // #1440: consolidated IPv4 outer builder. Sets DF=1
            // (RFC 791 §3.1 / RFC 6864 §3 compliance) and computes
            // the header checksum via the shared `checksum16`.
            // Wire-byte change vs the previous open-code:
            // ip[6..8] = 0x4000 (was 0x0000); IPv4 header checksum
            // recomputes accordingly.
            write_ipv4_header(
                out.get_mut(outer_ip_start..outer_ip_start + 20)?,
                src,
                dst,
                PROTO_GRE,
                outer_tos,
                endpoint.ttl,
                total_len,
            )?;
        }
        libc::AF_INET6 => {
            let src = match endpoint.source {
                IpAddr::V6(ip) => ip,
                _ => return None,
            };
            let dst = match endpoint.destination {
                IpAddr::V6(ip) => ip,
                _ => return None,
            };
            let payload_len = u16::try_from(gre_len + inner_packet.len()).ok()?;
            // #1440: consolidated IPv6 outer builder.
            write_ipv6_header(
                out.get_mut(outer_ip_start..outer_ip_start + 40)?,
                src,
                dst,
                PROTO_GRE,
                outer_tos,
                /* flow_label */ 0,
                endpoint.ttl,
                payload_len,
            )?;
        }
        _ => return None,
    }

    Some(out)
}
