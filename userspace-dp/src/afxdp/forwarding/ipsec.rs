//! #5650: IPsec traffic classification and inbound admission decision. Pure
//! code-motion split out of `forwarding/mod.rs` (behavior-identical).

use super::*;

/// Returns true if the packet is IPsec traffic (ESP protocol 50, AH protocol
/// 51, or IKE UDP ports 500/4500) that should be passed to the kernel for
/// XFRM processing.
///
/// AH (Authentication Header, proto 51) is a configurable host-terminated
/// IPsec protocol (`set security ipsec proposal ... protocol ah`,
/// pkg/config/schema_security.go). Like ESP it carries no transport port, so
/// only the protocol-number arm applies.
///
/// The predicate is family-symmetric — it keys solely on `meta.protocol` —
/// but in practice `meta.protocol == PROTO_AH` only ever occurs for **IPv4
/// AH**. The XDP shim's IPv6 parser treats AH as an extension header and
/// walks THROUGH it (`NEXTHDR_AUTH` arm in `userspace-xdp/src/lib.rs`),
/// setting `meta.protocol` to AH's inner next-header rather than 51. So the
/// `PROTO_AH` arm is a v4-only backstop; it never fires for IPv6 AH.
///
/// This is not a functional gap. IPv6 host-terminated AH-to-self still
/// reaches the kernel XFRM stack via the shim's `is_local_destination`
/// shunt, which fires for any local-destination packet *before* the
/// userspace dataplane runs this predicate; transit AH (v4 or v6) takes
/// ordinary forwarding. ESP (proto 50) is parsed as a terminal protocol on
/// both families, so ESP is recognized here for v4 and v6 alike. Giving this
/// predicate true IPv6 AH coverage would require the shim to surface an
/// "AH present" signal instead of walking past the header — out of scope
/// here, and unnecessary given the local-dest shunt.
#[inline]
pub(in crate::afxdp) fn is_ipsec_traffic(protocol: u8, dst_port: u16) -> bool {
    protocol == PROTO_ESP
        || protocol == PROTO_AH
        || (protocol == PROTO_UDP && (dst_port == 500 || dst_port == 4500))
}

/// #4323: the Stage-11 admission class of an IPsec packet that `is_ipsec_traffic`
/// already matched. Only a NEW inbound IKE initiation is subject to the per-zone
/// host-inbound `ike`/`ipsec` gate; every other IPsec class is unconditionally
/// exempt (the negotiated SA is the authorization).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::afxdp) enum IpsecAdmissionClass {
    /// ESP/AH raw data plane, ESP-in-UDP, a NAT-T keepalive, OR a NON-initial
    /// IKE packet (the exchange already carries a responder SPI). Always
    /// passthrough — mirrors the kernel host-inbound chain's global
    /// `meta l4proto { 50, 51 } accept` (ESP/AH) and `ct established,related
    /// accept` (later IKE), so the IPsec data plane and every return/reply IKE
    /// packet transit even on a zone that omits `ike`.
    Exempt,
    /// The FIRST packet of a NEW inbound IKE exchange (we would be the
    /// responder): an ISAKMP header whose Responder SPI/cookie is all-zero
    /// (IKEv2 IKE_SA_INIT request / IKEv1 Main- or Aggressive-mode first
    /// message). This is the packet the Junos `system-services ike` knob is
    /// meant to gate, so it is subject to the per-zone host-inbound admit check.
    NewInboundIke,
}

/// #6471: the ISAKMP demux of a UDP/500-or-4500 payload — the single source
/// of truth for "is this an IKE message, and where does its ISAKMP header
/// start" shared by [`classify_ipsec_admission`] and the SPI extractors
/// below. Callers guarantee `is_ipsec_traffic` already matched, so a
/// non-4500 UDP packet here is UDP/500 (direct ISAKMP, no marker).
enum IsakmpDemux<'a> {
    /// Not an IKE payload: ESP/AH (non-UDP protocol), ESP-in-UDP on 4500
    /// (non-zero ESP SPI in the first payload word), or a NAT-T keepalive.
    NotIsakmp,
    /// An IKE payload (possibly truncated — the caller bounds-checks the
    /// ISAKMP fields it reads).
    Isakmp(&'a [u8]),
    /// The UDP payload itself is truncated (frame ends inside the 8-byte
    /// UDP header) — unclassifiable, must fail CLOSED.
    Truncated,
}

/// #6471: demux the IKE payload out of a packet `is_ipsec_traffic` matched.
/// `l4_offset` is the UDP header offset within `packet_frame`; the ISAKMP
/// header follows the 8-byte UDP header (and, on NAT-T UDP 4500, the 4-byte
/// RFC 3948 non-ESP marker).
fn isakmp_demux(
    packet_frame: &[u8],
    l4_offset: usize,
    protocol: u8,
    dst_port: u16,
) -> IsakmpDemux<'_> {
    // ESP (50) / AH (51): raw IPsec data plane — never ISAKMP.
    if protocol != PROTO_UDP {
        return IsakmpDemux::NotIsakmp;
    }
    // UDP payload (ISAKMP or, on 4500, the NAT-T non-ESP marker) starts after
    // the fixed 8-byte UDP header.
    let Some(payload) = packet_frame.get(l4_offset + 8..) else {
        return IsakmpDemux::Truncated;
    };
    if dst_port == 4500 {
        // RFC 3948 NAT-T demux: a 4-byte all-zero non-ESP marker precedes IKE
        // on UDP 4500. Anything else on 4500 is ESP-in-UDP (its non-zero ESP
        // SPI is the first word) or a 1-byte NAT-T keepalive — both the IPsec
        // data plane, not IKE.
        match payload.get(0..4) {
            Some([0, 0, 0, 0]) => IsakmpDemux::Isakmp(&payload[4..]),
            _ => IsakmpDemux::NotIsakmp,
        }
    } else {
        // UDP 500 — ISAKMP directly, no non-ESP marker.
        IsakmpDemux::Isakmp(payload)
    }
}

/// #4323: classify an IPsec packet (one `is_ipsec_traffic` matched) into its
/// Stage-11 admission class. Only a NEW inbound IKE initiation
/// ([`IpsecAdmissionClass::NewInboundIke`]) is gated on host-inbound; every
/// other class is [`IpsecAdmissionClass::Exempt`] (unconditional passthrough).
///
/// New-vs-established is derived from the ISAKMP header: the first packet of
/// a new exchange has an all-zero Responder SPI, and every later packet
/// carries the responder's SPI. #6471 layers the live-exchange discriminator
/// on top of the `Exempt` class (see [`IkeExchangeTable`]): a non-zero
/// Responder SPI alone no longer proves established — it is attacker-
/// controlled, so an unmatched Responder-SPI-nonzero IKE packet is handed
/// back to the host-inbound gate instead of passing unconditionally.
///
/// `l4_offset` is the UDP header offset within `packet_frame`; the ISAKMP header
/// follows the 8-byte UDP header (and, on NAT-T UDP 4500, the 4-byte non-ESP
/// marker). A missing / too-short ISAKMP header fails CLOSED (`NewInboundIke`) so
/// a truncated IKE to an unpermitted source is gated, never silently admitted.
pub(in crate::afxdp) fn classify_ipsec_admission(
    packet_frame: &[u8],
    l4_offset: usize,
    protocol: u8,
    dst_port: u16,
) -> IpsecAdmissionClass {
    match isakmp_demux(packet_frame, l4_offset, protocol, dst_port) {
        IsakmpDemux::NotIsakmp => IpsecAdmissionClass::Exempt,
        IsakmpDemux::Truncated => IpsecAdmissionClass::NewInboundIke,
        // ISAKMP header: Initiator SPI [0..8], Responder SPI [8..16]. A new
        // exchange's first packet carries an all-zero Responder SPI; a set
        // Responder SPI means the exchange claims to be under way.
        IsakmpDemux::Isakmp(isakmp) => match isakmp.get(8..16) {
            Some(responder_spi) if responder_spi.iter().all(|&b| b == 0) => {
                IpsecAdmissionClass::NewInboundIke
            }
            Some(_) => IpsecAdmissionClass::Exempt,
            None => IpsecAdmissionClass::NewInboundIke,
        },
    }
}

/// #6471: the Initiator SPI of a genuine IKE INITIATION (an ISAKMP header
/// with an all-zero Responder SPI), or `None` when the packet is not a
/// parseable initiation (not IKE, truncated, or Responder SPI non-zero).
/// Used to SEED the exchange table only for real exchange starts — a
/// Responder-SPI-nonzero packet must never seed (a forged one would
/// otherwise mint its own "established" entry).
pub(in crate::afxdp) fn ike_initiation_spi(
    packet_frame: &[u8],
    l4_offset: usize,
    dst_port: u16,
) -> Option<u64> {
    let IsakmpDemux::Isakmp(isakmp) = isakmp_demux(packet_frame, l4_offset, PROTO_UDP, dst_port)
    else {
        return None;
    };
    let header = isakmp.get(0..16)?;
    let (initiator, responder) = header.split_at(8);
    if responder.iter().all(|&b| b == 0) {
        Some(u64::from_be_bytes(initiator.try_into().ok()?))
    } else {
        None
    }
}

/// #6471: the Initiator SPI of an IKE packet claiming to be ESTABLISHED (an
/// ISAKMP header with a non-zero Responder SPI), or `None` for every other
/// class (ESP-in-UDP, NAT-T keepalive, truncated, or a zero-Responder
/// initiation — those follow their own paths). The returned SPI keys the
/// live-exchange lookup: only a packet whose (Initiator SPI, peer/local
/// addresses) matches a seeded exchange is treated as established.
pub(in crate::afxdp) fn established_ike_initiator_spi(
    packet_frame: &[u8],
    l4_offset: usize,
    dst_port: u16,
) -> Option<u64> {
    let IsakmpDemux::Isakmp(isakmp) = isakmp_demux(packet_frame, l4_offset, PROTO_UDP, dst_port)
    else {
        return None;
    };
    let header = isakmp.get(0..16)?;
    let (initiator, responder) = header.split_at(8);
    if responder.iter().any(|&b| b != 0) {
        Some(u64::from_be_bytes(initiator.try_into().ok()?))
    } else {
        None
    }
}

/// #6471: hard cap on tracked live IKE exchanges per node. Far above any
/// legitimate site-to-site count on this class of box (hundreds); the bound
/// keeps a forged-initiation flood on an IKE-permitting zone from growing
/// the table without limit. On full, the OLDEST entry is evicted (see
/// [`IkeExchangeTable::seed`]).
pub(in crate::afxdp) const IKE_EXCHANGE_TABLE_CAP: usize = 4096;

/// #6471: sliding idle timeout for a seeded exchange. Refreshed on every
/// matched packet, so any live SA (rekeys, INFORMATIONALs, DPD all carry the
/// seeded Initiator SPI) keeps its seed; a seed outliving the SA by up to
/// this window is harmless — a forged packet still has to guess the 64-bit
/// Initiator SPI plus the exchange's address pair, and strongSwan rejects a
/// semantically invalid SPI regardless. 24h comfortably covers typical IKE
/// SA lifetimes (1-8h); an SA with rekeying disabled AND no DPD that stays
/// IKE-silent longer than this degrades to the post-restart posture
/// (follow-ups re-gated on host-inbound; self-heals on the firewall's next
/// outbound IKE for firewall-initiated exchanges).
pub(in crate::afxdp) const IKE_EXCHANGE_IDLE_NS: u64 = 24 * 3600 * 1_000_000_000;

const _: () = assert!(IKE_EXCHANGE_TABLE_CAP >= 1);

/// #6471: identity of a live IKE exchange for the established-vs-forged
/// discriminator. Keyed on the Initiator SPI plus the exchange's address
/// pair — NOT the IKE ports, so an RFC 5996 NAT-T port float (500 -> 4500
/// mid-exchange) does not strand the seed; the Initiator SPI (64-bit random
/// per exchange) is the collision-proof discriminator strongSwan itself
/// uses. The Responder SPI is deliberately absent: the responder's reply is
/// never observed on the inbound-only dataplane, so its value cannot be
/// learned here. This mirrors the kernel conntrack match the PRIMARY path
/// relies on (a 4-tuple-established entry, likewise MOBIKE-fragile) rather
/// than strengthening it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(in crate::afxdp) struct IkeExchangeKey {
    pub(in crate::afxdp) initiator_spi: u64,
    pub(in crate::afxdp) peer_ip: IpAddr,
    pub(in crate::afxdp) local_ip: IpAddr,
}

impl IkeExchangeKey {
    pub(in crate::afxdp) fn new(initiator_spi: u64, peer_ip: IpAddr, local_ip: IpAddr) -> Self {
        Self {
            initiator_spi,
            peer_ip,
            local_ip,
        }
    }
}

/// #6471: the shared table of live IKE exchanges backing the Stage-11
/// established-vs-forged discriminator on the AF_XDP SECONDARY path
/// (DNAT/static-NAT-to-self, native-GRE-inner). The PRIMARY path (direct IKE
/// to an interface IP) gets the same NEW-vs-established split from kernel
/// conntrack in the nftables host-inbound chain; the secondary path installs
/// no session for a passthrough flow, so it tracks exchanges explicitly:
///
/// - SEEDED inbound at Stage 11 when a NEW IKE initiation (all-zero
///   Responder SPI) PASSES the per-zone host-inbound `ike` gate. A denied
///   initiation MUST NOT seed — otherwise a forged follow-up on a
///   closed zone would mint its own "established" entry and re-open the
///   bypass this table closes.
/// - SEEDED outbound in the native-GRE local-origin path
///   (`build_local_origin_tunnel_tx_request`) when the firewall itself
///   initiates IKE through a tunnel: the peer's replies arrive GRE-inner on
///   Stage 11 with a non-zero Responder SPI and no inbound seed.
/// - MATCHED at Stage 11 for every Responder-SPI-nonzero IKE packet to a
///   firewall-local address: a hit (refreshed) admits; a miss hands the
///   packet to the SAME host-inbound gate a NEW initiation faces, so a
///   forged Responder SPI on a zone that omits `ike` is denied instead of
///   reaching strongSwan, while an IKE-permitting zone keeps its
///   config-sanctioned open posture (primary-path parity: the kernel chain
///   also admits NEW IKE there).
///
/// Sharing + locking: one table per node, shared by every packet worker and
/// the GRE local-origin threads (`Arc<IkeExchangeTable>` — RSS does not pin
/// an exchange's packets to the seeding worker, and the outbound seed is
/// written by a non-worker thread). The `Mutex` is taken ONLY for
/// IKE-to-self packets (control plane, pps-bounded, and flood-bounded
/// upstream by the stage-10 udp-flood screen) — never for ESP/AH or the
/// general session path — mirroring the `shared_sessions` precedent. A
/// poisoned lock is recovered (`into_inner`): a worker that panicked
/// mid-seed/match must not permanently deafen the gate — the same recovery
/// policy as `worker_queue::lock_recover` (#1807), whose helper is typed to
/// the command-queue deque and so cannot be reused for this map.
///
/// NOT HA-synced: after RG failover the new node's table is empty, so
/// secondary-path IKE control on `ike`-omitting zones stalls until the
/// exchange's next initiation — the SAME gap the primary path has (kernel
/// conntrack for host-terminated IKE is not synced either). Likewise an
/// xpfd restart drops all seeds; firewall-initiated exchanges re-seed on
/// strongSwan's next outbound IKE packet (DPD / rekey / re-auth), and the
/// ESP data plane is exempt throughout.
pub(in crate::afxdp) struct IkeExchangeTable {
    entries: Mutex<FastMap<IkeExchangeKey, u64>>, // key -> last-seen monotonic ns
}

impl IkeExchangeTable {
    pub(in crate::afxdp) fn new() -> Self {
        Self {
            entries: Mutex::new(FastMap::default()),
        }
    }

    fn lock_entries(&self) -> std::sync::MutexGuard<'_, FastMap<IkeExchangeKey, u64>> {
        self.entries.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Record (or refresh) a live exchange. On a full table the OLDEST entry
    /// is evicted to make room: refusing the insert (drop-newest) would
    /// strand the exchange that just legitimately started — its follow-ups
    /// would be host-inbound-gated and dropped on `ike`-omitting zones —
    /// while the oldest entry is the one most likely stale. A flood of
    /// forged initiations on an IKE-PERMITTING zone can still churn
    /// legitimate seeds out of the table (bounded by the cap); that zone
    /// already exposes strongSwan to the same flood by configuration, and
    /// the stage-10 udp-flood screen is the rate limiter.
    pub(in crate::afxdp) fn seed(&self, key: IkeExchangeKey, now_ns: u64) {
        let mut entries = self.lock_entries();
        if let Some(seen) = entries.get_mut(&key) {
            *seen = now_ns;
            return;
        }
        if entries.len() >= IKE_EXCHANGE_TABLE_CAP
            && let Some(oldest) = entries
                .iter()
                .min_by_key(|(_, seen)| **seen)
                .map(|(k, _)| k.clone())
        {
            entries.remove(&oldest);
        }
        entries.insert(key, now_ns);
    }

    /// True iff `key` names a live seeded exchange (and refreshes it —
    /// sliding window). A seed idle past [`IKE_EXCHANGE_IDLE_NS`] is reaped
    /// lazily here and treated as a miss, so a dead SA's seed cannot admit
    /// forged packets forever.
    pub(in crate::afxdp) fn matches(&self, key: &IkeExchangeKey, now_ns: u64) -> bool {
        let mut entries = self.lock_entries();
        let stale = match entries.get_mut(key) {
            Some(seen) => {
                if now_ns.saturating_sub(*seen) > IKE_EXCHANGE_IDLE_NS {
                    true
                } else {
                    *seen = now_ns;
                    false
                }
            }
            None => return false,
        };
        if stale {
            entries.remove(key);
            return false;
        }
        true
    }

    /// Test/telemetry seam: current entry count.
    #[cfg(test)]
    pub(in crate::afxdp) fn len(&self) -> usize {
        self.lock_entries().len()
    }
}

/// #6471: the shared handle workers + GRE local-origin threads hold.
pub(in crate::afxdp) type SharedIkeExchangeTable = Arc<IkeExchangeTable>;

/// #6471: seed the exchange table for a FIREWALL-INITIATED IKE exchange
/// routed via a local-origin tunnel (native GRE). The outbound initiation is
/// read off the tunnel's TUN device by `local_tunnel_source_loop` and never
/// crosses Stage 11, so without this seed the peer's replies (Responder SPI
/// non-zero) would fail the established-exchange lookup and be host-inbound
/// gated — a regression for firewall-initiated tunnels on zones that omit
/// `ike` (the primary path admits those replies via conntrack-established).
///
/// `packet_frame`/`l4_offset` describe the INNER frame (post
/// `wrap_raw_ip_packet_for_tunnel`, so offsets are L2-adjusted); `flow` is the
/// parsed inner flow — its `dst_ip` names the IKE peer and its `src_ip` the
/// firewall's local address (the seed is keyed reply-direction, so the
/// peer's inbound packets match). Only a genuine initiation (all-zero
/// Responder SPI) seeds — IKE replies/retransmissions the firewall sends
/// later in the exchange are ignored, and non-IKE UDP on 500/4500 cannot
/// parse as an initiation.
pub(in crate::afxdp) fn maybe_seed_local_origin_ike(
    table: &IkeExchangeTable,
    packet_frame: &[u8],
    l4_offset: usize,
    flow: &SessionFlow,
    now_ns: u64,
) {
    let protocol = flow.forward_key.protocol;
    let dst_port = flow.forward_key.dst_port;
    if protocol != PROTO_UDP || (dst_port != 500 && dst_port != 4500) {
        return;
    }
    if let Some(initiator_spi) = ike_initiation_spi(packet_frame, l4_offset, dst_port) {
        table.seed(
            IkeExchangeKey::new(initiator_spi, flow.dst_ip, flow.src_ip),
            now_ns,
        );
    }
}

#[cfg(test)]
mod tests {
    //! #6471: unit pins for the ISAKMP SPI extractors and the exchange-table
    //! state machine (seed / match / idle-reap / cap-evict). The Stage-11
    //! fail-on-revert coverage (forged Responder SPI denied, seeded exchange
    //! admitted) lives in `poll_stages_tests.rs`.
    use super::*;

    /// Minimal IPv4/UDP frame whose UDP payload carries an ISAKMP header;
    /// same layout contract as the poll_stages_tests `ike_v4_frame` (only
    /// the bytes at/after `l4_offset` = 34 matter).
    fn ike_frame(natt_marker: bool, initiator: u64, responder: u64) -> Vec<u8> {
        let mut frame = vec![0u8; 42];
        if natt_marker {
            frame.extend_from_slice(&[0, 0, 0, 0]);
        }
        frame.extend_from_slice(&initiator.to_be_bytes());
        frame.extend_from_slice(&responder.to_be_bytes());
        frame.extend_from_slice(&[0x00, 0x20, 0x22, 0x08]); // np/ver/exchange/flags
        frame.extend_from_slice(&0u32.to_be_bytes()); // message id
        frame.extend_from_slice(&0u32.to_be_bytes()); // length
        frame
    }

    #[test]
    fn initiation_spi_only_for_zero_responder() {
        let init = ike_frame(false, 0x1122_3344_5566_7788, 0);
        assert_eq!(
            ike_initiation_spi(&init, 34, 500),
            Some(0x1122_3344_5566_7788)
        );
        assert_eq!(established_ike_initiator_spi(&init, 34, 500), None);
        let est = ike_frame(false, 0x1122_3344_5566_7788, 0xdead_beef_cafe_0001);
        assert_eq!(ike_initiation_spi(&est, 34, 500), None);
        assert_eq!(
            established_ike_initiator_spi(&est, 34, 500),
            Some(0x1122_3344_5566_7788)
        );
    }

    #[test]
    fn spi_extractors_honor_natt_marker() {
        let init = ike_frame(true, 0xaabb_ccdd_eeff_0011, 0);
        assert_eq!(
            ike_initiation_spi(&init, 34, 4500),
            Some(0xaabb_ccdd_eeff_0011)
        );
        let est = ike_frame(true, 0xaabb_ccdd_eeff_0011, 1);
        assert_eq!(
            established_ike_initiator_spi(&est, 34, 4500),
            Some(0xaabb_ccdd_eeff_0011)
        );
        // ESP-in-UDP (non-zero first word, no marker) is NOT IKE: no SPI.
        let mut esp = vec![0u8; 42];
        esp.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd]);
        esp.extend_from_slice(&[0u8; 16]);
        assert_eq!(established_ike_initiator_spi(&esp, 34, 4500), None);
        assert_eq!(ike_initiation_spi(&esp, 34, 4500), None);
    }

    #[test]
    fn spi_extractors_fail_safe_on_truncation() {
        // Frame ends inside the ISAKMP header: neither extractor may invent
        // an SPI (classification still fails CLOSED via NewInboundIke).
        let short = vec![0u8; 42 + 8];
        assert_eq!(ike_initiation_spi(&short, 34, 500), None);
        assert_eq!(established_ike_initiator_spi(&short, 34, 500), None);
        // Frame ends inside the UDP header itself.
        let shorter = vec![0u8; 36];
        assert_eq!(ike_initiation_spi(&shorter, 34, 500), None);
        assert_eq!(established_ike_initiator_spi(&shorter, 34, 500), None);
    }

    #[test]
    fn classify_demux_unchanged_by_6471_refactor() {
        // Behavior-preservation pin for the isakmp_demux extraction: every
        // class resolves exactly as the pre-refactor open-coded match did.
        let init = ike_frame(false, 1, 0);
        assert_eq!(
            classify_ipsec_admission(&init, 34, PROTO_UDP, 500),
            IpsecAdmissionClass::NewInboundIke
        );
        let est = ike_frame(false, 1, 2);
        assert_eq!(
            classify_ipsec_admission(&est, 34, PROTO_UDP, 500),
            IpsecAdmissionClass::Exempt
        );
        let natt_init = ike_frame(true, 1, 0);
        assert_eq!(
            classify_ipsec_admission(&natt_init, 34, PROTO_UDP, 4500),
            IpsecAdmissionClass::NewInboundIke
        );
        let natt_est = ike_frame(true, 1, 2);
        assert_eq!(
            classify_ipsec_admission(&natt_est, 34, PROTO_UDP, 4500),
            IpsecAdmissionClass::Exempt
        );
        let mut esp_in_udp = vec![0u8; 42];
        esp_in_udp.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd]);
        esp_in_udp.extend_from_slice(&[0u8; 16]);
        assert_eq!(
            classify_ipsec_admission(&esp_in_udp, 34, PROTO_UDP, 4500),
            IpsecAdmissionClass::Exempt
        );
        // ESP / AH — the raw data plane.
        assert_eq!(
            classify_ipsec_admission(&init, 34, PROTO_ESP, 0),
            IpsecAdmissionClass::Exempt
        );
        assert_eq!(
            classify_ipsec_admission(&init, 34, PROTO_AH, 0),
            IpsecAdmissionClass::Exempt
        );
        // Truncated ISAKMP and truncated UDP payload fail CLOSED.
        let short = vec![0u8; 42 + 8];
        assert_eq!(
            classify_ipsec_admission(&short, 34, PROTO_UDP, 500),
            IpsecAdmissionClass::NewInboundIke
        );
        let shorter = vec![0u8; 36];
        assert_eq!(
            classify_ipsec_admission(&shorter, 34, PROTO_UDP, 500),
            IpsecAdmissionClass::NewInboundIke
        );
    }

    fn key(spi: u64) -> IkeExchangeKey {
        IkeExchangeKey::new(
            spi,
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)),
        )
    }

    #[test]
    fn exchange_seed_match_refresh() {
        let table = IkeExchangeTable::new();
        assert!(!table.matches(&key(7), 1_000));
        table.seed(key(7), 1_000);
        assert!(table.matches(&key(7), 2_000));
        // A different SPI or address pair must NOT match.
        assert!(!table.matches(&key(8), 2_000));
        assert!(!table.matches(
            &IkeExchangeKey::new(
                7,
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11)),
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5))
            ),
            2_000
        ));
    }

    #[test]
    fn exchange_idle_reap_treats_stale_as_miss() {
        let table = IkeExchangeTable::new();
        table.seed(key(7), 1_000);
        assert!(table.matches(&key(7), 1_000 + IKE_EXCHANGE_IDLE_NS));
        // Refresh slid the window: another full idle span is tolerated.
        let t2 = 1_000 + 2 * IKE_EXCHANGE_IDLE_NS;
        assert!(table.matches(&key(7), t2));
        // Past the window with no traffic: stale seed reaped, reads as miss.
        let t3 = t2 + IKE_EXCHANGE_IDLE_NS + 1;
        assert!(!table.matches(&key(7), t3));
        assert_eq!(table.len(), 0, "stale entry must be reaped, not retained");
    }

    #[test]
    fn exchange_full_evicts_oldest_not_newest() {
        let table = IkeExchangeTable::new();
        for spi in 0..IKE_EXCHANGE_TABLE_CAP as u64 {
            table.seed(key(spi), spi); // insertion order = age order
        }
        assert_eq!(table.len(), IKE_EXCHANGE_TABLE_CAP);
        let cap = IKE_EXCHANGE_TABLE_CAP as u64;
        table.seed(key(cap), cap);
        assert_eq!(table.len(), IKE_EXCHANGE_TABLE_CAP);
        // The OLDEST (spi 0) was evicted; the just-inserted seed survives —
        // refusing the insert would strand a live exchange's follow-ups.
        assert!(!table.matches(&key(0), cap + 1));
        assert!(table.matches(&key(cap), cap + 1));
        assert!(table.matches(&key(1), cap + 1));
    }

    #[test]
    fn local_origin_seed_only_for_udp_ike_initiation() {
        fn seed_flow(protocol: u8, dst_port: u16) -> SessionFlow {
            let src_ip = IpAddr::V4(Ipv4Addr::new(10, 255, 0, 1)); // firewall local
            let dst_ip = IpAddr::V4(Ipv4Addr::new(10, 255, 0, 2)); // tunnel peer
            SessionFlow {
                src_ip,
                dst_ip,
                forward_key: SessionKey {
                    addr_family: libc::AF_INET as u8,
                    protocol,
                    src_ip,
                    dst_ip,
                    src_port: 500,
                    dst_port,
                },
            }
        }
        let table = IkeExchangeTable::new();
        let src = IpAddr::V4(Ipv4Addr::new(10, 255, 0, 1)); // firewall local
        let dst = IpAddr::V4(Ipv4Addr::new(10, 255, 0, 2)); // tunnel peer
        let init = ike_frame(false, 0x5152_5354_5556_5758, 0);
        maybe_seed_local_origin_ike(&table, &init, 34, &seed_flow(PROTO_UDP, 500), 1_000);
        // The peer's REPLY direction lookup: (initiator SPI, peer, local).
        assert!(table.matches(&IkeExchangeKey::new(0x5152_5354_5556_5758, dst, src), 2_000));

        // Non-IKE UDP (wrong port), non-initiation (responder set), and ESP
        // must not seed.
        let table2 = IkeExchangeTable::new();
        maybe_seed_local_origin_ike(&table2, &init, 34, &seed_flow(PROTO_UDP, 53), 1_000);
        let est = ike_frame(false, 9, 9);
        maybe_seed_local_origin_ike(&table2, &est, 34, &seed_flow(PROTO_UDP, 500), 1_000);
        maybe_seed_local_origin_ike(&table2, &init, 34, &seed_flow(PROTO_ESP, 0), 1_000);
        assert_eq!(table2.len(), 0);
    }
}
