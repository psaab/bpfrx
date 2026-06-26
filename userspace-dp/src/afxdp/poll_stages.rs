//! #946 Phase 1 — per-packet pipeline stages.
//!
//! Pure code-motion extraction of seven sub-stages out of the
//! `poll_binding_process_descriptor` while-let body. No batch
//! reordering, no behavioral change. Each helper here is the
//! direct semantic equivalent of the inline block it replaces.
//!
//! Stages owned by Phase 1:
//! - stage 5: link-layer (ARP/NDP) classify  → [stage_link_layer_classify]
//! - stage 6: native GRE decap               → [stage_native_gre_decap]
//! - stage 7+8: parse flow + learn neighbor  → [stage_parse_flow_and_learn]
//! - stage 9: fabric-ingress classification  → [stage_classify_fabric_ingress]
//! - stage 10: screen / IDS slow-path        → [stage_screen_check]
//! - stage 11: IPsec passthrough             → [stage_ipsec_passthrough_check]
//!
//! Stages NOT in scope (kept inline in `poll_descriptor.rs` for
//! Phase 1; will be tackled in follow-up phases):
//! - stages 1-4: rx telemetry, parse meta, classify, slice
//! - stages 12+: flow-cache fast path, session lookup, slow-path
//!   policy/NAT/forwarding, reverse-NAT/ICMP, MissingNeighbor
//!
//! See `docs/pr/946-pipeline-phase1/plan.md` for the full plan,
//! the 9-continue table, and the hidden-invariants list.

use super::*;
use crate::screen::{SynCookieAckVerdict, SynCookieChallenge};

/// Generic outcome for a per-packet stage. The `RecycleAndContinue`
/// arm signals that the caller should push `desc.addr` to
/// `binding.scratch.scratch_recycle` and `continue` the while-let.
/// `Continue(T)` carries the stage's output to the next stage.
pub(super) enum StageOutcome<T> {
    RecycleAndContinue,
    Continue(T),
}

pub(super) enum ScreenCheckOutcome {
    Pass,
    SynCookieChallenge(SynCookieChallenge),
}

pub(super) enum SynCookieAckOutcome {
    Pass,
    Validated,
}

/// Output of `stage_classify_fabric_ingress`. The stage *also*
/// mutates `meta.meta_flags` to set `FABRIC_INGRESS_FLAG`; this
/// struct carries the two return values the caller needs separately.
pub(super) struct FabricIngressOutcome {
    pub(super) ingress_zone_override: Option<u16>,
    pub(super) packet_fabric_ingress: bool,
}

/// Stage 5 — ARP / NDP link-layer classification.
///
/// ARP frames (Reply / Request / Other) are recycled without
/// flowing through the rest of the pipeline. ARP Reply additionally
/// learns a dynamic neighbor and adds a kernel ARP entry.
///
/// NDP NA with a Target Link-Layer Address option learns a dynamic
/// neighbor and adds a kernel neighbor entry, then falls through to
/// normal IPv6 forwarding (the NA frame itself transits the
/// firewall).
///
/// Plain non-link-layer packets fall through unchanged.
///
/// Side effects on `worker_ctx.dynamic_neighbors` (interior
/// mutability behind `Arc`) and the kernel ARP/NDP table are kept
/// inside this helper — the caller does not need visibility into
/// the learned neighbor for the same packet.
#[inline]
pub(super) fn stage_link_layer_classify(
    raw_frame: &[u8],
    meta: UserspaceDpMeta,
    worker_ctx: &WorkerContext,
) -> StageOutcome<()> {
    // #2370: learn dynamic neighbors under the LOGICAL (L3) ifindex,
    // not the physical/parent ingress ifindex. The forwarder looks up
    // dynamic neighbors keyed by the connected-route ifindex, which is
    // the logical VLAN sub-interface (see `lookup_neighbor_entry` and
    // `forwarding_build/interfaces.rs` `ConnectedRouteV4/V6 { ifindex:
    // iface.ifindex }`). For an ARP/NDP frame arriving on a VLAN
    // sub-interface, `meta.ingress_ifindex` is the parent/bind ifindex
    // and `meta.ingress_vlan_id` selects the logical interface;
    // resolving (parent, vlan) -> logical makes the insert key match the
    // lookup key, so the just-learned entry is found instead of falling
    // through to the MissingNeighbor cold path. The SAME logical ifindex
    // keys `add_kernel_neighbor` too (already correct before this fix).
    // For untagged / non-VLAN interfaces the mapping resolves
    // physical == logical, so behavior is unchanged; if no logical
    // interface matches we fall back to the physical ifindex rather than
    // dropping the learned neighbor. Two VLANs sharing a physical port
    // resolve to distinct logical ifindexes (distinct (parent, vlan)
    // keys), so a same-IP-different-subnet neighbor never collides.
    //
    // The resolve is computed ONLY inside the ARP-reply / NDP-NA learn
    // arms below, NOT at the top of the stage. This stage runs per-packet
    // for ALL ingress traffic (before the flow-cache fast path), so the
    // overwhelming majority of packets (every non-ARP/non-NDP frame,
    // including flow-cache hits) must skip the FastMap lookup entirely —
    // they pay zero resolve cost, matching the pre-#2370 data path.
    let learn_ifindex = || {
        resolve_ingress_logical_ifindex(
            worker_ctx.forwarding,
            meta.ingress_ifindex as i32,
            meta.ingress_vlan_id,
        )
        .unwrap_or(meta.ingress_ifindex as i32)
    };
    match parser::classify_arp(raw_frame) {
        parser::ArpClassification::Reply(arp) => {
            // #2790: validate the advertised sender protocol address BEFORE
            // caching it. RFC 826 — a learnable ARP reply must name a single
            // unicast host. A reply claiming an unspecified / loopback /
            // multicast / broadcast sender IP would otherwise pollute both
            // the userspace `dynamic_neighbors` map and the kernel ARP table
            // (spoofed-reply DoS / routing disruption). Fail closed: recycle
            // the ARP frame (it never transits) but skip learning, mirroring
            // the #2369 fail-closed-on-malformed-ARP posture and the cold
            // neighbor warmer's unicast-only gate.
            // #2851: anti-poisoning own-IP gate, ADDITIONAL to the #2790
            // unicast-only gate above. Refuse to learn an ARP reply whose
            // advertised sender IP equals one of the router's OWN configured
            // interface IPs. A host on the local link could otherwise send an
            // unsolicited/spoofed reply claiming our own interface address and
            // teach us `(ifindex, our_ip) -> attacker_mac` in both
            // `dynamic_neighbors` and the kernel ARP table (RFC 826 — do not
            // install a neighbor entry for an address we own). This MUST run
            // BEFORE the `insert_if_changed` below so a rejected own-IP learn
            // neither inserts nor bumps `mac_change_epoch` (#3048/#3169).
            // (Solicited-only learning — only caching replies to probes we
            // actually sent — is a larger, separate concern, tracked as a
            // follow-up; this fix is the bounded own-IP rejection.)
            if neighbor_ip_is_learnable(arp.sender_ip)
                && !worker_ctx.forwarding.owns_configured_ip(arp.sender_ip)
            {
                let ifindex = learn_ifindex();
                // #3048: route the data-path learn through insert_if_changed
                // so a MAC change observed directly from an ARP reply
                // (e.g. an upstream gateway VRRP failover whose reply
                // traverses our XSK ingress) advances the neighbor
                // mac_change_epoch and evicts stale cached dst_macs. A plain
                // insert would silently overwrite the userspace map with the
                // new MAC, then SHADOW the kernel-monitor RTM_NEWNEIGH that
                // follows add_kernel_neighbor (the monitor would see
                // prior == new and not bump), leaving the flow cache stale.
                let _ = worker_ctx.dynamic_neighbors.insert_if_changed(
                    (ifindex, arp.sender_ip),
                    NeighborEntry {
                        mac: arp.sender_mac,
                    },
                );
                add_kernel_neighbor(ifindex, arp.sender_ip, arp.sender_mac);
            }
            return StageOutcome::RecycleAndContinue;
        }
        parser::ArpClassification::OtherArp => {
            return StageOutcome::RecycleAndContinue;
        }
        parser::ArpClassification::NotArp => {}
    }
    if let Some(na) = parser::parse_ndp_neighbor_advert(raw_frame)
        && let Some(mac) = na.target_mac
        // #2790: same unicast-only gate for the NDP NA target address —
        // an NA advertising an unspecified / loopback / multicast target
        // IP is not a learnable neighbor (RFC 4861 §7.2.4 targets are
        // unicast). The NA frame still transits (falls through below);
        // only the neighbor write is suppressed.
        && neighbor_ip_is_learnable(na.target_ip)
        // #2851: same anti-poisoning own-IP gate as the ARP-reply arm above.
        // An NDP NA advertising one of the router's OWN configured IPv6
        // addresses must not be learned — a local attacker could otherwise
        // poison `(ifindex, our_v6) -> attacker_mac` (RFC 4861: do not learn
        // an entry for an address we own from an unsolicited advert). Runs
        // BEFORE the `insert_if_changed` below so a rejected learn neither
        // inserts nor bumps `mac_change_epoch`.
        && !worker_ctx.forwarding.owns_configured_ip(na.target_ip)
    {
        let ifindex = learn_ifindex();
        // #3048: same change-detecting learn for NDP NA — a target-MAC
        // change observed on the data path must bump mac_change_epoch and
        // evict stale cached dst_macs (see the ARP-reply arm above).
        let _ = worker_ctx
            .dynamic_neighbors
            .insert_if_changed((ifindex, na.target_ip), NeighborEntry { mac });
        add_kernel_neighbor(ifindex, na.target_ip, mac);
    }
    StageOutcome::Continue(())
}

/// Stage 6 — native GRE decapsulation.
///
/// Returns the (possibly-updated) `meta` and the optional owned
/// decap frame. Caller binds the active slice locally:
///
/// ```text
/// let (meta, owned) = stage_native_gre_decap(raw_frame, meta, ...);
/// let packet_frame = owned.as_deref().unwrap_or(raw_frame);
/// ```
///
/// `owned_packet_frame: Option<Vec<u8>>` MUST be a `mut` binding at
/// the call site because the deferred stage-12+ code in
/// `poll_descriptor.rs` calls `.take()` on it (grep
/// `owned_packet_frame.take(` — the deferred flow-cache,
/// session-hit reverse-NAT, and missing-neighbor side-queue paths
/// each move the owned decap frame out before pushing the
/// resulting forward request). Symbol references rather than line
/// numbers because the line numbers drift any time a stage above
/// is touched.
///
/// The helper does NOT return the active slice — that would be a
/// self-referential return type (the slice would borrow from the
/// returned `Vec`).
#[inline]
pub(super) fn stage_native_gre_decap(
    raw_frame: &[u8],
    meta: UserspaceDpMeta,
    forwarding: &ForwardingState,
) -> (UserspaceDpMeta, Option<Vec<u8>>) {
    let native_gre_packet = try_native_gre_decap_from_frame(raw_frame, meta, forwarding);
    let new_meta = native_gre_packet
        .as_ref()
        .map(|packet| packet.meta)
        .unwrap_or(meta);
    let owned_packet_frame = native_gre_packet.map(|packet| packet.frame);
    (new_meta, owned_packet_frame)
}

/// Stage 7+8 — parse session flow and learn the source-side
/// dynamic neighbor.
///
/// `learn_from_live_frame` MUST be `owned_packet_frame.is_none()`
/// at the call site. Mirrors the GRE guard at
/// poll_descriptor.rs:113 — neighbor learning uses the un-decapped
/// raw_frame (via `area`/`desc`) so the source MAC comes from the
/// live UMEM Ethernet frame; learning from a decapped GRE inner
/// frame would record the GRE tunnel's egress MAC instead of the
/// outer host's.
///
/// Side effects: `worker_ctx.dynamic_neighbors` (interior mut),
/// `last_learned_neighbor` (caller's &mut), kernel neighbor table.
#[inline]
pub(super) fn stage_parse_flow_and_learn(
    area: &MmapArea,
    desc: XdpDesc,
    packet_frame: &[u8],
    meta: UserspaceDpMeta,
    learn_from_live_frame: bool,
    last_learned_neighbor: &mut Option<LearnedNeighborKey>,
    worker_ctx: &WorkerContext,
) -> Option<SessionFlow> {
    let flow = parse_session_flow_from_bytes(packet_frame, meta);
    if learn_from_live_frame && let Some(flow) = flow.as_ref() {
        learn_dynamic_neighbor_from_packet(
            area,
            desc,
            meta,
            flow.src_ip,
            last_learned_neighbor,
            worker_ctx.forwarding,
            worker_ctx.dynamic_neighbors,
        );
    }
    flow
}

/// Stage 9 — fabric-ingress classification.
///
/// Mutates `meta.meta_flags` to set `FABRIC_INGRESS_FLAG` when the
/// packet's ingress is a fabric overlay or carries a zone-encoded
/// fabric ingress marker. Returns the discovered zone override
/// (used by the screen stage) and the fabric flag (used by
/// downstream forwarding).
///
/// This stage MUST run before screen / IPsec / flow-cache because
/// those downstream stages read `meta.meta_flags` and the
/// `FABRIC_INGRESS_FLAG` is required to skip TTL decrement on
/// fabric-traversed packets (the sending peer already decremented
/// TTL when forwarding across the fabric link).
#[inline]
pub(super) fn stage_classify_fabric_ingress(
    packet_frame: &[u8],
    meta: &mut UserspaceDpMeta,
    worker_ctx: &WorkerContext,
) -> FabricIngressOutcome {
    let ingress_zone_override =
        parse_zone_encoded_fabric_ingress_from_frame(packet_frame, *meta, worker_ctx.forwarding);
    let packet_fabric_ingress = ingress_zone_override.is_some()
        || ingress_is_fabric_overlay(worker_ctx.forwarding, meta.ingress_ifindex as i32);
    if packet_fabric_ingress {
        meta.meta_flags |= FABRIC_INGRESS_FLAG;
    }
    FabricIngressOutcome {
        ingress_zone_override,
        packet_fabric_ingress,
    }
}

/// Stage 10 — screen / IDS slow-path check.
///
/// Only runs when screen profiles are configured (the `has_profiles`
/// gate). Resolves the ingress zone name (preferring the
/// fabric-zone override from stage 9), extracts a `ScreenPacketInfo`
/// from the packet, and runs `screen.check_packet`. On a Drop
/// verdict, bumps `counters.screen_drops` (batched, not direct
/// to `BindingLiveState` — #1187 DDoS-resilience: SYN flood is the
/// primary screen_drops trigger; unbatched atomics here would cause
/// MESI ping-pong with the coordinator's status reads under
/// volumetric attack) and returns `RecycleAndContinue`.
#[inline]
pub(super) fn stage_screen_check(
    flow: Option<&SessionFlow>,
    packet_frame: &[u8],
    meta: UserspaceDpMeta,
    ingress_zone_override: Option<u16>,
    now_secs: u64,
    screen: &mut ScreenState,
    counters: &mut BatchCounters,
    worker_ctx: &WorkerContext,
) -> StageOutcome<ScreenCheckOutcome> {
    if !screen.has_profiles() {
        return StageOutcome::Continue(ScreenCheckOutcome::Pass);
    }
    // Zone resolution is flow-INDEPENDENT: it is keyed on the packet's
    // ingress context (logical ifindex / VLAN / fabric override), not on the
    // transport flow. Resolving it BEFORE branching on `flow` lets the
    // flowless non-first-fragment path (#3064) reach the very same zone
    // screen profile the flow path uses.
    //
    // #3022: resolve the LOGICAL ingress ifindex before the zone lookup.
    // `ifindex_to_zone_id` is keyed by the logical unit ifindex; the raw
    // physical bind ifindex either misses (no zone on the parent → screen
    // skipped entirely) or returns the parent's first-subinterface zone
    // (wrong profile), bypassing/mis-applying screen profiles on VLAN
    // subinterfaces. Non-VLAN ports resolve physical == logical.
    let logical_ifindex = resolve_ingress_logical_ifindex(
        worker_ctx.forwarding,
        meta.ingress_ifindex as i32,
        meta.ingress_vlan_id,
    )
    .unwrap_or(meta.ingress_ifindex as i32);
    let zone_id = ingress_zone_override
        .filter(|id| worker_ctx.forwarding.zone_id_to_name.contains_key(id))
        .or_else(|| {
            worker_ctx
                .forwarding
                .ifindex_to_zone_id
                .get(&logical_ifindex)
                .copied()
        });
    let Some(zone_id) = zone_id else {
        return StageOutcome::Continue(ScreenCheckOutcome::Pass);
    };
    let Some(zone_name) = worker_ctx
        .forwarding
        .zone_id_to_name
        .get(&zone_id)
        .map(|s| s.as_str())
    else {
        return StageOutcome::Continue(ScreenCheckOutcome::Pass);
    };
    // L3 starts after the 802.1Q tag whenever a tag is PRESENT, not
    // only when the VID is non-zero. 802.1p priority-tagged frames
    // carry a real tag (TPID 0x8100 + PCP bits) with VID 0, so a
    // `vlan_id > 0` test would read the IP header at offset 14 and
    // parse the tag's TPID/TCI bytes as the IPv4/IPv6 header — the
    // #2145 misclassification. `ingress_vlan_present` is the
    // tag-presence signal the shim already sets (mirrors the CoS path
    // in tx/cos_classify.rs).
    let l3_off = if meta.ingress_vlan_present != 0 {
        18
    } else {
        14
    };
    // #3064: a non-first IP fragment has no transport flow —
    // `parse_session_flow_from_bytes` returns `None` for it (#2344, so the
    // fragment payload is never parsed as L4 ports). Such a fragment used to
    // return `Pass` here, which made the PER-FRAGMENT L3-header screens
    // (ping-of-death, teardrop, icmp-fragment) DEAD in the live pipeline —
    // hostile Teardrop / Ping-of-Death fragment contributions transited
    // unscreened. Run ONLY the L3-header fragment screens on the flowless
    // path: extract a header-only `ScreenPacketInfo` straight from the IP
    // header (placeholder L4 tuple — we never parse the fragment payload, so
    // the #2344 flowless fast path is NOT reintroduced) and evaluate the
    // three L3 fragment screens. Flow/session-dependent screens (land,
    // TCP-flag, flood counters, scan/sweep, SYN-cookie) stay on the
    // flow-present path below.
    let Some(flow) = flow else {
        // Placeholder L4 tuple: the L3 fragment screens (ping-of-death /
        // teardrop / icmp-fragment) never read src/dst IP or ports — they
        // operate purely on fragment offset / total/payload length /
        // protocol. tcp_flags is 0 because a non-first fragment carries no
        // L4 header. Unspecified addresses keep the drop-event log sane
        // without re-deriving the L3 addresses (out of scope for #3064).
        let (placeholder_src, placeholder_dst) = if meta.addr_family == libc::AF_INET6 as u8 {
            (
                IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            )
        } else {
            (
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            )
        };
        let screen_pkt = match extract_screen_info(
            packet_frame,
            meta.addr_family,
            meta.protocol,
            0,
            meta.pkt_len,
            placeholder_src,
            placeholder_dst,
            0,
            0,
            l3_off,
        ) {
            Ok(pkt) => pkt,
            // FAIL-CLOSED (#2146 parity): a frame whose L3/extension-header
            // chain cannot be parsed far enough to evaluate the fragment
            // screens is dropped on the flow path, so drop it here too rather
            // than admit an unparseable fragment unscreened.
            Err(err) => {
                let reason = err.screen_reason();
                emit_screen_drop_event(
                    worker_ctx.event_stream,
                    &screen_parse_error_info_flowless(meta.addr_family),
                    meta,
                    zone_id,
                    reason,
                    event_now_ns_from_secs(now_secs),
                );
                counters.touched = true;
                counters.screen_drops += 1;
                return StageOutcome::RecycleAndContinue;
            }
        };
        return match screen.check_fragment_screens_l3(zone_name, &screen_pkt) {
            ScreenVerdict::Drop(reason) => {
                emit_screen_drop_event(
                    worker_ctx.event_stream,
                    &screen_pkt,
                    meta,
                    zone_id,
                    reason,
                    event_now_ns_from_secs(now_secs),
                );
                counters.touched = true;
                counters.screen_drops += 1;
                StageOutcome::RecycleAndContinue
            }
            // The L3 fragment screens only ever return Pass or Drop — they
            // never mint a SYN-cookie challenge/bypass (those are
            // flow/TCP-only and stay on the flow-present path).
            _ => StageOutcome::Continue(ScreenCheckOutcome::Pass),
        };
    };
    let screen_pkt = match extract_screen_info(
        packet_frame,
        meta.addr_family,
        meta.protocol,
        meta.tcp_flags,
        meta.pkt_len,
        flow.src_ip,
        flow.dst_ip,
        flow.forward_key.src_port,
        flow.forward_key.dst_port,
        l3_off,
    ) {
        Ok(pkt) => pkt,
        // FAIL-CLOSED (#2146): the extractor could not parse the L3
        // header far enough to evaluate the fragment/TCP screens (e.g.
        // a truncated IPv6 extension-header chain). With screen
        // profiles active on this zone, drop the unparseable frame
        // rather than admit it — a SYN-bearing frame with a truncated
        // FRAGMENT header must not bypass `syn-frag`.
        Err(err) => {
            let reason = err.screen_reason();
            let drop_info = screen_parse_error_info(&meta, flow);
            emit_screen_drop_event(
                worker_ctx.event_stream,
                &drop_info,
                meta,
                zone_id,
                reason,
                event_now_ns_from_secs(now_secs),
            );
            counters.touched = true;
            counters.screen_drops += 1;
            return StageOutcome::RecycleAndContinue;
        }
    };
    match screen.check_packet_with_zone_id(zone_name, zone_id, &screen_pkt, now_secs) {
        ScreenVerdict::Pass => StageOutcome::Continue(ScreenCheckOutcome::Pass),
        ScreenVerdict::SynCookieBypass => {
            counters.touched = true;
            counters.syn_cookie_bypass += 1;
            StageOutcome::Continue(ScreenCheckOutcome::Pass)
        }
        ScreenVerdict::Drop(reason) => {
            emit_screen_drop_event(
                worker_ctx.event_stream,
                &screen_pkt,
                meta,
                zone_id,
                reason,
                event_now_ns_from_secs(now_secs),
            );
            counters.touched = true;
            counters.screen_drops += 1;
            if reason == "syn-cookie-unavailable" {
                counters.syn_cookie_secret_unavailable += 1;
            }
            StageOutcome::RecycleAndContinue
        }
        ScreenVerdict::SynCookieChallenge(challenge) => {
            emit_screen_drop_event(
                worker_ctx.event_stream,
                &screen_pkt,
                meta,
                zone_id,
                "syn-cookie",
                event_now_ns_from_secs(now_secs),
            );
            counters.touched = true;
            counters.screen_drops += 1;
            counters.syn_cookie_challenges += 1;
            StageOutcome::Continue(ScreenCheckOutcome::SynCookieChallenge(challenge))
        }
    }
}

/// SYN-cookie returning ACK validation on the session-miss path.
///
/// This runs after normal session lookup has failed, so established ACK traffic
/// keeps its normal fast/session path. A valid cookie ACK is consumed without
/// creating a session; the caller turns the `Validated` outcome into a bounded
/// RST reply and the validated-client cache lets the client's next SYN traverse
/// the ordinary policy/NAT/session path. Invalid cookie ACKs are dropped while
/// cookie mode is active. Poll-stage coverage intentionally pins only the
/// operational drop/bypass behavior here; the lower screen runtime owns cache
/// mechanics. `screen_tests.rs` covers bounded 4-way replacement, explicit
/// cache expiration, and current/previous secret-epoch validation.
#[inline]
pub(super) fn stage_screen_syn_cookie_ack_on_session_miss(
    flow: Option<&SessionFlow>,
    packet_frame: &[u8],
    meta: UserspaceDpMeta,
    ingress_zone_override: Option<u16>,
    now_secs: u64,
    screen: &mut ScreenState,
    counters: &mut BatchCounters,
    worker_ctx: &WorkerContext,
) -> StageOutcome<SynCookieAckOutcome> {
    if !screen.has_profiles() {
        return StageOutcome::Continue(SynCookieAckOutcome::Pass);
    }
    let Some(flow) = flow else {
        return StageOutcome::Continue(SynCookieAckOutcome::Pass);
    };
    // #3022: resolve the LOGICAL ingress ifindex first (see
    // `stage_screen_check`) so the SYN-cookie-ACK validation uses the VLAN
    // subinterface's own zone profile, not the parent's first-subinterface
    // zone. Non-VLAN ports resolve physical == logical.
    let logical_ifindex = resolve_ingress_logical_ifindex(
        worker_ctx.forwarding,
        meta.ingress_ifindex as i32,
        meta.ingress_vlan_id,
    )
    .unwrap_or(meta.ingress_ifindex as i32);
    let zone_id = ingress_zone_override
        .filter(|id| worker_ctx.forwarding.zone_id_to_name.contains_key(id))
        .or_else(|| {
            worker_ctx
                .forwarding
                .ifindex_to_zone_id
                .get(&logical_ifindex)
                .copied()
        });
    let Some(zone_id) = zone_id else {
        return StageOutcome::Continue(SynCookieAckOutcome::Pass);
    };
    let Some(zone_name) = worker_ctx
        .forwarding
        .zone_id_to_name
        .get(&zone_id)
        .map(|s| s.as_str())
    else {
        return StageOutcome::Continue(SynCookieAckOutcome::Pass);
    };
    // See `stage_screen_check`: decide L3 offset on tag PRESENCE, not
    // VID > 0, so a priority-tagged VID-0 cookie ACK is parsed at the
    // correct offset (18) instead of mis-reading the tag bytes (#2145).
    let l3_off = if meta.ingress_vlan_present != 0 {
        18
    } else {
        14
    };
    let screen_pkt = match extract_screen_info(
        packet_frame,
        meta.addr_family,
        meta.protocol,
        meta.tcp_flags,
        meta.pkt_len,
        flow.src_ip,
        flow.dst_ip,
        flow.forward_key.src_port,
        flow.forward_key.dst_port,
        l3_off,
    ) {
        Ok(pkt) => pkt,
        // FAIL-CLOSED (#2146): an unparseable L3 header on the
        // SYN-cookie ACK session-miss path is dropped, never admitted.
        Err(err) => {
            let reason = err.screen_reason();
            let drop_info = screen_parse_error_info(&meta, flow);
            emit_screen_drop_event(
                worker_ctx.event_stream,
                &drop_info,
                meta,
                zone_id,
                reason,
                event_now_ns_from_secs(now_secs),
            );
            counters.touched = true;
            counters.screen_drops += 1;
            return StageOutcome::RecycleAndContinue;
        }
    };
    match screen.validate_syn_cookie_ack_on_session_miss(zone_name, zone_id, &screen_pkt, now_secs)
    {
        SynCookieAckVerdict::NotApplicable => StageOutcome::Continue(SynCookieAckOutcome::Pass),
        SynCookieAckVerdict::Validated => {
            counters.touched = true;
            counters.syn_cookie_ack_valid += 1;
            StageOutcome::Continue(SynCookieAckOutcome::Validated)
        }
        SynCookieAckVerdict::Invalid => {
            emit_screen_drop_event(
                worker_ctx.event_stream,
                &screen_pkt,
                meta,
                zone_id,
                "syn-cookie",
                event_now_ns_from_secs(now_secs),
            );
            counters.touched = true;
            counters.screen_drops += 1;
            counters.syn_cookie_ack_invalid += 1;
            StageOutcome::RecycleAndContinue
        }
    }
}

/// Stage 11 — IPsec passthrough.
///
/// ESP (proto 50) and IKE (UDP 500/4500) must transit the kernel
/// XFRM subsystem. On a match, this stage builds a synthetic
/// `SessionDecision` with `LocalDelivery` disposition and
/// reinjects the packet via the slow-path TUN device, then signals
/// `RecycleAndContinue` so the caller drops the UMEM frame.
///
/// Non-IPsec packets fall through unchanged.
#[inline]
pub(super) fn stage_ipsec_passthrough_check(
    flow: Option<&SessionFlow>,
    packet_frame: &[u8],
    meta: UserspaceDpMeta,
    binding_live: &BindingLiveState,
    worker_ctx: &WorkerContext,
) -> StageOutcome<()> {
    let Some(flow) = flow else {
        return StageOutcome::Continue(());
    };
    if !is_ipsec_traffic(meta.protocol, flow.forward_key.dst_port) {
        return StageOutcome::Continue(());
    }
    let ipsec_decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::LocalDelivery,
            local_ifindex: 0,
            egress_ifindex: 0,
            tx_ifindex: 0,
            tunnel_endpoint_id: 0,
            next_hop: None,
            neighbor_mac: None,
            src_mac: None,
            tx_vlan_id: 0,
        },
        nat: NatDecision::default(),
    };
    maybe_reinject_slow_path_from_frame(
        &worker_ctx.ident,
        binding_live,
        worker_ctx.slow_path,
        worker_ctx.local_tunnel_deliveries,
        packet_frame,
        meta,
        ipsec_decision,
        worker_ctx.recent_exceptions,
        "slow_path",
        worker_ctx.forwarding,
    );
    StageOutcome::RecycleAndContinue
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_stream::DataplaneEventRateLimitConfig;
    use crate::event_stream::codec::DataplaneEventKind;
    use crate::test_zone_ids::TEST_LAN_ZONE_ID;

    const TEST_NOW_SECS: u64 = 128;
    const TCP_FLAG_ACK: u8 = 0x10;

    fn tcp_v4_frame(
        src: Ipv4Addr,
        dst: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        flags: u8,
        seq: u32,
        ack: u32,
    ) -> Vec<u8> {
        let mut frame = Vec::new();
        write_eth_header(
            &mut frame,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
            0,
            0x0800,
        );
        frame.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 64, PROTO_TCP, 0x00, 0x00,
        ]);
        frame.extend_from_slice(&src.octets());
        frame.extend_from_slice(&dst.octets());
        let ip_csum = checksum16(&frame[14..34]);
        frame[24..26].copy_from_slice(&ip_csum.to_be_bytes());
        frame.extend_from_slice(&src_port.to_be_bytes());
        frame.extend_from_slice(&dst_port.to_be_bytes());
        frame.extend_from_slice(&seq.to_be_bytes());
        frame.extend_from_slice(&ack.to_be_bytes());
        frame.extend_from_slice(&[0x50, flags, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00]);
        recompute_l4_checksum_ipv4(&mut frame[14..], 20, PROTO_TCP, false).expect("tcp checksum");
        frame
    }

    fn tcp_v4_meta(frame: &[u8], flags: u8) -> UserspaceDpMeta {
        UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            ingress_ifindex: 24,
            l3_offset: 14,
            l4_offset: 34,
            payload_offset: 54,
            pkt_len: (frame.len() - 14) as u16,
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            tcp_flags: flags,
            ..UserspaceDpMeta::default()
        }
    }

    /// Build an IPv4 TCP SYN with the L2 header chosen by `vlan`:
    /// `Vlan::None` → 14-byte untagged header; `Vlan::PriorityTagged`
    /// → an 802.1p priority tag (TPID 0x8100, PCP 5, **VID 0**), so the
    /// L3 header starts at offset 18 while `ingress_vlan_id` is 0. The
    /// IPv4 header is built with `ihl` 32-bit words (5 = no options;
    /// 6 = one option word carrying an LSRR source-route option, which
    /// trips the `ip-source-route` screen — #2973 requires a real
    /// LSRR/SSRR option, not just `ihl > 5`).
    fn tcp_v4_syn_frame_with_l2(vlan: Vlan, ihl: u8) -> Vec<u8> {
        let mut frame = Vec::new();
        let dst_mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let src_mac = [0x00, 0x25, 0x90, 0x12, 0x34, 0x56];
        frame.extend_from_slice(&dst_mac);
        frame.extend_from_slice(&src_mac);
        if let Vlan::PriorityTagged = vlan {
            // 802.1Q TPID + TCI. TCI = PCP(3) | DEI(1) | VID(12); here
            // PCP=5, DEI=0, VID=0 — the priority-tagged-VLAN-0 shape
            // that #2145 mis-parsed.
            frame.extend_from_slice(&0x8100u16.to_be_bytes());
            frame.extend_from_slice(&(0x5u16 << 13).to_be_bytes());
        }
        frame.extend_from_slice(&0x0800u16.to_be_bytes());
        let l3 = frame.len();
        let ihl_bytes = ihl as usize * 4;
        // IPv4 header: version/IHL, then the fixed 20-byte base header,
        // then `ihl_bytes - 20` NOP option bytes.
        frame.push(0x40 | ihl);
        frame.push(0x00);
        let total_len = (ihl_bytes + 20) as u16; // IP header + 20-byte TCP
        frame.extend_from_slice(&total_len.to_be_bytes());
        frame.extend_from_slice(&[0x00, 0x01, 0x40, 0x00, 64, PROTO_TCP, 0x00, 0x00]);
        frame.extend_from_slice(&Ipv4Addr::new(192, 0, 2, 10).octets());
        frame.extend_from_slice(&Ipv4Addr::new(198, 51, 100, 20).octets());
        // IPv4 options to reach `ihl_bytes`. When options are present
        // (ihl > 5) the first option is an actual LSRR (Loose Source
        // Route, option type 131) so the `ip-source-route` screen fires.
        // #2973 made that screen require a real LSRR/SSRR option (the
        // extractor decodes the options TLVs) instead of dropping on any
        // ihl > 5, so a NOP-only options region no longer trips it. The
        // remaining bytes stay NOP (0x01); the extractor detects the
        // source-route option from the kind byte alone.
        frame.resize(l3 + ihl_bytes, 0x01);
        if ihl > 5 {
            frame[l3 + 20] = 131; // LSRR
        }
        let ip_csum = checksum16(&frame[l3..l3 + ihl_bytes]);
        frame[l3 + 10..l3 + 12].copy_from_slice(&ip_csum.to_be_bytes());
        // TCP SYN.
        let l4 = frame.len();
        frame.extend_from_slice(&49152u16.to_be_bytes());
        frame.extend_from_slice(&443u16.to_be_bytes());
        frame.extend_from_slice(&1u32.to_be_bytes()); // seq
        frame.extend_from_slice(&0u32.to_be_bytes()); // ack
        frame.extend_from_slice(&[0x50, TCP_FLAG_SYN, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00]);
        recompute_l4_checksum_ipv4(&mut frame[l3..], ihl_bytes, PROTO_TCP, false)
            .expect("tcp checksum");
        let _ = l4;
        frame
    }

    #[derive(Clone, Copy)]
    enum Vlan {
        None,
        PriorityTagged,
    }

    /// Metadata mirroring the shim contract for the frame built above:
    /// tagged frames carry `ingress_vlan_present = 1` with
    /// `ingress_vlan_id = 0` (priority tag) and `l3_offset = 18`;
    /// untagged frames carry `present = 0`, `l3_offset = 14`.
    fn tcp_v4_syn_meta_with_l2(frame: &[u8], vlan: Vlan) -> UserspaceDpMeta {
        let (l3, present): (u16, u8) = match vlan {
            Vlan::None => (14, 0),
            Vlan::PriorityTagged => (18, 1),
        };
        UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            ingress_ifindex: 24,
            ingress_vlan_id: 0,
            ingress_pcp: if present != 0 { 5 } else { 0 },
            ingress_vlan_present: present,
            l3_offset: l3,
            l4_offset: l3 + 20,
            payload_offset: l3 + 40,
            pkt_len: frame.len() as u16 - l3,
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            tcp_flags: TCP_FLAG_SYN,
            ..UserspaceDpMeta::default()
        }
    }

    /// Screen state with only the IP source-route check armed. The
    /// check fires on an actual LSRR/SSRR option decoded from the IPv4
    /// options region (post-#2973) read from the frame at the computed
    /// L3 offset, so the verdict is a direct probe of whether the screen
    /// stage parsed the IP header at the right offset.
    fn source_route_screen() -> ScreenState {
        let mut profiles = FxHashMap::default();
        profiles.insert(
            "lan".to_string(),
            ScreenProfile {
                source_route: true,
                ..ScreenProfile::default()
            },
        );
        let mut screen = ScreenState::new();
        screen.update_profiles(profiles);
        screen
    }

    fn syn_cookie_screen() -> ScreenState {
        let mut profiles = FxHashMap::default();
        profiles.insert(
            "lan".to_string(),
            ScreenProfile {
                syn_flood_threshold: 1,
                syn_cookie: true,
                ..ScreenProfile::default()
            },
        );
        let mut screen = ScreenState::new();
        screen.update_profiles(profiles);
        screen.update_syn_cookie_master_key(Some([0x42; 16]));
        screen
    }

    #[test]
    fn session_miss_ack_stage_invokes_syn_cookie_runtime_validation() {
        let mut screen = syn_cookie_screen();
        let forwarding = build_forwarding_state(&super::super::test_fixtures::nat_snapshot());
        let ident = BindingIdentity {
            slot: 0,
            queue_id: 0,
            worker_id: 0,
            interface: Arc::<str>::from("reth1.0"),
            ifindex: 24,
        };
        let binding_lookup = WorkerBindingLookup::default();
        let mirror_targets = MirrorTargetMap::default();
        let ha_state = BTreeMap::new();
        let dynamic_neighbors = Arc::new(ShardedNeighborMap::default());
        let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
        let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
        let recent_exceptions = Arc::new(Mutex::new(VecDeque::new()));
        let last_resolution = Arc::new(Mutex::new(None));
        let peer_worker_commands = Vec::new();
        let dnat_fds = DnatTableFds::default();
        let rg_epochs = std::array::from_fn(|_| AtomicU32::new(0));
        let (event_handle, event_rx) = crate::event_stream::test_worker_handle(
            8,
            DataplaneEventRateLimitConfig {
                events_per_second: 0,
                burst: 0,
            },
        );
        let worker_ctx = WorkerContext {
            ident: &ident,
            binding_lookup: &binding_lookup,
            mirror_targets: &mirror_targets,
            forwarding: &forwarding,
            ha_state: &ha_state,
            dynamic_neighbors: &dynamic_neighbors,
            neighbor_resolver: None,
            shared_sessions: &shared_sessions,
            shared_nat_sessions: &shared_nat_sessions,
            shared_forward_wire_sessions: &shared_forward_wire_sessions,
            shared_owner_rg_indexes: &shared_owner_rg_indexes,
            slow_path: None,
            event_stream: Some(&event_handle),
            local_tunnel_deliveries: &local_tunnel_deliveries,
            recent_exceptions: &recent_exceptions,
            last_resolution: &last_resolution,
            peer_worker_commands: &peer_worker_commands,
            dnat_fds: &dnat_fds,
            rg_epochs: &rg_epochs,
            cold_path_sample_mask: 0xff,
        };

        let client = Ipv4Addr::new(192, 0, 2, 10);
        let server = Ipv4Addr::new(198, 51, 100, 20);
        let syn_frame = tcp_v4_frame(client, server, 49152, 443, TCP_FLAG_SYN, 1, 0);
        let syn_meta = tcp_v4_meta(&syn_frame, TCP_FLAG_SYN);
        let syn_flow =
            parse_session_flow_from_bytes(&syn_frame, syn_meta).expect("session flow from SYN");
        let syn_info = extract_screen_info(
            &syn_frame,
            syn_meta.addr_family,
            syn_meta.protocol,
            syn_meta.tcp_flags,
            syn_meta.pkt_len,
            syn_flow.src_ip,
            syn_flow.dst_ip,
            syn_flow.forward_key.src_port,
            syn_flow.forward_key.dst_port,
            syn_meta.l3_offset as usize,
        )
        .expect("valid SYN frame parses");

        assert_eq!(
            screen.check_packet_with_zone_id("lan", TEST_LAN_ZONE_ID, &syn_info, TEST_NOW_SECS),
            ScreenVerdict::Pass
        );
        let _challenge = match screen.check_packet_with_zone_id(
            "lan",
            TEST_LAN_ZONE_ID,
            &syn_info,
            TEST_NOW_SECS,
        ) {
            ScreenVerdict::SynCookieChallenge(challenge) => challenge,
            other => panic!("expected SYN-cookie challenge, got {other:?}"),
        };

        let invalid_ack_frame =
            tcp_v4_frame(client, server, 49152, 443, TCP_FLAG_ACK, 2, 0xdead_beef);
        let invalid_ack_meta = tcp_v4_meta(&invalid_ack_frame, TCP_FLAG_ACK);
        let invalid_ack_flow = parse_session_flow_from_bytes(&invalid_ack_frame, invalid_ack_meta)
            .expect("session flow from invalid ACK");
        let mut invalid_counters = BatchCounters::default();

        assert!(matches!(
            stage_screen_syn_cookie_ack_on_session_miss(
                Some(&invalid_ack_flow),
                &invalid_ack_frame,
                invalid_ack_meta,
                None,
                TEST_NOW_SECS,
                &mut screen,
                &mut invalid_counters,
                &worker_ctx,
            ),
            StageOutcome::RecycleAndContinue
        ));
        assert!(
            invalid_counters.touched,
            "invalid cookie ACK must be counted as a screen drop"
        );
        assert_eq!(invalid_counters.screen_drops, 1);
        assert_eq!(invalid_counters.syn_cookie_ack_invalid, 1);
        let screen_event = event_rx
            .try_recv()
            .expect("screen-drop event")
            .decode_dataplane_event()
            .expect("screen-drop payload");
        assert_eq!(screen_event.kind, DataplaneEventKind::ScreenDrop);
        assert_eq!(screen_event.ingress_zone_id, TEST_LAN_ZONE_ID);
        assert_eq!(screen_event.ingress_ifindex, 24);
        assert_eq!(screen_event.screen_id, 1 << 14);
        assert_eq!(event_handle.dataplane_event_stats().screen_drop.sent, 1);

        let challenge = match screen.check_packet_with_zone_id(
            "lan",
            TEST_LAN_ZONE_ID,
            &syn_info,
            TEST_NOW_SECS,
        ) {
            ScreenVerdict::SynCookieChallenge(challenge) => challenge,
            other => panic!("invalid ACK must not install SYN-cookie bypass, got {other:?}"),
        };

        let ack_frame = tcp_v4_frame(
            client,
            server,
            49152,
            443,
            TCP_FLAG_ACK,
            2,
            challenge.cookie_isn.wrapping_add(1),
        );
        let ack_meta = tcp_v4_meta(&ack_frame, TCP_FLAG_ACK);
        let ack_flow =
            parse_session_flow_from_bytes(&ack_frame, ack_meta).expect("session flow from ACK");
        let mut counters = BatchCounters::default();

        assert!(matches!(
            stage_screen_syn_cookie_ack_on_session_miss(
                Some(&ack_flow),
                &ack_frame,
                ack_meta,
                None,
                TEST_NOW_SECS,
                &mut screen,
                &mut counters,
                &worker_ctx,
            ),
            StageOutcome::Continue(SynCookieAckOutcome::Validated)
        ));
        assert!(
            counters.touched,
            "valid cookie ACK must be counted without counting a screen drop"
        );
        assert_eq!(counters.screen_drops, 0);
        assert_eq!(counters.syn_cookie_ack_valid, 1);
        assert!(
            event_rx.try_recv().is_err(),
            "valid cookie ACK must not emit a screen-drop event"
        );

        assert_eq!(
            screen.check_packet_with_zone_id("lan", TEST_LAN_ZONE_ID, &syn_info, TEST_NOW_SECS),
            ScreenVerdict::SynCookieBypass,
            "poll-stage session-miss ACK handling must invoke SYN-cookie validation"
        );
        assert!(
            matches!(
                screen.check_packet_with_zone_id("lan", TEST_LAN_ZONE_ID, &syn_info, TEST_NOW_SECS),
                ScreenVerdict::SynCookieChallenge(_)
            ),
            "validated SYN-cookie bypass must be single-use"
        );
    }

    /// #2145 regression: a priority-tagged VLAN-0 SYN
    /// (`ingress_vlan_present = 1`, `ingress_vlan_id = 0`) must have its
    /// IP header parsed at offset 18 by the screen + SYN-cookie stages,
    /// not at the untagged offset 14. The screen carries an IPv4 header
    /// with IHL = 6 holding an LSRR source-route option, so the
    /// `ip-source-route` check fires *iff* the stage reads the IP header
    /// (and decodes the option) from the real header at offset 18.
    /// Pre-fix (`ingress_vlan_id > 0`) the stage used offset 14, read the
    /// 802.1Q TPID byte (0x81) as the IP header → `ip_ihl = 1`,
    /// source-route did NOT fire, and the SYN passed. An untagged
    /// control frame (with the same IHL-6 header at offset 14) keeps
    /// dropping, proving the assertion is not tautological.
    #[test]
    fn priority_tagged_vlan0_screen_stage_parses_l3_at_offset_18() {
        let forwarding = build_forwarding_state(&super::super::test_fixtures::nat_snapshot());
        let ident = BindingIdentity {
            slot: 0,
            queue_id: 0,
            worker_id: 0,
            interface: Arc::<str>::from("reth1.0"),
            ifindex: 24,
        };
        let binding_lookup = WorkerBindingLookup::default();
        let mirror_targets = MirrorTargetMap::default();
        let ha_state = BTreeMap::new();
        let dynamic_neighbors = Arc::new(ShardedNeighborMap::default());
        let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
        let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
        let recent_exceptions = Arc::new(Mutex::new(VecDeque::new()));
        let last_resolution = Arc::new(Mutex::new(None));
        let peer_worker_commands = Vec::new();
        let dnat_fds = DnatTableFds::default();
        let rg_epochs = std::array::from_fn(|_| AtomicU32::new(0));
        let (event_handle, _event_rx) = crate::event_stream::test_worker_handle(
            8,
            DataplaneEventRateLimitConfig {
                events_per_second: 0,
                burst: 0,
            },
        );
        let worker_ctx = WorkerContext {
            ident: &ident,
            binding_lookup: &binding_lookup,
            mirror_targets: &mirror_targets,
            forwarding: &forwarding,
            ha_state: &ha_state,
            dynamic_neighbors: &dynamic_neighbors,
            neighbor_resolver: None,
            shared_sessions: &shared_sessions,
            shared_nat_sessions: &shared_nat_sessions,
            shared_forward_wire_sessions: &shared_forward_wire_sessions,
            shared_owner_rg_indexes: &shared_owner_rg_indexes,
            slow_path: None,
            event_stream: Some(&event_handle),
            local_tunnel_deliveries: &local_tunnel_deliveries,
            recent_exceptions: &recent_exceptions,
            last_resolution: &last_resolution,
            peer_worker_commands: &peer_worker_commands,
            dnat_fds: &dnat_fds,
            rg_epochs: &rg_epochs,
            cold_path_sample_mask: 0xff,
        };

        // Run one SYN through stage_screen_check and return the verdict
        // (true = dropped) plus the screen_drops delta.
        let run_screen = |vlan: Vlan| -> bool {
            let mut screen = source_route_screen();
            let frame = tcp_v4_syn_frame_with_l2(vlan, 6);
            let meta = tcp_v4_syn_meta_with_l2(&frame, vlan);
            let flow =
                parse_session_flow_from_bytes(&frame, meta).expect("session flow from tagged SYN");
            let mut counters = BatchCounters::default();
            let outcome = stage_screen_check(
                Some(&flow),
                &frame,
                meta,
                None,
                TEST_NOW_SECS,
                &mut screen,
                &mut counters,
                &worker_ctx,
            );
            matches!(outcome, StageOutcome::RecycleAndContinue)
        };

        // Priority-tagged VID-0 frame: real IP header (IHL 6) sits at
        // offset 18. Post-fix the stage reads it and source-route fires.
        assert!(
            run_screen(Vlan::PriorityTagged),
            "priority-tagged VLAN-0 SYN with IHL=6 must be parsed at \
             offset 18 and dropped by ip-source-route (#2145)"
        );
        // Untagged control: same IHL-6 header at offset 14, still dropped.
        assert!(
            run_screen(Vlan::None),
            "untagged SYN with IHL=6 must still be parsed at offset 14 \
             and dropped by ip-source-route"
        );

        // The same offset bug lives in the SYN-cookie ACK stage. The
        // returning cookie ACK's TCP acknowledgement number is read
        // from the frame at l3_off + ihl*4 + 8; if l3_off is wrong, the
        // cookie ack is read from the wrong bytes and validation fails.
        // Drive a real challenge/validate cycle with priority-tagged
        // VID-0 frames (IHL 5, so the TCP ack sits at offset 18+20+8 =
        // 46). Post-fix the stage reads the correct cookie+1 and
        // returns Validated; pre-fix it read offset 14, parsed garbage,
        // and returned Invalid → RecycleAndContinue.
        let mut cookie_screen = syn_cookie_screen();
        let syn_frame = tcp_v4_syn_frame_with_l2(Vlan::PriorityTagged, 5);
        let syn_meta = tcp_v4_syn_meta_with_l2(&syn_frame, Vlan::PriorityTagged);
        let syn_flow = parse_session_flow_from_bytes(&syn_frame, syn_meta)
            .expect("session flow from tagged SYN");
        let syn_info = extract_screen_info(
            &syn_frame,
            syn_meta.addr_family,
            syn_meta.protocol,
            syn_meta.tcp_flags,
            syn_meta.pkt_len,
            syn_flow.src_ip,
            syn_flow.dst_ip,
            syn_flow.forward_key.src_port,
            syn_flow.forward_key.dst_port,
            syn_meta.l3_offset as usize,
        )
        .expect("valid SYN frame parses");
        // First SYN passes; second crosses the flood threshold and
        // mints the cookie challenge (mirrors the SYN-cookie test).
        assert_eq!(
            cookie_screen.check_packet_with_zone_id(
                "lan",
                TEST_LAN_ZONE_ID,
                &syn_info,
                TEST_NOW_SECS
            ),
            ScreenVerdict::Pass
        );
        let challenge = match cookie_screen.check_packet_with_zone_id(
            "lan",
            TEST_LAN_ZONE_ID,
            &syn_info,
            TEST_NOW_SECS,
        ) {
            ScreenVerdict::SynCookieChallenge(challenge) => challenge,
            other => panic!("expected SYN-cookie challenge, got {other:?}"),
        };

        // Returning ACK: priority-tagged VID-0, ack = cookie + 1, with
        // the TCP ack field written at the correct offset-18 layout.
        let ack_frame = {
            let mut f = tcp_v4_syn_frame_with_l2(Vlan::PriorityTagged, 5);
            // l3=18, ihl=20 → TCP at 38, flags byte at 38+13=51, ack
            // field at 38+8=46.
            f[51] = TCP_FLAG_ACK;
            f[46..50].copy_from_slice(&challenge.cookie_isn.wrapping_add(1).to_be_bytes());
            recompute_l4_checksum_ipv4(&mut f[18..], 20, PROTO_TCP, false).expect("tcp checksum");
            f
        };
        let ack_meta = tcp_v4_syn_meta_with_l2(&ack_frame, Vlan::PriorityTagged);
        // The shim contract reports the real protocol/flags; flip the
        // meta's TCP flag to ACK so the stage routes this as a returning
        // ACK (the meta tcp_flags field is set by the parser, not read
        // from the frame's l3 offset).
        let ack_meta = UserspaceDpMeta {
            tcp_flags: TCP_FLAG_ACK,
            ..ack_meta
        };
        let ack_flow = parse_session_flow_from_bytes(&ack_frame, ack_meta)
            .expect("session flow from tagged ACK");
        let mut counters = BatchCounters::default();
        assert!(
            matches!(
                stage_screen_syn_cookie_ack_on_session_miss(
                    Some(&ack_flow),
                    &ack_frame,
                    ack_meta,
                    None,
                    TEST_NOW_SECS,
                    &mut cookie_screen,
                    &mut counters,
                    &worker_ctx,
                ),
                StageOutcome::Continue(SynCookieAckOutcome::Validated)
            ),
            "priority-tagged VLAN-0 cookie ACK must be parsed at offset \
             18 by the SYN-cookie stage so its TCP ack matches cookie+1 \
             (#2145); pre-fix it read offset 14 and rejected the cookie"
        );
        assert_eq!(
            counters.syn_cookie_ack_valid, 1,
            "the tagged cookie ACK must validate exactly once"
        );
    }

    // ===================================================================
    // #2370 — learned dynamic neighbors must be keyed by the LOGICAL
    // (L3 / VLAN sub-interface) ifindex the forwarder looks them up by,
    // not the physical/parent ingress ifindex they arrived on.
    // ===================================================================

    /// Build a `WorkerContext` over the supplied forwarding state and a
    /// fresh empty dynamic-neighbor map, returning the map so the test
    /// can assert the key the stage inserted under.
    ///
    /// The boxed values are intentionally `Box::leak`'d to obtain the
    /// `&'static` borrows the `WorkerContext<'a>` shape requires, instead
    /// of threading a dozen owned locals through every call site. The
    /// leak is NOT one-shot: a single test binary runs many tests in one
    /// process, so each `neighbor_learn_ctx` call adds a small, bounded
    /// allocation that persists for the test-binary lifetime. This is
    /// test-only and the per-call footprint is tiny (a handful of empty
    /// maps + the context struct), so the accumulation is harmless.
    fn neighbor_learn_ctx(
        forwarding: &'static ForwardingState,
    ) -> (&'static WorkerContext<'static>, Arc<ShardedNeighborMap>) {
        let dynamic_neighbors = Arc::new(ShardedNeighborMap::default());
        let ident = Box::leak(Box::new(BindingIdentity {
            slot: 0,
            queue_id: 0,
            worker_id: 0,
            interface: Arc::<str>::from("ge-0-0-0"),
            ifindex: 11,
        }));
        let binding_lookup = Box::leak(Box::new(WorkerBindingLookup::default()));
        let mirror_targets = Box::leak(Box::new(MirrorTargetMap::default()));
        let ha_state = Box::leak(Box::new(BTreeMap::new()));
        let dynamic_neighbors_ref =
            Box::leak(Box::new(dynamic_neighbors.clone())) as &'static Arc<_>;
        let shared_sessions = Box::leak(Box::new(Arc::new(Mutex::new(FastMap::default()))));
        let shared_nat_sessions = Box::leak(Box::new(Arc::new(Mutex::new(FastMap::default()))));
        let shared_forward_wire_sessions =
            Box::leak(Box::new(Arc::new(Mutex::new(FastMap::default()))));
        let shared_owner_rg_indexes = Box::leak(Box::new(SharedSessionOwnerRgIndexes::default()));
        let local_tunnel_deliveries =
            Box::leak(Box::new(Arc::new(ArcSwap::from_pointee(BTreeMap::new()))));
        let recent_exceptions = Box::leak(Box::new(Arc::new(Mutex::new(VecDeque::new()))));
        let last_resolution = Box::leak(Box::new(Arc::new(Mutex::new(None))));
        let peer_worker_commands = Box::leak(Box::new(Vec::new()));
        let dnat_fds = Box::leak(Box::new(DnatTableFds::default()));
        let rg_epochs = Box::leak(Box::new(std::array::from_fn(|_| AtomicU32::new(0))));
        let ctx = Box::leak(Box::new(WorkerContext {
            ident,
            binding_lookup,
            mirror_targets,
            forwarding,
            ha_state,
            dynamic_neighbors: dynamic_neighbors_ref,
            neighbor_resolver: None,
            shared_sessions,
            shared_nat_sessions,
            shared_forward_wire_sessions,
            shared_owner_rg_indexes,
            slow_path: None,
            event_stream: None,
            local_tunnel_deliveries,
            recent_exceptions,
            last_resolution,
            peer_worker_commands,
            dnat_fds,
            rg_epochs,
            cold_path_sample_mask: 0xff,
        }));
        (ctx, dynamic_neighbors)
    }

    /// ARP reply frame (untagged) with a configurable sender IP. The
    /// stage classifies it as `Reply` and learns `(learn_ifindex,
    /// sender_ip) -> sender_mac`.
    fn arp_reply_frame(sender_ip: Ipv4Addr, sender_mac: [u8; 6]) -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // dst
        f.extend_from_slice(&sender_mac); // src
        f.extend_from_slice(&[0x08, 0x06]); // ethertype ARP
        // htype=1, ptype=0x0800, hlen=6, plen=4, op=2 (reply)
        f.extend_from_slice(&[0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x02]);
        f.extend_from_slice(&sender_mac); // sender mac
        f.extend_from_slice(&sender_ip.octets()); // sender ip
        f.extend_from_slice(&[0x00; 6]); // target mac
        f.extend_from_slice(&[10, 0, 0, 1]); // target ip
        f
    }

    /// Meta for a frame arriving on physical ifindex `parent` with the
    /// given `vlan` (0 = untagged). Only the fields the link-layer stage
    /// reads (`ingress_ifindex`, `ingress_vlan_id`) matter here.
    fn link_layer_meta(parent: u32, vlan: u16) -> UserspaceDpMeta {
        UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            ingress_ifindex: parent,
            ingress_vlan_id: vlan,
            ingress_vlan_present: (vlan != 0) as u8,
            l3_offset: 14,
            ..UserspaceDpMeta::default()
        }
    }

    /// #2370 fail-on-revert (ARP, VLAN sub-interface). The `nat_snapshot`
    /// fixture defines `reth0.80` as logical ifindex 12 on parent
    /// ifindex 11 / VLAN 80. An ARP reply arriving on (parent=11,
    /// vlan=80) MUST be learned under the LOGICAL ifindex 12 — the key
    /// the forwarder's connected-route lookup uses — NOT the physical
    /// ifindex 11. If the insert reverts to `meta.ingress_ifindex` the
    /// entry lands under (11, ip), `lookup_neighbor_entry` (which probes
    /// the logical ifindex 12) misses, and these asserts fail.
    #[test]
    fn arp_learns_vlan_neighbor_under_logical_ifindex_2370() {
        let forwarding: &'static ForwardingState = Box::leak(Box::new(build_forwarding_state(
            &super::super::test_fixtures::nat_snapshot(),
        )));
        let (ctx, neighbors) = neighbor_learn_ctx(forwarding);

        let sender_ip = Ipv4Addr::new(172, 16, 80, 9);
        let sender_mac = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x09];
        let frame = arp_reply_frame(sender_ip, sender_mac);
        let meta = link_layer_meta(11, 80);

        // Sanity: the fixture really maps (parent=11, vlan=80) -> 12.
        assert_eq!(
            resolve_ingress_logical_ifindex(forwarding, 11, 80),
            Some(12),
            "fixture must map parent ifindex 11 / VLAN 80 to logical 12"
        );

        let outcome = stage_link_layer_classify(&frame, meta, ctx);
        assert!(matches!(outcome, StageOutcome::RecycleAndContinue));

        // The forwarder looks up by the logical (route egress) ifindex.
        let found = lookup_neighbor_entry(
            forwarding,
            Some(&neighbors),
            12, // logical ifindex (reth0.80)
            IpAddr::V4(sender_ip),
        );
        assert_eq!(
            found.map(|e| e.mac),
            Some(sender_mac),
            "ARP learned on a VLAN sub-interface must be found by the \
             forwarder's LOGICAL-ifindex (12) lookup (#2370); a physical \
             ifindex (11) key would miss here"
        );
        // And it must NOT have landed under the physical/parent ifindex.
        assert!(
            neighbors.get(&(11, IpAddr::V4(sender_ip))).is_none(),
            "the learned entry must not be keyed by the physical/parent \
             ifindex 11 (the bug); only the logical ifindex 12"
        );
    }

    /// #2370 — a non-VLAN (physical == logical) ARP neighbor still
    /// learns under the interface ifindex unchanged. `reth1.0` in the
    /// fixture has ifindex 24 and no parent (untagged), so
    /// `resolve_ingress_logical_ifindex(24, 0)` resolves to 24 and the
    /// learn key equals the lookup key.
    #[test]
    fn arp_learns_untagged_neighbor_under_same_ifindex_2370() {
        let forwarding: &'static ForwardingState = Box::leak(Box::new(build_forwarding_state(
            &super::super::test_fixtures::nat_snapshot(),
        )));
        let (ctx, neighbors) = neighbor_learn_ctx(forwarding);

        let sender_ip = Ipv4Addr::new(10, 0, 61, 50);
        let sender_mac = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x18];
        let frame = arp_reply_frame(sender_ip, sender_mac);
        let meta = link_layer_meta(24, 0);

        let outcome = stage_link_layer_classify(&frame, meta, ctx);
        assert!(matches!(outcome, StageOutcome::RecycleAndContinue));

        let found = lookup_neighbor_entry(forwarding, Some(&neighbors), 24, IpAddr::V4(sender_ip));
        assert_eq!(
            found.map(|e| e.mac),
            Some(sender_mac),
            "untagged ARP must learn under the (logical==physical) ifindex 24"
        );
    }

    /// #2370 multi-VLAN no-collision. Two VLAN sub-interfaces (VID 80 and
    /// VID 50) share ONE physical parent (ifindex 11) but own distinct
    /// logical ifindexes (12 and 13) in different subnets. The SAME
    /// neighbor IP learned on each VLAN must land under DISTINCT keys
    /// (12, ip) and (13, ip) — proving the logical-ifindex key keeps
    /// them apart. Keying by the shared physical ifindex would collapse
    /// both into (11, ip) and the second learn would overwrite the
    /// first, corrupting one VLAN's neighbor entry.
    #[test]
    fn arp_two_vlans_same_ip_distinct_logical_keys_2370() {
        let forwarding: &'static ForwardingState =
            Box::leak(Box::new(build_forwarding_state(&two_vlan_snapshot())));
        let (ctx, neighbors) = neighbor_learn_ctx(forwarding);

        assert_eq!(
            resolve_ingress_logical_ifindex(forwarding, 11, 80),
            Some(12),
            "parent 11 / VLAN 80 -> logical 12"
        );
        assert_eq!(
            resolve_ingress_logical_ifindex(forwarding, 11, 50),
            Some(13),
            "parent 11 / VLAN 50 -> logical 13"
        );

        let ip = Ipv4Addr::new(172, 16, 0, 99);
        let mac_v80 = [0x02, 0x00, 0x00, 0x00, 0x00, 0x80];
        let mac_v50 = [0x02, 0x00, 0x00, 0x00, 0x00, 0x50];

        // Same physical port (11), same neighbor IP, different VLANs.
        let _ =
            stage_link_layer_classify(&arp_reply_frame(ip, mac_v80), link_layer_meta(11, 80), ctx);
        let _ =
            stage_link_layer_classify(&arp_reply_frame(ip, mac_v50), link_layer_meta(11, 50), ctx);

        assert_eq!(
            neighbors.get(&(12, IpAddr::V4(ip))).map(|e| e.mac),
            Some(mac_v80),
            "VLAN-80 neighbor must be keyed by logical ifindex 12"
        );
        assert_eq!(
            neighbors.get(&(13, IpAddr::V4(ip))).map(|e| e.mac),
            Some(mac_v50),
            "VLAN-50 neighbor must be keyed by logical ifindex 13 — a \
             physical-ifindex key would collide both into (11, ip)"
        );
        assert!(
            neighbors.get(&(11, IpAddr::V4(ip))).is_none(),
            "neither learn may land under the shared physical ifindex 11"
        );
    }

    /// #2370 NDP variant. A valid Neighbor Advertisement (hop-limit 255,
    /// code 0, valid ICMPv6 checksum, TLLA option) arriving on a VLAN
    /// sub-interface must learn its target under the LOGICAL ifindex too.
    /// Shares the exact `learn_ifindex` computation with the ARP path.
    #[test]
    fn ndp_learns_vlan_neighbor_under_logical_ifindex_2370() {
        let forwarding: &'static ForwardingState = Box::leak(Box::new(build_forwarding_state(
            &super::super::test_fixtures::nat_snapshot(),
        )));
        let (ctx, neighbors) = neighbor_learn_ctx(forwarding);

        let (frame, target_ip, target_mac) = ndp_na_frame();
        // Frame is built untagged; the meta declares VLAN 80 on parent
        // 11 (the shim conveys the VLAN out-of-band in meta, not in the
        // already-stripped L2 header for the learn-key decision).
        let meta = link_layer_meta(11, 80);

        let outcome = stage_link_layer_classify(&frame, meta, ctx);
        assert!(matches!(outcome, StageOutcome::Continue(())));

        let found = lookup_neighbor_entry(forwarding, Some(&neighbors), 12, target_ip);
        assert_eq!(
            found.map(|e| e.mac),
            Some(target_mac),
            "NDP NA learned on a VLAN sub-interface must be found by the \
             forwarder's LOGICAL-ifindex (12) lookup (#2370)"
        );
        assert!(
            neighbors.get(&(11, target_ip)).is_none(),
            "the NDP entry must not be keyed by the physical ifindex 11"
        );
    }

    /// A `nat_snapshot`-shaped config with TWO VLAN sub-interfaces on the
    /// same physical parent (ifindex 11): `reth0.80` (logical 12, VID 80)
    /// and `reth0.50` (logical 13, VID 50), in different subnets.
    fn two_vlan_snapshot() -> crate::ConfigSnapshot {
        let mut snap = super::super::test_fixtures::nat_snapshot();
        // Existing reth0.80 already has ifindex 12, parent 11, VID 80.
        snap.interfaces.push(crate::InterfaceSnapshot {
            name: "reth0.50".to_string(),
            zone: "wan".to_string(),
            linux_name: "ge-0-0-0.50".to_string(),
            ifindex: 13,
            parent_ifindex: 11,
            redundancy_group: 1,
            vlan_id: 50,
            hardware_addr: "02:bf:72:00:50:08".to_string(),
            addresses: vec![crate::InterfaceAddressSnapshot {
                family: "inet".to_string(),
                address: "172.16.50.8/24".to_string(),
                scope: 0,
            }],
            ..Default::default()
        });
        snap
    }

    /// Build a minimal but VALID untagged IPv6 Neighbor Advertisement
    /// (hop-limit 255, code 0, TLLA option, correct ICMPv6 checksum) and
    /// return `(frame, target_ip, target_mac)`. Mirrors the parser-test
    /// builder; the checksum is stamped so the strict #2368 NA parser
    /// accepts it.
    fn ndp_na_frame() -> (Vec<u8>, IpAddr, [u8; 6]) {
        // Default advertised target: fe80::abcd:ef01:0:42 (a legitimate,
        // non-own unicast neighbor). #2851 tests pass an own-IP target.
        ndp_na_frame_with_target([
            0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0xab, 0xcd, 0xef, 0x01, 0x00, 0x00, 0x00, 0x42,
        ])
    }

    /// Same builder, but with a caller-supplied advertised target address.
    /// Used by the #2851 own-IP anti-poisoning tests to advertise one of
    /// the router's OWN configured IPv6 addresses.
    fn ndp_na_frame_with_target(target_bytes: [u8; 16]) -> (Vec<u8>, IpAddr, [u8; 6]) {
        const NEXT_HEADER_ICMPV6: u8 = 58;
        const ICMPV6_TYPE_NA: u8 = 136;
        const NDP_OPT_TARGET_LL: u8 = 2;
        let target_mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let mut f = Vec::new();
        f.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // dst
        f.extend_from_slice(&target_mac); // src
        f.extend_from_slice(&[0x86, 0xdd]); // ethertype IPv6
        let l3_start = 14usize;
        let payload_len = 32u16; // NA(24) + TLLA(8)
        f.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
        f.extend_from_slice(&payload_len.to_be_bytes());
        f.push(NEXT_HEADER_ICMPV6);
        f.push(255); // hop limit (required)
        // src ip fe80::abcd:ef01:0:1
        f.extend_from_slice(&[
            0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0xab, 0xcd, 0xef, 0x01, 0x00, 0x00, 0x00, 0x01,
        ]);
        // dst ip (all-ff placeholder; not validated for unicast target)
        f.extend_from_slice(&[0xff; 16]);
        let l4_start = l3_start + 40;
        f.push(ICMPV6_TYPE_NA);
        f.push(0); // code
        f.extend_from_slice(&[0x00, 0x00]); // checksum placeholder
        f.extend_from_slice(&[0; 4]); // flags
        // target (caller-supplied)
        f.extend_from_slice(&target_bytes);
        // TLLA option
        f.push(NDP_OPT_TARGET_LL);
        f.push(1);
        f.extend_from_slice(&target_mac);
        let packet_end = l3_start + 40 + payload_len as usize;
        // Shared stamper (single source of truth, also used by the #2368
        // parser tests) — the strict NA parser requires a valid checksum.
        super::super::test_fixtures::stamp_icmpv6_checksum(
            &mut f, l3_start, l4_start, packet_end,
        );
        (f, IpAddr::V6(Ipv6Addr::from(target_bytes)), target_mac)
    }

    /// #2790 fail-on-revert (ARP). A valid unicast on-subnet sender IS
    /// learned; an ARP reply whose sender protocol address is unspecified
    /// (`0.0.0.0`), the limited broadcast (`255.255.255.255`), or
    /// multicast (`224.0.0.1`) is NOT learned — the frame is still
    /// recycled (ARP never transits) but no neighbor write occurs.
    ///
    /// Reverting the `neighbor_ip_is_learnable(arp.sender_ip)` gate in
    /// `stage_link_layer_classify` caches the bad sender IPs, so the
    /// "must NOT be present" asserts fail RED. The valid-unicast assert
    /// keeps the gate from over-rejecting a legitimate neighbor.
    #[test]
    fn arp_invalid_sender_ip_not_learned_2790() {
        let forwarding: &'static ForwardingState = Box::leak(Box::new(build_forwarding_state(
            &super::super::test_fixtures::nat_snapshot(),
        )));
        let (ctx, neighbors) = neighbor_learn_ctx(forwarding);

        // reth1.0 is logical==physical ifindex 24 (untagged) in 10.0.61.0/24.
        let meta = link_layer_meta(24, 0);

        // 1) Valid unicast on-subnet sender — MUST be learned.
        let good_ip = Ipv4Addr::new(10, 0, 61, 50);
        let good_mac = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x18];
        let outcome =
            stage_link_layer_classify(&arp_reply_frame(good_ip, good_mac), meta, ctx);
        assert!(matches!(outcome, StageOutcome::RecycleAndContinue));
        assert_eq!(
            neighbors.get(&(24, IpAddr::V4(good_ip))).map(|e| e.mac),
            Some(good_mac),
            "a valid unicast on-subnet ARP sender must be learned (#2790 \
             gate must not over-reject)"
        );

        // 2) Illegitimate senders — each recycled but NEVER cached.
        for bad_ip in [
            Ipv4Addr::new(0, 0, 0, 0),             // unspecified
            Ipv4Addr::new(255, 255, 255, 255),     // limited broadcast
            Ipv4Addr::new(224, 0, 0, 1),           // multicast
            Ipv4Addr::new(127, 0, 0, 1),           // loopback
        ] {
            let bad_mac = [0x02, 0x00, 0x00, 0x00, 0xba, 0xad];
            let outcome =
                stage_link_layer_classify(&arp_reply_frame(bad_ip, bad_mac), meta, ctx);
            // ARP is always recycled (it never transits the firewall).
            assert!(
                matches!(outcome, StageOutcome::RecycleAndContinue),
                "ARP reply with sender {bad_ip} must still be recycled"
            );
            assert!(
                neighbors.get(&(24, IpAddr::V4(bad_ip))).is_none(),
                "ARP reply claiming illegitimate sender {bad_ip} must NOT be \
                 cached (#2790 cache-pollution gate)"
            );
        }
    }

    /// #2790 direct predicate coverage — `neighbor_ip_is_learnable`
    /// accepts only legitimate unicast addresses (the contract the ARP /
    /// NDP learn sites rely on).
    #[test]
    fn neighbor_ip_is_learnable_rejects_non_unicast_2790() {
        // Learnable unicast.
        assert!(neighbor_ip_is_learnable(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 50))));
        assert!(neighbor_ip_is_learnable(IpAddr::V6(Ipv6Addr::from([
            0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0xab, 0xcd, 0xef, 0x01, 0x00, 0x00, 0x00, 0x42,
        ]))));
        // Rejected IPv4 classes.
        assert!(!neighbor_ip_is_learnable(IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
        assert!(!neighbor_ip_is_learnable(IpAddr::V4(Ipv4Addr::BROADCAST)));
        assert!(!neighbor_ip_is_learnable(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1))));
        assert!(!neighbor_ip_is_learnable(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        // Rejected IPv6 classes (no broadcast in v6).
        assert!(!neighbor_ip_is_learnable(IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
        assert!(!neighbor_ip_is_learnable(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(!neighbor_ip_is_learnable(IpAddr::V6(Ipv6Addr::new(
            0xff02, 0, 0, 0, 0, 0, 0, 1
        ))));
    }

    /// #2851 fail-on-revert (ARP own-IP anti-poisoning). An ARP reply
    /// claiming one of the router's OWN configured interface IPs
    /// (`reth1.0` = 10.0.61.1 in the `nat_snapshot` fixture) must NOT be
    /// learned — neither into `dynamic_neighbors` nor (by extension) the
    /// kernel ARP table. A legitimate NON-own neighbor on the same
    /// interface must still learn unchanged (the own-IP gate must not
    /// over-reject). The frame is still recycled (ARP never transits).
    ///
    /// Reverting the `!worker_ctx.forwarding.owns_configured_ip(...)`
    /// guard in `stage_link_layer_classify` caches `(24, 10.0.61.1) ->
    /// attacker_mac`, so the "must NOT be present" assert fails RED; the
    /// non-own learn assert keeps the gate honest.
    #[test]
    fn arp_own_ip_reply_not_learned_2851() {
        let forwarding: &'static ForwardingState = Box::leak(Box::new(build_forwarding_state(
            &super::super::test_fixtures::nat_snapshot(),
        )));
        // The router's own reth1.0 (lan zone, ifindex 24) IPv4 must be in
        // the local-delivery set — the authoritative own-IP set this gate
        // reuses. (The wan reth0.80 IP is excluded as an interface-mode
        // SNAT translated address, which is why we assert on the lan IP.)
        let own_ip = Ipv4Addr::new(10, 0, 61, 1);
        assert!(
            forwarding.owns_configured_ip(IpAddr::V4(own_ip)),
            "test precondition: reth1.0 10.0.61.1 must be a configured \
             own IP in local_v4"
        );
        let (ctx, neighbors) = neighbor_learn_ctx(forwarding);
        let meta = link_layer_meta(24, 0);

        // 1) Spoofed reply claiming the router's OWN IP — must NOT learn.
        let attacker_mac = [0x02, 0x00, 0x00, 0x00, 0xba, 0xad];
        let outcome =
            stage_link_layer_classify(&arp_reply_frame(own_ip, attacker_mac), meta, ctx);
        assert!(
            matches!(outcome, StageOutcome::RecycleAndContinue),
            "an ARP reply (even an own-IP one) is still recycled"
        );
        assert!(
            neighbors.get(&(24, IpAddr::V4(own_ip))).is_none(),
            "an ARP reply claiming the router's OWN configured IP must NOT \
             be learned (#2851 anti-poisoning gate)"
        );

        // 2) A legitimate NON-own neighbor on the same interface still
        //    learns — the own-IP gate must not over-reject.
        let good_ip = Ipv4Addr::new(10, 0, 61, 50);
        let good_mac = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x18];
        let _ = stage_link_layer_classify(&arp_reply_frame(good_ip, good_mac), meta, ctx);
        assert_eq!(
            neighbors.get(&(24, IpAddr::V4(good_ip))).map(|e| e.mac),
            Some(good_mac),
            "a legitimate non-own ARP neighbor must still be learned"
        );
    }

    /// #2851 fail-on-revert (NDP NA own-IP anti-poisoning). A Neighbor
    /// Advertisement advertising one of the router's OWN configured IPv6
    /// addresses (`reth1.0` = 2001:559:8585:ef00::1) must NOT be learned.
    /// A legitimate non-own NA still learns. Mirrors the ARP test above.
    #[test]
    fn ndp_own_ip_advert_not_learned_2851() {
        let forwarding: &'static ForwardingState = Box::leak(Box::new(build_forwarding_state(
            &super::super::test_fixtures::nat_snapshot(),
        )));
        let own_v6_bytes = [
            0x20, 0x01, 0x05, 0x59, 0x85, 0x85, 0xef, 0x00, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ];
        let own_v6 = IpAddr::V6(Ipv6Addr::from(own_v6_bytes));
        assert!(
            forwarding.owns_configured_ip(own_v6),
            "test precondition: reth1.0 2001:559:8585:ef00::1 must be a \
             configured own IP in local_v6"
        );
        let (ctx, neighbors) = neighbor_learn_ctx(forwarding);
        // reth1.0 is untagged logical==physical ifindex 24; the NA learn
        // resolves to ifindex 24 too. (The own-IP gate is global, so the
        // exact learn ifindex is immaterial to the rejection.)
        let meta = link_layer_meta(24, 0);

        // 1) NA advertising the router's OWN IPv6 — must NOT learn.
        let (frame, target_ip, _mac) = ndp_na_frame_with_target(own_v6_bytes);
        assert_eq!(target_ip, own_v6, "frame target must be the own IPv6");
        let outcome = stage_link_layer_classify(&frame, meta, ctx);
        assert!(matches!(outcome, StageOutcome::Continue(())));
        assert!(
            neighbors.get(&(24, own_v6)).is_none(),
            "an NDP NA advertising the router's OWN configured IPv6 must \
             NOT be learned (#2851 anti-poisoning gate)"
        );

        // 2) A legitimate non-own NA still learns (own-IP gate must not
        //    over-reject). The default `ndp_na_frame()` advertises
        //    fe80::abcd:ef01:0:42 (non-own).
        let (good_frame, good_target, good_mac) = ndp_na_frame();
        assert!(
            !forwarding.owns_configured_ip(good_target),
            "the default NA target must be a non-own neighbor"
        );
        let _ = stage_link_layer_classify(&good_frame, meta, ctx);
        assert_eq!(
            neighbors.get(&(24, good_target)).map(|e| e.mac),
            Some(good_mac),
            "a legitimate non-own NDP NA neighbor must still be learned"
        );
    }

    // ===================================================================
    // #3021 / #3022 — the ingress ZONE lookup (zone-pair policy for
    // forwarding, and screen/SYN-cookie zone resolution) must key on the
    // LOGICAL (VLAN sub-interface) ifindex resolved through
    // `resolve_ingress_logical_ifindex`, NOT the raw physical
    // `meta.ingress_ifindex`. `ifindex_to_zone_id` is keyed by the logical
    // unit ifindex; the parent physical ifindex only ever maps to its
    // FIRST sub-interface's zone (forwarding_build/interfaces.rs:77), so a
    // parent carrying two VLAN units in DISTINCT zones would evaluate the
    // wrong zone — wrong policy (#3021) and the wrong/absent screen
    // profile (#3022) — for every unit but the first.
    // ===================================================================

    /// A snapshot with TWO VLAN sub-interfaces on the same physical parent
    /// (ifindex 11) in DISTINCT zones: `reth0.80` (logical 12, VID 80,
    /// zone `wan`, the parent's first sub-interface) and `reth0.50`
    /// (logical 13, VID 50, zone `lan`). The parent ifindex 11 inherits
    /// only the first sub-interface's zone (`wan`), so a physical-keyed
    /// lookup for the VID-50 unit returns `wan` instead of its own `lan`.
    fn two_vlan_distinct_zone_snapshot() -> crate::ConfigSnapshot {
        let mut snap = super::super::test_fixtures::nat_snapshot();
        // reth0.80 (logical 12, parent 11, VID 80) is already zone "wan".
        snap.interfaces.push(crate::InterfaceSnapshot {
            name: "reth0.50".to_string(),
            zone: "lan".to_string(),
            linux_name: "ge-0-0-0.50".to_string(),
            ifindex: 13,
            parent_ifindex: 11,
            redundancy_group: 1,
            vlan_id: 50,
            hardware_addr: "02:bf:72:00:50:08".to_string(),
            addresses: vec![crate::InterfaceAddressSnapshot {
                family: "inet".to_string(),
                address: "172.16.50.8/24".to_string(),
                scope: 0,
            }],
            ..Default::default()
        });
        snap
    }

    /// #3021 fail-on-revert. `zone_pair_ids_for_flow_with_override` derives
    /// the FROM-zone from the ingress ifindex it is handed. The forwarder
    /// (poll_descriptor/mod.rs) now resolves the logical ifindex first; this
    /// test proves the VID-50 unit's `from_zone` is its OWN `lan`, and that
    /// the pre-fix physical-keyed call would return the parent's `wan`. If
    /// the fix reverts to `meta.ingress_ifindex as i32`, the "correct"
    /// branch below collapses onto the "pre-fix" value and the distinct-zone
    /// assert fails RED.
    #[test]
    fn forwarding_zone_pair_uses_logical_ingress_ifindex_3021() {
        use crate::test_zone_ids::{TEST_LAN_ZONE_ID, TEST_WAN_ZONE_ID};
        let forwarding = build_forwarding_state(&two_vlan_distinct_zone_snapshot());

        // Fixture sanity: parent 11 / VID 50 -> logical 13 (zone lan);
        // parent 11 / VID 80 -> logical 12 (zone wan).
        assert_eq!(
            resolve_ingress_logical_ifindex(&forwarding, 11, 50),
            Some(13),
            "parent 11 / VLAN 50 must resolve to logical ifindex 13"
        );
        assert_eq!(
            forwarding.ifindex_to_zone_id.get(&13).copied(),
            Some(TEST_LAN_ZONE_ID),
            "logical ifindex 13 (reth0.50) is zone lan"
        );

        // egress is the WAN unit (logical 12) — to_zone is irrelevant here;
        // we only assert the from_zone (ingress) resolution.
        let egress_ifindex = 12;

        // Correct (#3021): classify the VID-50 ingress on the LOGICAL
        // ifindex 13 -> from_zone == lan.
        let logical = resolve_ingress_logical_ifindex(&forwarding, 11, 50).unwrap();
        let (from_correct, _) =
            zone_pair_ids_for_flow_with_override(&forwarding, logical, None, egress_ifindex);
        assert_eq!(
            from_correct, TEST_LAN_ZONE_ID,
            "the VID-50 unit must evaluate its OWN ingress zone (lan)"
        );

        // Pre-fix: classify on the raw PHYSICAL parent ifindex 11 ->
        // from_zone == wan (the parent's first-sub-interface zone). This is
        // the #3021 bug: the VID-50 unit would be policed under wan's
        // zone-pair, not lan's.
        let (from_physical, _) =
            zone_pair_ids_for_flow_with_override(&forwarding, 11, None, egress_ifindex);
        assert_eq!(
            from_physical, TEST_WAN_ZONE_ID,
            "the raw physical parent ifindex 11 wrongly resolves to wan \
             (the #3021 bug the logical-ifindex resolution fixes)"
        );
        assert_ne!(
            from_correct, from_physical,
            "logical-keyed (lan) and physical-keyed (wan) FROM-zones must \
             diverge, proving the fix changes the evaluated zone-pair"
        );
    }

    /// #3022 fail-on-revert (literal — drives `stage_screen_check`).
    /// `source_route_screen()` arms the `ip-source-route` profile ONLY on
    /// the `lan` zone. A SYN arriving on the VID-50 unit (logical 13, zone
    /// `lan`, parent physical 11) with an IHL-6 IP header must be DROPPED:
    /// the stage resolves the logical ifindex 13 -> zone lan -> the armed
    /// profile fires. If #3022 reverts to `meta.ingress_ifindex` (physical
    /// 11), the lookup returns the parent's first-sub-interface zone `wan`,
    /// which has NO profile, the stage returns `Pass`, and the drop assert
    /// fails RED. The untagged control (logical == physical) still drops,
    /// keeping the assertion non-tautological / preserving non-VLAN behavior.
    #[test]
    fn screen_zone_lookup_uses_logical_ingress_ifindex_3022() {
        let forwarding = build_forwarding_state(&two_vlan_distinct_zone_snapshot());
        let ident = BindingIdentity {
            slot: 0,
            queue_id: 0,
            worker_id: 0,
            interface: Arc::<str>::from("ge-0-0-0"),
            ifindex: 11,
        };
        let binding_lookup = WorkerBindingLookup::default();
        let mirror_targets = MirrorTargetMap::default();
        let ha_state = BTreeMap::new();
        let dynamic_neighbors = Arc::new(ShardedNeighborMap::default());
        let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
        let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
        let recent_exceptions = Arc::new(Mutex::new(VecDeque::new()));
        let last_resolution = Arc::new(Mutex::new(None));
        let peer_worker_commands = Vec::new();
        let dnat_fds = DnatTableFds::default();
        let rg_epochs = std::array::from_fn(|_| AtomicU32::new(0));
        let (event_handle, _event_rx) = crate::event_stream::test_worker_handle(
            8,
            DataplaneEventRateLimitConfig {
                events_per_second: 0,
                burst: 0,
            },
        );
        let worker_ctx = WorkerContext {
            ident: &ident,
            binding_lookup: &binding_lookup,
            mirror_targets: &mirror_targets,
            forwarding: &forwarding,
            ha_state: &ha_state,
            dynamic_neighbors: &dynamic_neighbors,
            neighbor_resolver: None,
            shared_sessions: &shared_sessions,
            shared_nat_sessions: &shared_nat_sessions,
            shared_forward_wire_sessions: &shared_forward_wire_sessions,
            shared_owner_rg_indexes: &shared_owner_rg_indexes,
            slow_path: None,
            event_stream: Some(&event_handle),
            local_tunnel_deliveries: &local_tunnel_deliveries,
            recent_exceptions: &recent_exceptions,
            last_resolution: &last_resolution,
            peer_worker_commands: &peer_worker_commands,
            dnat_fds: &dnat_fds,
            rg_epochs: &rg_epochs,
            cold_path_sample_mask: 0xff,
        };

        // Source-route SYN arriving on the VID-50 unit. The shim strips the
        // VLAN tag and conveys the VID out of band in meta (present=0, l3 at
        // 14), exactly as the ARP/NDP learn tests model it.
        let frame = tcp_v4_syn_frame_with_l2(Vlan::None, 6);
        let mut meta = tcp_v4_syn_meta_with_l2(&frame, Vlan::None);
        meta.ingress_ifindex = 11; // physical parent
        meta.ingress_vlan_id = 50; // -> logical 13 (zone lan)
        let flow = parse_session_flow_from_bytes(&frame, meta)
            .expect("session flow from source-route SYN");

        let mut screen = source_route_screen();
        let mut counters = BatchCounters::default();
        let outcome = stage_screen_check(
            Some(&flow),
            &frame,
            meta,
            None,
            TEST_NOW_SECS,
            &mut screen,
            &mut counters,
            &worker_ctx,
        );
        assert!(
            matches!(outcome, StageOutcome::RecycleAndContinue),
            "the VID-50 unit (logical 13, zone lan) must resolve its OWN \
             lan screen profile and DROP the source-route SYN (#3022); a \
             physical-keyed lookup resolves zone wan (no profile) and would \
             wrongly Pass"
        );
        assert_eq!(
            counters.screen_drops, 1,
            "exactly one screen drop must be recorded for the VID-50 unit"
        );

        // Counterfactual / non-VLAN preservation: the SAME source-route SYN
        // on the UNTAGGED reth1.0 (logical == physical == 24, zone lan) is
        // also dropped — the resolution is identity there, so the fix does
        // not change non-VLAN behavior, and the drop above is not a fluke of
        // a globally-armed profile.
        let mut frame_untagged = tcp_v4_syn_frame_with_l2(Vlan::None, 6);
        let _ = &mut frame_untagged;
        let mut meta_untagged = tcp_v4_syn_meta_with_l2(&frame_untagged, Vlan::None);
        meta_untagged.ingress_ifindex = 24;
        meta_untagged.ingress_vlan_id = 0;
        let flow_untagged = parse_session_flow_from_bytes(&frame_untagged, meta_untagged)
            .expect("session flow from untagged source-route SYN");
        let mut screen2 = source_route_screen();
        let mut counters2 = BatchCounters::default();
        let outcome_untagged = stage_screen_check(
            Some(&flow_untagged),
            &frame_untagged,
            meta_untagged,
            None,
            TEST_NOW_SECS,
            &mut screen2,
            &mut counters2,
            &worker_ctx,
        );
        assert!(
            matches!(outcome_untagged, StageOutcome::RecycleAndContinue),
            "the untagged reth1.0 unit (logical == physical 24, zone lan) \
             still drops the source-route SYN — non-VLAN behavior unchanged"
        );
    }

    /// Build an untagged IPv4 fragment frame (#3064 tests). `frag_off` is
    /// the raw 16-bit fragment-offset field (top 3 bits flags: 0x2000=MF;
    /// low 13 bits = offset in 8-byte units). `payload_len` bytes of zeroed
    /// L4/data follow the fixed 20-byte IPv4 header. IHL is 5 (no options).
    fn ipv4_fragment_frame(frag_off: u16, protocol: u8, payload_len: usize) -> Vec<u8> {
        let mut frame = Vec::new();
        write_eth_header(
            &mut frame,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
            0,
            0x0800,
        );
        let l3 = frame.len();
        frame.push(0x45); // IPv4, IHL 5
        frame.push(0x00); // DSCP/ECN
        let total_len = (20 + payload_len) as u16;
        frame.extend_from_slice(&total_len.to_be_bytes());
        frame.extend_from_slice(&[0x00, 0x01]); // identification
        frame.extend_from_slice(&frag_off.to_be_bytes()); // flags + frag offset
        frame.push(64); // TTL
        frame.push(protocol);
        frame.extend_from_slice(&[0x00, 0x00]); // header checksum placeholder
        frame.extend_from_slice(&Ipv4Addr::new(192, 0, 2, 10).octets());
        frame.extend_from_slice(&Ipv4Addr::new(198, 51, 100, 20).octets());
        let ip_csum = checksum16(&frame[l3..l3 + 20]);
        frame[l3 + 10..l3 + 12].copy_from_slice(&ip_csum.to_be_bytes());
        frame.resize(frame.len() + payload_len, 0x00);
        frame
    }

    /// Metadata for the untagged IPv4 fragment frame above: L3 at offset 14,
    /// ingress on ifindex 24 (zone `lan` in `nat_snapshot`). `tcp_flags` is
    /// 0 — a non-first fragment carries no L4 header.
    fn ipv4_fragment_meta(frame: &[u8], protocol: u8) -> UserspaceDpMeta {
        UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            ingress_ifindex: 24,
            ingress_vlan_id: 0,
            ingress_vlan_present: 0,
            l3_offset: 14,
            l4_offset: 34,
            payload_offset: 34,
            pkt_len: (frame.len() - 14) as u16,
            addr_family: libc::AF_INET as u8,
            protocol,
            tcp_flags: 0,
            ..UserspaceDpMeta::default()
        }
    }

    /// Screen profile (zone `lan`) arming the L3 fragment screens
    /// (ping-of-death, teardrop, icmp-fragment) PLUS three flow/L4-only
    /// screens (land, syn-fin, no-flag). The flow-only screens are armed
    /// deliberately: on the flowless non-first-fragment path they MUST NOT
    /// run. In particular `land` would drop the placeholder unspecified
    /// (src == dst) tuple if the flowless path wrongly invoked the full
    /// `check_packet_with_zone_id`, so a PASS on a benign fragment proves
    /// the #2344 flowless fast path is preserved (no transport
    /// classification, no land/flag screens).
    fn fragment_screen() -> ScreenState {
        let mut profiles = FxHashMap::default();
        profiles.insert(
            "lan".to_string(),
            ScreenProfile {
                ping_death: true,
                teardrop: true,
                icmp_fragment: true,
                land: true,
                syn_fin: true,
                no_flag: true,
                ..ScreenProfile::default()
            },
        );
        let mut screen = ScreenState::new();
        screen.update_profiles(profiles);
        screen
    }

    /// Drive ONE packet through the live `stage_screen_check` against a
    /// `nat_snapshot` forwarding state (ifindex 24 -> zone `lan`). Returns
    /// `(dropped, screen_drops)`. The whole worker context is built and torn
    /// down inside this helper so the #3064 cases below can be independent
    /// `#[test]` functions (each observable under fail-on-revert).
    fn run_stage_screen(
        screen: &mut ScreenState,
        frame: &[u8],
        meta: UserspaceDpMeta,
        flow: Option<&SessionFlow>,
    ) -> (bool, u64) {
        let forwarding = build_forwarding_state(&super::super::test_fixtures::nat_snapshot());
        let ident = BindingIdentity {
            slot: 0,
            queue_id: 0,
            worker_id: 0,
            interface: Arc::<str>::from("reth1.0"),
            ifindex: 24,
        };
        let binding_lookup = WorkerBindingLookup::default();
        let mirror_targets = MirrorTargetMap::default();
        let ha_state = BTreeMap::new();
        let dynamic_neighbors = Arc::new(ShardedNeighborMap::default());
        let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
        let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
        let recent_exceptions = Arc::new(Mutex::new(VecDeque::new()));
        let last_resolution = Arc::new(Mutex::new(None));
        let peer_worker_commands = Vec::new();
        let dnat_fds = DnatTableFds::default();
        let rg_epochs = std::array::from_fn(|_| AtomicU32::new(0));
        let (event_handle, _event_rx) = crate::event_stream::test_worker_handle(
            8,
            DataplaneEventRateLimitConfig {
                events_per_second: 0,
                burst: 0,
            },
        );
        let worker_ctx = WorkerContext {
            ident: &ident,
            binding_lookup: &binding_lookup,
            mirror_targets: &mirror_targets,
            forwarding: &forwarding,
            ha_state: &ha_state,
            dynamic_neighbors: &dynamic_neighbors,
            neighbor_resolver: None,
            shared_sessions: &shared_sessions,
            shared_nat_sessions: &shared_nat_sessions,
            shared_forward_wire_sessions: &shared_forward_wire_sessions,
            shared_owner_rg_indexes: &shared_owner_rg_indexes,
            slow_path: None,
            event_stream: Some(&event_handle),
            local_tunnel_deliveries: &local_tunnel_deliveries,
            recent_exceptions: &recent_exceptions,
            last_resolution: &last_resolution,
            peer_worker_commands: &peer_worker_commands,
            dnat_fds: &dnat_fds,
            rg_epochs: &rg_epochs,
            cold_path_sample_mask: 0xff,
        };
        let mut counters = BatchCounters::default();
        let outcome = stage_screen_check(
            flow,
            frame,
            meta,
            None,
            TEST_NOW_SECS,
            screen,
            &mut counters,
            &worker_ctx,
        );
        (
            matches!(outcome, StageOutcome::RecycleAndContinue),
            counters.screen_drops,
        )
    }

    const FRAG_PROTO_UDP: u8 = 17;

    /// #3064 fail-on-revert (1/4): a Teardrop non-first fragment (offset 1
    /// unit = 8 bytes, MF=0, payload 4 < 8) is DROPPED by the LIVE
    /// `stage_screen_check` even though it is flowless (#2344). Restoring the
    /// early `Continue(Pass)` on `flow == None` turns this RED.
    #[test]
    fn flowless_teardrop_fragment_dropped_3064() {
        let frame = ipv4_fragment_frame(0x0001, FRAG_PROTO_UDP, 4);
        let meta = ipv4_fragment_meta(&frame, FRAG_PROTO_UDP);
        assert!(
            parse_session_flow_from_bytes(&frame, meta).is_none(),
            "a non-first fragment must be flowless (#2344) so the live \
             screen stage sees flow == None"
        );
        let mut screen = fragment_screen();
        let (dropped, drops) = run_stage_screen(&mut screen, &frame, meta, None);
        assert!(
            dropped && drops == 1,
            "teardrop non-first fragment (payload < 8) must be DROPPED by \
             the flowless screen path (#3064)"
        );
    }

    /// #3064 fail-on-revert (2/4): a Ping-of-Death non-first fragment whose
    /// offset*8 + total length overflows the 65535 reassembly ceiling is
    /// DROPPED. frag_off 0x1FFE -> offset 8190 units -> 65520 bytes;
    /// total_len = 20 + 64 = 84 -> 65604 > 65535. Restoring the early
    /// `Continue(Pass)` on `flow == None` turns this RED.
    #[test]
    fn flowless_ping_of_death_fragment_dropped_3064() {
        let frame = ipv4_fragment_frame(0x1FFE, FRAG_PROTO_UDP, 64);
        let meta = ipv4_fragment_meta(&frame, FRAG_PROTO_UDP);
        assert!(parse_session_flow_from_bytes(&frame, meta).is_none());
        let mut screen = fragment_screen();
        let (dropped, drops) = run_stage_screen(&mut screen, &frame, meta, None);
        assert!(
            dropped && drops == 1,
            "ping-of-death non-first fragment (offset*8 + total > 65535) \
             must be DROPPED by the flowless screen path (#3064)"
        );
    }

    /// #3064 fail-on-revert (3/4): a benign non-first fragment (offset 10
    /// units = 80 bytes, 100-byte payload, UDP) PASSES — no L3 fragment
    /// screen fires AND no flow/port classification happens. The flow-only
    /// `land`/`syn-fin`/`no-flag` screens are armed but MUST NOT run on the
    /// flowless path (if the full `check_packet` ran, `land` would drop the
    /// placeholder src == dst tuple). This proves the #2344 flowless fast
    /// path is preserved, and it STAYS GREEN under the early-return revert.
    #[test]
    fn flowless_benign_fragment_passes_and_skips_classification_3064() {
        let frame = ipv4_fragment_frame(0x000A, FRAG_PROTO_UDP, 100);
        let meta = ipv4_fragment_meta(&frame, FRAG_PROTO_UDP);
        assert!(
            parse_session_flow_from_bytes(&frame, meta).is_none(),
            "benign non-first fragment is flowless — proves the #2344 fast \
             path is intact (no port classification)"
        );
        let mut screen = fragment_screen();
        let (dropped, drops) = run_stage_screen(&mut screen, &frame, meta, None);
        assert!(
            !dropped && drops == 0,
            "benign non-first fragment must PASS — no false positive and no \
             flow/port classification (land/syn-fin/no-flag must not fire)"
        );
    }

    /// #3064 fail-on-revert (4/4) — regression: a non-fragmented packet
    /// still takes the FLOW path and is screened by the full `check_packet`.
    /// `land` (a flow-only screen) fires on src == dst; a benign packet
    /// passes. This proves the flow-present path behaves exactly as before
    /// the #3064 change, and it STAYS GREEN under the early-return revert.
    #[test]
    fn flow_path_nonfragment_still_screens_3064() {
        let land_frame = tcp_v4_frame(
            Ipv4Addr::new(203, 0, 113, 7),
            Ipv4Addr::new(203, 0, 113, 7),
            40000,
            443,
            TCP_FLAG_SYN,
            1,
            0,
        );
        let land_meta = tcp_v4_meta(&land_frame, TCP_FLAG_SYN);
        let land_flow = parse_session_flow_from_bytes(&land_frame, land_meta)
            .expect("non-fragmented TCP yields a session flow (flow path)");
        let mut screen = fragment_screen();
        let (dropped, drops) = run_stage_screen(&mut screen, &land_frame, land_meta, Some(&land_flow));
        assert!(
            dropped && drops == 1,
            "regression: a non-fragmented packet still flows through the \
             flow path and the full check_packet runs land (src == dst)"
        );

        let benign_frame = tcp_v4_frame(
            Ipv4Addr::new(203, 0, 113, 7),
            Ipv4Addr::new(203, 0, 113, 9),
            40000,
            443,
            TCP_FLAG_ACK,
            1,
            1,
        );
        let benign_meta = tcp_v4_meta(&benign_frame, TCP_FLAG_ACK);
        let benign_flow = parse_session_flow_from_bytes(&benign_frame, benign_meta)
            .expect("non-fragmented TCP yields a session flow (flow path)");
        let mut screen = fragment_screen();
        let (dropped, drops) =
            run_stage_screen(&mut screen, &benign_frame, benign_meta, Some(&benign_flow));
        assert!(
            !dropped && drops == 0,
            "regression: a benign non-fragmented packet still passes the \
             flow path with no false positive"
        );
    }
}
