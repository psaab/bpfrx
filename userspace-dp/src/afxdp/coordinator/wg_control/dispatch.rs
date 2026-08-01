//! WG control-thread inbound dispatch + TUN-read encap: the type-byte
//! dispatch (handshake consume, cookie challenge/consume, transport
//! decap → TUN write), the auth-before-roam `InboundOutcome`
//! contract, and the cryptokey-routed encap-and-send egress helper.

use super::super::*;
use super::mtu::wg_inner_fits_outer_mtu;
use super::policy_gate::{InnerVerdict, evaluate_wg_inner_ingress};
use super::sock::wg_send_to;
use crate::afxdp::wg::counters::WgCounters;
use std::net::{SocketAddr, UdpSocket};
use std::os::fd::AsRawFd;

/// One inbound datagram's disposition. Handshake completions must be
/// handled INLINE at this site — before the same iteration's TUN
/// burst — so the attempt machine's later pass cannot erase legitimate
/// post-completion state (plan v9, Codex r5/r6 ordering traces).
pub(super) enum InboundOutcome {
    /// Failed authentication / cookie / unknown type — no endpoint
    /// learning, no stamps.
    Unauthenticated,
    /// Authenticated transport record (data or keepalive). Carries the
    /// peer that owned the session (#1434: endpoint roaming is
    /// per-peer — we learn THIS peer's endpoint from `from`).
    Authenticated([u8; 32]),
    /// Valid msg2 consumed — initiator-side handshake completion (carries
    /// the responding peer).
    CompletedInitiator([u8; 32]),
    /// Valid msg1 consumed + msg2 sent — responder-side completion
    /// (carries the initiating peer).
    CompletedResponder([u8; 32]),
}

impl InboundOutcome {
    pub(super) fn authenticated(&self) -> bool {
        !matches!(self, InboundOutcome::Unauthenticated)
    }

    /// The authenticated peer's pubkey, if any (#1434 per-peer endpoint
    /// learning).
    pub(super) fn peer(&self) -> Option<[u8; 32]> {
        match self {
            InboundOutcome::Unauthenticated => None,
            InboundOutcome::Authenticated(pk)
            | InboundOutcome::CompletedInitiator(pk)
            | InboundOutcome::CompletedResponder(pk) => Some(*pk),
        }
    }
}

/// Dispatch one inbound WG datagram on its type byte. The returned
/// `InboundOutcome` tells the caller (a) whether the datagram
/// cryptographically AUTHENTICATED — gating endpoint-learning so a
/// spoofed source cannot redirect egress (Codex r3 MAJOR) — and (b)
/// whether it COMPLETED a handshake, which the caller must handle
/// inline (edge drain + post-msg2 keepalive) before this iteration's
/// TUN burst (plan v9 completion-site ordering). Type-3 (cookie),
/// unknown types, and failed authentication are `Unauthenticated`.
#[allow(clippy::too_many_arguments)]
pub(super) fn dispatch_inbound(
    engine: &crate::afxdp::wg::WgEngine,
    socket: &UdpSocket,
    socket_is_v6: bool,
    tun: &mut std::fs::File,
    datagram: &[u8],
    from: SocketAddr,
    outer_ecn: Option<u8>,
    decap_buf: &mut [u8],
    response_buf: &mut [u8],
    // #5618: the live forwarding snapshot + this tunnel's endpoint id and
    // a synthetic-frame scratch, so decapped plaintext gets an xpf FORWARD
    // ZONE-POLICY verdict before it can reach the kernel.
    forwarding: &ForwardingState,
    tunnel_endpoint_id: u16,
    gate_buf: &mut [u8],
    tunnel_name: &str,
    recent_exceptions: &Arc<Mutex<ExceptionEventRing>>,
) -> InboundOutcome {
    let Some(&wg_type) = datagram.first() else {
        return InboundOutcome::Unauthenticated;
    };
    match wg_type {
        crate::afxdp::wg::WG_TYPE_INITIATION => {
            // #4094 PR-A: responder under-load cookie gate. Before spending
            // a Noise handshake, classify the initiation — under load a
            // valid-MAC1 initiation without a valid MAC2 is answered with a
            // type-3 cookie challenge and dropped (no crypto), defeating a
            // spoofed-source initiation flood. `classify_initiation` writes
            // the cookie into `response_buf` only on the SendCookie arm, so
            // the buffer is free for the response on the Process arm.
            let now = engine.now_ns();
            match engine.classify_initiation(datagram, from, response_buf, now) {
                crate::afxdp::wg::InitiationAction::SendCookie(len) => {
                    // Challenge the real source; DROP the initiation. Not
                    // authenticated for endpoint-learning (a cookie reply is
                    // not proof the source holds the keys).
                    if let Err(e) = wg_send_to(socket, socket_is_v6, &response_buf[..len], from) {
                        WgCounters::bump(&engine.counters().hs_send_errors);
                        record_local_tunnel_exception(
                            recent_exceptions,
                            tunnel_name,
                            format!("wg_cookie_send:{from}:{e}"),
                        );
                    }
                    return InboundOutcome::Unauthenticated;
                }
                crate::afxdp::wg::InitiationAction::Drop => {
                    // Under load, cookie-reply budget exhausted — drop
                    // silently (the counter recorded it).
                    return InboundOutcome::Unauthenticated;
                }
                crate::afxdp::wg::InitiationAction::Process => {}
            }
            match engine.consume_initiation_create_response(datagram, response_buf) {
                Ok((peer_pubkey, _local_index)) => {
                    let len = crate::afxdp::wg::WG_MSG_RESPONSE_LEN;
                    // #1865: the response send error was silently
                    // discarded (`let _ =`) — the responder mirror of
                    // the #1736 initiator-EINVAL class. Count + record.
                    match wg_send_to(socket, socket_is_v6, &response_buf[..len], from) {
                        Ok(_) => {
                            // #1888 S5: msg2 on the wire is an
                            // authenticated SEND.
                            engine.note_handshake_sent(&peer_pubkey, monotonic_nanos());
                        }
                        Err(e) => {
                            WgCounters::bump(&engine.counters().hs_send_errors);
                            record_local_tunnel_exception(
                                recent_exceptions,
                                tunnel_name,
                                format!("wg_response_send:{from}:{e}"),
                            );
                        }
                    }
                    InboundOutcome::CompletedResponder(peer_pubkey)
                }
                Err(_e) => {
                    debug_log!("WG[{}]: drop initiation reason={:?}", tunnel_name, _e);
                    InboundOutcome::Unauthenticated
                }
            }
        }
        crate::afxdp::wg::WG_TYPE_RESPONSE => match engine.consume_response(datagram) {
            Ok((peer_pubkey, _idx)) => InboundOutcome::CompletedInitiator(peer_pubkey),
            Err(_e) => {
                debug_log!("WG[{}]: drop response reason={:?}", tunnel_name, _e);
                InboundOutcome::Unauthenticated
            }
        },
        crate::afxdp::wg::WG_TYPE_COOKIE => {
            // #4094 PR-B: initiator-side cookie-reply consume. A responder
            // under load answers our valid-MAC1 initiation with a type-3
            // cookie-reply instead of a handshake response; decrypt it and
            // store the cookie so our NEXT initiation to that peer carries a
            // valid MAC2 (completing the handshake under load). NOT
            // authenticated for endpoint-learning: a cookie-reply is
            // XChaCha-sealed under our own public-key-derived key and proves
            // nothing about whether the source holds the peer's keys.
            // consume_cookie_reply counts internally (hs_rx_cookie_consumed
            // on success, hs_rx_cookie_unsupported on a drop).
            if !engine.consume_cookie_reply(datagram, engine.now_ns()) {
                // Reply we could not attribute (no matching in-flight
                // initiation) or could not decrypt (wrong key / bad AAD /
                // tampered).
                debug_log!("WG[{}]: drop cookie (unconsumable)", tunnel_name);
            }
            InboundOutcome::Unauthenticated
        }
        crate::afxdp::wg::WG_TYPE_DATA => {
            match engine.try_decap(datagram, decap_buf) {
                Ok(outcome) => {
                    // #2317: RFC 6040 §4.2 decap-side ECN combine. The
                    // outer ECN was captured out-of-band via recvmsg's
                    // IP_RECVTOS / IPV6_RECVTCLASS cmsg (the kernel UDP
                    // stack stripped the outer IP header before this WG
                    // record reached userspace). Fold it into the
                    // freshly-decrypted inner IP packet: an outer CE
                    // upgrades an ECN-capable inner to CE (recomputing the
                    // inner IPv4 header checksum), and the illegal
                    // outer-CE / inner-Not-ECT combination is dropped
                    // (counter bumped in apply_decap_ecn_combine). Reuses
                    // the GRE decap combine body, with the WG-specific
                    // illegal-drop counter. Skipped when no TOS cmsg
                    // arrived (`outer_ecn` is None) or the inner family is
                    // unrecognizable — never mutate on a malformed inner.
                    if let Some(outer_ecn) = outer_ecn {
                        let inner = &mut decap_buf[..outcome.len];
                        let inner_family = match inner.first().map(|b| b >> 4) {
                            Some(4) => Some(libc::AF_INET as u8),
                            Some(6) => Some(libc::AF_INET6 as u8),
                            _ => None,
                        };
                        if let Some(fam) = inner_family
                            && !crate::afxdp::gre::apply_decap_ecn_combine(
                                inner,
                                fam,
                                outer_ecn,
                                &crate::afxdp::gre::WG_DECAP_ECN_ILLEGAL_DROPS,
                            )
                        {
                            // Illegal RFC 6040 §4.2 combination — drop the
                            // inner without writing it to the TUN. The
                            // datagram still authenticated (the peer holds
                            // the keys), so endpoint-learning proceeds.
                            return InboundOutcome::Authenticated(outcome.peer_pubkey);
                        }
                    }
                    // #5618: xpf FORWARD ZONE-POLICY authority over the
                    // decapped plaintext, BEFORE it can reach the kernel.
                    // Pre-#5618 this site wrote straight to the TUN and
                    // the kernel FIB decided everything, so a flow the
                    // operator's from-zone/to-zone policy DENIES still
                    // transited — the AllowedIPs gate inside try_decap is
                    // a cryptographic peer/source-ownership check, not the
                    // SRX zone-pair authority. `evaluate_wg_inner_ingress`
                    // resolves the from-zone from the tunnel's LOGICAL
                    // interface (the same model native GRE decap uses),
                    // routes the inner destination in that interface's
                    // routing instance to get the to-zone, and runs
                    // `evaluate_policy`. A non-permit verdict DROPS here:
                    // no TUN write, so the kernel never sees the packet.
                    //
                    // The datagram still AUTHENTICATED (the peer holds the
                    // keys), so the return is `Authenticated` and
                    // endpoint-learning proceeds exactly as for the
                    // RFC 6040 illegal-ECN drop above — a policy verdict
                    // on the inner flow says nothing about the outer
                    // peer's identity.
                    //
                    // Counted, not evented: a deny flood would churn the
                    // bounded exception ring and evict real tunnel
                    // exceptions, so this follows the existing WG
                    // drop-by-reason discipline (`decap_drops_*`) and
                    // surfaces through the counter. The RT_FLOW
                    // policy-deny record for inner ingress needs the full
                    // worker re-entry (#5618 residual).
                    match evaluate_wg_inner_ingress(
                        forwarding,
                        tunnel_endpoint_id,
                        &decap_buf[..outcome.len],
                        gate_buf,
                    ) {
                        InnerVerdict::Permit => {}
                        InnerVerdict::Deny {
                            from_zone: _from_zone,
                            to_zone: _to_zone,
                        } => {
                            WgCounters::bump(&engine.counters().inner_policy_denies);
                            debug_log!(
                                "WG[{}]: inner policy DENY zone {} -> {}",
                                tunnel_name,
                                _from_zone,
                                _to_zone
                            );
                            return InboundOutcome::Authenticated(outcome.peer_pubkey);
                        }
                        InnerVerdict::ForwardDrop(_reason) => {
                            // xpf has a definite NON-policy verdict of
                            // its own — its FIB said discard, or the
                            // inner packet is uninspectable (truncated
                            // header, over-limit IPv6 extension chain,
                            // non-IP payload). Handing the plaintext to
                            // the kernel after that would be incoherent,
                            // and an uninspectable inner is exactly the
                            // ext-header IDS-evasion shape #4743 fails
                            // closed on in the mainline forward path.
                            WgCounters::bump(&engine.counters().inner_forward_drops);
                            debug_log!(
                                "WG[{}]: inner forward drop ({})",
                                tunnel_name,
                                _reason
                            );
                            return InboundOutcome::Authenticated(outcome.peer_pubkey);
                        }
                        InnerVerdict::Unadjudicated(_reason) => {
                            // xpf had no forward authority over this
                            // packet: unzoned tunnel/egress, host-bound
                            // destination (a host-inbound question, a
                            // different policy plane), or no FIB egress.
                            // Preserve the S2a kernel delegation rather
                            // than drop on a zone pair we could not
                            // compute — but COUNT it, so the residual
                            // delegation is operator-visible.
                            WgCounters::bump(&engine.counters().inner_policy_unadjudicated);
                            debug_log!(
                                "WG[{}]: inner policy unadjudicated ({})",
                                tunnel_name,
                                _reason
                            );
                        }
                    }
                    // Write the plaintext inner IP to the wgN TUN; the
                    // kernel routes/firewalls it (the xpf zone-pair
                    // verdict above has already permitted it, or declined
                    // authority over it).
                    //
                    // #2438: the wgN TUN fd is O_NONBLOCK, so this uses
                    // the single-write whole-packet seam
                    // (`write_packet_nonblocking`) — never std
                    // `Write::write_all`, whose short-count stream-resume
                    // would re-write `buf[n..]` and inject the remainder
                    // as a SECOND, malformed inner packet (the #2407
                    // corruption class). The seam retries the WHOLE
                    // packet on WouldBlock/EINTR and drops (counted) on a
                    // genuine partial.
                    if let Err(e) = crate::slowpath::write_packet_nonblocking(
                        tun.as_raw_fd(),
                        &decap_buf[..outcome.len],
                    ) {
                        WgCounters::bump(&engine.counters().tun_write_errors);
                        record_local_tunnel_exception(
                            recent_exceptions,
                            tunnel_name,
                            format!("wg_tun_write:{e}"),
                        );
                    }
                    InboundOutcome::Authenticated(outcome.peer_pubkey)
                }
                Err(crate::afxdp::wg::DecapError::MalformedInner) => {
                    // MalformedInner is only ever returned POST-AEAD:
                    // the authenticated zero-length keepalive exits
                    // decap through it by design (#1865), and a
                    // malformed-but-authenticated inner also proves
                    // the peer holds the session keys. Both count for
                    // endpoint learning (this closes the #1865 plan §9
                    // latent gap: a keepalive-only roaming peer now
                    // updates our egress endpoint). #1434: try_decap's
                    // MalformedInner/keepalive arm does not surface the
                    // peer, so per-peer endpoint learning is only
                    // unambiguous when the tunnel has exactly ONE peer
                    // (the keepalive-roaming case the #1865 fix targets).
                    // With multiple peers we cannot attribute a bare
                    // keepalive to a specific peer here, so skip the
                    // learn for THIS datagram (the next DATA record from
                    // the peer learns it via the Authenticated(peer)
                    // arm above). Return Unauthenticated so no wrong-peer
                    // endpoint is learned.
                    match engine.single_peer_pubkey() {
                        Some(pk) => InboundOutcome::Authenticated(pk),
                        None => InboundOutcome::Unauthenticated,
                    }
                }
                Err(_e) => {
                    debug_log!("WG[{}]: drop transport reason={:?}", tunnel_name, _e);
                    InboundOutcome::Unauthenticated
                }
            }
        }
        _ => {
            // #1865: type byte outside {1,2,3,4}. Zero-length
            // datagrams never reach here (the recv loop's
            // `Ok(_) => break` arm consumes them), so this counter is
            // exactly "well-formed UDP, non-WG type byte".
            WgCounters::bump(&engine.counters().rx_unknown_type);
            debug_log!("WG[{}]: drop unknown type {}", tunnel_name, wg_type);
            InboundOutcome::Unauthenticated
        }
    }
}

/// Encap one inner IP packet read from the TUN and send it to the peer.
/// NoSession arms the (control-thread) initiation timer; a single
/// round-trip increments the WG egress counter exactly once (telemetry
/// is consolidated on the engine, not per call site).
#[allow(clippy::too_many_arguments)]
pub(super) fn encap_and_send(
    engine: &crate::afxdp::wg::WgEngine,
    socket: &UdpSocket,
    socket_is_v6: bool,
    peer_pubkey: &[u8; 32],
    endpoint: SocketAddr,
    inner_ip: &[u8],
    out: &mut [u8],
    outer_mtu: usize,
    tunnel_name: &str,
    recent_exceptions: &Arc<Mutex<ExceptionEventRing>>,
) {
    // Exact pad-aware MTU guard (plan §4.3 / AGY H1) — symmetric with the
    // transit-egress guard in frame/wg.rs, AND against the SAME MTU model
    // (#2300): `outer_mtu` is the real underlay-egress MTU, not the old
    // `WG_OUTER_MTU = 1500` hardcode. #5291: the caller resolves this
    // PER PEER (the SELECTED peer's underlay, via `per_peer_outer_mtu`),
    // so a multi-peer tunnel with asymmetric underlays sizes each peer's
    // encap against its own path — matching the transit path's per-peer
    // resolution (#2845/#3219). Drop oversize
    // inner rather than emitting an outer datagram the kernel must
    // fragment. The wgN TUN MTU (Go-side) is the first line; this is
    // defense-in-depth for a mis-set MTU or a jumbo inner read off the TUN.
    if !wg_inner_fits_outer_mtu(inner_ip.len(), endpoint.is_ipv6(), outer_mtu) {
        // #1865: the #1736 v4-mapped blackhole class — full-MSS inner
        // packets silently vanishing here moved ZERO bytes of forward
        // TCP while pings passed. Now release-visible.
        WgCounters::bump(&engine.counters().encap_mtu_drops);
        debug_log!(
            "WG[{}]: drop oversize inner {} (encapped > {})",
            tunnel_name,
            inner_ip.len(),
            outer_mtu
        );
        return;
    }
    match engine.try_encap(peer_pubkey, inner_ip, out) {
        Ok(outcome) => {
            if let Err(e) = wg_send_to(socket, socket_is_v6, &out[..outcome.len], endpoint) {
                WgCounters::bump(&engine.counters().transport_send_errors);
                record_local_tunnel_exception(
                    recent_exceptions,
                    tunnel_name,
                    format!("wg_socket_send:{e}"),
                );
            }
        }
        Err(crate::afxdp::wg::EncapError::NoSession) => {
            // No confirmed session yet — request a handshake for THIS peer
            // (rate-limited, #5164) and drop this packet.
            engine.request_handshake(peer_pubkey, monotonic_nanos());
        }
        Err(_e) => {
            debug_log!("WG[{}]: encap drop reason={:?}", tunnel_name, _e);
        }
    }
}
