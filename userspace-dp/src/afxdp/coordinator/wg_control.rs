//! WireGuard control thread (#1432 S2a).
//!
//! One supervised aux thread per `mode == "wireguard"` tunnel endpoint,
//! modeled on `spawn_local_tunnel_sources` (the GRE local-origin
//! template). The thread owns three handles:
//!
//!   - `Arc<WgEngine>` — the S1 wire-compliant engine (shared with the
//!     dataplane workers via `ForwardingState.wg_engines`).
//!   - a `UdpSocket` bound on `wg_listen_port` (outer transport, RX+TX).
//!   - the persistent `wgN` **TUN** (inner). The kernel routes inner
//!     traffic to/from it; xpf does not re-implement inner routing or
//!     policy in S2a.
//!
//! ## RX model — kernel socket, ESP/IPsec precedent (plan §3.4)
//!
//! WG-to-firewall is local-destination UDP. The XDP shim passes
//! local-destination UDP to the kernel via `cpumap_or_pass` (the same
//! path ESP rides), and a dedicated shim early-return steers WG-port
//! local-destination UDP to the kernel deterministically, so this kernel
//! `UdpSocket` receives ALL inbound WG datagrams — handshake AND
//! transport. There is no AF_XDP hot-path decap stage and no
//! worker→control packet channel in S2a; the only worker→control
//! coupling is the relaxed-atomic NoSession handshake-request edge that
//! `WgEngine::request_handshake` records and this thread consumes.
//!
//! ## Directions
//!
//!   - **Inbound** (kernel socket → engine → TUN): dispatch on the WG
//!     type byte. type 1 → `consume_initiation_create_response` + send
//!     the response; type 2 → `consume_response`; type 3 (cookie) →
//!     drop+count (S7); type 4 (transport) → `try_decap` (the engine
//!     AllowedIPs-gates the inner src) → write the plaintext inner IP to
//!     the `wgN` TUN, where the kernel routes/firewalls it.
//!   - **Egress** (TUN → engine → kernel socket): inner IP packets the
//!     kernel routes onto `wgN` are read, `try_encap`'d, and sent to the
//!     peer endpoint. The transit AF_XDP egress is the other encap site
//!     (frame/mod.rs).

use super::*;
use crate::afxdp::wg::{POLY1305_TAG_LEN, WG_DATA_HEADER_LEN};
use std::io::{Read, Write};
use std::net::{SocketAddr, UdpSocket};
use std::os::fd::AsRawFd;

/// Outer MTU assumed for the WG transport path (S2a single-tunnel;
/// matches the Go-side wgN MTU cap in pkg/routing/tunnel.go). The exact
/// pad-aware guard below drops any inner packet whose encapped size
/// would exceed this, mirroring the transit-egress guard in
/// frame/wg.rs (plan §4.3, §7 — the guard must hold in BOTH directions).
const WG_OUTER_MTU: usize = 1500;

/// Round `n` up to the nearest multiple of 16 (WG §5.4.6 pad).
#[inline]
const fn pad_to_16(n: usize) -> usize {
    (n + 15) & !15
}

/// Exact pad-aware encapped wire size for an `inner_len`-byte inner
/// packet plus the outer L3/L4. Mirrors `frame::wg::wg_encapped_size`.
#[inline]
fn wg_encapped_size(inner_len: usize, outer_v6: bool) -> usize {
    let outer_ip_len = if outer_v6 { 40 } else { 20 };
    WG_DATA_HEADER_LEN + pad_to_16(inner_len) + POLY1305_TAG_LEN + outer_ip_len + 8
}

/// Socket/TUN read budget per poll tick — drains a bounded burst before
/// yielding so a flood cannot starve the TUN-read direction (and vice
/// versa).
const WG_RX_BURST: usize = 64;

/// Poll sleep when both directions are idle.
const WG_IDLE_SLEEP: Duration = Duration::from_millis(1);

/// Initiator re-init poll interval: when an endpoint is configured and
/// no confirmed session exists, re-drive the handshake at most this
/// often.
const WG_INITIATOR_POLL_NS: u64 = 1_000_000_000;

#[allow(clippy::too_many_arguments)]
pub(super) fn wg_control_loop(
    tunnel_name: String,
    tunnel_endpoint_id: u16,
    engine: Arc<crate::afxdp::wg::WgEngine>,
    listen_port: u16,
    peer_endpoint: Option<SocketAddr>,
    recent_exceptions: Arc<Mutex<VecDeque<ExceptionStatus>>>,
    stop: Arc<AtomicBool>,
) {
    // Bind the UDP socket. v6 dual-stack ([::]:port) accepts both v4 and
    // v6 peers where the kernel allows it; fall back to v4 if the v6
    // bind fails. EADDRINUSE here means a host kernel wgX claims the port
    // (mutually exclusive with userspace-WG — surface a clear error).
    let socket = match bind_wg_socket(listen_port) {
        Ok(sock) => sock,
        Err(err) => {
            record_local_tunnel_exception(
                &recent_exceptions,
                &tunnel_name,
                format!("wg_bind_listen_port:{listen_port}:{err}"),
            );
            return;
        }
    };
    if let Err(err) = socket.set_nonblocking(true) {
        record_local_tunnel_exception(
            &recent_exceptions,
            &tunnel_name,
            format!("wg_socket_nonblocking:{err}"),
        );
        return;
    }

    // Attach to the persistent wgN TUN (Go pre-created it; open_tun
    // attaches to the existing device by name). Non-blocking.
    let mut tun = match open_tun(&tunnel_name) {
        Ok((file, _actual_name)) => file,
        Err(err) => {
            record_local_tunnel_exception(&recent_exceptions, &tunnel_name, err);
            return;
        }
    };
    if let Err(err) = set_fd_nonblocking(tun.as_raw_fd()) {
        record_local_tunnel_exception(&recent_exceptions, &tunnel_name, err);
        return;
    }

    let peer_pubkey = engine.first_peer_pubkey();
    let mut last_initiate_ns: u64 = 0;
    // The endpoint used for egress + re-init. Starts at the configured
    // `wg_endpoint` (initiator role) and is LEARNED from the source of
    // any inbound WG datagram for a responder-only peer (Codex BLOCKER:
    // a responder-only peer has no configured endpoint, so without
    // endpoint-learning the TUN-read egress would have nowhere to send
    // and the tunnel would black-hole the reply path). This is the WG
    // endpoint-roaming behavior peer.rs documents as required.
    let mut effective_endpoint: Option<SocketAddr> = peer_endpoint;
    // 64 KiB scratch for both directions (max IP packet; WG records are
    // smaller). Single allocation at thread start — no per-packet alloc.
    let mut sock_buf = vec![0u8; 65_535];
    let mut tun_buf = vec![0u8; 65_535];
    let mut decap_buf = vec![0u8; 65_535];
    let mut encap_buf = vec![0u8; 65_535];

    // Initial initiator bring-up: if an endpoint is configured, kick a
    // handshake immediately so the tunnel comes up without waiting for
    // egress traffic.
    if let (Some(ep), Some(pk)) = (effective_endpoint, peer_pubkey) {
        last_initiate_ns = monotonic_nanos();
        drive_initiation(&engine, &socket, &pk, ep, &mut encap_buf, &tunnel_name, &recent_exceptions);
    }

    while !stop.load(Ordering::Relaxed) {
        let mut did_work = false;

        // --- Inbound: kernel socket → engine → TUN ---
        for _ in 0..WG_RX_BURST {
            match socket.recv_from(&mut sock_buf) {
                Ok((len, from)) if len > 0 => {
                    did_work = true;
                    // Learn / refresh the peer endpoint from the source of
                    // any inbound datagram (WG roaming + responder-only
                    // support). We only have one configured peer in S2a,
                    // so attributing inbound to it is unambiguous; the
                    // engine still cryptographically authenticates the
                    // session, so a spoofed source cannot inject traffic,
                    // only (at worst) redirect our egress — bounded to the
                    // same single peer.
                    effective_endpoint = Some(from);
                    dispatch_inbound(
                        &engine,
                        &socket,
                        &mut tun,
                        &sock_buf[..len],
                        from,
                        &mut decap_buf,
                        &mut encap_buf,
                        &tunnel_name,
                        &recent_exceptions,
                    );
                }
                Ok(_) => break,
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    record_local_tunnel_exception(
                        &recent_exceptions,
                        &tunnel_name,
                        format!("wg_socket_recv:{e}"),
                    );
                    break;
                }
            }
        }

        // --- Egress: TUN → engine → kernel socket ---
        if let (Some(ep), Some(pk)) = (effective_endpoint, peer_pubkey) {
            for _ in 0..WG_RX_BURST {
                match tun.read(&mut tun_buf) {
                    Ok(len) if len > 0 => {
                        did_work = true;
                        encap_and_send(
                            &engine,
                            &socket,
                            &pk,
                            ep,
                            &tun_buf[..len],
                            &mut encap_buf,
                            &tunnel_name,
                            &recent_exceptions,
                        );
                    }
                    Ok(_) => break,
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => {
                        record_local_tunnel_exception(
                            &recent_exceptions,
                            &tunnel_name,
                            format!("wg_tun_read:{e}"),
                        );
                        break;
                    }
                }
            }
        } else {
            // Responder-only peer that hasn't been heard from yet: drain
            // the TUN so the kernel does not back up, but we have no
            // endpoint to send to until the peer initiates.
            while let Ok(len) = tun.read(&mut tun_buf) {
                if len == 0 {
                    break;
                }
                did_work = true;
            }
        }

        // --- Initiator re-init: NoSession edge OR coarse timer ---
        // Only initiate toward an endpoint we actually know (configured
        // OR learned). A responder-only peer we have never heard from has
        // no endpoint, so we wait for it to initiate.
        if let (Some(ep), Some(pk)) = (effective_endpoint, peer_pubkey) {
            let now = monotonic_nanos();
            let requested = engine.take_handshake_request();
            let timer_due = now.saturating_sub(last_initiate_ns) >= WG_INITIATOR_POLL_NS;
            // Only the configured-initiator role re-drives on the timer; a
            // purely learned endpoint (responder-only) initiates only on
            // an explicit NoSession egress request, never on the bare
            // timer, so we don't spam a peer that is the designated
            // initiator.
            let allow_timer = peer_endpoint.is_some() && timer_due;
            if (requested || allow_timer) && !engine.peer_has_confirmed_session(&pk) {
                last_initiate_ns = now;
                drive_initiation(&engine, &socket, &pk, ep, &mut encap_buf, &tunnel_name, &recent_exceptions);
                did_work = true;
            }
        }

        if !did_work {
            thread::sleep(WG_IDLE_SLEEP);
        }
    }
    let _ = tunnel_endpoint_id;
}

/// Bind the WG listen socket. Prefer a v6 dual-stack bind so a single
/// socket serves both v4-mapped and v6 peers; fall back to a v4 bind if
/// the v6 bind fails.
///
/// Codex MAJOR: a bare `[::]` bind is v6-ONLY on hosts where
/// `net.ipv6.bindv6only=1`, silently black-holing v4 peers. We clear
/// `IPV6_V6ONLY` on the fd before returning so the dual-stack guarantee
/// holds regardless of the sysctl default. If clearing it fails (e.g. a
/// hardened kernel forbids it), fall back to a v4 bind so v4 peers — the
/// common case — are never left unserved.
///
/// VRF/routing-instance note (Codex BLOCKER, S2a known limitation): this
/// socket binds the wildcard address in the MAIN routing table. A WG
/// tunnel placed inside a routing-instance whose peer route lives only in
/// that VRF is NOT yet supported — SO_BINDTODEVICE/VRF-fd binding is
/// owned by the S6 multi-instance work (#1434). S2a single-tunnel scope
/// is the default table.
fn bind_wg_socket(port: u16) -> io::Result<UdpSocket> {
    match UdpSocket::bind((std::net::Ipv6Addr::UNSPECIFIED, port)) {
        Ok(sock) => {
            if clear_ipv6_v6only(&sock).is_err() {
                // Could not guarantee dual-stack; rebind v4 so v4 peers work.
                drop(sock);
                return UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, port));
            }
            Ok(sock)
        }
        Err(_) => UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, port)),
    }
}

/// Clear IPV6_V6ONLY so a `[::]` socket also accepts v4-mapped peers.
fn clear_ipv6_v6only(sock: &UdpSocket) -> io::Result<()> {
    let off: libc::c_int = 0;
    let rc = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::IPPROTO_IPV6,
            libc::IPV6_V6ONLY,
            &off as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Build + send a fresh initiation toward the peer endpoint. A send
/// error is surfaced as an exception (the next tick retries); a missing
/// session keeps the timer armed.
fn drive_initiation(
    engine: &crate::afxdp::wg::WgEngine,
    socket: &UdpSocket,
    peer_pubkey: &[u8; 32],
    endpoint: SocketAddr,
    out: &mut [u8],
    tunnel_name: &str,
    recent_exceptions: &Arc<Mutex<VecDeque<ExceptionStatus>>>,
) {
    if let Ok(_local_index) = engine.create_initiation(peer_pubkey, out) {
        let len = crate::afxdp::wg::WG_MSG_INIT_LEN;
        if let Err(e) = socket.send_to(&out[..len], endpoint) {
            record_local_tunnel_exception(
                recent_exceptions,
                tunnel_name,
                format!("wg_initiation_send:{endpoint}:{e}"),
            );
        }
    }
}

/// Dispatch one inbound WG datagram on its type byte.
#[allow(clippy::too_many_arguments)]
fn dispatch_inbound(
    engine: &crate::afxdp::wg::WgEngine,
    socket: &UdpSocket,
    tun: &mut std::fs::File,
    datagram: &[u8],
    from: SocketAddr,
    decap_buf: &mut [u8],
    response_buf: &mut [u8],
    tunnel_name: &str,
    recent_exceptions: &Arc<Mutex<VecDeque<ExceptionStatus>>>,
) {
    let Some(&wg_type) = datagram.first() else {
        return;
    };
    match wg_type {
        crate::afxdp::wg::WG_TYPE_INITIATION => {
            match engine.consume_initiation_create_response(datagram, response_buf) {
                Ok((_peer_pubkey, _local_index)) => {
                    let len = crate::afxdp::wg::WG_MSG_RESPONSE_LEN;
                    let _ = socket.send_to(&response_buf[..len], from);
                }
                Err(_e) => {
                    debug_log!("WG[{}]: drop initiation reason={:?}", tunnel_name, _e);
                }
            }
        }
        crate::afxdp::wg::WG_TYPE_RESPONSE => {
            if let Err(_e) = engine.consume_response(datagram) {
                debug_log!("WG[{}]: drop response reason={:?}", tunnel_name, _e);
            }
        }
        crate::afxdp::wg::WG_TYPE_COOKIE => {
            // Cookie/MAC2 reply handling is S7; drop for now.
            debug_log!("WG[{}]: drop cookie (S7)", tunnel_name);
        }
        crate::afxdp::wg::WG_TYPE_DATA => {
            match engine.try_decap(datagram, decap_buf) {
                Ok(outcome) => {
                    // Write the plaintext inner IP to the wgN TUN; the
                    // kernel routes/firewalls it (NOT the AF_XDP policy
                    // engine — the AllowedIPs gate inside try_decap is
                    // S2a's inner-src control).
                    if let Err(e) = tun.write_all(&decap_buf[..outcome.len]) {
                        record_local_tunnel_exception(
                            recent_exceptions,
                            tunnel_name,
                            format!("wg_tun_write:{e}"),
                        );
                    }
                }
                Err(_e) => {
                    debug_log!("WG[{}]: drop transport reason={:?}", tunnel_name, _e);
                }
            }
        }
        _ => {
            debug_log!("WG[{}]: drop unknown type {}", tunnel_name, wg_type);
        }
    }
}

/// Encap one inner IP packet read from the TUN and send it to the peer.
/// NoSession arms the (control-thread) initiation timer; a single
/// round-trip increments the WG egress counter exactly once (telemetry
/// is consolidated on the engine, not per call site).
#[allow(clippy::too_many_arguments)]
fn encap_and_send(
    engine: &crate::afxdp::wg::WgEngine,
    socket: &UdpSocket,
    peer_pubkey: &[u8; 32],
    endpoint: SocketAddr,
    inner_ip: &[u8],
    out: &mut [u8],
    tunnel_name: &str,
    recent_exceptions: &Arc<Mutex<VecDeque<ExceptionStatus>>>,
) {
    // Exact pad-aware MTU guard (plan §4.3 / AGY H1) — symmetric with the
    // transit-egress guard in frame/wg.rs. Drop oversize inner rather
    // than emitting an outer datagram the kernel must fragment. The wgN
    // TUN MTU (Go-side) is the first line; this is defense-in-depth for a
    // mis-set MTU or a jumbo inner read off the TUN.
    if wg_encapped_size(inner_ip.len(), endpoint.is_ipv6()) > WG_OUTER_MTU {
        debug_log!(
            "WG[{}]: drop oversize inner {} (encapped > {})",
            tunnel_name,
            inner_ip.len(),
            WG_OUTER_MTU
        );
        return;
    }
    match engine.try_encap(peer_pubkey, inner_ip, out) {
        Ok(outcome) => {
            if let Err(e) = socket.send_to(&out[..outcome.len], endpoint) {
                record_local_tunnel_exception(
                    recent_exceptions,
                    tunnel_name,
                    format!("wg_socket_send:{e}"),
                );
            }
        }
        Err(crate::afxdp::wg::EncapError::NoSession) => {
            // No confirmed session yet — request a handshake (rate-
            // limited) and drop this packet.
            engine.request_handshake(monotonic_nanos());
        }
        Err(_e) => {
            debug_log!("WG[{}]: encap drop reason={:?}", tunnel_name, _e);
        }
    }
}
