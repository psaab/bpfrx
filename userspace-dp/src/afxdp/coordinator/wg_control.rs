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
    let (socket, socket_is_v6) = match bind_wg_socket(listen_port) {
        Ok(pair) => pair,
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
        drive_initiation(
            &engine, &socket, socket_is_v6, &pk, ep, &mut encap_buf, &tunnel_name,
            &recent_exceptions,
        );
    }

    while !stop.load(Ordering::Relaxed) {
        let mut did_work = false;

        // --- Inbound: kernel socket → engine → TUN ---
        for _ in 0..WG_RX_BURST {
            match socket.recv_from(&mut sock_buf) {
                Ok((len, from)) if len > 0 => {
                    did_work = true;
                    // Learn / refresh the peer endpoint from `from` ONLY
                    // after the datagram cryptographically authenticates
                    // (Codex r3 MAJOR): updating on any inbound packet
                    // would let a spoofed source redirect our encrypted
                    // egress. dispatch_inbound returns true only on a
                    // successful consume_*/try_decap.
                    let authenticated = dispatch_inbound(
                        &engine,
                        &socket,
                        socket_is_v6,
                        &mut tun,
                        &sock_buf[..len],
                        from,
                        &mut decap_buf,
                        &mut encap_buf,
                        &tunnel_name,
                        &recent_exceptions,
                    );
                    if authenticated {
                        effective_endpoint = Some(canonicalize_endpoint(from));
                    }
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
                            socket_is_v6,
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
            // endpoint to send to until the peer initiates. Bounded by
            // WG_RX_BURST (Codex r3 MAJOR — an unbounded drain under
            // continuous local traffic could starve socket RX and delay
            // stop/join during reconcile).
            for _ in 0..WG_RX_BURST {
                match tun.read(&mut tun_buf) {
                    Ok(len) if len > 0 => did_work = true,
                    _ => break,
                }
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
                drive_initiation(
                    &engine, &socket, socket_is_v6, &pk, ep, &mut encap_buf, &tunnel_name,
                    &recent_exceptions,
                );
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
///
/// IPV6_V6ONLY must be cleared BEFORE bind (Linux rejects it post-bind
/// with EINVAL — Codex r3 MAJOR), so the v6 socket is created with raw
/// libc, the option is set, then bind() is called. On any v6 failure we
/// fall back to a plain v4 bind so v4 peers (the common case) work.
/// Returns the socket plus whether it is the AF_INET6 dual-stack one
/// (v4 send targets must then be v4-mapped — see `wg_send_to`).
fn bind_wg_socket(port: u16) -> io::Result<(UdpSocket, bool)> {
    match bind_dual_stack_v6(port) {
        Ok(sock) => Ok((sock, true)),
        Err(_) => UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, port)).map(|s| (s, false)),
    }
}

/// Create a `[::]:port` UDP socket with IPV6_V6ONLY cleared before bind.
fn bind_dual_stack_v6(port: u16) -> io::Result<UdpSocket> {
    use std::os::fd::FromRawFd;
    // socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0)
    let fd = unsafe {
        libc::socket(
            libc::AF_INET6,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // Own the fd immediately so any early return closes it.
    let sock = unsafe { UdpSocket::from_raw_fd(fd) };
    // Clear IPV6_V6ONLY BEFORE bind.
    let off: libc::c_int = 0;
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_V6ONLY,
            &off as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    // bind([::]:port)
    let addr = libc::sockaddr_in6 {
        sin6_family: libc::AF_INET6 as libc::sa_family_t,
        sin6_port: port.to_be(),
        sin6_flowinfo: 0,
        sin6_addr: libc::in6_addr { s6_addr: [0u8; 16] },
        sin6_scope_id: 0,
    };
    let rc = unsafe {
        libc::bind(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(sock)
}

/// Canonicalize a learned peer endpoint: the dual-stack `[::]` socket
/// reports IPv4 peers as V4-MAPPED IPv6 (`::ffff:a.b.c.d`), and a
/// mapped address answers `is_ipv6() == true`, which made the exact
/// pad-aware encap MTU guard charge the 40-byte IPv6 outer overhead
/// for what is really a 20-byte IPv4 outer. Found live in #1736 S2b:
/// after the first authenticated inbound replaced the configured v4
/// endpoint with its mapped form, every inner packet in the
/// (pad-aware) 1409..=1425 window was silently dropped by the guard —
/// pings passed, but full-MSS forward TCP moved ZERO bytes (the
/// kernel-wg peer's iperf3 stalled at cwnd 1.34 KB) while reverse
/// traffic was fine. Unmap to the canonical V4 form so overhead math,
/// logs, and configured-endpoint comparisons all see the real family.
fn canonicalize_endpoint(addr: SocketAddr) -> SocketAddr {
    if let SocketAddr::V6(v6) = addr {
        if let Some(v4) = v6.ip().to_ipv4_mapped() {
            return SocketAddr::new(std::net::IpAddr::V4(v4), v6.port());
        }
    }
    addr
}

/// Send a WG datagram to `target`, mapping an IPv4 target to its
/// V4-MAPPED IPv6 form when the local socket is the dual-stack
/// AF_INET6 one. Linux REJECTS an `AF_INET` destination sockaddr on an
/// AF_INET6 socket — found live in #1736 S2b as a silent
/// `sendto = EINVAL` once per initiator tick (strace-proven): the
/// configured v4 `wg_endpoint` could never be initiated to AT ALL on
/// the dual-stack socket, while the logical/canonical V4 form is still
/// what the MTU guard and endpoint-learning must see
/// (`canonicalize_endpoint` above is the mirror direction). The
/// fallback v4-bound socket sends to V4 targets natively (mapping only
/// applies when `socket_is_v6`).
fn wg_send_to(
    socket: &UdpSocket,
    socket_is_v6: bool,
    buf: &[u8],
    target: SocketAddr,
) -> io::Result<usize> {
    let wire_target = match target {
        SocketAddr::V4(v4) if socket_is_v6 => SocketAddr::new(
            std::net::IpAddr::V6(v4.ip().to_ipv6_mapped()),
            v4.port(),
        ),
        other => other,
    };
    socket.send_to(buf, wire_target)
}

/// Build + send a fresh initiation toward the peer endpoint. A send
/// error is surfaced as an exception (the next tick retries); a missing
/// session keeps the timer armed.
#[allow(clippy::too_many_arguments)]
fn drive_initiation(
    engine: &crate::afxdp::wg::WgEngine,
    socket: &UdpSocket,
    socket_is_v6: bool,
    peer_pubkey: &[u8; 32],
    endpoint: SocketAddr,
    out: &mut [u8],
    tunnel_name: &str,
    recent_exceptions: &Arc<Mutex<VecDeque<ExceptionStatus>>>,
) {
    if let Ok(_local_index) = engine.create_initiation(peer_pubkey, out) {
        let len = crate::afxdp::wg::WG_MSG_INIT_LEN;
        if let Err(e) = wg_send_to(socket, socket_is_v6, &out[..len], endpoint) {
            record_local_tunnel_exception(
                recent_exceptions,
                tunnel_name,
                format!("wg_initiation_send:{endpoint}:{e}"),
            );
        }
    }
}

/// Dispatch one inbound WG datagram on its type byte. Returns `true`
/// iff the datagram cryptographically AUTHENTICATED (a successful
/// consume_initiation/consume_response/try_decap) — the caller uses that
/// to gate endpoint-learning so a spoofed source cannot redirect egress
/// (Codex r3 MAJOR). Type-3 (cookie), unknown, and any failed
/// authentication return `false`.
#[allow(clippy::too_many_arguments)]
fn dispatch_inbound(
    engine: &crate::afxdp::wg::WgEngine,
    socket: &UdpSocket,
    socket_is_v6: bool,
    tun: &mut std::fs::File,
    datagram: &[u8],
    from: SocketAddr,
    decap_buf: &mut [u8],
    response_buf: &mut [u8],
    tunnel_name: &str,
    recent_exceptions: &Arc<Mutex<VecDeque<ExceptionStatus>>>,
) -> bool {
    let Some(&wg_type) = datagram.first() else {
        return false;
    };
    match wg_type {
        crate::afxdp::wg::WG_TYPE_INITIATION => {
            match engine.consume_initiation_create_response(datagram, response_buf) {
                Ok((_peer_pubkey, _local_index)) => {
                    let len = crate::afxdp::wg::WG_MSG_RESPONSE_LEN;
                    let _ = wg_send_to(socket, socket_is_v6, &response_buf[..len], from);
                    true
                }
                Err(_e) => {
                    debug_log!("WG[{}]: drop initiation reason={:?}", tunnel_name, _e);
                    false
                }
            }
        }
        crate::afxdp::wg::WG_TYPE_RESPONSE => match engine.consume_response(datagram) {
            Ok(_) => true,
            Err(_e) => {
                debug_log!("WG[{}]: drop response reason={:?}", tunnel_name, _e);
                false
            }
        },
        crate::afxdp::wg::WG_TYPE_COOKIE => {
            // Cookie/MAC2 reply handling is S7; drop for now. Not
            // authenticated for endpoint-learning purposes.
            debug_log!("WG[{}]: drop cookie (S7)", tunnel_name);
            false
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
                    true
                }
                Err(_e) => {
                    debug_log!("WG[{}]: drop transport reason={:?}", tunnel_name, _e);
                    false
                }
            }
        }
        _ => {
            debug_log!("WG[{}]: drop unknown type {}", tunnel_name, wg_type);
            false
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
    socket_is_v6: bool,
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
            if let Err(e) = wg_send_to(socket, socket_is_v6, &out[..outcome.len], endpoint) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    /// #1736 S2b regression: a v4-mapped learned endpoint must unmap to
    /// canonical V4 so the encap MTU guard charges IPv4 outer overhead.
    #[test]
    fn canonicalize_endpoint_unmaps_v4_mapped() {
        let mapped: SocketAddr = "[::ffff:10.0.61.103]:51820".parse().unwrap();
        let got = canonicalize_endpoint(mapped);
        assert_eq!(
            got,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 103)), 51820)
        );
        assert!(!got.is_ipv6());
    }

    /// Native v6 and native v4 endpoints pass through untouched.
    #[test]
    fn canonicalize_endpoint_passthrough() {
        let v6: SocketAddr = "[2001:db8::1]:51820".parse().unwrap();
        assert_eq!(canonicalize_endpoint(v6), v6);
        let v4: SocketAddr = "192.0.2.1:51820".parse().unwrap();
        assert_eq!(canonicalize_endpoint(v4), v4);
        // A non-mapped v6 with an embedded v4-looking tail stays v6.
        let nat64: SocketAddr =
            SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0x0a00, 0x3d67)), 51820);
        assert_eq!(canonicalize_endpoint(nat64), nat64);
    }

    /// #1736 S2b regression (strace-proven live): a v4 target on the
    /// dual-stack AF_INET6 socket must be sent as its V4-MAPPED form —
    /// Linux returns EINVAL for an AF_INET destination sockaddr on an
    /// AF_INET6 socket, which silently killed every initiation toward
    /// the configured v4 endpoint. Loopback round-trip proves the
    /// mapped send actually lands.
    #[test]
    fn wg_send_to_maps_v4_target_on_v6_socket() {
        let (rx, rx_is_v6) = bind_wg_socket(0).expect("bind rx");
        assert!(rx_is_v6, "test host lacks dual-stack v6 sockets");
        let rx_port = rx.local_addr().unwrap().port();
        let (tx, tx_is_v6) = bind_wg_socket(0).expect("bind tx");
        // The plain V4 loopback target — the failing live shape.
        let target: SocketAddr = format!("127.0.0.1:{rx_port}").parse().unwrap();
        wg_send_to(&tx, tx_is_v6, b"wg-test", target).expect("mapped v4 send must succeed");
        rx.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let mut buf = [0u8; 16];
        let (n, _) = rx.recv_from(&mut buf).expect("datagram must arrive");
        assert_eq!(&buf[..n], b"wg-test");
        // Direct unmapped send documents WHY the helper exists; accept
        // either kernel behavior (EINVAL on Linux mainline) without
        // asserting it so the test stays portable.
        let _ = tx.send_to(b"raw", target);
    }

    /// The guard math this protects: at the v4/v6 boundary the same
    /// padded inner either fits (v4 outer) or exceeds (v6 outer) the
    /// 1500 outer MTU — the live-blackhole window.
    #[test]
    fn encapped_size_v4_vs_v6_window() {
        // inner 1409 pads to 1424: v4 outer = 1484 (fits), v6 = 1504 (drops).
        assert!(wg_encapped_size(1409, false) <= WG_OUTER_MTU);
        assert!(wg_encapped_size(1409, true) > WG_OUTER_MTU);
        // inner 1408 fits either way (the pre-fix observable cutoff).
        assert!(wg_encapped_size(1408, true) <= WG_OUTER_MTU);
    }
}
