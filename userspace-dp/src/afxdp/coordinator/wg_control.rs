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
//!
//! ## Timers + idle wait (#1888 S5 / #1889)
//!
//! The loop blocks in poll(2) over {socket, TUN} POLLIN when idle
//! (timeout = min(next timer deadline, 100ms cap) — the cap bounds
//! stop/join and worker-edge latency) and runs a 1s-granularity timer
//! arm: session expiry (REJECT_AFTER_TIME teardown), the pure
//! `WgEngine::timer_pass` (passive/persistent keepalives, no-reply
//! reinit), and the handshake ATTEMPT machine (5s retransmit pacing,
//! 90s give-up window, identity-based success). Per-use T1/T2/T3 age
//! enforcement lives in the engine's encap/decap paths; this loop owns
//! all sends. Design of record:
//! `docs/research/1888-wg-timers/plan.md` (plan v9, 3/3 PLAN-READY).

use super::*;
use crate::afxdp::wg::counters::WgCounters;
use crate::afxdp::wg::{POLY1305_TAG_LEN, WG_DATA_HEADER_LEN};
use std::io::Read;
use std::net::{SocketAddr, UdpSocket};
use std::os::fd::AsRawFd;

/// Fallback outer (underlay) MTU for the WG transport path when the
/// real egress MTU cannot be resolved at spawn (#2300). The control
/// thread is now handed the resolved underlay-egress MTU
/// (`resolve_wg_outer_mtu` in tunnel_supervision.rs), so this constant
/// is ONLY the last-resort default for an unconfigured / unroutable
/// endpoint — it is no longer the hardcoded outer MTU. The exact
/// pad-aware guard in `encap_and_send` drops any inner packet whose
/// encapped size would exceed the threaded value, mirroring the
/// transit-egress guard in frame/wg.rs (plan §4.3, §7 — the guard must
/// hold in BOTH directions, against the SAME MTU model).
pub(super) const WG_DEFAULT_OUTER_MTU: usize = 1500;

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

/// Whether an `inner_len`-byte inner packet fits the outer MTU once
/// WG-encapped. The single guard predicate the control-thread egress
/// uses, against the THREADED `outer_mtu` (#2300) — extracted so the
/// "real underlay MTU, not a 1500 constant" behavior is unit-testable
/// without a live socket.
#[inline]
fn wg_inner_fits_outer_mtu(inner_len: usize, outer_v6: bool, outer_mtu: usize) -> bool {
    wg_encapped_size(inner_len, outer_v6) <= outer_mtu
}

/// Socket/TUN read budget per poll tick — drains a bounded burst before
/// yielding so a flood cannot starve the TUN-read direction (and vice
/// versa).
const WG_RX_BURST: usize = 64;

/// poll(2) timeout cap when both directions are idle (#1889). Bounds
/// stop/join latency and worker-edge (relaxed atomic) pickup latency at
/// ~100ms; idle wakeups drop from 1,000/s (the prior 1ms sleep) to
/// ~10/s per tunnel. With every timer deadline >= 1s out the idle
/// timeout is effectively this constant — the deadline term only
/// becomes load-bearing if the cap is ever raised.
const WG_POLL_CAP_MS: i32 = 100;

/// Timer decision pass granularity (#1888 S5): expiry, T6/T7/T8, and
/// the handshake attempt machine run at most once per tick — plus
/// whenever a computed deadline is due (a mid-tick deadline gated on
/// the tick alone would saturate the poll timeout to 0 and busy-spin).
const WG_TIMER_TICK_NS: u64 = 1_000_000_000;

/// Consecutive fatal (non-WouldBlock) TUN read errors before the
/// thread exits (the TUN device was destroyed under us — poll returns
/// instantly forever, reads keep failing; exiting hands recovery to
/// the #1872 tombstone + backoff respawn machinery).
const WG_TUN_FATAL_READ_LIMIT: u32 = 8;

#[allow(clippy::too_many_arguments)]
pub(super) fn wg_control_loop(
    tunnel_name: String,
    tunnel_endpoint_id: u16,
    engine: Arc<crate::afxdp::wg::WgEngine>,
    listen_port: u16,
    outer_mtu: usize,
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
            eprintln!(
                "xpf-userspace-dp: WG control thread exiting tun={tunnel_name}: bind :{listen_port} failed: {err}"
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
        eprintln!(
            "xpf-userspace-dp: WG control thread exiting tun={tunnel_name}: set_nonblocking failed: {err}"
        );
        return;
    }
    // #2317: request the outer IP TOS / Traffic Class as ancillary data so
    // the RFC 6040 §4.2 decap ECN combine has the outer ECN to fold into
    // the decrypted inner packet. The kernel UDP socket strips the outer
    // IP header before the WG record reaches userspace, so `IP_RECVTOS`
    // (v4 / v4-mapped) and `IPV6_RECVTCLASS` (v6) are the only way to see
    // it. Best-effort: a kernel that rejects the option just leaves the
    // outer ECN unseen and the combine is skipped (the pre-#2317
    // behavior) — never fatal to the tunnel.
    set_recv_tos_options(socket.as_raw_fd(), socket_is_v6);

    // Attach to the persistent wgN TUN (Go pre-created it; open_tun
    // attaches to the existing device by name). Non-blocking.
    let mut tun = match open_tun(&tunnel_name) {
        Ok((file, _actual_name)) => file,
        Err(err) => {
            eprintln!(
                "xpf-userspace-dp: WG control thread exiting tun={tunnel_name}: open_tun failed: {err}"
            );
            record_local_tunnel_exception(&recent_exceptions, &tunnel_name, err);
            return;
        }
    };
    if let Err(err) = set_fd_nonblocking(tun.as_raw_fd()) {
        eprintln!(
            "xpf-userspace-dp: WG control thread exiting tun={tunnel_name}: tun set_nonblocking failed: {err}"
        );
        record_local_tunnel_exception(&recent_exceptions, &tunnel_name, err);
        return;
    }

    run_wg_control_loop(
        &tunnel_name,
        &engine,
        &socket,
        socket_is_v6,
        tun,
        outer_mtu,
        &recent_exceptions,
        &stop,
    );
    // #1866 D3: clean stop-flag exit (teardown) — rare, one line.
    eprintln!("xpf-userspace-dp: WG control thread stopped tun={tunnel_name}");
    let _ = tunnel_endpoint_id;
}

/// One inbound datagram's disposition. Handshake completions must be
/// handled INLINE at this site — before the same iteration's TUN
/// burst — so the attempt machine's later pass cannot erase legitimate
/// post-completion state (plan v9, Codex r5/r6 ordering traces).
enum InboundOutcome {
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
    fn authenticated(&self) -> bool {
        !matches!(self, InboundOutcome::Unauthenticated)
    }

    /// The authenticated peer's pubkey, if any (#1434 per-peer endpoint
    /// learning).
    fn peer(&self) -> Option<[u8; 32]> {
        match self {
            InboundOutcome::Unauthenticated => None,
            InboundOutcome::Authenticated(pk)
            | InboundOutcome::CompletedInitiator(pk)
            | InboundOutcome::CompletedResponder(pk) => Some(*pk),
        }
    }
}

/// #1888 S5 handshake attempt window (thread-local state machine).
/// While active, initiations retry every REKEY_TIMEOUT (5s) BYPASSING
/// the confirmed-session gate (the attempt encodes the decision to
/// replace the current session — losing one datagram must not starve a
/// rekey until the 180s hard expiry); the window ends on SUCCESS (the
/// peer's current-session identity changed — clock comparisons across
/// the install seam are fragile, so identity it is) or GIVE-UP at
/// REKEY_ATTEMPT_TIME (90s), which releases the pending reservation so
/// a stale msg2 cannot complete later.
struct HandshakeAttempt {
    started_ns: u64,
    last_tx_ns: u64,
    baseline_session: Option<u32>,
}

/// Why an attempt is being started — picks the telemetry counter.
#[derive(Clone, Copy, PartialEq, Eq)]
enum AttemptTrigger {
    /// Configured-initiator bring-up (thread start).
    BringUp,
    /// Worker NoSession edge (gated on !confirmed, today's rule).
    NoSessionEdge,
    /// T1/T2/send-side-T3 rekey edge (ungated — replaces a live
    /// confirmed-but-stale session).
    RekeyEdge,
    /// T7 no-reply reinit.
    DeadPeer,
    /// T8 persistent-keepalive due with no usable session.
    KeepaliveNoSession,
}

/// poll(2) wait disposition.
enum PollWait {
    /// Timed out — run the timer arm and loop.
    Idle,
    /// At least one fd is readable (or EINTR — treat as a wakeup).
    Ready,
    /// Unrecoverable fd state — exit the thread (tombstone respawn is
    /// the recovery path).
    Fatal(&'static str),
}

/// Block in poll(2) on {socket, tun} POLLIN with `timeout_ms`.
/// Fatal-exit policy (plan v6/v9): the TUN's POLLERR/POLLHUP/POLLNVAL
/// are fatal (device destroyed/downed under us — poll would return
/// instantly forever); the UDP socket's POLLNVAL is fatal (fd invalid);
/// UDP POLLERR/POLLHUP are NOT fatal (ICMP errors are normal and are
/// drained via the recv_from error arm).
fn wg_poll_wait(socket_fd: i32, tun_fd: i32, timeout_ms: i32) -> PollWait {
    let mut fds = [
        libc::pollfd {
            fd: socket_fd,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: tun_fd,
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    let rc = unsafe { libc::poll(fds.as_mut_ptr(), 2, timeout_ms) };
    if rc < 0 {
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::Interrupted {
            return PollWait::Ready; // spurious wakeup — re-run the loop
        }
        return PollWait::Fatal("poll_failed");
    }
    if rc == 0 {
        return PollWait::Idle;
    }
    if fds[1].revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
        return PollWait::Fatal("tun_revents");
    }
    if fds[0].revents & libc::POLLNVAL != 0 {
        return PollWait::Fatal("socket_pollnval");
    }
    PollWait::Ready
}

/// Clamp the next timer deadline into a poll(2) timeout in ms
/// (explicit ns->ms conversion, capped at WG_POLL_CAP_MS).
fn poll_timeout_ms(next_deadline_ns: u64, now_ns: u64) -> i32 {
    ((next_deadline_ns.saturating_sub(now_ns) / 1_000_000).min(WG_POLL_CAP_MS as u64)) as i32
}

/// The per-tunnel control loop proper, on pre-opened fds so the loop
/// logic is unit-testable without a real TUN device (the production
/// caller binds the socket and attaches the persistent wgN TUN above).
#[allow(clippy::too_many_arguments)]
fn run_wg_control_loop(
    tunnel_name: &str,
    engine: &crate::afxdp::wg::WgEngine,
    socket: &UdpSocket,
    socket_is_v6: bool,
    mut tun: std::fs::File,
    outer_mtu: usize,
    recent_exceptions: &Arc<Mutex<VecDeque<ExceptionStatus>>>,
    stop: &AtomicBool,
) {
    use std::collections::HashMap;
    // #1434 multi-peer: the control loop tracks PER-PEER state. The
    // effective endpoint (configured initiator endpoint, or the source
    // LEARNED from an authenticated inbound datagram for a responder-only
    // peer — WG endpoint roaming) is per-peer, as is the handshake
    // attempt window. Egress TUN packets are LPM-routed to the peer that
    // owns the inner destination's AllowedIPs (cryptokey routing); each
    // peer drives its own keepalive/rekey timers.
    let peer_pubkeys: Vec<[u8; 32]> = engine.peer_pubkeys();
    let mut effective_endpoints: HashMap<[u8; 32], SocketAddr> = HashMap::new();
    for (pk, ep) in engine.peer_endpoints() {
        if let Some(ep) = ep {
            effective_endpoints.insert(pk, ep);
        }
    }
    // 64 KiB scratch for both directions (max IP packet; WG records are
    // smaller). Single allocation at thread start — no per-packet alloc.
    let mut sock_buf = vec![0u8; 65_535];
    let mut tun_buf = vec![0u8; 65_535];
    let mut decap_buf = vec![0u8; 65_535];
    let mut encap_buf = vec![0u8; 65_535];

    let socket_fd = socket.as_raw_fd();
    let tun_fd = tun.as_raw_fd();

    // #1888 S5 / #1434 per-peer timer state. `next_deadline` starts at 0
    // so the FIRST iteration always runs a timer pass and computes real
    // deadlines (u64::MAX = no deadline; never a stale past value).
    let mut attempts: HashMap<[u8; 32], HandshakeAttempt> = HashMap::new();
    let mut next_deadline: u64 = 0;
    let mut last_timer_pass_ns: u64 = 0;
    let mut tun_fatal_reads: u32 = 0;

    // Initial initiator bring-up: every peer with a configured endpoint
    // starts a real attempt window (BringUp class) so the REKEY_TIMEOUT/
    // REKEY_ATTEMPT_TIME discipline applies from packet one and boot does
    // not double-fire.
    for pk in &peer_pubkeys {
        if let Some(&ep) = effective_endpoints.get(pk) {
            if let Some(att) = start_attempt(
                engine,
                socket,
                socket_is_v6,
                pk,
                ep,
                AttemptTrigger::BringUp,
                monotonic_nanos(),
                &mut encap_buf,
                tunnel_name,
                recent_exceptions,
            ) {
                attempts.insert(*pk, att);
            }
        }
    }

    while !stop.load(Ordering::Relaxed) {
        let mut did_work = false;

        // --- Inbound: kernel socket → engine → TUN ---
        for _ in 0..WG_RX_BURST {
            // #2317: recvmsg (not recv_from) so the outer IP TOS /
            // Traffic Class arrives as ancillary data — the only way to
            // see the outer ECN the kernel UDP stack stripped with the
            // outer IP header. `outer_ecn` is None when no TOS cmsg
            // arrived (kernel ignored the sockopt); the decap combine is
            // then skipped.
            match wg_recvmsg(socket, &mut sock_buf) {
                Ok(WgRecv {
                    len,
                    from,
                    outer_ecn,
                }) if len > 0 => {
                    did_work = true;
                    // Learn / refresh the peer endpoint from `from` ONLY
                    // after the datagram cryptographically authenticates
                    // (Codex r3 MAJOR): updating on any inbound packet
                    // would let a spoofed source redirect our encrypted
                    // egress.
                    let outcome = dispatch_inbound(
                        engine,
                        socket,
                        socket_is_v6,
                        &mut tun,
                        &sock_buf[..len],
                        from,
                        outer_ecn,
                        &mut decap_buf,
                        &mut encap_buf,
                        tunnel_name,
                        recent_exceptions,
                    );
                    // #1434: learn THIS peer's endpoint from `from` (WG
                    // endpoint roaming is per-peer). Only the
                    // authenticated peer's egress target is updated — a
                    // spoofed source for one peer cannot redirect another
                    // peer's traffic.
                    if let Some(peer) = outcome.peer() {
                        effective_endpoints.insert(peer, canonicalize_endpoint(from));
                    }
                    // Completion-site cleanup (plan v9, Codex r5/r6):
                    // a handshake completion obsoletes any request
                    // edges armed by during-attempt egress on the old
                    // session — drain them HERE, before this
                    // iteration's TUN burst, so post-completion egress
                    // can legitimately re-arm them. (The stale T7 arm
                    // was already cleared inside the engine completion
                    // path — a valid msg1/msg2 is an authenticated
                    // receive.)
                    match outcome {
                        InboundOutcome::CompletedInitiator(peer) => {
                            let _ = engine.take_rekey_request();
                            let _ = engine.take_handshake_request();
                            // Post-msg2 key-confirmation keepalive
                            // (Codex r2 C4, Linux receive.c parity):
                            // the peer's responder-role session is
                            // unconfirmed until it authenticates our
                            // first transport record. Send one
                            // keepalive now so a handshake we
                            // initiated with nothing to send does not
                            // leave the peer's egress blackholed.
                            send_keepalive(
                                engine,
                                socket,
                                socket_is_v6,
                                &peer,
                                canonicalize_endpoint(from),
                                crate::afxdp::wg::timers::KeepaliveKind::Passive,
                                monotonic_nanos(),
                                &mut encap_buf,
                                tunnel_name,
                                recent_exceptions,
                            );
                        }
                        InboundOutcome::CompletedResponder(_) => {
                            let _ = engine.take_rekey_request();
                            let _ = engine.take_handshake_request();
                        }
                        _ => {}
                    }
                }
                Ok(_) => break,
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    record_local_tunnel_exception(
                        recent_exceptions,
                        tunnel_name,
                        format!("wg_socket_recv:{e}"),
                    );
                    break;
                }
            }
        }

        // --- Egress: TUN → engine → kernel socket ---
        // #1434 cryptokey routing: each inner packet read off the TUN is
        // routed to the peer whose AllowedIPs cover its DESTINATION
        // (longest-prefix match), then encapped toward THAT peer's
        // effective endpoint. A packet whose dst no peer claims, or whose
        // peer has no known endpoint yet (responder-only, pre-handshake),
        // is dropped (counted) — there is nowhere to send it.
        for _ in 0..WG_RX_BURST {
            match tun.read(&mut tun_buf) {
                Ok(len) if len > 0 => {
                    did_work = true;
                    tun_fatal_reads = 0;
                    let inner = &tun_buf[..len];
                    // The TUN delivers a bare inner IP packet (no L2).
                    // Sniff the family from the version nibble.
                    let af = match inner.first().map(|b| b >> 4) {
                        Some(4) => libc::AF_INET as u8,
                        Some(6) => libc::AF_INET6 as u8,
                        _ => {
                            WgCounters::bump(&engine.counters().tun_rx_drops_no_endpoint);
                            continue;
                        }
                    };
                    let Some(dst) = crate::afxdp::gre::inner_dst_ip(inner, af) else {
                        WgCounters::bump(&engine.counters().tun_rx_drops_no_endpoint);
                        continue;
                    };
                    let Some((pk, _ep)) = engine.peer_for_dest(dst) else {
                        // No peer owns this destination's AllowedIPs.
                        WgCounters::bump(&engine.counters().tun_rx_drops_no_endpoint);
                        continue;
                    };
                    let Some(&ep) = effective_endpoints.get(&pk) else {
                        // The owning peer has no known endpoint yet
                        // (responder-only, learned at runtime). Drop —
                        // the reply path opens once the peer is heard
                        // from (#1865 endpoint-learning, now per-peer).
                        WgCounters::bump(&engine.counters().tun_rx_drops_no_endpoint);
                        continue;
                    };
                    encap_and_send(
                        engine,
                        socket,
                        socket_is_v6,
                        &pk,
                        ep,
                        inner,
                        &mut encap_buf,
                        outer_mtu,
                        tunnel_name,
                        recent_exceptions,
                    );
                }
                Ok(_) => break,
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    tun_fatal_reads += 1;
                    record_local_tunnel_exception(
                        recent_exceptions,
                        tunnel_name,
                        format!("wg_tun_read:{e}"),
                    );
                    break;
                }
            }
        }
        if tun_fatal_reads >= WG_TUN_FATAL_READ_LIMIT {
            // Device destroyed/downed under us: poll would report the
            // TUN ready forever while reads fail — exit cleanly and
            // let the #1872 tombstone + backoff respawn recover.
            record_local_tunnel_exception(
                recent_exceptions,
                tunnel_name,
                "wg_tun_fatal_reads:exiting".to_string(),
            );
            return;
        }

        // --- #1888 S5 timer arm (replaces the 1s re-init check) ---
        // Runs when the 1s tick elapses OR a computed deadline is due
        // (gating on the tick alone lets a mid-tick deadline saturate
        // the poll timeout to 0 and busy-spin until the tick boundary).
        let now = monotonic_nanos();
        let tick_due = now.saturating_sub(last_timer_pass_ns) >= WG_TIMER_TICK_NS;
        if tick_due || now >= next_deadline {
            next_deadline = crate::afxdp::wg::timers::WG_NO_DEADLINE_NS;
            // Session expiry is engine-wide (sweeps every peer's
            // sessions); run it once per pass, not per peer.
            engine.expire_sessions(now);
            // #1434: drive each peer's keepalive/rekey timers and
            // attempt machine independently. The earliest deadline
            // across ALL peers gates the poll timeout.
            for pk in &peer_pubkeys {
                let effective_endpoint = effective_endpoints.get(pk).copied();
                let endpoint_known = effective_endpoint.is_some();
                let actions = engine.timer_pass_for_peer(pk, now, endpoint_known);
                if let Some(kind) = actions.send_keepalive {
                    if let Some(ep) = effective_endpoint {
                        send_keepalive(
                            engine, socket, socket_is_v6, pk, ep, kind, now,
                            &mut encap_buf, tunnel_name, recent_exceptions,
                        );
                    } else {
                        pace_keepalive_skip(engine, pk, kind, now);
                    }
                }
                let mut attempt = attempts.remove(pk);
                let attempt_deadline = drive_attempt_machine(
                    engine,
                    socket,
                    socket_is_v6,
                    pk,
                    effective_endpoint,
                    &actions,
                    now,
                    &mut attempt,
                    &mut encap_buf,
                    tunnel_name,
                    recent_exceptions,
                );
                if let Some(att) = attempt {
                    attempts.insert(*pk, att);
                }
                next_deadline = next_deadline
                    .min(actions.next_deadline_ns)
                    .min(attempt_deadline);
            }
            if tick_due {
                // Only tick-condition runs advance the 1s anchor —
                // frequent sub-second deadline runs must not starve
                // the periodic tick work (expiry).
                last_timer_pass_ns = now;
            }
        }

        if !did_work {
            match wg_poll_wait(socket_fd, tun_fd, poll_timeout_ms(next_deadline, now)) {
                PollWait::Idle | PollWait::Ready => {}
                PollWait::Fatal(reason) => {
                    record_local_tunnel_exception(
                        recent_exceptions,
                        tunnel_name,
                        format!("wg_poll_fatal:{reason}"),
                    );
                    return;
                }
            }
        }
    }
}

/// Start a handshake attempt: consume the T7 obligation (it transfers
/// to the attempt machine), advance the T8 anchor when T8 triggered,
/// count the timer-driven rekey classes, send the first initiation,
/// and record the baseline session identity the success check compares
/// against.
#[allow(clippy::too_many_arguments)]
fn start_attempt(
    engine: &crate::afxdp::wg::WgEngine,
    socket: &UdpSocket,
    socket_is_v6: bool,
    peer_pubkey: &[u8; 32],
    endpoint: SocketAddr,
    trigger: AttemptTrigger,
    now_ns: u64,
    encap_buf: &mut [u8],
    tunnel_name: &str,
    recent_exceptions: &Arc<Mutex<VecDeque<ExceptionStatus>>>,
) -> Option<HandshakeAttempt> {
    engine.clear_t7_arm(peer_pubkey);
    let counters = engine.counters();
    match trigger {
        AttemptTrigger::RekeyEdge => WgCounters::bump(&counters.rekeys_initiated_age),
        AttemptTrigger::DeadPeer => WgCounters::bump(&counters.rekeys_initiated_dead_peer),
        AttemptTrigger::KeepaliveNoSession => {
            WgCounters::bump(&counters.rekeys_initiated_keepalive_no_session);
            engine.note_t8_attempt(peer_pubkey, now_ns);
        }
        AttemptTrigger::BringUp | AttemptTrigger::NoSessionEdge => {}
    }
    let baseline_session = engine.current_session_local_index(peer_pubkey);
    drive_initiation(
        engine,
        socket,
        socket_is_v6,
        peer_pubkey,
        endpoint,
        encap_buf,
        tunnel_name,
        recent_exceptions,
    );
    Some(HandshakeAttempt {
        started_ns: now_ns,
        last_tx_ns: now_ns,
        baseline_session,
    })
}

/// One step of the handshake attempt machine (runs inside the timer
/// arm). Returns the machine's next deadline (retry or give-up) for
/// the poll-timeout computation; WG_NO_DEADLINE_NS when idle.
#[allow(clippy::too_many_arguments)]
fn drive_attempt_machine(
    engine: &crate::afxdp::wg::WgEngine,
    socket: &UdpSocket,
    socket_is_v6: bool,
    peer_pubkey: &[u8; 32],
    effective_endpoint: Option<SocketAddr>,
    actions: &crate::afxdp::wg::timers::TimerActions,
    now_ns: u64,
    attempt: &mut Option<HandshakeAttempt>,
    encap_buf: &mut [u8],
    tunnel_name: &str,
    recent_exceptions: &Arc<Mutex<VecDeque<ExceptionStatus>>>,
) -> u64 {
    use crate::afxdp::wg::session::{REKEY_ATTEMPT_TIME_NS, REKEY_TIMEOUT_NS};
    use crate::afxdp::wg::timers::{InitiateReason, WG_NO_DEADLINE_NS};

    // End checks. SUCCESS is an identity test: the current session's
    // local_index changed from the attempt-start baseline (and is
    // present — a mid-attempt expiry clearing current to None must NOT
    // read as success). The success path mutates NOTHING beyond the
    // attempt slot: all success-side cleanup ran inline at the
    // authenticated completion site, before any same-iteration egress
    // (plan v9).
    if let Some(att) = attempt.as_ref() {
        let current = engine.current_session_local_index(peer_pubkey);
        if current.is_some() && current != att.baseline_session {
            *attempt = None;
        } else if now_ns.saturating_sub(att.started_ns) >= REKEY_ATTEMPT_TIME_NS {
            // GIVE-UP: release the pending reservation (a stale msg2
            // must not complete later), clear the T7 arm (egress
            // during the attempt re-armed it; carried across the
            // boundary it would reopen a fresh window next tick), and
            // drain the request edges armed by during-attempt sends.
            // Only traffic AFTER this boundary may re-trigger.
            engine.abort_pending_for_peer(peer_pubkey);
            engine.clear_t7_arm(peer_pubkey);
            let _ = engine.take_rekey_request();
            let _ = engine.take_handshake_request();
            *attempt = None;
            // Codex code-r1 BLOCKER: `actions` was computed BEFORE this
            // cleanup — a T7 DeadPeer (or stale-edge) trigger captured
            // in it would resurrect a fresh 90s window in the SAME
            // pass, bypassing the boundary we just enforced. Return
            // without evaluating triggers; the next pass (<=1s tick)
            // recomputes actions from the post-cleanup state, where a
            // genuinely-due T8 still starts its fresh window (AGY F4).
            return WG_NO_DEADLINE_NS;
        }
    }

    // Retry while active, paced by REKEY_TIMEOUT, BYPASSING the
    // confirmed-session gate (the attempt encodes the decision).
    if let Some(att) = attempt.as_mut() {
        if now_ns.saturating_sub(att.last_tx_ns) >= REKEY_TIMEOUT_NS {
            if let Some(ep) = effective_endpoint {
                drive_initiation(
                    engine,
                    socket,
                    socket_is_v6,
                    peer_pubkey,
                    ep,
                    encap_buf,
                    tunnel_name,
                    recent_exceptions,
                );
            }
            // A failed/skipped send still advances the pacing anchor
            // (skip-pacing — the deadline must be strictly future).
            att.last_tx_ns = now_ns;
        }
        return (att.last_tx_ns.saturating_add(REKEY_TIMEOUT_NS))
            .min(att.started_ns.saturating_add(REKEY_ATTEMPT_TIME_NS));
    }

    // No attempt active: evaluate the start triggers per the plan's §3
    // initiation-predicate table. Edges are consume-once; a consumed
    // edge with no known endpoint is dropped (any subsequent send on a
    // stale session re-arms it, so it cannot be permanently lost).
    let rekey_edge = engine.take_rekey_request();
    let nosession_edge = engine.take_handshake_request();
    let trigger = if rekey_edge {
        Some(AttemptTrigger::RekeyEdge)
    } else if nosession_edge && !engine.peer_has_confirmed_session(peer_pubkey) {
        Some(AttemptTrigger::NoSessionEdge)
    } else {
        match actions.initiate {
            Some(InitiateReason::DeadPeer) => Some(AttemptTrigger::DeadPeer),
            Some(InitiateReason::KeepaliveNoSession) => {
                Some(AttemptTrigger::KeepaliveNoSession)
            }
            None => None,
        }
    };
    if let (Some(trigger), Some(ep)) = (trigger, effective_endpoint) {
        *attempt = start_attempt(
            engine,
            socket,
            socket_is_v6,
            peer_pubkey,
            ep,
            trigger,
            now_ns,
            encap_buf,
            tunnel_name,
            recent_exceptions,
        );
        return now_ns.saturating_add(REKEY_TIMEOUT_NS);
    }
    WG_NO_DEADLINE_NS
}

/// Emit one keepalive (T6 passive / T8 persistent / post-msg2
/// confirmation) toward the peer endpoint. Failure paths advance the
/// corresponding pacing anchor so a due-but-unsendable keepalive can
/// never leave a past deadline spinning the poll loop (skip-pacing).
#[allow(clippy::too_many_arguments)]
fn send_keepalive(
    engine: &crate::afxdp::wg::WgEngine,
    socket: &UdpSocket,
    socket_is_v6: bool,
    peer_pubkey: &[u8; 32],
    endpoint: SocketAddr,
    kind: crate::afxdp::wg::timers::KeepaliveKind,
    now_ns: u64,
    encap_buf: &mut [u8],
    tunnel_name: &str,
    recent_exceptions: &Arc<Mutex<VecDeque<ExceptionStatus>>>,
) {
    use crate::afxdp::wg::timers::KeepaliveKind;
    match engine.create_keepalive(peer_pubkey, encap_buf) {
        Ok(outcome) => {
            match wg_send_to(socket, socket_is_v6, &encap_buf[..outcome.len], endpoint) {
                Ok(_) => {
                    let counters = engine.counters();
                    match kind {
                        KeepaliveKind::Passive => {
                            WgCounters::bump(&counters.keepalives_tx_passive)
                        }
                        KeepaliveKind::Persistent => {
                            WgCounters::bump(&counters.keepalives_tx_persistent);
                            engine.note_t8_attempt(peer_pubkey, now_ns);
                        }
                    }
                }
                Err(e) => {
                    WgCounters::bump(&engine.counters().transport_send_errors);
                    record_local_tunnel_exception(
                        recent_exceptions,
                        tunnel_name,
                        format!("wg_keepalive_send:{e}"),
                    );
                    pace_keepalive_skip(engine, peer_pubkey, kind, now_ns);
                }
            }
        }
        // No usable session (engine gate) — T8 handles this via its
        // KeepaliveNoSession initiation; pace so we don't re-fire
        // every iteration.
        Err(_) => pace_keepalive_skip(engine, peer_pubkey, kind, now_ns),
    }
}

/// Skip-pacing by keepalive class (AGY r3 G1).
fn pace_keepalive_skip(
    engine: &crate::afxdp::wg::WgEngine,
    peer_pubkey: &[u8; 32],
    kind: crate::afxdp::wg::timers::KeepaliveKind,
    now_ns: u64,
) {
    match kind {
        crate::afxdp::wg::timers::KeepaliveKind::Passive => {
            engine.pace_passive_keepalive_skip(peer_pubkey, now_ns)
        }
        crate::afxdp::wg::timers::KeepaliveKind::Persistent => {
            engine.note_t8_attempt(peer_pubkey, now_ns)
        }
    }
}

/// Bind the WG listen socket./// Bind the WG listen socket. Prefer a v6 dual-stack bind so a single
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
    crate::afxdp::wg::canonicalize_endpoint(addr)
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

/// #2317: enable receiving the outer IP TOS / Traffic Class as ancillary
/// data on the WG listen socket so the RFC 6040 §4.2 decap ECN combine
/// can fold the outer ECN into the decrypted inner packet (the kernel
/// UDP socket strips the outer IP header before the WG record reaches
/// userspace). Sets `IP_RECVTOS` on every socket (it governs both native
/// v4 and the v4-mapped datagrams the dual-stack v6 socket delivers) and
/// additionally `IPV6_RECVTCLASS` on the dual-stack v6 socket for native
/// v6 peers. Best-effort: a failure is logged via the return value being
/// ignored by the caller — the combine is simply skipped when no cmsg
/// arrives, which is the pre-#2317 behavior, so this is never fatal.
/// #2317: enable outer-TOS ancillary delivery (`IP_RECVTOS` /
/// `IPV6_RECVTCLASS`) on a WG UDP socket so the decap ECN combine can see
/// the outer DS byte the kernel UDP stack otherwise strips. Best-effort:
/// a kernel that rejects the sockopt (very old, or a restricted sandbox)
/// simply delivers no TOS cmsg and the combine is skipped (outer_ecn =
/// None). A failure is logged once here — this runs only at socket
/// creation, never on the packet path — so an operator can see why ECN
/// propagation is inactive.
fn set_recv_tos_options(fd: i32, socket_is_v6: bool) {
    let on: libc::c_int = 1;
    // IP_RECVTOS — outer IPv4 TOS (also delivered for v4-mapped peers on
    // the dual-stack socket).
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_RECVTOS,
            &on as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        eprintln!(
            "xpf-wg: IP_RECVTOS not enabled (fd {fd}): {} — decap ECN combine inactive for v4",
            io::Error::last_os_error()
        );
    }
    if socket_is_v6 {
        // IPV6_RECVTCLASS — outer IPv6 Traffic Class for native v6 peers.
        let rc6 = unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IPV6,
                libc::IPV6_RECVTCLASS,
                &on as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if rc6 != 0 {
            eprintln!(
                "xpf-wg: IPV6_RECVTCLASS not enabled (fd {fd}): {} — decap ECN combine inactive for v6",
                io::Error::last_os_error()
            );
        }
    }
}

/// #2317: outcome of a single `recvmsg` on the WG socket — the datagram
/// length plus the 2-bit outer ECN parsed from the `IP_RECVTOS` /
/// `IPV6_RECVTCLASS` ancillary data (None when no TOS cmsg arrived, e.g.
/// the kernel did not honor the sockopt, in which case the decap combine
/// is skipped).
struct WgRecv {
    len: usize,
    from: SocketAddr,
    outer_ecn: Option<u8>,
}

/// #2334: 256-byte recvmsg control buffer, over-aligned to 8 bytes so the
/// `cmsghdr` header-field reads the `CMSG_*` macros perform through a
/// `*const cmsghdr` pointing into this storage are naturally aligned.
///
/// A bare `[u8; N]` has alignment 1; `cmsghdr` (containing a `size_t`
/// `cmsg_len` plus two `c_int`s on LP64) has alignment 8. `CMSG_FIRSTHDR`
/// returns the buffer base and `parse_outer_ecn_from_cmsg` then reads the
/// multi-byte `cmsg_len` / `cmsg_level` / `cmsg_type` fields through that
/// pointer — an unaligned dereference (UB in Rust, a SIGBUS / alignment-
/// trap risk on strict-alignment targets such as ARMv8) unless the base
/// is `cmsghdr`-aligned. `align(8)` covers `align_of::<cmsghdr>()`; the
/// static assertion below fails to compile if that ever regresses.
#[repr(C, align(8))]
struct CmsgBuf([u8; 256]);

// Fail-on-revert sentinel: the control buffer MUST be at least as aligned
// as `cmsghdr`, or the header-field reads in `parse_outer_ecn_from_cmsg`
// become unaligned dereferences (#2334). A future change that drops the
// `#[repr(align(8))]` (or replaces the wrapper with a bare `[u8; N]`)
// breaks compilation here rather than reintroducing latent UB.
const _: () = assert!(
    std::mem::align_of::<CmsgBuf>() >= std::mem::align_of::<libc::cmsghdr>(),
    "CmsgBuf must be at least cmsghdr-aligned (see #2334)"
);

/// #2317: receive one WG datagram via `recvmsg`, capturing the outer IP
/// TOS / Traffic Class from the ancillary `IP_RECVTOS` /
/// `IPV6_RECVTCLASS` control message. Replaces `recv_from` so the outer
/// ECN — stripped by the kernel UDP stack with the outer IP header —
/// reaches the RFC 6040 §4.2 decap combine.
///
/// The cmsg buffer is a fixed 256-byte stack array (a single TOS cmsg is
/// ~16-20 bytes; 256 covers both the v4 and v6 TOS cmsgs with margin and
/// never allocates on the hot path). It is wrapped in the 8-byte-aligned
/// `CmsgBuf` so the `cmsghdr` header-field reads are aligned (#2334).
/// `MSG_TRUNC`/`MSG_CTRUNC` are not requested — the data buffer is the
/// loop's 64 KiB scratch (max IP datagram) so transport records never
/// truncate, and a truncated cmsg only loses the (best-effort) ECN, not
/// the datagram.
fn wg_recvmsg(socket: &UdpSocket, buf: &mut [u8]) -> io::Result<WgRecv> {
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut cmsg_space = CmsgBuf([0u8; 256]);
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = &mut storage as *mut _ as *mut libc::c_void;
    msg.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_space.0.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_space.0.len() as _;

    let n = unsafe { libc::recvmsg(socket.as_raw_fd(), &mut msg, 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    let len = n as usize;
    let from = sockaddr_storage_to_socketaddr(&storage, msg.msg_namelen)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "recvmsg bad sockaddr"))?;
    // If the kernel truncated the ancillary data (MSG_CTRUNC), the cmsg
    // chain may be incomplete — don't trust it for the best-effort ECN.
    // The 256-byte control buffer is sized so this never triggers for a
    // single ~20-byte TOS cmsg, but skip defensively rather than walk a
    // partial chain (worst case: the decap combine is skipped this once).
    let outer_ecn = if msg.msg_flags & libc::MSG_CTRUNC != 0 {
        None
    } else {
        parse_outer_ecn_from_cmsg(&msg)
    };
    Ok(WgRecv {
        len,
        from,
        outer_ecn,
    })
}

/// #2317: walk the control-message chain of a populated `msghdr` and
/// return the 2-bit ECN (low 2 bits of the DS byte) from the first
/// `IP_RECVTOS` / `IPV6_TCLASS` cmsg found. `IP_RECVTOS` delivers the
/// IPv4 TOS as a single byte (some kernels pad it into an `int`-sized
/// payload); `IPV6_TCLASS` delivers the Traffic Class as an `int`. We
/// read the FIRST payload byte in both cases — the DS byte is the
/// low-order byte on the little-endian hosts xpf targets and, more
/// robustly, IP_RECVTOS's documented payload is a `u8`. Returns `None`
/// when no TOS cmsg is present (kernel ignored the sockopt, or a
/// truncated cmsg).
fn parse_outer_ecn_from_cmsg(msg: &libc::msghdr) -> Option<u8> {
    // SAFETY: `msg` is a fully-initialized msghdr returned by recvmsg
    // (msg_control / msg_controllen describe a valid buffer). The control
    // buffer is the 8-byte-aligned `CmsgBuf` (#2334), so the `cmsghdr`
    // base CMSG_FIRSTHDR/CMSG_NXTHDR return — and therefore the multi-byte
    // `cmsg_len` / `cmsg_level` / `cmsg_type` header-field reads below —
    // are naturally aligned (cmsghdr has alignment 8 on LP64). The single
    // payload byte at CMSG_DATA is read only after the `cmsg_len` guard
    // confirms it lies within the cmsg.
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(msg);
        while !cmsg.is_null() {
            let level = (*cmsg).cmsg_level;
            let ctype = (*cmsg).cmsg_type;
            let is_v4_tos = level == libc::IPPROTO_IP && ctype == libc::IP_TOS;
            let is_v6_tclass = level == libc::IPPROTO_IPV6 && ctype == libc::IPV6_TCLASS;
            if is_v4_tos || is_v6_tclass {
                let data = libc::CMSG_DATA(cmsg);
                // cmsg_len includes the header; the payload starts at
                // CMSG_DATA. Guard with `>=` against a malformed/truncated
                // cmsg_len shorter than the header offset (a raw
                // subtraction would underflow the unsigned length): require
                // cmsg_len to cover the header plus at least one payload
                // byte before reading the DS byte.
                let data_off = data as usize - cmsg as usize;
                if (*cmsg).cmsg_len as usize >= data_off + 1 {
                    let ds = *data;
                    return Some(ds & 0x03);
                }
            }
            cmsg = libc::CMSG_NXTHDR(msg, cmsg);
        }
    }
    None
}

/// #2317: convert a `recvmsg`-populated `sockaddr_storage` to a Rust
/// `SocketAddr`. The dual-stack v6 socket reports v4 peers as v4-mapped
/// IPv6 (caller `canonicalize_endpoint`s the result, as the prior
/// `recv_from` path did). Returns `None` for an unrecognized family.
fn sockaddr_storage_to_socketaddr(
    storage: &libc::sockaddr_storage,
    len: libc::socklen_t,
) -> Option<SocketAddr> {
    match storage.ss_family as libc::c_int {
        libc::AF_INET => {
            if (len as usize) < std::mem::size_of::<libc::sockaddr_in>() {
                return None;
            }
            // SAFETY: family is AF_INET and len covers a sockaddr_in.
            let sin = unsafe { &*(storage as *const _ as *const libc::sockaddr_in) };
            let ip = std::net::Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
            let port = u16::from_be(sin.sin_port);
            Some(SocketAddr::new(std::net::IpAddr::V4(ip), port))
        }
        libc::AF_INET6 => {
            if (len as usize) < std::mem::size_of::<libc::sockaddr_in6>() {
                return None;
            }
            // SAFETY: family is AF_INET6 and len covers a sockaddr_in6.
            let sin6 = unsafe { &*(storage as *const _ as *const libc::sockaddr_in6) };
            let ip = std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr);
            let port = u16::from_be(sin6.sin6_port);
            // #2995: preserve `sin6_scope_id` (and `sin6_flowinfo`). A
            // link-local WG peer endpoint (`fe80::/10`) carries the
            // receiving interface scope in the kernel-populated
            // `sockaddr_in6`; `SocketAddr::new` would drop it (scope_id =
            // 0), and the next `wg_send_to` toward that learned endpoint
            // would be rejected with EINVAL/ENODEV (a link-local
            // destination requires a non-zero scope). For a global v6
            // endpoint `sin6_scope_id` is already 0, so this is a no-op
            // there. `sin6_scope_id` / `sin6_flowinfo` are stored in host
            // byte order by the kernel, so no byte-swap is applied.
            Some(SocketAddr::V6(std::net::SocketAddrV6::new(
                ip,
                port,
                sin6.sin6_flowinfo,
                sin6.sin6_scope_id,
            )))
        }
        _ => None,
    }
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
    // #1865: create_initiation Ok/Err accounting is engine-internal
    // (hs_initiations_created / hs_initiation_build_failures); the
    // send failure is OURS to count — created↑ + send_errors↑ +
    // completions flat is the #1736 EINVAL fingerprint.
    if let Ok(_local_index) = engine.create_initiation(peer_pubkey, out) {
        let len = crate::afxdp::wg::WG_MSG_INIT_LEN;
        match wg_send_to(socket, socket_is_v6, &out[..len], endpoint) {
            Ok(_) => {
                // #1888 S5: a handshake initiation on the wire is an
                // authenticated SEND — clears the T6 arm, paces T8.
                engine.note_handshake_sent(peer_pubkey, monotonic_nanos());
            }
            Err(e) => {
                WgCounters::bump(&engine.counters().hs_send_errors);
                record_local_tunnel_exception(
                    recent_exceptions,
                    tunnel_name,
                    format!("wg_initiation_send:{endpoint}:{e}"),
                );
            }
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
fn dispatch_inbound(
    engine: &crate::afxdp::wg::WgEngine,
    socket: &UdpSocket,
    socket_is_v6: bool,
    tun: &mut std::fs::File,
    datagram: &[u8],
    from: SocketAddr,
    outer_ecn: Option<u8>,
    decap_buf: &mut [u8],
    response_buf: &mut [u8],
    tunnel_name: &str,
    recent_exceptions: &Arc<Mutex<VecDeque<ExceptionStatus>>>,
) -> InboundOutcome {
    let Some(&wg_type) = datagram.first() else {
        return InboundOutcome::Unauthenticated;
    };
    match wg_type {
        crate::afxdp::wg::WG_TYPE_INITIATION => {
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
            // Cookie/MAC2 reply handling is S7; drop for now. Not
            // authenticated for endpoint-learning purposes.
            WgCounters::bump(&engine.counters().hs_rx_cookie_unsupported);
            debug_log!("WG[{}]: drop cookie (S7)", tunnel_name);
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
                    // Write the plaintext inner IP to the wgN TUN; the
                    // kernel routes/firewalls it (NOT the AF_XDP policy
                    // engine — the AllowedIPs gate inside try_decap is
                    // S2a's inner-src control).
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
fn encap_and_send(
    engine: &crate::afxdp::wg::WgEngine,
    socket: &UdpSocket,
    socket_is_v6: bool,
    peer_pubkey: &[u8; 32],
    endpoint: SocketAddr,
    inner_ip: &[u8],
    out: &mut [u8],
    outer_mtu: usize,
    tunnel_name: &str,
    recent_exceptions: &Arc<Mutex<VecDeque<ExceptionStatus>>>,
) {
    // Exact pad-aware MTU guard (plan §4.3 / AGY H1) — symmetric with the
    // transit-egress guard in frame/wg.rs, AND against the SAME MTU model
    // (#2300): `outer_mtu` is the real underlay-egress MTU resolved at
    // spawn, not the old `WG_OUTER_MTU = 1500` hardcode. Drop oversize
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
        if !rx_is_v6 {
            // Production supports the v4-fallback socket on hosts
            // without dual-stack v6; the mapped-send regression is
            // untestable there (covered by the v4 round-trip below).
            return;
        }
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

    /// The v4-fallback socket path: native v4 sends must pass through
    /// wg_send_to UNMAPPED (socket_is_v6=false) and round-trip.
    #[test]
    fn wg_send_to_native_v4_socket_roundtrip() {
        let rx = UdpSocket::bind("127.0.0.1:0").expect("bind v4 rx");
        let rx_port = rx.local_addr().unwrap().port();
        let tx = UdpSocket::bind("127.0.0.1:0").expect("bind v4 tx");
        let target: SocketAddr = format!("127.0.0.1:{rx_port}").parse().unwrap();
        wg_send_to(&tx, false, b"wg-v4", target).expect("native v4 send");
        rx.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let mut buf = [0u8; 16];
        let (n, _) = rx.recv_from(&mut buf).expect("datagram must arrive");
        assert_eq!(&buf[..n], b"wg-v4");
    }

    /// Build a `recvmsg`-shaped `sockaddr_storage` for an AF_INET6 peer
    /// with an explicit interface scope, mirroring what the kernel writes
    /// into `msg_name` for a datagram received from a link-local source.
    fn make_sin6_storage(
        ip: Ipv6Addr,
        port: u16,
        flowinfo: u32,
        scope_id: u32,
    ) -> (libc::sockaddr_storage, libc::socklen_t) {
        let sin6 = libc::sockaddr_in6 {
            sin6_family: libc::AF_INET6 as libc::sa_family_t,
            sin6_port: port.to_be(),
            sin6_flowinfo: flowinfo,
            sin6_addr: libc::in6_addr {
                s6_addr: ip.octets(),
            },
            sin6_scope_id: scope_id,
        };
        // SAFETY: sockaddr_storage is large enough for sockaddr_in6 and we
        // only read back the populated prefix via the conversion under test.
        let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        unsafe {
            std::ptr::copy_nonoverlapping(
                &sin6 as *const libc::sockaddr_in6 as *const u8,
                &mut storage as *mut libc::sockaddr_storage as *mut u8,
                std::mem::size_of::<libc::sockaddr_in6>(),
            );
        }
        (
            storage,
            std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
        )
    }

    /// #2995 fail-on-revert: a link-local (`fe80::/10`) WG peer endpoint
    /// learned from `recvmsg` MUST carry the receiving interface scope
    /// (`sin6_scope_id` = ifindex) through `sockaddr_storage_to_socketaddr`.
    /// If the conversion reverts to `SocketAddr::new(...)` the scope is
    /// dropped to 0 and `wg_send_to` toward the endpoint is rejected with
    /// EINVAL/ENODEV, so the tunnel never establishes. This asserts the
    /// scope (and `sin6_flowinfo`) survive; it goes RED if scope_id == 0.
    #[test]
    fn sockaddr_storage_to_socketaddr_preserves_link_local_scope() {
        let ll = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x1);
        let ifindex: u32 = 7;
        let flowinfo: u32 = 0x0001_2345;
        let (storage, len) = make_sin6_storage(ll, 51820, flowinfo, ifindex);
        let got = sockaddr_storage_to_socketaddr(&storage, len)
            .expect("AF_INET6 storage must convert");
        match got {
            SocketAddr::V6(v6) => {
                assert_eq!(*v6.ip(), ll);
                assert_eq!(v6.port(), 51820);
                assert_eq!(
                    v6.scope_id(),
                    ifindex,
                    "link-local scope_id must equal the receiving ifindex \
                     (reverting to SocketAddr::new drops it to 0)"
                );
                assert_eq!(v6.flowinfo(), flowinfo, "flowinfo must survive");
            }
            other => panic!("expected V6, got {other:?}"),
        }
    }

    /// A global v6 endpoint carries scope_id 0 from the kernel; the
    /// conversion must preserve that 0 unchanged (the fix is a no-op for
    /// global addresses — it only matters for link-local).
    #[test]
    fn sockaddr_storage_to_socketaddr_global_v6_scope_zero() {
        let g = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x1);
        let (storage, len) = make_sin6_storage(g, 51820, 0, 0);
        let got = sockaddr_storage_to_socketaddr(&storage, len).expect("convert");
        match got {
            SocketAddr::V6(v6) => {
                assert_eq!(*v6.ip(), g);
                assert_eq!(v6.scope_id(), 0);
            }
            other => panic!("expected V6, got {other:?}"),
        }
    }

    // =======================================================================
    // #1889: poll(2) loop tests on pre-opened fds (run_wg_control_loop —
    // a pipe read-end stands in for the TUN; no real device needed).
    // =======================================================================

    fn poll_loop_fixture() -> (
        std::sync::Arc<crate::afxdp::wg::WgEngine>,
        UdpSocket,
        std::fs::File,             // tun stand-in (pipe read end)
        std::fs::File,             // pipe write end (keep open!)
        std::sync::Arc<Mutex<VecDeque<ExceptionStatus>>>,
        std::sync::Arc<AtomicBool>,
    ) {
        use std::os::fd::FromRawFd;
        let engine = std::sync::Arc::new(crate::afxdp::wg::WgEngine::new(
            crate::afxdp::wg::WgEngineConfig {
                local_private_key: [7u8; 32],
                listen_port: 0,
                peers: vec![crate::afxdp::wg::WgPeerConfig {
                    pubkey: [9u8; 32],
                    endpoint: None, // responder-only: no bring-up sends
                    persistent_keepalive: 0,
                    allowed_ips: vec![],
                    preshared_key: [0u8; 32],
                }],
            },
        ));
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind");
        socket.set_nonblocking(true).unwrap();
        let mut fds = [0i32; 2];
        let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
        assert_eq!(rc, 0, "pipe");
        let (read_fd, write_fd) = (fds[0], fds[1]);
        set_fd_nonblocking(read_fd).unwrap();
        let tun = unsafe { std::fs::File::from_raw_fd(read_fd) };
        let pipe_w = unsafe { std::fs::File::from_raw_fd(write_fd) };
        let exceptions = std::sync::Arc::new(Mutex::new(VecDeque::new()));
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        (engine, socket, tun, pipe_w, exceptions, stop)
    }

    fn spawn_poll_loop(
        engine: std::sync::Arc<crate::afxdp::wg::WgEngine>,
        socket: UdpSocket,
        tun: std::fs::File,
        exceptions: std::sync::Arc<Mutex<VecDeque<ExceptionStatus>>>,
        stop: std::sync::Arc<AtomicBool>,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            run_wg_control_loop(
                "wg-test",
                &engine,
                &socket,
                false,
                tun,
                WG_DEFAULT_OUTER_MTU,
                &exceptions,
                &stop,
            );
        })
    }

    /// #1889 constraint 1: an idle-blocked loop must stop+join within
    /// the poll cap budget (no eventfd — the 100ms cap bounds it).
    #[test]
    fn poll_loop_stop_joins_promptly_while_idle_blocked() {
        let (engine, socket, tun, _pipe_w, exceptions, stop) = poll_loop_fixture();
        let handle = spawn_poll_loop(engine, socket, tun, exceptions, stop.clone());
        // Let the loop settle into its idle poll.
        std::thread::sleep(Duration::from_millis(150));
        let started = std::time::Instant::now();
        stop.store(true, Ordering::Relaxed);
        handle.join().expect("join");
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "stop->join took {:?} (budget 500ms; cap is 100ms)",
            started.elapsed()
        );
    }

    /// #1889 constraint 2: a datagram arriving while idle-blocked wakes
    /// the loop and is processed promptly (no 1s timer wait). A non-WG
    /// type byte lands in rx_unknown_type deterministically.
    #[test]
    fn poll_loop_wakes_on_socket_readiness() {
        let (engine, socket, tun, _pipe_w, exceptions, stop) = poll_loop_fixture();
        let target = socket.local_addr().unwrap();
        let counters_engine = engine.clone();
        let handle = spawn_poll_loop(engine, socket, tun, exceptions, stop.clone());
        std::thread::sleep(Duration::from_millis(120)); // reach idle poll
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        tx.send_to(&[0xee, 1, 2, 3], target).unwrap();
        let mut seen = false;
        for _ in 0..30 {
            if counters_engine
                .counters()
                .rx_unknown_type
                .load(Ordering::Relaxed)
                == 1
            {
                seen = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        stop.store(true, Ordering::Relaxed);
        handle.join().expect("join");
        assert!(seen, "datagram not processed within 300ms of arrival");
    }

    /// Fatal-fd guard: destroying the TUN under the loop (pipe write
    /// end dropped => POLLHUP on the read end) exits the thread
    /// cleanly WITHOUT the stop flag — the #1872 tombstone respawn is
    /// the recovery path. No busy-spin, no hang.
    #[test]
    fn poll_loop_exits_on_tun_teardown() {
        let (engine, socket, tun, pipe_w, exceptions, stop) = poll_loop_fixture();
        let handle = spawn_poll_loop(engine, socket, tun, exceptions, stop.clone());
        std::thread::sleep(Duration::from_millis(120));
        drop(pipe_w); // TUN "destroyed": POLLHUP forever
        let started = std::time::Instant::now();
        // Join must complete without stop ever being set.
        handle.join().expect("join");
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "fatal-TUN exit took {:?}",
            started.elapsed()
        );
        assert!(!stop.load(Ordering::Relaxed));
    }

    /// Codex code-r1 BLOCKER regression: a T5 give-up must NOT
    /// evaluate the (pre-cleanup) TimerActions in the same pass — a T7
    /// DeadPeer trigger captured before the cleanup would resurrect a
    /// fresh 90s window immediately, bypassing the give-up boundary.
    #[test]
    fn attempt_give_up_ignores_same_pass_stale_actions() {
        use crate::afxdp::wg::session::REKEY_ATTEMPT_TIME_NS;
        use crate::afxdp::wg::timers::{InitiateReason, TimerActions, WG_NO_DEADLINE_NS};
        let (engine, socket, _tun, _pipe_w, exceptions, _stop) = poll_loop_fixture();
        let pk = engine.first_peer_pubkey().unwrap();
        let ep: SocketAddr = "127.0.0.1:39999".parse().unwrap();
        let mut encap_buf = vec![0u8; 2048];
        let now = 200_000_000_000u64;
        let mut attempt = Some(HandshakeAttempt {
            started_ns: now - REKEY_ATTEMPT_TIME_NS - 1,
            last_tx_ns: now - 1_000_000_000,
            baseline_session: None,
        });
        // Stale actions captured BEFORE the give-up cleanup, carrying a
        // due T7 trigger.
        let stale_actions = TimerActions {
            initiate: Some(InitiateReason::DeadPeer),
            send_keepalive: None,
            next_deadline_ns: WG_NO_DEADLINE_NS,
        };
        let deadline = drive_attempt_machine(
            &engine,
            &socket,
            false,
            &pk,
            Some(ep),
            &stale_actions,
            now,
            &mut attempt,
            &mut encap_buf,
            "wg-test",
            &exceptions,
        );
        assert!(
            attempt.is_none(),
            "give-up must not resurrect an attempt from stale same-pass actions"
        );
        assert_eq!(deadline, WG_NO_DEADLINE_NS);
        assert_eq!(
            engine
                .counters()
                .rekeys_initiated_dead_peer
                .load(Ordering::Relaxed),
            0,
            "no DeadPeer attempt may start in the give-up pass"
        );
    }

    /// AGY r3 G3: the ns->ms conversion clamps to the cap and never
    /// yields a negative/zero-spin timeout for future deadlines.
    #[test]
    fn poll_timeout_ms_clamps_and_converts() {
        let now = 1_000_000_000u64;
        // Far-future deadline: capped.
        assert_eq!(poll_timeout_ms(u64::MAX, now), WG_POLL_CAP_MS);
        // 7ms out: exact conversion.
        assert_eq!(poll_timeout_ms(now + 7_000_000, now), 7);
        // Past deadline: 0 (the timer arm runs it on the next
        // iteration via the now >= next_deadline condition).
        assert_eq!(poll_timeout_ms(now - 1, now), 0);
    }

    /// The guard math this protects: at the v4/v6 boundary the same
    /// padded inner either fits (v4 outer) or exceeds (v6 outer) the
    /// 1500 outer MTU — the live-blackhole window.
    #[test]
    fn encapped_size_v4_vs_v6_window() {
        // inner 1409 pads to 1424: v4 outer = 1484 (fits), v6 = 1504 (drops).
        assert!(wg_encapped_size(1409, false) <= WG_DEFAULT_OUTER_MTU);
        assert!(wg_encapped_size(1409, true) > WG_DEFAULT_OUTER_MTU);
        // inner 1408 fits either way (the pre-fix observable cutoff).
        assert!(wg_encapped_size(1408, true) <= WG_DEFAULT_OUTER_MTU);
    }

    /// #2300: the egress guard uses the THREADED outer MTU, not the
    /// 1500 constant. A 1409-byte inner (v4 outer, encapped 1484) fits a
    /// 1500 link but MUST be dropped on a 1450 underlay (PPPoE-class) —
    /// the topology-dependent bug the old hardcode created.
    #[test]
    fn guard_uses_threaded_outer_mtu_not_constant() {
        // 1500 link: 1409 fits.
        assert!(wg_inner_fits_outer_mtu(1409, false, 1500));
        // 1450 link: 1484 > 1450, dropped. Fail-on-revert: a hardcoded
        // 1500 guard would have let this through and forced the underlay
        // to fragment or drop.
        assert!(!wg_inner_fits_outer_mtu(1409, false, 1450));
        // 1492 link (PPPoE): 1484 still fits.
        assert!(wg_inner_fits_outer_mtu(1409, false, 1492));
        // Jumbo 9000 link: a 5000-byte inner (encapped ~5044) fits —
        // the old constant would have capped this at 1500.
        assert!(wg_inner_fits_outer_mtu(5000, false, 9000));
        assert!(!wg_inner_fits_outer_mtu(5000, false, 1500));
    }

    // =======================================================================
    // #2317: recvmsg / cmsg outer-ECN capture + RFC 6040 §4.2 WG decap
    // combine. The cmsg-parse tests build a synthetic control buffer with
    // the real libc CMSG_* macros and feed it to the same
    // `parse_outer_ecn_from_cmsg` the recv path uses, so the alignment +
    // walk logic is exercised exactly as in production.
    // =======================================================================

    /// Build a `msghdr` whose msg_control holds a single cmsg of
    /// `(level, ctype)` carrying the one-byte DS payload `ds`, and return
    /// the parsed outer ECN. The cmsg buffer is a stack `CmsgBuf`
    /// (8-byte-aligned, #2334) that the msghdr borrows for the duration
    /// of the parse.
    fn parse_ecn_with_cmsg(level: libc::c_int, ctype: libc::c_int, ds: u8) -> Option<u8> {
        unsafe {
            // CMSG_SPACE(1) bytes hold a header + 1 padded payload byte.
            // Back the control buffer with the same 8-byte-aligned `CmsgBuf`
            // the production recv path uses (#2334) so the synthetic cmsg
            // header-field writes/reads here are aligned exactly as in
            // `wg_recvmsg` — a bare `vec![0u8; _]` would be align-1.
            let space = libc::CMSG_SPACE(1) as usize;
            assert!(space <= 256, "CMSG_SPACE(1) exceeds CmsgBuf storage");
            let mut buf = CmsgBuf([0u8; 256]);
            let mut msg: libc::msghdr = std::mem::zeroed();
            msg.msg_control = buf.0.as_mut_ptr() as *mut libc::c_void;
            msg.msg_controllen = space as _;
            let cmsg = libc::CMSG_FIRSTHDR(&msg);
            assert!(!cmsg.is_null(), "CMSG_FIRSTHDR null");
            (*cmsg).cmsg_level = level;
            (*cmsg).cmsg_type = ctype;
            (*cmsg).cmsg_len = libc::CMSG_LEN(1) as _;
            *libc::CMSG_DATA(cmsg) = ds;
            // msg_controllen must reflect the actual bytes written for the
            // walk to terminate correctly.
            msg.msg_controllen = libc::CMSG_SPACE(1) as _;
            parse_outer_ecn_from_cmsg(&msg)
        }
    }

    #[test]
    fn cmsg_parse_v4_ip_tos_extracts_ecn() {
        // IPv4 IP_TOS cmsg: DS byte 0xB8 = EF (DSCP 46) + Not-ECT(00).
        assert_eq!(
            parse_ecn_with_cmsg(libc::IPPROTO_IP, libc::IP_TOS, 0xB8),
            Some(0b00)
        );
        // DS byte with ECT(0) low bits: DSCP 0 + ECT(0)=0b10.
        assert_eq!(
            parse_ecn_with_cmsg(libc::IPPROTO_IP, libc::IP_TOS, 0b10),
            Some(0b10)
        );
        // DS byte with CE low bits: AF41 (DSCP 34 << 2 = 0x88) | CE(0b11).
        assert_eq!(
            parse_ecn_with_cmsg(libc::IPPROTO_IP, libc::IP_TOS, 0x88 | 0b11),
            Some(0b11)
        );
    }

    #[test]
    fn cmsg_parse_v6_tclass_extracts_ecn() {
        // IPv6 IPV6_TCLASS cmsg: Traffic Class byte with ECT(1) low bits.
        assert_eq!(
            parse_ecn_with_cmsg(libc::IPPROTO_IPV6, libc::IPV6_TCLASS, 0b01),
            Some(0b01)
        );
        // CE in the low 2 bits.
        assert_eq!(
            parse_ecn_with_cmsg(libc::IPPROTO_IPV6, libc::IPV6_TCLASS, 0xFF),
            Some(0b11)
        );
    }

    #[test]
    fn cmsg_parse_ignores_unrelated_cmsg() {
        // A non-TOS cmsg (e.g. SOL_SOCKET / SO_TIMESTAMP-shaped) yields no
        // ECN — only IP_TOS / IPV6_TCLASS are honored.
        assert_eq!(
            parse_ecn_with_cmsg(libc::SOL_SOCKET, libc::SCM_RIGHTS, 0xFF),
            None
        );
    }

    #[test]
    fn cmsg_parse_empty_control_yields_none() {
        // No control buffer at all (kernel ignored the sockopt) → None,
        // and the decap combine is skipped.
        unsafe {
            let mut msg: libc::msghdr = std::mem::zeroed();
            msg.msg_control = std::ptr::null_mut();
            msg.msg_controllen = 0;
            assert_eq!(parse_outer_ecn_from_cmsg(&msg), None);
        }
    }

    /// The WG decap site reuses the shared `apply_decap_ecn_combine`: an
    /// outer CE over an ECN-capable IPv4 inner upgrades the inner to CE
    /// and recomputes the IPv4 header checksum, and a LEGAL upgrade does
    /// NOT touch the (per-tunnel) illegal-drop counter. A test-local
    /// `AtomicU64` stands in for the counter so the strict delta is
    /// deterministic regardless of concurrent tests touching the
    /// process-global GRE/WG statics.
    #[test]
    fn wg_apply_combine_sets_ipv4_ce_and_recomputes_checksum() {
        use crate::afxdp::gre::apply_decap_ecn_combine;
        // Minimal 20-byte IPv4 header, DSCP 0 + ECT(0), valid checksum.
        let mut inner = vec![0u8; 20];
        inner[0] = 0x45; // version 4, IHL 5
        inner[1] = 0b10; // DSCP 0, ECT(0)
        inner[9] = PROTO_TCP;
        let cs = crate::afxdp::frame::checksum16(&inner[..20]);
        inner[10..12].copy_from_slice(&cs.to_be_bytes());
        assert_eq!(crate::afxdp::frame::checksum16(&inner[..20]), 0);

        let counter = AtomicU64::new(0);
        let forward = apply_decap_ecn_combine(&mut inner, libc::AF_INET as u8, 0b11, &counter);
        assert!(forward, "ECT inner + outer CE forwards after CE upgrade");
        assert_eq!(inner[1] & 0x03, 0b11, "inner ECN upgraded to CE");
        assert_eq!(inner[1] >> 2, 0, "inner DSCP untouched");
        assert_eq!(
            crate::afxdp::frame::checksum16(&inner[..20]),
            0,
            "IPv4 header checksum recomputed after the TOS change"
        );
        assert_eq!(
            counter.load(Ordering::Relaxed),
            0,
            "a legal CE upgrade must not bump the illegal-drop counter"
        );
    }

    /// The illegal §4.2 combo (outer CE over a Not-ECT inner) DROPS and
    /// bumps the passed counter exactly once. The WG production wiring
    /// passes `WG_DECAP_ECN_ILLEGAL_DROPS` (asserted separately below with
    /// a concurrency-tolerant `>=` check); the strict +1 is verified on a
    /// test-local atomic so it is deterministic under parallel tests.
    #[test]
    fn wg_apply_combine_drops_illegal_combo_and_counts() {
        use crate::afxdp::gre::{apply_decap_ecn_combine, WG_DECAP_ECN_ILLEGAL_DROPS};
        let mut inner = vec![0u8; 20];
        inner[0] = 0x45;
        inner[1] = 0x88; // AF41 (DSCP 34), ECN Not-ECT(00)

        // Strict +1 on an isolated counter — deterministic.
        let counter = AtomicU64::new(0);
        let forward = apply_decap_ecn_combine(&mut inner, libc::AF_INET as u8, 0b11, &counter);
        assert!(!forward, "outer CE over a Not-ECT inner must DROP (§4.2)");
        assert_eq!(
            counter.load(Ordering::Relaxed),
            1,
            "the illegal combo must bump the passed counter exactly once"
        );

        // Production wiring: the WG global advances (>= because other
        // parallel tests may also bump it). Proves the WG path routes to
        // the WG counter, not just an arbitrary one.
        let wg_before = WG_DECAP_ECN_ILLEGAL_DROPS.load(Ordering::Relaxed);
        let mut inner2 = vec![0u8; 20];
        inner2[0] = 0x45;
        inner2[1] = 0x88;
        assert!(!apply_decap_ecn_combine(
            &mut inner2,
            libc::AF_INET as u8,
            0b11,
            &WG_DECAP_ECN_ILLEGAL_DROPS,
        ));
        assert!(
            WG_DECAP_ECN_ILLEGAL_DROPS.load(Ordering::Relaxed) >= wg_before + 1,
            "the WG global illegal-drop counter must advance on the WG path"
        );
    }
}
