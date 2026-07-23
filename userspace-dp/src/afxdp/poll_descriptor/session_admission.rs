// #6386 leaf extraction: the new-flow session-admission predicates
// (#2134 per-IP session-limit, #4400 strict-syn-check bare-RST/FIN drop),
// lifted verbatim out of poll_descriptor/mod.rs. Each moved bare fn
// becomes pub(super); both keep their existing #[inline]. Attr-verbatim,
// no other non-motion change. Bodies byte-identical to their prior
// location.

use super::*;

/// #2134: per-IP session-limit enforcement at the NEW-FLOW decision.
///
/// Junos `limit-session source-ip-based <n>` / `destination-ip-based <n>`
/// caps the concurrent locally-admitted sessions a single source /
/// destination IP may hold. The decision MUST fire exactly once per new
/// flow, before that flow's own session exists — NOT in the per-packet
/// screen stage, which runs on every data packet of every flow and would
/// re-check an established flow's own counted session and self-drop it at
/// the limit boundary (#2134 r2 BLOCKER).
///
/// This is a read-only query on the per-worker `SessionTable` count
/// (maintained at the install/remove sinks + HA promote/demote), so it
/// preserves the #2128 leak-fix (closed by #2159) by construction: an IP
/// that never installs a session never gets a map entry. Returns the
/// screen-drop reason if the new flow must
/// be rejected, or `None` to proceed to install. Cold path (session
/// miss only); the profile lookup short-circuits on the common
/// no-`limit-session` zone.
#[inline]
pub(super) fn new_flow_session_limit_drop(
    forwarding: &ForwardingState,
    sessions: &SessionTable,
    from_zone: &str,
    src_ip: IpAddr,
    dst_ip: IpAddr,
) -> Option<&'static str> {
    // `screen_profiles` is keyed by zone NAME. An empty/absent zone or a
    // zone with no `limit-session` configured short-circuits with no cost
    // beyond the map probe.
    let profile = forwarding.screen_profiles.get(from_zone)?;
    if profile.session_limit_src > 0
        && sessions.session_limit_src_count(src_ip) >= profile.session_limit_src
    {
        return Some("session-limit-src");
    }
    if profile.session_limit_dst > 0
        && sessions.session_limit_dst_count(dst_ip) >= profile.session_limit_dst
    {
        return Some("session-limit-dst");
    }
    None
}

/// #4400: strict-syn-check-style guard for the TCP session-MISS install
/// path.
///
/// Junos `security flow tcp-session strict-syn-check` requires the FIRST
/// packet of a TCP flow to be a SYN and drops a non-SYN first packet. xpf
/// deliberately keeps the looser Junos default (no-syn-check) so a SYN-ACK /
/// bare ACK / data first packet may still open an ESTABLISHED session
/// (#3152), preserving asymmetric-routing mid-stream pickup. A bare RST/FIN,
/// however — a connection-CLOSING control bit (FIN or RST) with NO SYN — can
/// never legitimately OPEN a connection: a real flow starts with a SYN, and
/// a RST/FIN for a flow this node does not track is either a late segment for
/// an already-GC'd session or an attack. Installing a session for it (which
/// the ForwardCandidate / MissingNeighbor session-miss install sites would
/// otherwise do, seeding an immediately-`closing`/`reset` entry — see
/// `session/install.rs` lines that set `closing` / `reset` from `tcp_flags`)
/// provides no forwarding value and lets a RST/FIN flood churn the per-worker
/// session table (a real DoS surface, #4400, confirmed 4x).
///
/// This predicate returns true for exactly that pathological case (TCP, FIN
/// or RST set, SYN clear); the session-MISS cold path drops such a packet
/// before it reaches an install site. Non-TCP traffic and any SYN-bearing
/// segment (bare SYN, SYN-ACK, the malformed SYN-FIN the `tcp-syn-fin` screen
/// check owns) return false — unchanged behavior. Applied unconditionally
/// (no config knob): a stray RST/FIN opening a closing session is never
/// useful regardless of the operator's strict-syn-check setting, so this is
/// the safe stateful-firewall default. Host-inbound (LocalDelivery) traffic
/// is exempt at the call site so a peer RST tearing down a firewall-
/// originated TCP session (BGP, IKE, management) still reaches the local
/// stack.
#[inline]
pub(super) fn strict_syn_check_drops_new_flow(protocol: u8, tcp_flags: u8) -> bool {
    matches!(protocol, crate::ip_proto::PROTO_TCP)
        && crate::tcp_flags::is_closing(tcp_flags)
        && !crate::tcp_flags::has_syn(tcp_flags)
}

#[cfg(test)]
#[path = "session_admission_tests.rs"]
mod tests;
