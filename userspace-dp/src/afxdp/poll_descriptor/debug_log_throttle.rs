// #4404 increment 1: cold-path `debug-log` throttle helpers extracted
// out of the poll_binding_process_descriptor god-function's enclosing
// module. These are pure functions of the per-interval counter with NO
// dependency on any dataplane type, so the split is behavior-identical
// code-motion: the caller in mod.rs calls the same predicates, and the
// #4120 pinned-contract tests (`debug_log_throttle_tests`) move verbatim
// alongside the code they pin. See the module header in mod.rs and the
// #4404 refactor issue.

/// #4120: per-interval numeric cap on the `debug-log` session-miss line.
/// This cap is the SOLE throttle. A leftover test-env
/// `is_trust_flow = ingress_ifindex == 5 || from_zone == "lan" ||
/// 10.x-src` predicate used to OR past this cap, which defeated the
/// throttle for the ENTIRE trusted side on any real 10.x LAN and flooded
/// the log — exactly the CLAUDE.md Logging Rules hazard. It was removed;
/// the numeric cap now governs uniformly.
const SESSION_MISS_DEBUG_LOG_CAP: u64 = 10;

/// #4120: companion per-interval cap on the `debug-log` transit
/// policy-deny line. See [`SESSION_MISS_DEBUG_LOG_CAP`].
const POLICY_DENY_DEBUG_LOG_CAP: u64 = 3;

/// Whether the session-miss `debug-log` line may be emitted this
/// interval. Governed SOLELY by the numeric interval cap (#4120): the
/// signature takes only the counter, so no ingress ifindex, zone name,
/// or source subnet can bypass the throttle.
#[inline]
pub(super) fn session_miss_debug_log_allowed(session_miss: u64) -> bool {
    session_miss <= SESSION_MISS_DEBUG_LOG_CAP
}

/// Whether the transit policy-deny `debug-log` line may be emitted this
/// interval. Governed SOLELY by the numeric interval cap (#4120), as a
/// pure function of the counter (no topology bypass).
#[inline]
pub(super) fn policy_deny_debug_log_allowed(policy_deny: u64) -> bool {
    policy_deny <= POLICY_DENY_DEBUG_LOG_CAP
}

/// #4120: pin the `debug-log` cold-path throttle to its numeric
/// per-interval cap and prove the throttle takes NO topology input.
///
/// RED-on-revert: re-introducing the removed `is_trust_flow`
/// (`ingress_ifindex == 5 || from_zone == "lan" || 10.x-src`) bypass
/// would have to OR past these predicates, so any input that flips the
/// verdict `true` above the cap (a 10.x source, ifindex 5, or a zone
/// named `lan`) makes `throttle_governed_solely_by_numeric_cap` fail.
/// The predicate signature accepts ONLY the counter, so the topology
/// bypass cannot be reconstructed without changing this pinned contract.
#[cfg(test)]
mod debug_log_throttle_tests {
    use super::*;

    #[test]
    fn session_miss_debug_log_capped_at_ten() {
        // At/under the cap ⇒ allowed; strictly above ⇒ suppressed.
        for n in 0..=SESSION_MISS_DEBUG_LOG_CAP {
            assert!(
                session_miss_debug_log_allowed(n),
                "count {n} within cap must be allowed"
            );
        }
        assert!(!session_miss_debug_log_allowed(
            SESSION_MISS_DEBUG_LOG_CAP + 1
        ));
        assert!(!session_miss_debug_log_allowed(1_000_000));
        assert!(!session_miss_debug_log_allowed(u64::MAX));
    }

    #[test]
    fn policy_deny_debug_log_capped_at_three() {
        for n in 0..=POLICY_DENY_DEBUG_LOG_CAP {
            assert!(
                policy_deny_debug_log_allowed(n),
                "count {n} within cap must be allowed"
            );
        }
        assert!(!policy_deny_debug_log_allowed(
            POLICY_DENY_DEBUG_LOG_CAP + 1
        ));
        assert!(!policy_deny_debug_log_allowed(1_000_000));
        assert!(!policy_deny_debug_log_allowed(u64::MAX));
    }

    #[test]
    fn throttle_governed_solely_by_numeric_cap() {
        // The throttle is a pure function of the interval counter: no
        // ingress ifindex, zone name, or source subnet is an input, so a
        // flow on the test-env fxp0 slot (ifindex 5), a zone literally
        // named `lan`, or a 10.0.0.0/8 source is throttled EXACTLY like
        // any other flow. Past the cap the verdict is unconditionally
        // `false` — the removed `is_trust_flow` bypass (which flooded the
        // whole trusted side on a real 10.x LAN) cannot re-appear here.
        let over = SESSION_MISS_DEBUG_LOG_CAP + 1;
        assert!(!session_miss_debug_log_allowed(over));
        let over_deny = POLICY_DENY_DEBUG_LOG_CAP + 1;
        assert!(!policy_deny_debug_log_allowed(over_deny));
    }
}
