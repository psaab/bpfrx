//! Per-IP session counter for session-limit screen.

use rustc_hash::FxHashMap;
use std::net::IpAddr;

/// Per-IP session counter for session limiting.
#[derive(Debug, Clone, Default)]
pub(super) struct SessionLimitTracker {
    src_counts: FxHashMap<IpAddr, u32>,
    dst_counts: FxHashMap<IpAddr, u32>,
}

impl SessionLimitTracker {
    /// Look up the current session count for a source IP and return true
    /// if it already meets or exceeds `limit`. This is strictly read-only —
    /// the count is moved only by [`session_created`] / [`session_expired`].
    /// The orchestrator runs this BEFORE session creation so the
    /// (limit+1)-th attempt is dropped.
    ///
    /// The receiver is `&self` deliberately: an earlier implementation used
    /// `entry(ip).or_insert(0)` to read the count, which inserted a phantom
    /// zero-count entry as a side effect for every distinct source IP that
    /// reached the screen stage. Those entries were never reclaimed
    /// (`session_expired` only removes entries first incremented by
    /// `session_created`), so a flood from many distinct/spoofed source IPs
    /// grew this per-worker map without bound — a memory-exhaustion DoS
    /// (issue #2128). An absent IP reads as 0, so the first session attempt
    /// for a never-seen IP still passes, identical to the old freshly-
    /// inserted-zero behaviour. Keeping this `&self` makes the read-only
    /// contract compiler-enforced so the leak cannot regress.
    pub(super) fn check_src(&self, ip: IpAddr, limit: u32) -> bool {
        if limit == 0 {
            return false;
        }
        self.src_counts.get(&ip).copied().unwrap_or(0) >= limit
    }

    /// Look up the current session count for a destination IP and return
    /// true if it already meets or exceeds `limit`. Mirror of
    /// [`check_src`]; strictly read-only (see #2128).
    pub(super) fn check_dst(&self, ip: IpAddr, limit: u32) -> bool {
        if limit == 0 {
            return false;
        }
        self.dst_counts.get(&ip).copied().unwrap_or(0) >= limit
    }

    /// Called when a new session is created (after the check passes).
    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) fn session_created(&mut self, src_ip: IpAddr, dst_ip: IpAddr) {
        *self.src_counts.entry(src_ip).or_insert(0) += 1;
        *self.dst_counts.entry(dst_ip).or_insert(0) += 1;
    }

    /// Called when a session expires.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) fn session_expired(&mut self, src_ip: IpAddr, dst_ip: IpAddr) {
        if let Some(c) = self.src_counts.get_mut(&src_ip) {
            *c = c.saturating_sub(1);
            if *c == 0 {
                self.src_counts.remove(&src_ip);
            }
        }
        if let Some(c) = self.dst_counts.get_mut(&dst_ip) {
            *c = c.saturating_sub(1);
            if *c == 0 {
                self.dst_counts.remove(&dst_ip);
            }
        }
    }

    /// Number of live source-IP entries. Used by tests to assert the map
    /// stays bounded (does not leak phantom zero-count entries, #2128).
    #[cfg(test)]
    pub(super) fn src_len(&self) -> usize {
        self.src_counts.len()
    }

    /// Number of live destination-IP entries. Mirror of [`src_len`].
    #[cfg(test)]
    pub(super) fn dst_len(&self) -> usize {
        self.dst_counts.len()
    }
}
