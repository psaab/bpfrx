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
    /// Increment session count for a source IP. Returns true if limit exceeded.
    pub(super) fn check_src(&mut self, ip: IpAddr, limit: u32) -> bool {
        if limit == 0 {
            return false;
        }
        let count = self.src_counts.entry(ip).or_insert(0);
        *count >= limit
    }

    /// Increment session count for a destination IP. Returns true if limit exceeded.
    pub(super) fn check_dst(&mut self, ip: IpAddr, limit: u32) -> bool {
        if limit == 0 {
            return false;
        }
        let count = self.dst_counts.entry(ip).or_insert(0);
        *count >= limit
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
}
