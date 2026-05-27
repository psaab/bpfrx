//! Port-scan + IP-sweep windowed trackers used by the advanced screen
//! checks. Each tracks a per-source-IP unique-set over a 10-second
//! detection window.

use rustc_hash::{FxHashMap, FxHashSet};
use std::net::IpAddr;

/// Tracks unique destination ports per source IP within a time window.
#[derive(Debug, Clone)]
pub(super) struct PortScanTracker {
    per_src: FxHashMap<IpAddr, (u64, FxHashSet<u16>)>, // (window_start_secs, unique_ports)
    window_secs: u64,
}

impl Default for PortScanTracker {
    fn default() -> Self {
        Self {
            per_src: FxHashMap::default(),
            window_secs: 10, // 10-second detection window
        }
    }
}

impl PortScanTracker {
    /// Check if src_ip has exceeded the port scan threshold. Returns true if exceeded.
    pub(super) fn check(
        &mut self,
        src_ip: IpAddr,
        dst_port: u16,
        now_secs: u64,
        threshold: u32,
    ) -> bool {
        if threshold == 0 {
            return false;
        }
        let entry = self
            .per_src
            .entry(src_ip)
            .or_insert_with(|| (now_secs, FxHashSet::default()));
        // Reset window if expired
        if now_secs.saturating_sub(entry.0) >= self.window_secs {
            entry.0 = now_secs;
            entry.1.clear();
        }
        entry.1.insert(dst_port);
        entry.1.len() as u32 > threshold
    }

    /// Remove entries with empty sets (periodic cleanup).
    pub(super) fn cleanup(&mut self, now_secs: u64) {
        self.per_src.retain(|_, (start, ports)| {
            now_secs.saturating_sub(*start) < self.window_secs && !ports.is_empty()
        });
    }
}

/// Tracks unique destination IPs per source IP within a time window.
#[derive(Debug, Clone)]
pub(super) struct IpSweepTracker {
    per_src: FxHashMap<IpAddr, (u64, FxHashSet<IpAddr>)>, // (window_start_secs, unique_dst_ips)
    window_secs: u64,
}

impl Default for IpSweepTracker {
    fn default() -> Self {
        Self {
            per_src: FxHashMap::default(),
            window_secs: 10, // 10-second detection window
        }
    }
}

impl IpSweepTracker {
    /// Check if src_ip has exceeded the IP sweep threshold. Returns true if exceeded.
    pub(super) fn check(
        &mut self,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        now_secs: u64,
        threshold: u32,
    ) -> bool {
        if threshold == 0 {
            return false;
        }
        let entry = self
            .per_src
            .entry(src_ip)
            .or_insert_with(|| (now_secs, FxHashSet::default()));
        // Reset window if expired
        if now_secs.saturating_sub(entry.0) >= self.window_secs {
            entry.0 = now_secs;
            entry.1.clear();
        }
        entry.1.insert(dst_ip);
        entry.1.len() as u32 > threshold
    }

    /// Remove entries with empty sets (periodic cleanup).
    pub(super) fn cleanup(&mut self, now_secs: u64) {
        self.per_src.retain(|_, (start, ips)| {
            now_secs.saturating_sub(*start) < self.window_secs && !ips.is_empty()
        });
    }
}
