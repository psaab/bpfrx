//! Per-zone 1-second-window rate counters used by ICMP/UDP/SYN flood
//! detection and SYN-cookie standby ACK rate limiting.

/// Simple rate counter: counts events within a 1-second window.
#[derive(Debug, Clone, Default)]
pub(super) struct RateCounter {
    pub(super) count: u32,
    window_start_secs: u64,
}

impl RateCounter {
    /// Increment and return true if the threshold is exceeded.
    pub(super) fn increment(&mut self, now_secs: u64, threshold: u32) -> bool {
        if now_secs != self.window_start_secs {
            self.count = 0;
            self.window_start_secs = now_secs;
        }
        self.count += 1;
        self.count > threshold
    }

    /// Reset counter (used in tests).
    #[cfg(test)]
    #[allow(dead_code)]
    pub(super) fn reset(&mut self) {
        self.count = 0;
        self.window_start_secs = 0;
    }
}
