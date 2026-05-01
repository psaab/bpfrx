// Token-bucket policer state extracted from filter.rs (#1049 P2 structural split).
// Pure relocation — bodies are byte-for-byte identical; only the
// enclosing module and visibility paths change.

use super::*;

/// Token-bucket policer state.
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub(crate) struct PolicerState {
    pub(crate) name: String,
    /// Refill rate in bytes per nanosecond (bandwidth_bps / 8 / 1e9).
    pub(crate) rate_bytes_per_ns: f64,
    /// Maximum bucket size in bytes.
    pub(crate) burst_bytes: u64,
    /// Current token count (bytes).
    pub(crate) tokens: f64,
    /// Last refill timestamp (monotonic nanoseconds).
    pub(crate) last_refill_ns: u64,
    /// Whether to discard excess traffic (vs. mark).
    pub(crate) discard_excess: bool,
    /// Whether the policer has been initialized with the first packet time.
    initialized: bool,
}

impl PolicerState {
    pub(crate) fn new(
        name: String,
        bandwidth_bps: u64,
        burst_bytes: u64,
        discard_excess: bool,
    ) -> Self {
        let rate_bytes_per_ns = (bandwidth_bps as f64) / 8.0 / 1_000_000_000.0;
        Self {
            name,
            rate_bytes_per_ns,
            burst_bytes,
            tokens: burst_bytes as f64,
            last_refill_ns: 0,
            discard_excess,
            initialized: false,
        }
    }

    /// Refill tokens based on elapsed time and try to consume `packet_bytes`.
    /// Returns true if the packet is within the rate limit (conforming).
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn consume(&mut self, now_ns: u64, packet_bytes: u64) -> bool {
        if !self.initialized {
            self.initialized = true;
            self.last_refill_ns = now_ns;
            self.tokens = self.burst_bytes as f64;
        }
        // Refill tokens
        if now_ns > self.last_refill_ns {
            let elapsed_ns = now_ns - self.last_refill_ns;
            let refill = elapsed_ns as f64 * self.rate_bytes_per_ns;
            self.tokens = (self.tokens + refill).min(self.burst_bytes as f64);
            self.last_refill_ns = now_ns;
        }
        // Try to consume
        let cost = packet_bytes as f64;
        if self.tokens >= cost {
            self.tokens -= cost;
            true
        } else {
            false
        }
    }
}

