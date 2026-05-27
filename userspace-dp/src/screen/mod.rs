//! Screen/IDS attack protection checks for the userspace dataplane.
//!
//! Implements pre-session packet validation that mirrors the eBPF screen stage
//! (`bpf/xdp/xdp_screen.c`). Checks run on every packet BEFORE session lookup.
//!
//! Supported checks:
//! - Land attack (src == dst)
//! - TCP SYN+FIN
//! - TCP no-flag (null scan)
//! - TCP FIN without ACK
//! - WinNuke (URG to port 139)
//! - Ping of death (oversized ICMP)
//! - Teardrop (overlapping fragments)
//! - ICMP fragment
//! - IP source route options
//! - Rate limiting (ICMP, UDP flood)
//! - SYN flood (per-zone rate)
//!
//! Layout (#1543, Wave-5): the runtime is split across focused
//! sibling submodules so SYN-cookie crypto can be audited
//! independently from packet policy:
//!
//! - `packet`        — shared `ScreenPacketInfo`, `ScreenProfile`,
//!                     `ScreenVerdict`, protocol/flag constants.
//! - `syncookie`     — `SynCookieCodec`, `SipHash24`,
//!                     `SynCookieValidatedCache`, all cookie types.
//! - `rate`          — per-zone 1-second window `RateCounter`.
//! - `stateless`     — side-effect-free packet-policy helpers.
//! - `scan`          — port-scan + IP-sweep windowed trackers.
//! - `session_limit` — per-IP session-count tracker.
//! - `extract`       — allocation-free IP/TCP header parser.
//! - `tests`         — relocated screen_tests.rs (loaded via #[path]).

use rustc_hash::FxHashMap;
use std::net::IpAddr;

mod extract;
mod packet;
mod rate;
mod scan;
mod session_limit;
mod stateless;
mod syncookie;

pub(crate) use extract::extract_screen_info;
pub(crate) use packet::{ScreenPacketInfo, ScreenProfile, ScreenVerdict};
pub(crate) use syncookie::{
    SYN_COOKIE_MSS_VALUES, SynCookieAckVerdict, SynCookieChallenge, SynCookieCodec,
    SynCookieTuple, SynCookieValidation,
};

// Test-only re-exports — screen/tests.rs constructs SipHash24 and
// SynCookieValidatedCache directly in vector / eviction tests and
// inspects bit-layout constants when validating the cookie codec
// output. Production builds never see these symbols outside the
// crypto submodule (they are imported via `use syncookie::...`
// below for `ScreenState` to use, but not re-exported except under
// `cfg(test)`).
#[cfg(test)]
pub(crate) use syncookie::{
    SYN_COOKIE_EPOCH_MASK, SYN_COOKIE_EPOCH_SHIFT, SYN_COOKIE_ISN_BITS, SYN_COOKIE_LAYOUT_BITS,
    SYN_COOKIE_MSS_MASK, SYN_COOKIE_MSS_SHIFT, SipHash24, SynCookieValidatedCache,
};

use packet::{PROTO_ICMP, PROTO_ICMPV6, PROTO_TCP, PROTO_UDP, TCP_ACK, TCP_FIN, TCP_RST, TCP_SYN};
#[cfg(test)]
use packet::TCP_URG;
use rate::RateCounter;
use scan::{IpSweepTracker, PortScanTracker};
use session_limit::SessionLimitTracker;
#[cfg(not(test))]
use syncookie::SynCookieValidatedCache;
use syncookie::SYN_COOKIE_STANDBY_ACK_VALIDATION_RATE_LIMIT_PER_SEC;

/// Per-zone screen state with mutable rate counters and advanced trackers.
pub(crate) struct ScreenState {
    profiles: FxHashMap<String, ScreenProfile>, // zone_name -> profile
    // Per-zone rate counters
    icmp_counters: FxHashMap<String, RateCounter>,
    udp_counters: FxHashMap<String, RateCounter>,
    syn_counters: FxHashMap<String, RateCounter>,
    syn_cookie_active_until_secs: FxHashMap<String, u64>,
    syn_cookie_standby_ack_counters: FxHashMap<String, RateCounter>,
    syn_cookie_codec: Option<SynCookieCodec>,
    syn_cookie_validated: SynCookieValidatedCache,
    syn_cookie_last_full_epoch: u64,
    #[cfg(test)]
    syn_cookie_full_epoch_override: Option<u64>,
    // Advanced screen trackers (shared across all zones since they track per-IP)
    session_limits: SessionLimitTracker,
    port_scan: PortScanTracker,
    ip_sweep: IpSweepTracker,
    last_cleanup_secs: u64,
}

impl ScreenState {
    pub fn new() -> Self {
        Self {
            profiles: FxHashMap::default(),
            icmp_counters: FxHashMap::default(),
            udp_counters: FxHashMap::default(),
            syn_counters: FxHashMap::default(),
            syn_cookie_active_until_secs: FxHashMap::default(),
            syn_cookie_standby_ack_counters: FxHashMap::default(),
            syn_cookie_codec: None,
            syn_cookie_validated: SynCookieValidatedCache::default(),
            syn_cookie_last_full_epoch: 0,
            #[cfg(test)]
            syn_cookie_full_epoch_override: None,
            session_limits: SessionLimitTracker::default(),
            port_scan: PortScanTracker::default(),
            ip_sweep: IpSweepTracker::default(),
            last_cleanup_secs: 0,
        }
    }

    /// Replace all screen profiles (called on config update).
    pub fn update_profiles(&mut self, profiles: FxHashMap<String, ScreenProfile>) {
        // Clear rate counters for zones that no longer have profiles
        self.icmp_counters.retain(|k, _| profiles.contains_key(k));
        self.udp_counters.retain(|k, _| profiles.contains_key(k));
        self.syn_counters.retain(|k, _| profiles.contains_key(k));
        self.syn_cookie_active_until_secs
            .retain(|k, _| profiles.contains_key(k));
        self.syn_cookie_standby_ack_counters
            .retain(|k, _| profiles.contains_key(k));
        for zone in profiles.keys() {
            self.icmp_counters.entry(zone.clone()).or_default();
            self.udp_counters.entry(zone.clone()).or_default();
            self.syn_counters.entry(zone.clone()).or_default();
            self.syn_cookie_active_until_secs
                .entry(zone.clone())
                .or_insert(0);
            self.syn_cookie_standby_ack_counters
                .entry(zone.clone())
                .or_default();
        }
        self.profiles = profiles;
    }

    /// Publish the cluster-wide SYN-cookie master key into this worker's screen
    /// state. Production snapshots derive this key from committed config and
    /// the cookie epoch is based on Unix wall-clock seconds, so HA peers use
    /// the same epoch/MAC material across failover when clocks are in sync.
    /// `None` still clears the codec and validated-client cache fail-closed.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn update_syn_cookie_master_key(&mut self, master_key: Option<[u8; 16]>) {
        if let Some(master_key) = master_key {
            let codec = SynCookieCodec::new(master_key);
            self.syn_cookie_validated
                .set_hash_keys(codec.cache_hash_keys());
            self.syn_cookie_codec = Some(codec);
        } else {
            self.syn_cookie_codec = None;
            self.syn_cookie_validated.clear();
        }
    }

    fn current_syn_cookie_full_epoch(&mut self) -> u64 {
        #[cfg(test)]
        if let Some(epoch) = self.syn_cookie_full_epoch_override {
            return epoch;
        }
        let epoch = SynCookieCodec::current_full_epoch();
        self.syn_cookie_last_full_epoch = self.syn_cookie_last_full_epoch.max(epoch);
        self.syn_cookie_last_full_epoch
    }

    #[cfg(test)]
    fn set_syn_cookie_full_epoch_for_test(&mut self, full_epoch: u64) {
        self.syn_cookie_full_epoch_override = Some(full_epoch);
    }

    fn standby_syn_cookie_ack_validation_limited(&mut self, zone: &str, now_secs: u64) -> bool {
        self.syn_cookie_standby_ack_counters
            .get_mut(zone)
            .map(|counter| {
                counter.increment(
                    now_secs,
                    SYN_COOKIE_STANDBY_ACK_VALIDATION_RATE_LIMIT_PER_SEC,
                )
            })
            .unwrap_or(true)
    }

    /// Returns true if any zone has a screen profile configured.
    pub fn has_profiles(&self) -> bool {
        !self.profiles.is_empty()
    }

    /// Run all screen checks for a packet arriving on the given zone.
    /// Returns `ScreenVerdict::Pass` if the packet is clean, or
    /// `ScreenVerdict::Drop(reason)` if it should be dropped.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn check_packet(
        &mut self,
        zone: &str,
        pkt: &ScreenPacketInfo,
        now_secs: u64,
    ) -> ScreenVerdict {
        self.check_packet_with_zone_id(zone, 0, pkt, now_secs)
    }

    /// Run all screen checks with the stable numeric zone id available to
    /// SYN-cookie MACs. `check_packet` remains for callers/tests that do not
    /// need cookie mode.
    pub fn check_packet_with_zone_id(
        &mut self,
        zone: &str,
        zone_id: u16,
        pkt: &ScreenPacketInfo,
        now_secs: u64,
    ) -> ScreenVerdict {
        let profile = match self.profiles.get(zone) {
            Some(p) => p.clone(), // clone to avoid borrow issues with &mut self
            None => return ScreenVerdict::Pass,
        };

        // --- Stateless checks (side-effect-free) ---
        if let Some(reason) = stateless::check_land(&profile, pkt) {
            return ScreenVerdict::Drop(reason);
        }
        if let Some(reason) = stateless::check_tcp_flag_screens(&profile, pkt) {
            return ScreenVerdict::Drop(reason);
        }
        if let Some(reason) = stateless::check_ping_of_death(&profile, pkt) {
            return ScreenVerdict::Drop(reason);
        }
        if let Some(reason) = stateless::check_teardrop(&profile, pkt) {
            return ScreenVerdict::Drop(reason);
        }
        if let Some(reason) = stateless::check_icmp_fragment(&profile, pkt) {
            return ScreenVerdict::Drop(reason);
        }
        if let Some(reason) = stateless::check_source_route(&profile, pkt) {
            return ScreenVerdict::Drop(reason);
        }

        // --- Rate-based flood checks ---
        let mut syn_cookie_bypassed = false;

        // ICMP flood
        if profile.icmp_flood_threshold > 0
            && (pkt.protocol == PROTO_ICMP || pkt.protocol == PROTO_ICMPV6)
        {
            if let Some(counter) = self.icmp_counters.get_mut(zone) {
                if counter.increment(now_secs, profile.icmp_flood_threshold) {
                    return ScreenVerdict::Drop("icmp-flood");
                }
            }
        }

        // UDP flood
        if profile.udp_flood_threshold > 0 && pkt.protocol == PROTO_UDP {
            if let Some(counter) = self.udp_counters.get_mut(zone) {
                if counter.increment(now_secs, profile.udp_flood_threshold) {
                    return ScreenVerdict::Drop("udp-flood");
                }
            }
        }

        // SYN flood: count TCP SYN (without ACK) per zone
        if profile.syn_flood_threshold > 0 && pkt.protocol == PROTO_TCP {
            let tf = pkt.tcp_flags;
            if (tf & TCP_SYN) != 0 && (tf & TCP_ACK) == 0 {
                let syn_cookie_validated = profile.syn_cookie
                    && self.syn_cookie_validated.take_valid(
                        zone_id,
                        SynCookieTuple::from_packet(pkt),
                        now_secs,
                    );
                if syn_cookie_validated {
                    syn_cookie_bypassed = true;
                }
                if !syn_cookie_validated {
                    if let Some(counter) = self.syn_counters.get_mut(zone)
                        && counter.increment(now_secs, profile.syn_flood_threshold)
                    {
                        if profile.syn_cookie {
                            if let Some(active_until) =
                                self.syn_cookie_active_until_secs.get_mut(zone)
                            {
                                *active_until =
                                    now_secs.saturating_add(SynCookieCodec::EPOCH_SECS);
                            } else {
                                debug_assert!(
                                    false,
                                    "screen profile update prepopulates SYN-cookie active state"
                                );
                            }
                            let Some(codec) = self.syn_cookie_codec else {
                                return ScreenVerdict::Drop("syn-cookie-unavailable");
                            };
                            let full_epoch = self.current_syn_cookie_full_epoch();
                            let cookie_isn = codec.mint_isn(
                                SynCookieTuple::from_packet(pkt),
                                zone_id,
                                full_epoch,
                                pkt.tcp_mss,
                            );
                            return ScreenVerdict::SynCookieChallenge(SynCookieChallenge {
                                cookie_isn,
                                peer_mss: pkt.tcp_mss,
                            });
                        }
                        return ScreenVerdict::Drop("syn-flood");
                    }
                }
            }
        }

        // --- Advanced stateful checks ---
        // These run only on TCP SYN (new connection attempts) to avoid
        // false positives on established traffic.
        if pkt.protocol == PROTO_TCP {
            let tf = pkt.tcp_flags;
            let is_syn = (tf & TCP_SYN) != 0 && (tf & TCP_ACK) == 0;

            // Port scan detection: count unique dst ports per src IP
            if is_syn && profile.port_scan_threshold > 0 {
                if self.port_scan.check(
                    pkt.src_ip,
                    pkt.dst_port,
                    now_secs,
                    profile.port_scan_threshold,
                ) {
                    return ScreenVerdict::Drop("port-scan");
                }
            }
        }

        // IP sweep detection: count unique dst IPs per src IP (all protocols)
        if profile.ip_sweep_threshold > 0 {
            if self
                .ip_sweep
                .check(pkt.src_ip, pkt.dst_ip, now_secs, profile.ip_sweep_threshold)
            {
                return ScreenVerdict::Drop("ip-sweep");
            }
        }

        // Per-IP session limits: check before session creation
        if profile.session_limit_src > 0 {
            if self
                .session_limits
                .check_src(pkt.src_ip, profile.session_limit_src)
            {
                return ScreenVerdict::Drop("session-limit-src");
            }
        }
        if profile.session_limit_dst > 0 {
            if self
                .session_limits
                .check_dst(pkt.dst_ip, profile.session_limit_dst)
            {
                return ScreenVerdict::Drop("session-limit-dst");
            }
        }

        // Periodic cleanup of tracker state (every 30 seconds)
        if now_secs.saturating_sub(self.last_cleanup_secs) >= 30 {
            self.port_scan.cleanup(now_secs);
            self.ip_sweep.cleanup(now_secs);
            self.last_cleanup_secs = now_secs;
        }

        if syn_cookie_bypassed {
            ScreenVerdict::SynCookieBypass
        } else {
            ScreenVerdict::Pass
        }
    }

    /// Validate a returning SYN-cookie ACK only after the caller has already
    /// established that no normal session matched. This preserves established
    /// ACK traffic and prevents random ACKs from installing sessions while a
    /// cookie flood is active.
    pub fn validate_syn_cookie_ack_on_session_miss(
        &mut self,
        zone: &str,
        zone_id: u16,
        pkt: &ScreenPacketInfo,
        now_secs: u64,
    ) -> SynCookieAckVerdict {
        let Some(profile) = self.profiles.get(zone) else {
            return SynCookieAckVerdict::NotApplicable;
        };
        if !profile.syn_cookie || profile.syn_flood_threshold == 0 || pkt.protocol != PROTO_TCP {
            return SynCookieAckVerdict::NotApplicable;
        }
        let flags = pkt.tcp_flags;
        if (flags & TCP_ACK) == 0 || (flags & TCP_SYN) != 0 {
            return SynCookieAckVerdict::NotApplicable;
        }
        let locally_active = self
            .syn_cookie_active_until_secs
            .get(zone)
            .copied()
            .is_some_and(|until| until > now_secs);
        if (flags & (TCP_FIN | TCP_RST)) != 0 {
            return if locally_active {
                SynCookieAckVerdict::Invalid
            } else {
                SynCookieAckVerdict::NotApplicable
            };
        }
        let Some(codec) = self.syn_cookie_codec else {
            return if locally_active {
                SynCookieAckVerdict::Invalid
            } else {
                SynCookieAckVerdict::NotApplicable
            };
        };
        let cookie_isn = pkt.tcp_ack.wrapping_sub(1);
        let current_epoch = self.current_syn_cookie_full_epoch();
        if !locally_active {
            if !SynCookieCodec::wire_epoch_matches_validation_window(current_epoch, cookie_isn) {
                return SynCookieAckVerdict::NotApplicable;
            }
            if self.standby_syn_cookie_ack_validation_limited(zone, now_secs) {
                return SynCookieAckVerdict::NotApplicable;
            }
        }
        let tuple = SynCookieTuple::from_packet(pkt);
        if codec
            .validate_isn(tuple, zone_id, current_epoch, cookie_isn)
            .is_some()
        {
            self.syn_cookie_validated.insert(zone_id, tuple, now_secs);
            SynCookieAckVerdict::Validated
        } else if locally_active {
            SynCookieAckVerdict::Invalid
        } else {
            SynCookieAckVerdict::NotApplicable
        }
    }

    #[cfg(test)]
    fn syn_cookie_validated_len(&self) -> usize {
        self.syn_cookie_validated.len()
    }

    #[cfg(test)]
    fn syn_cookie_active_zone_count(&self) -> usize {
        self.syn_cookie_active_until_secs.len()
    }

    #[cfg(test)]
    fn syn_cookie_standby_ack_count(&self, zone: &str) -> u32 {
        self.syn_cookie_standby_ack_counters
            .get(zone)
            .map(|counter| counter.count)
            .unwrap_or(0)
    }

    /// Notify the screen state that a new session was created. This increments
    /// per-IP session counters for session limiting.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn session_created(&mut self, src_ip: IpAddr, dst_ip: IpAddr) {
        self.session_limits.session_created(src_ip, dst_ip);
    }

    /// Notify the screen state that a session has expired. This decrements
    /// per-IP session counters for session limiting.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn session_expired(&mut self, src_ip: IpAddr, dst_ip: IpAddr) {
        self.session_limits.session_expired(src_ip, dst_ip);
    }

    /// Returns true if any zone has session limits, port scan, or IP sweep enabled.
    #[allow(dead_code)]
    pub fn has_advanced_features(&self) -> bool {
        self.profiles.values().any(|p| {
            p.session_limit_src > 0
                || p.session_limit_dst > 0
                || p.port_scan_threshold > 0
                || p.ip_sweep_threshold > 0
        })
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
