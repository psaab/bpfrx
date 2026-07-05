//! Screen/IDS attack protection checks for the userspace dataplane.
//!
//! Implements pre-session packet validation that mirrors the eBPF screen stage
//! (`bpf/xdp/xdp_screen.c`). The stateless + rate-based checks run on every
//! packet BEFORE session lookup. The stateful scan/sweep detectors
//! (port-scan, IP-sweep) and the per-IP session limit are NOT pre-session —
//! they run at the NEW-FLOW / session-MISS decision in `poll_descriptor`
//! (`scan_sweep_drop_on_new_flow` here, `new_flow_session_limit_drop`
//! there) so an established flow's mid-stream packets never count toward a
//! scan/sweep or a session limit (#2210 / #2134 ACK-evasion contract).
//!
//! Supported checks:
//! - Land attack (src_ip == dst_ip, any L4 ports — #2215 BPF parity)
//! - TCP SYN+FIN
//! - TCP no-flag (null scan)
//! - TCP FIN without ACK
//! - WinNuke (URG to port 139)
//! - Ping of death (IPv4 fragment whose offset+total-length would
//!   reassemble past 65535 bytes — #893/#2215 formula, any protocol)
//! - Teardrop (overlapping fragments, plus a non-first fragment with no
//!   /negative payload `ip_total_len <= hdr_len` — #3027)
//! - ICMP fragment
//! - IP source route — IPv4 LSRR/SSRR options and IPv6 Routing Header
//!   (source-route routing type), not every IHL>5 packet (#2973)
//! - Rate limiting (ICMP, UDP flood) — per-DESTINATION cap (Junos parity:
//!   ICMP per destination IP, UDP per destination IP+port; #4112) with the
//!   per-zone aggregate retained as a coarser secondary zone-saturation ceiling
//! - SYN flood (per-zone aggregate + per-source/per-destination sub-caps, #3315;
//!   per-destination evaluated before the aggregate cookie/Drop verdict, #4112)
//!
//! ## Missing-screen-profile signal (#3082)
//!
//! A zone may REFERENCE a screen profile that was never defined. #3078 closed
//! the COMMIT path (strict reject / lenient-load warn, #1960), but the
//! dataplane still has no resolved profile for such a zone and so cannot run
//! screen checks for it. This is reachable on the lenient/HA-sync path
//! (older-binary `active.json` on upgrade, or an HA sync from an un-upgraded
//! primary). The Go control plane now threads the set of zones that reference a
//! missing profile (`ConfigSnapshot.screen_missing_profile_zones`) so the
//! None branch can distinguish "zone has no screen configured" (legit Pass,
//! silent) from "zone references a MISSING screen". For the latter it emits a
//! runtime WARN, rate-limited to one per zone per second (sustained traffic
//! produces essentially one WARN until it subsides) so a packet flood to a
//! misconfigured zone cannot spam the log. BOTH the flow-present
//! (`check_packet_with_zone_id`) and the flowless (`check_flowless_screens`,
//! #3908) None branches call `maybe_warn_missing_profile`, so a flowless packet
//! (non-first fragment / non-query ICMP) to a broken-profile zone is as
//! observable as a flow-bearing one. The verdict STILL stays
//! `ScreenVerdict::Pass` — a runtime fail-CLOSED posture would itself be an
//! availability brick (the #1960 no-brick rationale), so the fail-closed-vs-pass
//! posture is a deferred design decision (the /research half of #3082). This
//! change only makes the lenient-path fail-open OBSERVABLE at the dataplane.
//!
//! Layout (#1543, Wave-5): the runtime is split across focused
//! sibling submodules so SYN-cookie crypto can be audited
//! independently from packet policy:
//!
//! - `packet`        — shared `ScreenPacketInfo`, `ScreenProfile`,
//!                     `ScreenVerdict`, protocol/flag constants.
//! - `syncookie`     — `SynCookieCodec`, `SipHash24`,
//!                     `SynCookieValidatedCache`, all cookie types.
//! - `rate`          — per-zone sliding 1-second window `RateCounter`
//!                     (two-bucket counter; no fixed wall-second reset, #2937).
//! - `stateless`     — side-effect-free packet-policy helpers.
//! - `scan`          — port-scan + IP-sweep windowed trackers.
//! - `session_limit` — per-IP session-count tracker.
//! - `extract`       — allocation-free IP/TCP header parser.
//! - `tests`         — relocated screen_tests.rs (loaded via #[path]).

use rustc_hash::FxHashMap;
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

mod extract;
mod packet;
mod rate;
mod scan;
mod stateless;
mod syn_rate;
mod syncookie;

pub(crate) use extract::extract_screen_info;
pub(crate) use packet::{ScreenPacketInfo, ScreenProfile, ScreenVerdict};
// `ScreenParseError` is named only by `extract.rs` (via the `packet`
// path) and by the test module. Production call sites in `afxdp/`
// consume the error by calling `.screen_reason()` on the value returned
// from `extract_screen_info`, so the crate-wide re-export is test-only
// (#2189 removed the last non-test consumer in `afxdp/mod.rs`).
#[cfg(test)]
pub(crate) use packet::ScreenParseError;
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

/// #3343: number of per-screen-reason DROP counters published to the Go
/// control plane. Each ordinal maps 1:1 to a `GlobalCtrScreen*` index on the
/// Go side (`pkg/dataplane.ScreenReasonCounters`, which is a fixed-size array
/// of exactly this many entries). The wire array `BindingStatus.screen_reason_drops`
/// carries one u64 per ordinal; the committed `tests/fixtures/protocol_wire_v1.json`
/// fixture pins the length so a divergence between the two sides fails the
/// `wire_invariant_default_specimens` test.
pub(crate) const SCREEN_REASON_DROP_COUNT: usize = 15;

/// Map a screen DROP reason string to its published per-reason counter ordinal
/// (#3343), or `None` for reasons that are surfaced only through the aggregate
/// `screen_drops` counter (SYN-cookie challenge/validation drops,
/// ICMP-fragment, IP-malformed parse-error). The ordinal order MUST stay in
/// lockstep with `pkg/dataplane.ScreenReasonCounters`. The two `session-limit-*`
/// reasons fold onto the single `session-limit` ordinal because the Go side
/// exposes one combined `GlobalCtrScreenSessionLimit` counter.
#[inline]
pub(crate) fn screen_reason_drop_index(reason: &str) -> Option<usize> {
    Some(match reason {
        "syn-flood" => 0,
        "icmp-flood" => 1,
        "udp-flood" => 2,
        "port-scan" => 3,
        "ip-sweep" => 4,
        "land-attack" => 5,
        "ping-of-death" => 6,
        "teardrop" => 7,
        "tcp-syn-fin" => 8,
        "tcp-no-flag" => 9,
        "tcp-fin-no-ack" => 10,
        "winnuke" => 11,
        "ip-source-route" => 12,
        "syn-frag" => 13,
        "session-limit-src" | "session-limit-dst" => 14,
        _ => return None,
    })
}

use crate::tcp_flags::{is_closing, is_initial_syn};
use packet::{PROTO_ICMP, PROTO_ICMPV6, PROTO_TCP, PROTO_UDP, TCP_ACK, TCP_SYN};
// #2151: production screen no longer references these directly (the
// FIN/closing checks moved to is_closing); the screen test module still
// builds flag bytes with the named bits, so keep them test-visible.
#[cfg(test)]
use packet::{TCP_FIN, TCP_URG};
use rate::RateCounter;
use scan::{IpSweepTracker, PortScanTracker};
use syn_rate::SynRateSketch;
#[cfg(not(test))]
use syncookie::SynCookieValidatedCache;
use syncookie::SYN_COOKIE_STANDBY_ACK_VALIDATION_RATE_LIMIT_PER_SEC;

/// Per-zone screen state with mutable rate counters and advanced trackers.
pub(crate) struct ScreenState {
    profiles: FxHashMap<String, ScreenProfile>, // zone_name -> profile
    // Per-zone AGGREGATE rate counters. #4112: for ICMP/UDP these are now the
    // SECONDARY zone-saturation ceiling (checked at `SECONDARY_FLOOD_CEILING_MULT
    // × threshold`) above the PRIMARY per-destination sketches below; Junos
    // measures the ICMP/UDP flood rate per destination, not per zone.
    icmp_counters: FxHashMap<String, RateCounter>,
    udp_counters: FxHashMap<String, RateCounter>,
    syn_counters: FxHashMap<String, RateCounter>,
    /// #4112: per-zone per-DESTINATION-IP ICMP flood sketch (Junos `icmp flood
    /// threshold` is per destination). Present (Some) only for zones whose
    /// `icmp_flood_threshold > 0`; reuses the #3315 count-min `SynRateSketch`
    /// substrate. PRIMARY cap — checked before the per-zone aggregate ceiling.
    icmp_dst_sketch: FxHashMap<String, SynRateSketch>,
    /// #4112: per-zone per-DESTINATION (IP + PORT) UDP flood sketch (Junos `udp
    /// flood threshold` is per destination IP AND port). Present only for zones
    /// whose `udp_flood_threshold > 0`; reuses the #3315 sketch via
    /// `increment_ip_port`. PRIMARY cap — checked before the per-zone aggregate.
    udp_dst_sketch: FxHashMap<String, SynRateSketch>,
    syn_cookie_active_until_secs: FxHashMap<String, u64>,
    syn_cookie_standby_ack_counters: FxHashMap<String, RateCounter>,
    syn_cookie_codec: Option<SynCookieCodec>,
    syn_cookie_validated: SynCookieValidatedCache,
    /// #2446: per-zone SYN-cookie profile generation. Bumped in
    /// `update_profiles` whenever a zone's SYN-cookie-relevant profile fields
    /// (`syn_cookie` enable, `syn_flood_threshold`) change — including the
    /// zone gaining or losing a profile, which is how a zone→profile
    /// rebinding manifests. The current generation is stamped into a
    /// validated-cache entry on insert and compared on consume, so a tuple
    /// validated under an old profile is treated as a cache miss after the
    /// profile changes and is re-validated under the new profile (its
    /// SYN-flood counter then sees the connection). Keyed by zone name to
    /// match `profiles`; the cache is keyed by `zone_id`, but both the insert
    /// and consume sites carry the zone name, so the name→gen lookup happens
    /// there.
    syn_cookie_profile_gen: FxHashMap<String, u64>,
    syn_cookie_last_full_epoch: u64,
    /// #3032: Unix wall-clock seconds cached for SYN-cookie epoch math,
    /// refreshed at most once per monotonic second (see
    /// `current_syn_cookie_full_epoch`) so the SYN-flood hot path does not
    /// read the OS clock per packet.
    syn_cookie_epoch_wall_secs: u64,
    /// #3032: the monotonic second at which `syn_cookie_epoch_wall_secs` was
    /// last refreshed. `u64::MAX` is the "never refreshed" sentinel so the
    /// first cookie mint/validate always samples the wall clock.
    syn_cookie_epoch_clock_mono_secs: u64,
    #[cfg(test)]
    syn_cookie_full_epoch_override: Option<u64>,
    // Advanced screen trackers (shared across all zones since they track per-IP)
    port_scan: PortScanTracker,
    ip_sweep: IpSweepTracker,
    last_cleanup_secs: u64,
    /// #3082: zone → name of a screen profile the zone REFERENCES but that was
    /// undefined when the snapshot was built (lenient/HA-sync path). A zone in
    /// this map but absent from `profiles` is failing OPEN at the dataplane —
    /// the `None` branch of `check_packet_with_zone_id` distinguishes it from a
    /// zone with no screen configured and emits a rate-limited runtime WARN
    /// (the verdict still stays Pass; fail-closed posture is deferred).
    missing_profile_refs: FxHashMap<String, String>,
    /// #3082: per-zone rate counter that bounds the missing-profile WARN to
    /// `MISSING_PROFILE_WARN_RATE_LIMIT_PER_SEC` per zone so a flood of packets
    /// to a misconfigured zone cannot spam the log (CLAUDE.md log-flood rule).
    missing_profile_warn_counters: FxHashMap<String, RateCounter>,
    /// #3082: count of WARNs actually emitted (post rate-limit). Test seam so a
    /// unit test can assert the WARN path was taken without scraping stderr.
    missing_profile_warn_count: u64,
    /// #3315: per-zone per-DESTINATION SYN-flood rate sketch. Present (Some) only
    /// for zones whose `destination-threshold` is configured; `get_mut(zone)`
    /// returning Some both enables and supplies the limiter (no separate enable
    /// bool needed). The per-dest control is PRIMARY and spoof-resistant (all
    /// SYNs to a victim hit the same `d` CMS cells) and runs even when the zone
    /// is SYN-cookie active.
    syn_dst_sketch: FxHashMap<String, SynRateSketch>,
    /// #3315: per-zone per-SOURCE SYN-flood rate sketch. Present only for zones
    /// whose `source-threshold` is configured. SECONDARY/best-effort: it is
    /// SKIPPED while the zone is SYN-cookie active (the cookie governs the
    /// high-cardinality spoofed-flood regime and per-source is spoof-defeated
    /// there anyway), which confines the sketch to the accurate sub-aggregate
    /// regime.
    syn_src_sketch: FxHashMap<String, SynRateSketch>,
    /// #3315: per-zone last second a SYN-flood alarm event was raised, for the
    /// ≤1/sec/zone cadence. Populated in `update_profiles` for alarm-enabled
    /// zones so the hot path never allocates. `u64::MAX` = never emitted.
    syn_alarm_last_emit_sec: FxHashMap<String, u64>,
    /// #3315: set when the just-checked packet crossed `alarm-threshold` (below
    /// attack-threshold) and the per-zone cadence admits a new alarm. Drained by
    /// `take_syn_alarm_event()` at the poll stage (which has the packet/zone in
    /// scope to emit the out-of-band alarm event). The verdict is NOT a drop.
    syn_alarm_pending: bool,
    /// #3315: sub-attribution test seams (per-worker). The drop verdict reuses
    /// the existing `"syn-flood"` reason id (no Go gRPC/CLI change), so these
    /// counters let tests assert WHICH sub-threshold tripped without scraping
    /// the event stream. Surfacing them on `show security screen` is a tracked
    /// follow-up; the drops are already counted via `screen_drops` and emit a
    /// `syn-flood` event, and the alarm emits a `syn-flood-alarm` event.
    syn_flood_dst_drops: u64,
    syn_flood_src_drops: u64,
    syn_flood_alarm_events: u64,
}

/// #3082: at most one missing-screen-profile WARN per zone per second.
const MISSING_PROFILE_WARN_RATE_LIMIT_PER_SEC: u32 = 1;

/// #4112: multiplier for the per-zone ICMP/UDP flood aggregate SECONDARY
/// ceiling. Junos measures the ICMP/UDP flood rate PER DESTINATION, so the
/// per-destination sketch (threshold `T`) is the PRIMARY cap. The per-zone
/// aggregate `RateCounter` is retained as a coarse zone-saturation backstop that
/// fires at `SECONDARY_FLOOD_CEILING_MULT × T`: a zone with up to this many
/// simultaneously-hot legitimate destinations (each under the per-destination
/// cap) is NOT false-dropped (the #4112 F18 fix — two legit high-volume services
/// no longer SUM into one counter), while a flood spread thin across many
/// destinations is still bounded zone-wide (an operator relying on the zone-wide
/// cap still gets it). The aggregate counts only per-destination-ADMITTED
/// packets (the per-destination check short-circuits first), so it bounds the
/// admitted zone-wide rate. There is no separate Junos knob for this ceiling, so
/// it is derived from the single configured per-destination threshold.
const SECONDARY_FLOOD_CEILING_MULT: u32 = 8;

impl ScreenState {
    pub fn new() -> Self {
        Self {
            profiles: FxHashMap::default(),
            icmp_counters: FxHashMap::default(),
            udp_counters: FxHashMap::default(),
            syn_counters: FxHashMap::default(),
            icmp_dst_sketch: FxHashMap::default(),
            udp_dst_sketch: FxHashMap::default(),
            syn_cookie_active_until_secs: FxHashMap::default(),
            syn_cookie_standby_ack_counters: FxHashMap::default(),
            syn_cookie_codec: None,
            syn_cookie_validated: SynCookieValidatedCache::default(),
            syn_cookie_profile_gen: FxHashMap::default(),
            syn_cookie_last_full_epoch: 0,
            syn_cookie_epoch_wall_secs: 0,
            syn_cookie_epoch_clock_mono_secs: u64::MAX,
            #[cfg(test)]
            syn_cookie_full_epoch_override: None,
            port_scan: PortScanTracker::default(),
            ip_sweep: IpSweepTracker::default(),
            last_cleanup_secs: 0,
            missing_profile_refs: FxHashMap::default(),
            missing_profile_warn_counters: FxHashMap::default(),
            missing_profile_warn_count: 0,
            syn_dst_sketch: FxHashMap::default(),
            syn_src_sketch: FxHashMap::default(),
            syn_alarm_last_emit_sec: FxHashMap::default(),
            syn_alarm_pending: false,
            syn_flood_dst_drops: 0,
            syn_flood_src_drops: 0,
            syn_flood_alarm_events: 0,
        }
    }

    /// #3082: replace the set of zones that reference an undefined screen
    /// profile (called on config update alongside `update_profiles`). Retains
    /// only the WARN rate counters for zones still in the set so a removed /
    /// fixed reference stops warning and frees its counter.
    pub fn update_missing_profiles(&mut self, missing: FxHashMap<String, String>) {
        self.missing_profile_warn_counters
            .retain(|k, _| missing.contains_key(k));
        self.missing_profile_refs = missing;
    }

    /// #3082: emit a rate-limited runtime WARN if `zone` references a screen
    /// profile that was undefined at snapshot-build time. The verdict is
    /// unchanged (the caller still returns `ScreenVerdict::Pass`); this only
    /// makes the lenient-path fail-open observable at the dataplane. O(1)
    /// lookup; the WARN is bounded to one per zone per second.
    fn maybe_warn_missing_profile(&mut self, zone: &str, now_secs: u64) {
        let Some(profile) = self.missing_profile_refs.get(zone) else {
            // Zone has no screen configured at all — legit Pass, no signal.
            return;
        };
        let limited = self
            .missing_profile_warn_counters
            .entry(zone.to_string())
            .or_default()
            .increment(now_secs, MISSING_PROFILE_WARN_RATE_LIMIT_PER_SEC);
        if !limited {
            self.missing_profile_warn_count = self.missing_profile_warn_count.wrapping_add(1);
            eprintln!(
                "xpf-userspace-dp: screen WARN: zone {zone:?} references undefined \
                 screen profile {profile:?}; dataplane is failing OPEN (Pass) for \
                 this zone (#3082 lenient/HA-sync path) — fix the config or upgrade \
                 the HA peer",
                zone = zone,
                profile = profile,
            );
        }
    }

    /// #3082: number of missing-profile WARNs actually emitted (post
    /// rate-limit). Test seam.
    #[cfg(test)]
    pub(crate) fn missing_profile_warn_count(&self) -> u64 {
        self.missing_profile_warn_count
    }

    /// Replace all screen profiles (called on config update).
    pub fn update_profiles(&mut self, profiles: FxHashMap<String, ScreenProfile>) {
        // Clear rate counters for zones that no longer have profiles
        self.icmp_counters.retain(|k, _| profiles.contains_key(k));
        self.udp_counters.retain(|k, _| profiles.contains_key(k));
        self.syn_counters.retain(|k, _| profiles.contains_key(k));
        // #4112: drop the per-destination ICMP/UDP flood sketches for zones that
        // lost the corresponding threshold (memory tracks live config), mirroring
        // the #3315 SYN sketches below.
        self.icmp_dst_sketch
            .retain(|k, _| profiles.get(k).is_some_and(|p| p.icmp_flood_threshold > 0));
        self.udp_dst_sketch
            .retain(|k, _| profiles.get(k).is_some_and(|p| p.udp_flood_threshold > 0));
        self.syn_cookie_active_until_secs
            .retain(|k, _| profiles.contains_key(k));
        self.syn_cookie_standby_ack_counters
            .retain(|k, _| profiles.contains_key(k));
        // #2446: drop generation tracking for zones that lost their profile.
        // If such a zone is reconfigured later, the absence (gen 0 vs. a
        // freshly bumped gen) makes the next change a bump as well — but the
        // master-key clear plus the per-entry TTL already bound any window,
        // and a removed zone has no live cache consumers of its old gen.
        self.syn_cookie_profile_gen
            .retain(|k, _| profiles.contains_key(k));
        for zone in profiles.keys() {
            self.icmp_counters.entry(zone.clone()).or_default();
            self.udp_counters.entry(zone.clone()).or_default();
            self.syn_counters.entry(zone.clone()).or_default();
            // #4112: allocate the per-destination ICMP/UDP flood sketches ONCE
            // per zone that configures the threshold (`or_insert_with` preserves
            // in-flight counters across an unrelated profile edit; the
            // per-increment threshold means a threshold change needs no realloc).
            if profiles[zone].icmp_flood_threshold > 0 {
                self.icmp_dst_sketch
                    .entry(zone.clone())
                    .or_insert_with(SynRateSketch::for_dst);
            }
            if profiles[zone].udp_flood_threshold > 0 {
                self.udp_dst_sketch
                    .entry(zone.clone())
                    .or_insert_with(SynRateSketch::for_dst);
            }
            self.syn_cookie_active_until_secs
                .entry(zone.clone())
                .or_insert(0);
            self.syn_cookie_standby_ack_counters
                .entry(zone.clone())
                .or_default();
            // #2446: bump the per-zone SYN-cookie profile generation when a
            // SYN-cookie-relevant field changes (or the zone newly gains a
            // profile). Only `syn_cookie` (enable/disable) and
            // `syn_flood_threshold` (the gate that consumes a validated-cache
            // entry) affect whether a cached validation may legitimately
            // bypass the SYN-flood counter, so unrelated profile edits
            // (e.g. teardrop, port-scan) do NOT churn the validated cache.
            let new_sig = Self::syn_cookie_profile_signature(&profiles[zone]);
            let old_sig = self.profiles.get(zone).map(Self::syn_cookie_profile_signature);
            if old_sig != Some(new_sig) {
                let zone_gen = self.syn_cookie_profile_gen.entry(zone.clone()).or_insert(0);
                *zone_gen = zone_gen.wrapping_add(1);
            }
        }
        // #3315: maintain the per-source / per-destination SYN-rate sketches and
        // the alarm cadence map. Allocate ONLY for zones whose threshold is
        // configured (192 KiB/zone for both); drop the table when the threshold
        // is removed so memory tracks live config. The sketch is allocated ONCE
        // per zone (not on every reload) — `entry(..).or_insert_with` preserves
        // an existing sketch's in-flight counters across an unrelated profile
        // edit; the per-increment threshold means a threshold change needs no
        // realloc.
        self.syn_dst_sketch
            .retain(|k, _| profiles.get(k).is_some_and(|p| p.syn_flood_dst_threshold > 0));
        self.syn_src_sketch
            .retain(|k, _| profiles.get(k).is_some_and(|p| p.syn_flood_src_threshold > 0));
        self.syn_alarm_last_emit_sec
            .retain(|k, _| profiles.get(k).is_some_and(|p| p.syn_flood_alarm_threshold > 0));
        for (zone, profile) in &profiles {
            if profile.syn_flood_dst_threshold > 0 {
                self.syn_dst_sketch
                    .entry(zone.clone())
                    .or_insert_with(SynRateSketch::for_dst);
            }
            if profile.syn_flood_src_threshold > 0 {
                self.syn_src_sketch
                    .entry(zone.clone())
                    .or_insert_with(SynRateSketch::for_src);
            }
            if profile.syn_flood_alarm_threshold > 0 {
                self.syn_alarm_last_emit_sec
                    .entry(zone.clone())
                    .or_insert(u64::MAX);
            }
        }
        self.profiles = profiles;
    }

    /// #3315: drain a pending SYN-flood alarm. Returns true at most once per
    /// second per zone (the cadence is enforced at set-time in the SYN check).
    /// The poll stage calls this immediately after `check_packet_with_zone_id`
    /// — where the packet/zone are in scope — to emit the out-of-band alarm
    /// event. The packet still forwards (the alarm is log-only, not a drop).
    pub fn take_syn_alarm_event(&mut self) -> bool {
        let pending = self.syn_alarm_pending;
        self.syn_alarm_pending = false;
        pending
    }

    /// #3315: sub-attribution test seams (per-destination / per-source drops,
    /// alarm events). Used by unit tests to assert WHICH SYN-flood sub-threshold
    /// tripped without scraping the event stream.
    #[cfg(test)]
    pub(crate) fn syn_flood_dst_drops(&self) -> u64 {
        self.syn_flood_dst_drops
    }
    #[cfg(test)]
    pub(crate) fn syn_flood_src_drops(&self) -> u64 {
        self.syn_flood_src_drops
    }
    #[cfg(test)]
    pub(crate) fn syn_flood_alarm_events(&self) -> u64 {
        self.syn_flood_alarm_events
    }

    /// #2446: the SYN-cookie-relevant slice of a zone profile. Two profiles
    /// with the same signature are interchangeable for the validated-ACK
    /// cache: a tuple validated under one may bypass the SYN-flood counter
    /// under the other without changing the security posture. Any change here
    /// bumps the zone's profile generation and invalidates its cached
    /// validations. `(syn_cookie, syn_flood_threshold)` — NOT the stateless
    /// screens, scan/sweep, or other flood thresholds, which never gate the
    /// validated cache.
    fn syn_cookie_profile_signature(profile: &ScreenProfile) -> (bool, u32) {
        (profile.syn_cookie, profile.syn_flood_threshold)
    }

    /// #2446: current SYN-cookie profile generation for a zone (0 if the zone
    /// has no profile or has never been configured). Stamped into validated-
    /// cache entries on insert and compared on consume.
    fn syn_cookie_profile_gen(&self, zone: &str) -> u64 {
        self.syn_cookie_profile_gen.get(zone).copied().unwrap_or(0)
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

    /// Current SYN-cookie full epoch, latched non-decreasing.
    ///
    /// `mono_now_secs` is the batch-cached `CLOCK_MONOTONIC` second already
    /// threaded into `check_packet_with_zone_id` / the standby-ACK path. It
    /// is used ONLY as a once-per-second refresh gate (#3032): the actual
    /// epoch is derived from a cached *Unix wall-clock* sample, not from
    /// `mono_now_secs`. The monotonic clock is unsuitable as the epoch input
    /// because HA peers have unrelated monotonic bases — the wall clock is
    /// the shared (NTP-synced) domain that lets a cookie minted on one node
    /// validate on its peer. The OS wall clock is read at most once per
    /// monotonic second, so a SYN flood no longer pays `SystemTime::now()`
    /// per packet (every cookie in the same second shares one 64s epoch).
    fn current_syn_cookie_full_epoch(&mut self, mono_now_secs: u64) -> u64 {
        #[cfg(test)]
        if let Some(epoch) = self.syn_cookie_full_epoch_override {
            return epoch;
        }
        if self.syn_cookie_epoch_clock_mono_secs != mono_now_secs {
            self.syn_cookie_epoch_wall_secs = Self::read_unix_wall_secs();
            self.syn_cookie_epoch_clock_mono_secs = mono_now_secs;
        }
        let epoch = SynCookieCodec::current_full_epoch(self.syn_cookie_epoch_wall_secs);
        self.syn_cookie_last_full_epoch = self.syn_cookie_last_full_epoch.max(epoch);
        self.syn_cookie_last_full_epoch
    }

    /// Read Unix wall-clock seconds. The single OS-clock read behind the
    /// SYN-cookie epoch (#3032); kept off the per-packet leaf
    /// (`SynCookieCodec::current_full_epoch`, which is pure).
    fn read_unix_wall_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0)
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

    /// #4112 F18: ICMP flood admission. Junos measures the ICMP flood rate PER
    /// DESTINATION IP, not per zone. (1) the per-destination count-min sketch is
    /// the PRIMARY cap at the configured `threshold`; (2) the per-zone aggregate
    /// counter is a coarse SECONDARY zone-saturation ceiling at
    /// `SECONDARY_FLOOD_CEILING_MULT × threshold`. The per-destination check
    /// short-circuits, so the aggregate counts only per-destination-admitted
    /// packets (it bounds the admitted zone-wide rate). Returns true when the
    /// packet must be dropped as an ICMP flood. Shared by the flow-present and
    /// flowless (`check_flowless_screens`) paths so both enforce identically.
    fn icmp_flood_drop(
        &mut self,
        zone: &str,
        dst_ip: &IpAddr,
        threshold: u32,
        now_secs: u64,
    ) -> bool {
        // (1) per-DESTINATION cap — PRIMARY (Junos parity).
        if let Some(sketch) = self.icmp_dst_sketch.get_mut(zone)
            && sketch.increment(dst_ip, now_secs, threshold)
        {
            return true;
        }
        // (2) per-zone aggregate — SECONDARY ceiling.
        if let Some(counter) = self.icmp_counters.get_mut(zone) {
            return counter.increment(
                now_secs,
                threshold.saturating_mul(SECONDARY_FLOOD_CEILING_MULT),
            );
        }
        false
    }

    /// #4112 F18: UDP flood admission — like `icmp_flood_drop`, but the PRIMARY
    /// per-destination cap keys on `(dst_ip, dst_port)` (Junos `udp flood
    /// threshold` caps the rate to a destination IP AND port). On the flowless
    /// path a non-first fragment carries no L4 port, so `dst_port` is 0 there and
    /// the cap degrades to per-destination-IP (the best available for a fragment).
    fn udp_flood_drop(
        &mut self,
        zone: &str,
        dst_ip: &IpAddr,
        dst_port: u16,
        threshold: u32,
        now_secs: u64,
    ) -> bool {
        // (1) per-DESTINATION (IP + PORT) cap — PRIMARY (Junos parity).
        if let Some(sketch) = self.udp_dst_sketch.get_mut(zone)
            && sketch.increment_ip_port(dst_ip, dst_port, now_secs, threshold)
        {
            return true;
        }
        // (2) per-zone aggregate — SECONDARY ceiling.
        if let Some(counter) = self.udp_counters.get_mut(zone) {
            return counter.increment(
                now_secs,
                threshold.saturating_mul(SECONDARY_FLOOD_CEILING_MULT),
            );
        }
        false
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
        self.check_packet_with_zone_id_opts(zone, zone_id, pkt, now_secs, false)
    }

    /// As `check_packet_with_zone_id`, but `skip_rate_flood` suppresses the
    /// rate-based flood counters (icmp/udp/syn-flood + SYN-cookie) while still
    /// running the stateless per-packet screens.
    ///
    /// #4155: fabric-redirected traffic in a chassis cluster was already
    /// rate-screened on the ingress node before it crossed the fabric link.
    /// The RG owner must NOT re-run the rate counters on that same packet —
    /// re-counting double-counts it against the per-zone / per-destination
    /// flood thresholds, so a legit high-pps synced session can false-trip a
    /// flood Drop and defeat fabric cross-chassis forwarding
    /// (`docs/fabric-cross-chassis-fwd.md`). The caller passes
    /// `skip_rate_flood = (meta.meta_flags & FABRIC_INGRESS_FLAG) != 0`.
    pub fn check_packet_with_zone_id_opts(
        &mut self,
        zone: &str,
        zone_id: u16,
        pkt: &ScreenPacketInfo,
        now_secs: u64,
        skip_rate_flood: bool,
    ) -> ScreenVerdict {
        // #2209 perf: borrow the profile instead of cloning it. The
        // stateless/rate checks below read `self.profiles` immutably while
        // mutating disjoint per-zone counter fields (`icmp_counters`,
        // `syn_counters`, …) and the SYN-cookie sub-state — Rust's
        // disjoint-field borrow rules permit holding `&self.profiles[..]`
        // across `self.<other_field>.get_mut(..)`. The pre-#2209 per-packet
        // `ScreenProfile::clone()` was a convenience to dodge a borrow
        // conflict that does not actually exist; on the screen hot path it
        // was a full-struct copy on every screened packet. Helper methods
        // that need `&mut self` (SYN-cookie codec/epoch/validated-cache)
        // copy the small fields they need out of `*profile` first so the
        // immutable `profiles` borrow is not held across them.
        let Some(profile) = self.profiles.get(zone) else {
            // #3082: no resolved profile for this zone. Distinguish the two
            // None cases: a zone that references a MISSING screen profile
            // (lenient/HA-sync fail-open) gets a rate-limited runtime WARN; a
            // zone with no screen configured passes silently. The verdict is
            // Pass in BOTH cases — the fail-closed-vs-pass posture is deferred.
            self.maybe_warn_missing_profile(zone, now_secs);
            return ScreenVerdict::Pass;
        };

        // --- Stateless checks (side-effect-free) ---
        if let Some(reason) = stateless::check_land(profile, pkt) {
            return ScreenVerdict::Drop(reason);
        }
        if let Some(reason) = stateless::check_tcp_flag_screens(profile, pkt) {
            return ScreenVerdict::Drop(reason);
        }
        if let Some(reason) = stateless::check_ping_of_death(profile, pkt) {
            return ScreenVerdict::Drop(reason);
        }
        if let Some(reason) = stateless::check_teardrop(profile, pkt) {
            return ScreenVerdict::Drop(reason);
        }
        if let Some(reason) = stateless::check_icmp_fragment(profile, pkt) {
            return ScreenVerdict::Drop(reason);
        }
        if let Some(reason) = stateless::check_source_route(profile, pkt) {
            return ScreenVerdict::Drop(reason);
        }

        // #4155: fabric-redirected traffic was already rate-screened on the
        // ingress node before it crossed the fabric link. Skip the rate-based
        // flood counters (icmp/udp/syn-flood + SYN-cookie) so the same packet
        // is not counted a SECOND time against the per-zone / per-destination
        // flood thresholds on the RG owner. Re-counting would let a legit
        // high-pps synced session false-trip a flood Drop, dropping exactly
        // the traffic fabric cross-chassis forwarding exists to protect during
        // failback / asymmetric-routing windows (vSRX does not re-screen
        // fabric-forwarded traffic). The stateless per-packet screens above
        // already ran and are idempotent; only the RATE counters must fire
        // once, on the true ingress node. The per-destination flood sketches
        // (#4132) are left intact — this skips the re-count, it does not
        // disable the screen. A `SynCookieBypass` verdict is likewise
        // suppressed: a fabric-redirected SYN belongs to a session the peer
        // already admitted, so the owner mints no cookie challenge/bypass.
        if skip_rate_flood {
            return ScreenVerdict::Pass;
        }

        // --- Rate-based flood checks ---
        // Copy the small scalar thresholds/flags out of the profile so the
        // immutable `self.profiles` borrow is released before the SYN-cookie
        // path needs `&mut self` (`current_syn_cookie_full_epoch`,
        // `syn_cookie_validated`). The flood counters below are disjoint
        // fields so they could borrow alongside `profile`, but pulling the
        // scalars up front keeps the SYN-cookie borrow story trivial.
        let icmp_flood_threshold = profile.icmp_flood_threshold;
        let udp_flood_threshold = profile.udp_flood_threshold;
        let syn_flood_threshold = profile.syn_flood_threshold;
        let syn_cookie = profile.syn_cookie;
        // #3315: SYN-flood sub-thresholds (0 = disabled). Pulled up front with
        // the other scalars so the immutable `self.profiles` borrow is released
        // before the per-source/per-destination sketches and the alarm map need
        // `&mut self`.
        let syn_alarm_threshold = profile.syn_flood_alarm_threshold;
        let syn_dst_threshold = profile.syn_flood_dst_threshold;
        let syn_src_threshold = profile.syn_flood_src_threshold;
        // `profile` borrow ends here (NLL): no further reads of
        // `self.profiles` in this method. Scan/sweep moved to the new-flow
        // hook (`scan_sweep_drop_on_new_flow`), so the advanced trackers are
        // not touched on this per-packet path anymore (#2210).

        let mut syn_cookie_bypassed = false;

        // ICMP flood — per-DESTINATION cap (PRIMARY) + per-zone aggregate ceiling
        // (SECONDARY). Junos measures this rate per destination IP (#4112 F18).
        if icmp_flood_threshold > 0
            && (pkt.protocol == PROTO_ICMP || pkt.protocol == PROTO_ICMPV6)
            && self.icmp_flood_drop(zone, &pkt.dst_ip, icmp_flood_threshold, now_secs)
        {
            return ScreenVerdict::Drop("icmp-flood");
        }

        // UDP flood — per-DESTINATION (IP + PORT) cap (PRIMARY) + per-zone
        // aggregate ceiling (SECONDARY). Junos caps per destination IP AND port
        // (#4112 F18).
        if udp_flood_threshold > 0
            && pkt.protocol == PROTO_UDP
            && self.udp_flood_drop(
                zone,
                &pkt.dst_ip,
                pkt.dst_port,
                udp_flood_threshold,
                now_secs,
            )
        {
            return ScreenVerdict::Drop("udp-flood");
        }

        // SYN flood: count TCP SYN (without ACK) per zone.
        //
        // #3315 + #4112 F19 enforcement order (aggregate counts first, per-dst
        // authoritative over the aggregate cookie/Drop verdict, per-src additive):
        //   1. aggregate `attack-threshold` (+ `alarm-threshold`) — ALWAYS counts
        //      via a SINGLE window advance so its cookie-activation side-effect
        //      can never be skipped. It does NOT return here.
        //   2. per-DESTINATION cap (primary, spoof-resistant) — evaluated BEFORE
        //      the aggregate over-attack early-return (#4112 F19), so a per-dst
        //      trip HARD-DROPS the flooded victim even while the zone is over
        //      attack-threshold and minting cookies for validated clients. Runs
        //      even when cookie-active.
        //   3. aggregate over-attack verdict — mint a SYN-cookie challenge (or
        //      Drop when cookies are disabled); UNCHANGED for the case where the
        //      per-dst cap did not trip.
        //   4. per-SOURCE cap (secondary) — SKIPPED while the zone is cookie-
        //      active (the cookie governs the spoofed-flood regime; per-source is
        //      spoof-defeated there and the sketch would over-throttle).
        // A validated returning SYN-cookie client bypasses ALL of the above.
        if syn_flood_threshold > 0 && pkt.protocol == PROTO_TCP {
            let tf = pkt.tcp_flags;
            if is_initial_syn(tf) {
                let profile_gen = self.syn_cookie_profile_gen(zone);
                let syn_cookie_validated = syn_cookie
                    && self.syn_cookie_validated.take_valid(
                        zone_id,
                        profile_gen,
                        SynCookieTuple::from_packet(pkt),
                        now_secs,
                    );
                if syn_cookie_validated {
                    syn_cookie_bypassed = true;
                }
                if !syn_cookie_validated {
                    // (1) Aggregate dual-threshold in a SINGLE window advance
                    // (D7): one compare against attack, one against alarm. When
                    // alarm is disabled, pass u32::MAX so `over_alarm` is always
                    // false and the alarm branch is dead.
                    let alarm_arg = if syn_alarm_threshold > 0 {
                        syn_alarm_threshold
                    } else {
                        u32::MAX
                    };
                    let (over_attack, over_alarm) = self
                        .syn_counters
                        .get_mut(zone)
                        .map(|counter| {
                            counter.increment_and_classify(
                                now_secs,
                                syn_flood_threshold,
                                alarm_arg,
                            )
                        })
                        .unwrap_or((false, false));
                    // (2) per-DESTINATION cap — PRIMARY. Evaluated BEFORE the
                    // aggregate over-attack early-return (#4112 F19) so a
                    // per-destination trip HARD-DROPS the flooded victim even
                    // while the zone is over attack-threshold and minting cookies
                    // for validated clients. destination-threshold's purpose
                    // (shield a single over-threshold backend even from
                    // cookie-completing clients) was otherwise defeated in exactly
                    // the high-load regime it is configured for: `if over_attack`
                    // returned the cookie challenge before the per-dst sketch at
                    // the old site (2) was ever reached. The aggregate counter
                    // above ALWAYS counts first (its cookie-activation side-effect
                    // is never skipped); a per-dst trip never flips zone cookie
                    // state. Runs even when the zone is cookie-active.
                    if syn_dst_threshold > 0
                        && let Some(sketch) = self.syn_dst_sketch.get_mut(zone)
                        && sketch.increment(&pkt.dst_ip, now_secs, syn_dst_threshold)
                    {
                        self.syn_flood_dst_drops = self.syn_flood_dst_drops.wrapping_add(1);
                        return ScreenVerdict::Drop("syn-flood");
                    }
                    if over_attack {
                        if syn_cookie {
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
                            let full_epoch = self.current_syn_cookie_full_epoch(now_secs);
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
                    // Alarm-threshold crossed but below attack (we returned
                    // above otherwise): raise a log-only alarm at most once per
                    // second per zone. The verdict is unaffected — the packet
                    // continues to the per-IP checks and (if clean) forwards.
                    if syn_alarm_threshold > 0
                        && over_alarm
                        && let Some(last) = self.syn_alarm_last_emit_sec.get_mut(zone)
                        && *last != now_secs
                    {
                        *last = now_secs;
                        self.syn_alarm_pending = true;
                        self.syn_flood_alarm_events = self.syn_flood_alarm_events.wrapping_add(1);
                    }
                    // (3) per-SOURCE cap — SECONDARY, skipped while the zone is
                    // SYN-cookie active (D3). The cookie-active window is the
                    // high-cardinality spoofed-flood regime where per-source is
                    // both spoof-defeated and prone to sketch over-throttling.
                    let cookie_active = syn_cookie
                        && self
                            .syn_cookie_active_until_secs
                            .get(zone)
                            .is_some_and(|&until| until > now_secs);
                    if syn_src_threshold > 0
                        && !cookie_active
                        && let Some(sketch) = self.syn_src_sketch.get_mut(zone)
                        && sketch.increment(&pkt.src_ip, now_secs, syn_src_threshold)
                    {
                        self.syn_flood_src_drops = self.syn_flood_src_drops.wrapping_add(1);
                        return ScreenVerdict::Drop("syn-flood");
                    }
                }
            }
        }

        // #2210: port-scan / IP-sweep are NOT evaluated here. They used to
        // run on this per-packet pre-session stage, so IP-sweep counted
        // EVERY packet — including mid-flow established TCP ACKs/data and
        // UDP — before the dataplane knew whether a session already
        // existed. A single legitimate high-fan-out client (one host with
        // live connections to many backends) would trip ip-sweep without
        // ever sending a probe, and the original #867 ACK-evasion contract
        // ("an ACK that matches a live session is not a sweep probe") was
        // lost. The scan/sweep mutation now lives in
        // `scan_sweep_drop_on_new_flow`, invoked from the new-flow /
        // session-MISS decision in `poll_descriptor` (the same hook that
        // owns the #2134 per-IP session-limit check), so only a genuinely
        // new flow counts toward a scan/sweep.

        // #2134: per-IP session limits are NOT checked here either, for the
        // same reason — they live at the new-flow / session-MISS decision in
        // `poll_descriptor`, where they fire exactly once per new flow
        // before that flow's session exists. See
        // `session::SessionTable::session_limit_{src,dst}_count` and the
        // count maintenance at the install/remove sinks.

        if syn_cookie_bypassed {
            ScreenVerdict::SynCookieBypass
        } else {
            ScreenVerdict::Pass
        }
    }

    /// #3064 + #3902: run the SOURCE-INDEPENDENT screens for a packet that
    /// has NO transport flow — a non-first IP fragment or a non-query
    /// ICMP/ICMPv6 control message that `parse_session_flow_from_bytes`
    /// deliberately leaves flowless (#2344, to avoid treating fragment
    /// payload as L4 ports; #3290, to avoid keying a session on a non-port
    /// ICMP control word). Every screen evaluated here is genuinely
    /// flow/session-INDEPENDENT — it reads only the L3 header (and per-zone
    /// rate counters keyed on protocol), never a per-flow tuple:
    ///
    ///   - **LAND anti-spoof** (`src_ip == dst_ip`): reads only the L3
    ///     addresses. The caller derives the REAL source/destination from
    ///     the IP header and sets `addrs_known`; when it could not (frame too
    ///     short to hold the addresses) LAND is skipped so a placeholder
    ///     `src == dst == unspecified` is not mistaken for a spoofed frame.
    ///   - **ping-of-death / teardrop / icmp-fragment** (#3064): the L3
    ///     fragment screens — fragment offset, total/payload length,
    ///     protocol only.
    ///   - **ip-source-route** (IPv4 LSRR/SSRR, IPv6 RH0/RH1): read from the
    ///     IP-header options / extension-header chain by `extract.rs`.
    ///   - **ICMP flood / UDP flood**: per-zone rate counters keyed purely
    ///     on protocol.
    ///
    /// Before #3902 the flowless branch ran ONLY the three fragment screens,
    /// so a crafted non-first fragment / non-query ICMP BYPASSED LAND,
    /// ip-source-route, and the ICMP/UDP flood counters (screen fail-open) —
    /// an attack the operator explicitly enabled the screen to block
    /// transited on the flowless path.
    ///
    /// Flow/session-dependent screens (TCP-flag bits, the SYN-flood
    /// per-source/per-destination sketches, scan/sweep, SYN-cookie) require
    /// a flow / real TCP header and stay gated on the flow-present
    /// `check_packet_with_zone_id` path. The drop precedence of the screens
    /// run here matches that method's relative order exactly (LAND →
    /// ping-of-death → teardrop → icmp-fragment → source-route → icmp-flood
    /// → udp-flood).
    ///
    /// When the zone has no resolved profile this mirrors the flow-present
    /// path's None branch (#3908): a zone that REFERENCES a screen profile
    /// undefined at snapshot-build time gets a rate-limited runtime WARN via
    /// `maybe_warn_missing_profile`, while a zone with no screen configured
    /// passes silently. The verdict is `Pass` in both cases (watch-log-only,
    /// no drop-behavior change — see the #3082 module note).
    pub(crate) fn check_flowless_screens(
        &mut self,
        zone: &str,
        pkt: &ScreenPacketInfo,
        addrs_known: bool,
        now_secs: u64,
    ) -> ScreenVerdict {
        self.check_flowless_screens_opts(zone, pkt, addrs_known, now_secs, false)
    }

    /// As `check_flowless_screens`, but `skip_rate_flood` suppresses the
    /// source-independent rate-based flood counters (icmp/udp-flood) while
    /// still running the stateless source-independent screens.
    ///
    /// #4155: a fabric-redirected non-first fragment / non-query ICMP control
    /// message was already rate-screened on the ingress node; the RG owner
    /// must not re-count it. See `check_packet_with_zone_id_opts`.
    pub(crate) fn check_flowless_screens_opts(
        &mut self,
        zone: &str,
        pkt: &ScreenPacketInfo,
        addrs_known: bool,
        now_secs: u64,
        skip_rate_flood: bool,
    ) -> ScreenVerdict {
        let Some(profile) = self.profiles.get(zone) else {
            // #3908: mirror the flow-present `check_packet_with_zone_id` None
            // branch so the flowless path is as observable as the flow path.
            // A zone that REFERENCES a screen profile undefined at
            // snapshot-build time (lenient/HA-sync fail-open) gets a
            // rate-limited runtime WARN; a zone with no screen configured
            // passes silently (the helper distinguishes the two). Verdict is
            // still Pass in BOTH cases — watch-log-only, no drop-behavior
            // change (the fail-closed-vs-pass posture is the deferred #3082
            // design decision). O(1): one hashmap lookup + a rate-limited
            // increment; no unwrap/panic on the hot flowless path.
            self.maybe_warn_missing_profile(zone, now_secs);
            return ScreenVerdict::Pass;
        };
        // --- Stateless, source-independent checks (side-effect-free) ---
        // LAND is address-dependent: only evaluate it when the caller
        // supplied the real L3 addresses (`addrs_known`).
        if addrs_known && let Some(reason) = stateless::check_land(profile, pkt) {
            return ScreenVerdict::Drop(reason);
        }
        if let Some(reason) = stateless::check_ping_of_death(profile, pkt) {
            return ScreenVerdict::Drop(reason);
        }
        if let Some(reason) = stateless::check_teardrop(profile, pkt) {
            return ScreenVerdict::Drop(reason);
        }
        if let Some(reason) = stateless::check_icmp_fragment(profile, pkt) {
            return ScreenVerdict::Drop(reason);
        }
        if let Some(reason) = stateless::check_source_route(profile, pkt) {
            return ScreenVerdict::Drop(reason);
        }
        // #4155: fabric-redirected flowless traffic was already rate-screened
        // on the ingress node — skip the re-count (see
        // `check_packet_with_zone_id_opts`). Stateless source-independent
        // screens above already ran and are idempotent.
        if skip_rate_flood {
            return ScreenVerdict::Pass;
        }
        // --- Rate-based flood checks (source-independent, per-zone) ---
        // Copy the scalar thresholds out so the immutable `self.profiles`
        // borrow is released before the `&mut self` per-zone counter maps
        // (mirrors `check_packet_with_zone_id`).
        let icmp_flood_threshold = profile.icmp_flood_threshold;
        let udp_flood_threshold = profile.udp_flood_threshold;
        // `profile` borrow ends here (NLL): no further reads of `self.profiles`.

        // ICMP flood — per-DESTINATION cap (PRIMARY) + per-zone aggregate ceiling
        // (SECONDARY), same as the flow-present path (#4112 F18). Keeps a
        // fragment-based flood from evading the per-destination cap.
        if icmp_flood_threshold > 0
            && (pkt.protocol == PROTO_ICMP || pkt.protocol == PROTO_ICMPV6)
            && self.icmp_flood_drop(zone, &pkt.dst_ip, icmp_flood_threshold, now_secs)
        {
            return ScreenVerdict::Drop("icmp-flood");
        }

        // UDP flood — per-DESTINATION cap (PRIMARY) + per-zone aggregate ceiling
        // (SECONDARY). A flowless non-first fragment has no L4 port, so `dst_port`
        // is 0 here and the cap degrades to per-destination-IP (#4112 F18).
        if udp_flood_threshold > 0
            && pkt.protocol == PROTO_UDP
            && self.udp_flood_drop(
                zone,
                &pkt.dst_ip,
                pkt.dst_port,
                udp_flood_threshold,
                now_secs,
            )
        {
            return ScreenVerdict::Drop("udp-flood");
        }

        ScreenVerdict::Pass
    }

    /// #2210 + #2209: port-scan / IP-sweep evaluation at the NEW-FLOW
    /// decision, mirroring the #2134 session-limit-on-miss hook.
    ///
    /// This MUST be called only after the caller has determined the packet
    /// is a session MISS (no established session matched). That is what
    /// preserves the ACK-evasion contract: an established flow's mid-stream
    /// packets are session HITS and never reach this hook, so they never
    /// inflate the sweep counter (the #2210 false-positive root cause).
    /// port-scan additionally keeps its TCP-initial-SYN gate; IP-sweep
    /// counts the new flow on any protocol.
    ///
    /// State is keyed by `(zone_id, src_ip)` (per-zone, #2209) and bounded
    /// (per-zone source cap + per-source unique-entry cap, fail-safe on
    /// overflow — see `scan.rs`). Returns the screen-drop reason if the new
    /// flow crosses a threshold, or `None` to proceed. Cold path
    /// (session-miss only).
    pub fn scan_sweep_drop_on_new_flow(
        &mut self,
        zone: &str,
        zone_id: u16,
        pkt: &ScreenPacketInfo,
        now_secs: u64,
    ) -> Option<&'static str> {
        let Some(profile) = self.profiles.get(zone) else {
            return None;
        };
        let port_scan_threshold = profile.port_scan_threshold;
        let ip_sweep_threshold = profile.ip_sweep_threshold;
        // `profile` borrow ends here (NLL).
        if port_scan_threshold == 0 && ip_sweep_threshold == 0 {
            // Still tick the cleanup so a config with the feature briefly
            // enabled-then-disabled cannot strand tracker state.
            self.maybe_cleanup_trackers(now_secs);
            return None;
        }

        // Port scan: count unique dst ports per (zone, src) on initial SYN.
        if port_scan_threshold > 0
            && pkt.protocol == PROTO_TCP
            && is_initial_syn(pkt.tcp_flags)
            && self
                .port_scan
                .check(zone_id, pkt.src_ip, pkt.dst_port, now_secs, port_scan_threshold)
        {
            self.maybe_cleanup_trackers(now_secs);
            return Some("port-scan");
        }

        // IP sweep: count unique dst IPs per (zone, src) for the new flow
        // (any protocol). Because this only runs on a session MISS, an
        // established flow's packets never count.
        if ip_sweep_threshold > 0
            && self
                .ip_sweep
                .check(zone_id, pkt.src_ip, pkt.dst_ip, now_secs, ip_sweep_threshold)
        {
            self.maybe_cleanup_trackers(now_secs);
            return Some("ip-sweep");
        }

        self.maybe_cleanup_trackers(now_secs);
        None
    }

    /// Periodic (>=30s) budgeted cleanup of the scan/sweep trackers. Driven
    /// from the new-flow hook so it is co-located with the only site that
    /// mutates the trackers.
    fn maybe_cleanup_trackers(&mut self, now_secs: u64) {
        if now_secs.saturating_sub(self.last_cleanup_secs) >= 30 {
            self.port_scan.cleanup(now_secs);
            self.ip_sweep.cleanup(now_secs);
            self.last_cleanup_secs = now_secs;
        }
    }

    /// #2209: total scan/sweep records skipped because a per-zone source
    /// cap or per-source unique-entry cap was hit (fail-safe overflow
    /// pressure). Pure observability; never affects a verdict.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn scan_sweep_skipped_pressure(&self) -> u64 {
        self.port_scan.skipped_pressure() + self.ip_sweep.skipped_pressure()
    }

    /// #2227 MAJOR-1: total scan/sweep checks whose operator threshold
    /// exceeded the supported maximum (`MAX_UNIQUE_PER_SOURCE - 1`) and was
    /// clamped to it (fail-closed clamp — detection fires AT THE CAP rather
    /// than never). Pure observability; surfaces an operator misconfiguration
    /// (a threshold the bounded set could never reach un-clamped). The Go
    /// control plane also warns at commit time when a threshold exceeds the
    /// supported maximum.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn scan_sweep_threshold_clamped(&self) -> u64 {
        self.port_scan.threshold_clamped() + self.ip_sweep.threshold_clamped()
    }

    /// #2234: total stalest-evictions on the scan/sweep source-saturation
    /// path. A non-zero value means the per-zone source table hit its cap and
    /// the detector displaced stale sources to keep a fresh real scanner
    /// trackable (it no longer silently drops new sources on a full table).
    /// Pure observability; never affects a verdict.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn scan_sweep_evicted_pressure(&self) -> u64 {
        self.port_scan.evicted_pressure() + self.ip_sweep.evicted_pressure()
    }

    /// #2234: returns `true` on a rare (logarithmic) eviction-rate threshold
    /// crossing, signalling the caller to emit a `scan-table-pressure` screen
    /// event so the operator is told the scan/sweep detector is saturated.
    /// Fires at most a handful of times under a sustained flood (powers of
    /// two in the cumulative eviction count) — NEVER per flow, honouring the
    /// no-per-packet-logging rule. The crossing is consumed on read.
    pub fn take_scan_table_pressure_event(&mut self) -> bool {
        // Evaluate BOTH so each tracker's epoch advances independently; the
        // `|` (not `||`) avoids short-circuiting the second take.
        let port = self.port_scan.take_pressure_event();
        let sweep = self.ip_sweep.take_pressure_event();
        port | sweep
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
        if is_closing(flags) {
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
        let current_epoch = self.current_syn_cookie_full_epoch(now_secs);
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
            let profile_gen = self.syn_cookie_profile_gen(zone);
            self.syn_cookie_validated
                .insert(zone_id, profile_gen, tuple, now_secs);
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

    /// #2134: true iff any zone configures a per-IP session limit
    /// (`limit-session source-ip-based` / `destination-ip-based`). Drives
    /// the `SessionTable` session-limit OFF-gate so install/remove pay
    /// nothing when the feature is unconfigured. Separate from
    /// `has_advanced_features` (which also covers port-scan / ip-sweep,
    /// neither of which touches the SessionTable count).
    pub fn any_session_limit_configured(&self) -> bool {
        self.profiles
            .values()
            .any(|p| p.session_limit_src > 0 || p.session_limit_dst > 0)
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
