package userspace

import (
	"log/slog"
	"math"

	"github.com/psaab/xpf/pkg/config"
)

// #1977: several FlowSnapshot/FlowExportSnapshot fields are Go signed `int` on
// the control-socket snapshot wire but Rust **unsigned** (u16/u32/u64). A
// negative or out-of-range value (e.g. an operator typo `tcp-mss-gre-in 70000`,
// or a sampling input-rate exceeding u32) serializes fine from Go but makes
// `serde_json::from_str::<ControlRequest>` ERROR on the helper, aborting the
// ENTIRE apply_snapshot decode — the helper stays unconfigured and forwarding
// silently breaks (the #1961 failure class). `buildFlowSnapshot` /
// `buildFlowExportSnapshot` are the sole pre-wire constructor of these structs
// (called only from `buildSnapshot`), so coercing each field into its Rust wire
// range here guards every input path (CLI, gRPC, file). In-range values pass
// through unchanged; out-of-range values are coerced to a safe sentinel and a
// single warning is logged (this runs once per config commit, never per
// packet). The complementary commit-time CLI validation (a clear `commit check`
// error instead of silent coercion) is tracked as a follow-up; this guard is
// the dataplane-safety guarantee.

// coerceWireU16 clamps an int destined for a Rust u16 wire field. Out-of-range
// (negative or >65535) becomes 0 — the "disabled"/"use default" sentinel these
// MSS fields already use (for GRE-out, Rust 0 means MTU-derived MSS).
func coerceWireU16(field string, v int) int {
	if v < 0 || v > math.MaxUint16 {
		slog.Warn("userspace: out-of-range u16 wire value coerced to 0 (#1977)",
			"field", field, "value", v)
		return 0
	}
	return v
}

// coerceWireU32Timeout clamps an int destined for a Rust u32 timeout field:
// negative -> 0 (= use default), >u32max -> u32max. u32max*1e9 fits in u64, so
// there is no Rust-side multiplication overflow at the cap.
func coerceWireU32Timeout(field string, v int) int {
	if v < 0 {
		slog.Warn("userspace: negative u32 wire timeout coerced to 0 (#1977)",
			"field", field, "value", v)
		return 0
	}
	if int64(v) > math.MaxUint32 {
		slog.Warn("userspace: out-of-range u32 wire timeout capped to u32 max (#1977)",
			"field", field, "value", v)
		return math.MaxUint32
	}
	return v
}

// coerceWireSessionTimeout clamps an int destined for a Rust u64 session-timeout
// field. The cap is MaxDurationSeconds (= MaxInt64/1e9), NOT u64 max, because
// the helper's SessionTimeouts::from_seconds multiplies seconds*1e9 without
// checked arithmetic; MaxDurationSeconds keeps the product within u64.
func coerceWireSessionTimeout(field string, v int) int {
	if v < 0 {
		slog.Warn("userspace: negative session timeout coerced to 0 (#1977)",
			"field", field, "value", v)
		return 0
	}
	if int64(v) > config.MaxDurationSeconds {
		slog.Warn("userspace: session timeout capped to MaxDurationSeconds (#1977)",
			"field", field, "value", v, "cap", config.MaxDurationSeconds)
		return int(config.MaxDurationSeconds)
	}
	return v
}

func buildFlowSnapshot(cfg *config.Config) FlowSnapshot {
	snap := FlowSnapshot{
		AllowDNSReply:      cfg.Security.Flow.AllowDNSReply,
		AllowEmbeddedICMP:  cfg.Security.Flow.AllowEmbeddedICMP,
		TCPMSSIPsecVPN:     coerceWireU16("tcp_mss_ipsec_vpn", cfg.Security.Flow.TCPMSSIPsecVPN),
		TCPMSSGreIn:        coerceWireU16("tcp_mss_gre_in", cfg.Security.Flow.TCPMSSGreIn),
		TCPMSSGreOut:       coerceWireU16("tcp_mss_gre_out", cfg.Security.Flow.TCPMSSGreOut),
		UDPSessionTimeout:  coerceWireSessionTimeout("udp_session_timeout", cfg.Security.Flow.UDPSessionTimeout),
		ICMPSessionTimeout: coerceWireSessionTimeout("icmp_session_timeout", cfg.Security.Flow.ICMPSessionTimeout),
		GREAcceleration:    cfg.Security.Flow.GREPerformanceAcceleration,
		PowerModeDisable:   cfg.Security.Flow.PowerModeDisable,
		Lo0FilterInputV4:   cfg.System.Lo0FilterInputV4,
		Lo0FilterInputV6:   cfg.System.Lo0FilterInputV6,
	}
	// TCPMSSAllTCP is in the wire contract (Rust u16) but is not populated by
	// this builder today; coerce defensively so it stays safe if it is ever
	// wired from config (#1977, Codex r2). No-op while it remains zero.
	snap.TCPMSSAllTCP = coerceWireU16("tcp_mss_all_tcp", snap.TCPMSSAllTCP)
	if cfg.Security.Flow.TCPSession != nil {
		snap.TCPSessionTimeout = coerceWireSessionTimeout(
			"tcp_session_timeout", cfg.Security.Flow.TCPSession.EstablishedTimeout)
	}
	snap.ALGDisableFlags = algDisableFlags(&cfg.Security.ALG)
	return snap
}

// algDisableFlags packs the `security alg <proto> disable` knobs into the
// bitfield the userspace dataplane consumes (#2008 H3/H4). The bit layout
// MUST match pkg/dataplane/compiler.go's legacy flow_config_map encoding and
// the Rust ALG_DISABLE_* constants: DNS=0x01, FTP=0x02, SIP=0x04, TFTP=0x08.
func algDisableFlags(alg *config.ALGConfig) uint8 {
	if alg == nil {
		return 0
	}
	var flags uint8
	if alg.DNSDisable {
		flags |= 0x01
	}
	if alg.FTPDisable {
		flags |= 0x02
	}
	if alg.SIPDisable {
		flags |= 0x04
	}
	if alg.TFTPDisable {
		flags |= 0x08
	}
	return flags
}

func buildFlowExportSnapshot(cfg *config.Config) *FlowExportSnapshot {
	if cfg == nil || cfg.Services.FlowMonitoring == nil {
		return nil
	}
	fm := cfg.Services.FlowMonitoring
	if fm.Version9 == nil || len(fm.Version9.Templates) == 0 {
		return nil
	}
	// Find sampling config for flow server
	if cfg.ForwardingOptions.Sampling == nil {
		return nil
	}
	for _, inst := range cfg.ForwardingOptions.Sampling.Instances {
		if inst == nil {
			continue
		}
		rate := inst.InputRate
		if rate <= 0 {
			rate = 1
		}
		// #1977: SamplingRate is a Rust u32; cap an out-of-range input rate so
		// it cannot abort the apply_snapshot decode.
		if int64(rate) > math.MaxUint32 {
			slog.Warn("userspace: sampling input rate capped to u32 max (#1977)",
				"value", inst.InputRate)
			rate = math.MaxUint32
		}
		families := []*config.SamplingFamily{inst.FamilyInet, inst.FamilyInet6}
		for _, fam := range families {
			if fam == nil {
				continue
			}
			for _, server := range fam.FlowServers {
				if server == nil || server.Address == "" {
					continue
				}
				// #1977: CollectorPort is a Rust u16. Port 0 is the existing
				// "absent" sentinel (skip silently); a negative or >65535 port
				// is invalid — skip that server (do not abort the whole export)
				// and warn so it is visible on a non-CLI path.
				if server.Port == 0 {
					continue
				}
				if server.Port < 0 || server.Port > math.MaxUint16 {
					slog.Warn("userspace: skipping flow-server with out-of-range port (#1977)",
						"address", server.Address, "port", server.Port)
					continue
				}
				snap := &FlowExportSnapshot{
					CollectorAddress: server.Address,
					CollectorPort:    server.Port,
					SamplingRate:     rate,
				}
				// Use template config if the server references one
				if server.Version9Template != "" && fm.Version9.Templates != nil {
					if tmpl, ok := fm.Version9.Templates[server.Version9Template]; ok {
						snap.ActiveTimeout = coerceWireU32Timeout(
							"active_timeout", tmpl.FlowActiveTimeout)
						snap.InactiveTimeout = coerceWireU32Timeout(
							"inactive_timeout", tmpl.FlowInactiveTimeout)
					}
				}
				return snap
			}
		}
	}
	return nil
}
