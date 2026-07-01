package policymatch

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func u8(v uint8) *uint8 { return &v }

// TestICMPTypeConstraintParity pins the #3284 fix: the simulator must enforce
// an application's ICMP/ICMPv6 type/code constraint the way the dataplane does
// (policy.rs CompiledApplications.matches, fed packet_icmp). junos-ping is
// echo-request ONLY (ICMP type 8), junos-pingv6 is ICMPv6 type 128; the
// pre-#3284 simulator matched them on protocol alone and over-permitted every
// ICMP message.
func TestICMPTypeConstraintParity(t *testing.T) {
	pingCfg := cfgWith(config.SecurityConfig{
		DefaultPolicy: config.PolicyDeny,
		Zones:         zones("trust", "untrust"),
		Policies: []*config.ZonePairPolicies{
			zonePair("trust", "untrust", permit("allow-ping",
				config.PolicyMatch{Applications: []string{"junos-ping"}})),
		},
	}, config.ApplicationsConfig{})

	allIcmpCfg := cfgWith(config.SecurityConfig{
		DefaultPolicy: config.PolicyDeny,
		Zones:         zones("trust", "untrust"),
		Policies: []*config.ZonePairPolicies{
			zonePair("trust", "untrust", permit("allow-all-icmp",
				config.PolicyMatch{Applications: []string{"junos-icmp-all"}})),
		},
	}, config.ApplicationsConfig{})

	pingv6Cfg := cfgWith(config.SecurityConfig{
		DefaultPolicy: config.PolicyDeny,
		Zones:         zones("trust", "untrust"),
		Policies: []*config.ZonePairPolicies{
			zonePair("trust", "untrust", permit("allow-ping6",
				config.PolicyMatch{Applications: []string{"junos-pingv6"}})),
		},
	}, config.ApplicationsConfig{})

	tests := []struct {
		name        string
		cfg         *config.Config
		q           Query
		wantMatched bool
		wantAction  config.PolicyAction
	}{
		{
			name:        "junos-ping permits ICMP echo type 8",
			cfg:         pingCfg,
			q:           Query{FromZone: "trust", ToZone: "untrust", Protocol: "icmp", ICMPType: u8(8)},
			wantMatched: true, wantAction: config.PolicyPermit,
		},
		{
			// timestamp request (type 13) is NOT echo-request: junos-ping must
			// NOT match -> default deny. The old simulator reported permit.
			name:        "junos-ping denies ICMP timestamp type 13",
			cfg:         pingCfg,
			q:           Query{FromZone: "trust", ToZone: "untrust", Protocol: "icmp", ICMPType: u8(13)},
			wantMatched: false, wantAction: config.PolicyDeny,
		},
		{
			// No type supplied for an ICMP query: a type-constrained term fails
			// closed (mirrors the dataplane packet_icmp = None path).
			name:        "junos-ping fails closed when type omitted",
			cfg:         pingCfg,
			q:           Query{FromZone: "trust", ToZone: "untrust", Protocol: "icmp"},
			wantMatched: false, wantAction: config.PolicyDeny,
		},
		{
			// An UNCONSTRAINED ICMP app (junos-icmp-all) still matches every
			// ICMP type, including timestamp and even with no type supplied.
			name:        "junos-icmp-all permits timestamp type 13",
			cfg:         allIcmpCfg,
			q:           Query{FromZone: "trust", ToZone: "untrust", Protocol: "icmp", ICMPType: u8(13)},
			wantMatched: true, wantAction: config.PolicyPermit,
		},
		{
			name:        "junos-icmp-all permits with no type supplied",
			cfg:         allIcmpCfg,
			q:           Query{FromZone: "trust", ToZone: "untrust", Protocol: "icmp"},
			wantMatched: true, wantAction: config.PolicyPermit,
		},
		{
			name:        "junos-pingv6 permits ICMPv6 echo type 128",
			cfg:         pingv6Cfg,
			q:           Query{FromZone: "trust", ToZone: "untrust", Protocol: "icmpv6", ICMPType: u8(128)},
			wantMatched: true, wantAction: config.PolicyPermit,
		},
		{
			// Router advertisement (type 134) is not echo-request.
			name:        "junos-pingv6 denies ICMPv6 router-advert type 134",
			cfg:         pingv6Cfg,
			q:           Query{FromZone: "trust", ToZone: "untrust", Protocol: "icmpv6", ICMPType: u8(134)},
			wantMatched: false, wantAction: config.PolicyDeny,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := Match(tt.cfg, tt.q)
			if res.Matched != tt.wantMatched {
				t.Errorf("Matched = %v, want %v (policy %q)", res.Matched, tt.wantMatched, res.PolicyName)
			}
			if res.Action != tt.wantAction {
				t.Errorf("Action = %v, want %v", res.Action, tt.wantAction)
			}
		})
	}
}

// TestICMPTypeConstrainedProtocolLessAppNeverMatches pins the #3323 parity
// contract for a protocol-less named application that carries ONLY an ICMP type.
// Such an app is UNREPRESENTABLE by the dataplane and is never enforced:
// deriveUserspaceCapabilities (pkg/dataplane/userspace/capabilities.go) fails
// closed for proto=="" with NO ICMP-protocol inference
// (normalizeUserspaceApplicationProtocol("")=="") → the __unsupported__ sentinel
// → whole-snapshot reject (#3261), and strict commit hard-rejects a protocol-less
// app (pkg/config/compiler_validate_strict.go). It is also not constructible via
// real config: as of #3348 a user app CAN carry an ICMP type (via the
// `icmp-type`/`icmp-code` grammar or a junos-ping/junos-pingv6 protocol alias),
// but the application compiler (compiler_applications.go) only ever attaches a
// type alongside a pinned ICMP protocol — and validateApplicationSpecsStrict
// rejects an icmp-type on a non-ICMP protocol and a protocol-less app outright.
// So a real config can never produce Protocol=="" with ICMPType set; this case
// is the hand-built unrepresentable shape the runtime drops.
//
// The simulator must therefore report NO concrete match for this app, for EVERY
// query protocol — mirroring the dataplane reject. Before #3323 the
// matchSingleApp protocol gate was skipped when app.Protocol=="" and this term
// falsely matched an ICMP query (a simulator-vs-runtime over-report). The
// protocol gate (now unconditional) catches it first; the residual ICMP-family
// gate remains as belt-and-suspenders for a protocol-PINNED ICMP app
// (junos-ping), whose type/code check is still live and exercised by the cases
// table above.
func TestICMPTypeConstrainedProtocolLessAppNeverMatches(t *testing.T) {
	cfg := cfgWith(config.SecurityConfig{
		DefaultPolicy: config.PolicyDeny,
		Zones:         zones("trust", "untrust"),
		Policies: []*config.ZonePairPolicies{
			zonePair("trust", "untrust", permit("allow-custom",
				config.PolicyMatch{Applications: []string{"custom-icmp-noproto"}})),
		},
	}, config.ApplicationsConfig{
		Applications: map[string]*config.Application{
			// No Protocol pinned — only an ICMP type constraint. Not
			// constructible via real config; the dataplane rejects it.
			"custom-icmp-noproto": {Name: "custom-icmp-noproto", ICMPType: u8(8)},
		},
	})

	// A TCP query carrying ICMPType 8 must NOT match (default deny).
	tcp := Match(cfg, Query{FromZone: "trust", ToZone: "untrust", Protocol: "tcp", ICMPType: u8(8)})
	if tcp.Matched || tcp.Action != config.PolicyDeny {
		t.Errorf("TCP query matched a protocol-less term: Matched=%v Action=%v", tcp.Matched, tcp.Action)
	}

	// #3323: an ICMP query must ALSO not match — the dataplane rejects a
	// protocol-less app, so the simulator must not report it as a concrete
	// permit. (Pre-#3323 this falsely permitted.)
	icmp := Match(cfg, Query{FromZone: "trust", ToZone: "untrust", Protocol: "icmp", ICMPType: u8(8)})
	if icmp.Matched || icmp.Action != config.PolicyDeny {
		t.Errorf("ICMP query matched a protocol-less app the dataplane rejects: Matched=%v Action=%v", icmp.Matched, icmp.Action)
	}
}

// TestParseICMPValue covers the shared ICMP type/code token parser used by the
// REST/gRPC/CLI/test-policy surfaces.
func TestParseICMPValue(t *testing.T) {
	if v, err := ParseICMPValue(""); err != nil || v != nil {
		t.Errorf("empty: got (%v,%v), want (nil,nil)", v, err)
	}
	if v, err := ParseICMPValue("0"); err != nil || v == nil || *v != 0 {
		t.Errorf("0: got (%v,%v), want (*0,nil)", v, err)
	}
	if v, err := ParseICMPValue("255"); err != nil || v == nil || *v != 255 {
		t.Errorf("255: got (%v,%v), want (*255,nil)", v, err)
	}
	if _, err := ParseICMPValue("256"); err == nil {
		t.Error("256: want range error")
	}
	if _, err := ParseICMPValue("-1"); err == nil {
		t.Error("-1: want range error")
	}
	if _, err := ParseICMPValue("abc"); err == nil {
		t.Error("abc: want parse error")
	}
	// #3679 FAIL-ON-REVERT: strconv.Atoi accepts a leading '+', so the old
	// parser read "+8" as ICMP echo-request (type 8) and "+0" as echo-reply.
	// Routing through config.ParseCanonicalUint rejects the signed spelling,
	// matching the canonical rule the commit-time / dataplane parsers enforce.
	// Restoring Atoi flips these back to accepted and turns the cases red.
	if _, err := ParseICMPValue("+8"); err == nil {
		t.Error("+8: want canonical-form error (Atoi accepted it as 8)")
	}
	if _, err := ParseICMPValue("+0"); err == nil {
		t.Error("+0: want canonical-form error (Atoi accepted it as 0)")
	}
}
