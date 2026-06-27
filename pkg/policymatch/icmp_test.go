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
}
