package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #2362: the firewall-filter compiler parses tcp-flags / is-fragment /
// icmp-type / icmp-code into config.FirewallFilterTerm, but the userspace
// snapshot builder previously dropped all four — so a term like
// `from { tcp-flags syn; }` silently matched broader than authored
// (discard-all-TCP instead of discard-SYN). These tests fail on the pre-fix
// builder (the fields never reach FirewallTermSnapshot) and pass after the
// wire-through fix.

// perPacketMatchCfg builds a config with one inet filter whose single term
// carries all four per-packet L4 match conditions.
func perPacketMatchCfg() *config.Config {
	cfg := &config.Config{}
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"edge": {
			Name: "edge",
			Terms: []*config.FirewallFilterTerm{
				{
					Name:       "syn-only",
					Protocol:   "tcp",
					TCPFlags:   []string{"syn"},
					IsFragment: false,
					ICMPType:   -1,
					ICMPCode:   -1,
					Action:     "discard",
				},
			},
		},
	}
	return cfg
}

func TestFilterSnapshotTCPFlagsSerialized(t *testing.T) {
	snaps := buildFirewallFilterSnapshots(perPacketMatchCfg())
	if len(snaps) != 1 || len(snaps[0].Terms) != 1 {
		t.Fatalf("expected 1 filter with 1 term, got %#v", snaps)
	}
	term := snaps[0].Terms[0]
	if term.TCPFlags == nil {
		t.Fatal("tcp-flags syn was dropped from the snapshot (#2362)")
	}
	// SYN == 0x02; the mask must require exactly the SYN bit.
	if *term.TCPFlags != 0x02 {
		t.Errorf("tcp_flags mask = 0x%02x, want 0x02 (SYN)", *term.TCPFlags)
	}
}

func TestFilterSnapshotTCPFlagsMultipleAreAnded(t *testing.T) {
	cfg := &config.Config{}
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"f": {Name: "f", Terms: []*config.FirewallFilterTerm{{
			Name: "t", Protocol: "tcp", TCPFlags: []string{"syn", "ack"},
			ICMPType: -1, ICMPCode: -1, Action: "discard",
		}}},
	}
	snaps := buildFirewallFilterSnapshots(cfg)
	term := snaps[0].Terms[0]
	if term.TCPFlags == nil {
		t.Fatal("tcp-flags dropped")
	}
	// SYN(0x02) | ACK(0x10) == 0x12.
	if *term.TCPFlags != 0x12 {
		t.Errorf("tcp_flags mask = 0x%02x, want 0x12 (SYN|ACK)", *term.TCPFlags)
	}
}

func TestFilterSnapshotTCPFlagsUnknownYieldsNil(t *testing.T) {
	// The parser can store the unsupported expression form (e.g. the literal
	// "(syn & !ack)") as a single token. It is not a recognized flag name, so
	// the mask must stay nil (no constraint) rather than 0 (matches all).
	cfg := &config.Config{}
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"f": {Name: "f", Terms: []*config.FirewallFilterTerm{{
			Name: "t", Protocol: "tcp", TCPFlags: []string{"(syn & !ack)"},
			ICMPType: -1, ICMPCode: -1, Action: "discard",
		}}},
	}
	snaps := buildFirewallFilterSnapshots(cfg)
	if got := snaps[0].Terms[0].TCPFlags; got != nil {
		t.Errorf("unrecognized tcp-flags expression should yield nil mask, got 0x%02x", *got)
	}
}

func TestFilterSnapshotIsFragmentSerialized(t *testing.T) {
	cfg := &config.Config{}
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"f": {Name: "f", Terms: []*config.FirewallFilterTerm{{
			Name: "t", IsFragment: true, ICMPType: -1, ICMPCode: -1, Action: "discard",
		}}},
	}
	snaps := buildFirewallFilterSnapshots(cfg)
	if !snaps[0].Terms[0].IsFragment {
		t.Error("is-fragment was dropped from the snapshot (#2362)")
	}
}

func TestFilterSnapshotICMPTypeCodeSerialized(t *testing.T) {
	cfg := &config.Config{}
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"f": {Name: "f", Terms: []*config.FirewallFilterTerm{{
			Name: "t", Protocol: "icmp", ICMPType: 8, ICMPCode: 0, Action: "discard",
		}}},
	}
	snaps := buildFirewallFilterSnapshots(cfg)
	term := snaps[0].Terms[0]
	if term.ICMPType == nil || *term.ICMPType != 8 {
		t.Errorf("icmp-type = %v, want 8 (echo-request) (#2362)", term.ICMPType)
	}
	if term.ICMPCode == nil || *term.ICMPCode != 0 {
		t.Errorf("icmp-code = %v, want 0 (#2362)", term.ICMPCode)
	}
}

func TestFilterSnapshotICMPUnsetStaysNil(t *testing.T) {
	// The compiler uses -1 for "not set"; an unset icmp-type/code must not
	// serialize a bogus 0 constraint.
	cfg := &config.Config{}
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"f": {Name: "f", Terms: []*config.FirewallFilterTerm{{
			Name: "t", Protocol: "tcp", ICMPType: -1, ICMPCode: -1, Action: "accept",
		}}},
	}
	snaps := buildFirewallFilterSnapshots(cfg)
	term := snaps[0].Terms[0]
	if term.ICMPType != nil {
		t.Errorf("unset icmp-type should be nil, got %d", *term.ICMPType)
	}
	if term.ICMPCode != nil {
		t.Errorf("unset icmp-code should be nil, got %d", *term.ICMPCode)
	}
}

func TestTCPFlagsMaskHelper(t *testing.T) {
	cases := []struct {
		in   []string
		want uint8
		ok   bool
	}{
		{nil, 0, false},
		{[]string{}, 0, false},
		{[]string{"syn"}, 0x02, true},
		{[]string{"SYN"}, 0x02, true},
		{[]string{"fin", "syn", "rst", "psh", "ack", "urg"}, 0x3f, true},
		{[]string{"bogus"}, 0, false},
		{[]string{"syn", "bogus"}, 0x02, true},
	}
	for _, c := range cases {
		got, ok := tcpFlagsMask(c.in)
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("tcpFlagsMask(%v) = (0x%02x, %v), want (0x%02x, %v)", c.in, got, ok, c.want, c.ok)
		}
	}
}
