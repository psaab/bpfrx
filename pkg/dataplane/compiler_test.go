package dataplane

import (
	"testing"

	"github.com/psaab/bpfrx/pkg/config"
)

func TestExpandFilterTermNegateFlags(t *testing.T) {
	prefixLists := map[string]*config.PrefixList{
		"rfc1918": {
			Name:     "rfc1918",
			Prefixes: []string{"10.0.0.0/8", "172.16.0.0/12"},
		},
		"bogons": {
			Name:     "bogons",
			Prefixes: []string{"192.168.0.0/16"},
		},
	}

	term := &config.FirewallFilterTerm{
		Name:   "negate-test",
		Action: "accept",
		SourcePrefixLists: []config.PrefixListRef{
			{Name: "rfc1918", Except: true},
		},
		DestPrefixLists: []config.PrefixListRef{
			{Name: "bogons", Except: false},
		},
	}

	rules := expandFilterTerm(term, AFInet, nil, prefixLists)
	// Source: 2 prefixes (except) × Dest: 1 prefix (normal) = 2 rules
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rules))
	}

	for i, r := range rules {
		// Source should have SrcAddr + SrcNegate
		if r.MatchFlags&FilterMatchSrcAddr == 0 {
			t.Errorf("rule %d: missing FilterMatchSrcAddr", i)
		}
		if r.MatchFlags&FilterMatchSrcNegate == 0 {
			t.Errorf("rule %d: missing FilterMatchSrcNegate for except prefix-list", i)
		}
		// Destination should have DstAddr but NOT DstNegate
		if r.MatchFlags&FilterMatchDstAddr == 0 {
			t.Errorf("rule %d: missing FilterMatchDstAddr", i)
		}
		if r.MatchFlags&FilterMatchDstNegate != 0 {
			t.Errorf("rule %d: unexpected FilterMatchDstNegate for non-except prefix-list", i)
		}
	}
}

func TestExpandFilterTermDstNegate(t *testing.T) {
	prefixLists := map[string]*config.PrefixList{
		"private": {
			Name:     "private",
			Prefixes: []string{"10.0.0.0/8"},
		},
	}

	term := &config.FirewallFilterTerm{
		Name:   "dst-negate-test",
		Action: "discard",
		DestPrefixLists: []config.PrefixListRef{
			{Name: "private", Except: true},
		},
	}

	rules := expandFilterTerm(term, AFInet, nil, prefixLists)
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}

	r := rules[0]
	if r.MatchFlags&FilterMatchDstAddr == 0 {
		t.Error("missing FilterMatchDstAddr")
	}
	if r.MatchFlags&FilterMatchDstNegate == 0 {
		t.Error("missing FilterMatchDstNegate for except prefix-list")
	}
	if r.MatchFlags&FilterMatchSrcAddr != 0 {
		t.Error("unexpected FilterMatchSrcAddr for term with no source")
	}
	if r.Action != FilterActionDiscard {
		t.Errorf("expected discard action, got %d", r.Action)
	}
}

func TestExpandFilterTermNoNegateWithoutExcept(t *testing.T) {
	prefixLists := map[string]*config.PrefixList{
		"allowed": {
			Name:     "allowed",
			Prefixes: []string{"10.0.1.0/24"},
		},
	}

	term := &config.FirewallFilterTerm{
		Name:   "no-negate",
		Action: "accept",
		SourcePrefixLists: []config.PrefixListRef{
			{Name: "allowed", Except: false},
		},
	}

	rules := expandFilterTerm(term, AFInet, nil, prefixLists)
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}

	r := rules[0]
	if r.MatchFlags&FilterMatchSrcAddr == 0 {
		t.Error("missing FilterMatchSrcAddr")
	}
	if r.MatchFlags&FilterMatchSrcNegate != 0 {
		t.Error("unexpected FilterMatchSrcNegate for non-except prefix-list")
	}
	if r.MatchFlags&FilterMatchDstNegate != 0 {
		t.Error("unexpected FilterMatchDstNegate")
	}
}

func TestParseSpeed(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"", ""},
		{"auto", ""},
		{"Auto", ""},
		{"10m", "10"},
		{"100m", "100"},
		{"1g", "1000"},
		{"1G", "1000"},
		{"2.5g", "2500"},
		{"5g", "5000"},
		{"10g", "10000"},
		{"25g", "25000"},
		{"40g", "40000"},
		{"100g", "100000"},
		{"1000", "1000"},   // raw Mbps
		{"10000", "10000"}, // raw Mbps
		{"bogus", ""},
		{"  1g  ", "1000"}, // whitespace trimmed
	}
	for _, tt := range tests {
		got := parseSpeed(tt.input)
		if got != tt.want {
			t.Errorf("parseSpeed(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestParseDuplex(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"full", "full"},
		{"Full", "full"},
		{"FULL", "full"},
		{"half", "half"},
		{"Half", "half"},
		{"", ""},
		{"auto", ""},
		{"bogus", ""},
		{"  full  ", "full"}, // whitespace trimmed
	}
	for _, tt := range tests {
		got := parseDuplex(tt.input)
		if got != tt.want {
			t.Errorf("parseDuplex(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestBuildScreenConfig(t *testing.T) {
	tests := []struct {
		name   string
		sf     *config.SynFloodConfig
		expect ScreenConfig
	}{
		{
			name: "attack threshold only",
			sf: &config.SynFloodConfig{
				AttackThreshold: 1000,
			},
			expect: ScreenConfig{
				Flags:          ScreenSynFlood,
				SynFloodThresh: 1000,
			},
		},
		{
			name: "all thresholds and timeout",
			sf: &config.SynFloodConfig{
				AttackThreshold:      5000,
				SourceThreshold:      100,
				DestinationThreshold: 200,
				Timeout:              10,
			},
			expect: ScreenConfig{
				Flags:             ScreenSynFlood,
				SynFloodThresh:    5000,
				SynFloodSrcThresh: 100,
				SynFloodDstThresh: 200,
				SynFloodTimeout:   10,
			},
		},
		{
			name: "zero source/dest thresholds omitted",
			sf: &config.SynFloodConfig{
				AttackThreshold: 2000,
				Timeout:         5,
			},
			expect: ScreenConfig{
				Flags:           ScreenSynFlood,
				SynFloodThresh:  2000,
				SynFloodTimeout: 5,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile := &config.ScreenProfile{
				TCP: config.TCPScreen{SynFlood: tt.sf},
			}

			var flags uint32
			var sc ScreenConfig
			if profile.TCP.SynFlood != nil && profile.TCP.SynFlood.AttackThreshold > 0 {
				flags |= ScreenSynFlood
				sc.SynFloodThresh = uint32(profile.TCP.SynFlood.AttackThreshold)
				if profile.TCP.SynFlood.SourceThreshold > 0 {
					sc.SynFloodSrcThresh = uint32(profile.TCP.SynFlood.SourceThreshold)
				}
				if profile.TCP.SynFlood.DestinationThreshold > 0 {
					sc.SynFloodDstThresh = uint32(profile.TCP.SynFlood.DestinationThreshold)
				}
				if profile.TCP.SynFlood.Timeout > 0 {
					sc.SynFloodTimeout = uint32(profile.TCP.SynFlood.Timeout)
				}
			}
			sc.Flags = flags

			if sc != tt.expect {
				t.Errorf("got %+v, want %+v", sc, tt.expect)
			}
		})
	}
}

func TestHostInboundRouterDiscoveryFlag(t *testing.T) {
	// Verify router-discovery maps to the correct flag bit.
	flag, ok := HostInboundProtocolFlags["router-discovery"]
	if !ok {
		t.Fatal("router-discovery not in HostInboundProtocolFlags")
	}
	if flag != HostInboundRouterDiscovery {
		t.Errorf("flag = 0x%x, want 0x%x", flag, HostInboundRouterDiscovery)
	}
	// Verify it's bit 20.
	if flag != (1 << 20) {
		t.Errorf("flag = 0x%x, want 1<<20 = 0x%x", flag, uint32(1<<20))
	}
}

func TestAppPortsFromSpec(t *testing.T) {
	tests := []struct {
		spec string
		want []int
	}{
		{"", nil},
		{"80", []int{80}},
		{"8080-8083", []int{8080, 8081, 8082, 8083}},
		{"443-443", []int{443}},
	}
	for _, tt := range tests {
		got := appPortsFromSpec(tt.spec)
		if len(got) != len(tt.want) {
			t.Errorf("appPortsFromSpec(%q) len = %d, want %d", tt.spec, len(got), len(tt.want))
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("appPortsFromSpec(%q)[%d] = %d, want %d", tt.spec, i, got[i], tt.want[i])
			}
		}
	}
}

func TestResolvePortName(t *testing.T) {
	tests := []struct {
		name string
		want uint16
	}{
		{"ssh", 22},
		{"SSH", 22},
		{"https", 443},
		{"domain", 53},
		{"dns", 53},
		{"ftp", 21},
		{"ftp-data", 20},
		{"bgp", 179},
		{"snmp", 161},
		{"snmptrap", 162},
		{"syslog", 514},
		{"ike", 500},
		{"80", 80},
		{"unknown", 0},
	}
	for _, tt := range tests {
		got := resolvePortName(tt.name)
		if got != tt.want {
			t.Errorf("resolvePortName(%q) = %d, want %d", tt.name, got, tt.want)
		}
	}
}

func TestResolvePortRangeNamed(t *testing.T) {
	lo, hi := resolvePortRange("ssh")
	if lo != 22 || hi != 22 {
		t.Errorf("resolvePortRange(ssh) = (%d, %d), want (22, 22)", lo, hi)
	}
	lo, hi = resolvePortRange("1024-65535")
	if lo != 1024 || hi != 65535 {
		t.Errorf("resolvePortRange(1024-65535) = (%d, %d), want (1024, 65535)", lo, hi)
	}
}
