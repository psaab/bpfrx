package natshow

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// natFixtureConfig builds a deterministic NAT configuration exercising
// source, destination, static, and nptv6 rule-sets so the golden
// renderers below assert byte-for-byte output. The bytes here are the
// pre-#1687 gRPC ShowText contract (server_show_nat.go); the CLI path
// produced identical bytes and both now route through these funcs.
func natFixtureConfig() *config.Config {
	cfg := &config.Config{}
	cfg.Security.NAT.Source = []*config.NATRuleSet{
		{
			Name: "rs-src", FromZone: "trust", ToZone: "untrust",
			Rules: []*config.NATRule{
				{
					Name:  "r1",
					Match: config.NATMatch{SourceAddress: "10.0.1.0/24", Protocol: "tcp"},
					Then:  config.NATThen{PoolName: "p-src"},
				},
			},
		},
	}
	cfg.Security.NAT.SourcePools = map[string]*config.NATPool{
		"p-src": {Name: "p-src", Addresses: []string{"203.0.113.1"}, PortLow: 0, PortHigh: 0},
	}
	cfg.Security.NAT.Destination = &config.DestinationNATConfig{
		Pools: map[string]*config.NATPool{
			"p-dst": {Name: "p-dst", Address: "10.0.30.5", Port: 8080},
		},
		RuleSets: []*config.NATRuleSet{
			{
				Name: "rs-dst", FromZone: "untrust", ToZone: "dmz",
				Rules: []*config.NATRule{
					{
						Name:  "d1",
						Match: config.NATMatch{DestinationAddress: "198.51.100.7/32", DestinationPort: 443, Protocol: "tcp"},
						Then:  config.NATThen{PoolName: "p-dst"},
					},
				},
			},
		},
	}
	cfg.Security.NAT.Static = []*config.StaticNATRuleSet{
		{
			Name: "rs-static", FromZone: "trust",
			Rules: []*config.StaticNATRule{
				{Name: "s1", Match: "192.0.2.10", Then: "10.0.1.10"},
				{Name: "n1", Match: "2001:db8:a::/64", Then: "fd00:a::/64", IsNPTv6: true},
			},
		},
	}
	return cfg
}

func TestRenderSourceRuleDetailGolden(t *testing.T) {
	cfg := natFixtureConfig()
	dp := dataplane.New() // IsLoaded() == false -> no session counts
	var b strings.Builder
	RenderSourceRuleDetail(&b, cfg, dp, nil)
	want := "source NAT rule: r1\n" +
		"  Rule-set: rs-src                        ID: 1\n" +
		"    From zone: trust    To zone: untrust\n" +
		"    Match:\n" +
		"      Source addresses:      10.0.1.0/24\n" +
		"      Destination addresses: 0.0.0.0/0\n" +
		"      IP protocol:           tcp\n" +
		"    Action:                  pool p-src\n" +
		"    Pool addresses:          203.0.113.1\n" +
		"    Port range:              1024-65535\n" +
		"    Number of sessions:      0\n\n"
	if got := b.String(); got != want {
		t.Fatalf("RenderSourceRuleDetail mismatch:\n got=%q\nwant=%q", got, want)
	}
}

func TestRenderSourceRuleDetailEmpty(t *testing.T) {
	var b strings.Builder
	RenderSourceRuleDetail(&b, &config.Config{}, nil, nil)
	if got, want := b.String(), "No source NAT rules configured\n"; got != want {
		t.Fatalf("empty source: got=%q want=%q", got, want)
	}
}

func TestRenderDestRuleDetailGolden(t *testing.T) {
	cfg := natFixtureConfig()
	dp := dataplane.New()
	var b strings.Builder
	RenderDestRuleDetail(&b, cfg, dp, nil)
	want := "destination NAT rule: d1\n" +
		"  Rule-set: rs-dst                        ID: 1\n" +
		"    From zone: untrust    To zone: dmz\n" +
		"    Match:\n" +
		"      Destination addresses: 198.51.100.7/32\n" +
		"      Destination port:      443\n" +
		"      IP protocol:           tcp\n" +
		"    Action:                  pool p-dst\n" +
		"    Pool address:            10.0.30.5\n" +
		"    Pool port:               8080\n" +
		"    Number of sessions:      0\n\n"
	if got := b.String(); got != want {
		t.Fatalf("RenderDestRuleDetail mismatch:\n got=%q\nwant=%q", got, want)
	}
}

func TestRenderDestRuleDetailEmpty(t *testing.T) {
	// nil cfg, nil Destination, and empty RuleSets all share the gRPC
	// guard message.
	for _, c := range []*config.Config{nil, {}} {
		var b strings.Builder
		RenderDestRuleDetail(&b, c, nil, nil)
		if got, want := b.String(), "No destination NAT rules configured\n"; got != want {
			t.Fatalf("empty dest: got=%q want=%q", got, want)
		}
	}
}

func TestRenderStaticGolden(t *testing.T) {
	cfg := natFixtureConfig()
	var b strings.Builder
	RenderStatic(&b, cfg)
	want := "Static NAT rule-set: rs-static\n" +
		"  From zone: trust\n" +
		"  Rule: s1\n" +
		"    Match destination-address: 192.0.2.10\n" +
		"    Then static-nat prefix:    10.0.1.10\n" +
		"  Rule: n1\n" +
		"    Match destination-address: 2001:db8:a::/64\n" +
		"    Then nptv6-prefix:         fd00:a::/64\n" +
		"\n"
	if got := b.String(); got != want {
		t.Fatalf("RenderStatic mismatch:\n got=%q\nwant=%q", got, want)
	}
}

func TestRenderStaticEmpty(t *testing.T) {
	var b strings.Builder
	RenderStatic(&b, &config.Config{})
	if got, want := b.String(), "No static NAT rules configured.\n"; got != want {
		t.Fatalf("empty static: got=%q want=%q", got, want)
	}
}

func TestRenderNPTv6Golden(t *testing.T) {
	cfg := natFixtureConfig()
	var b strings.Builder
	RenderNPTv6(&b, cfg)
	want := "Rule-set             Rule                 External prefix                                    Internal prefix                                   \n" +
		"rs-static            n1                   2001:db8:a::/64                                    fd00:a::/64                                       \n"
	if got := b.String(); got != want {
		t.Fatalf("RenderNPTv6 mismatch:\n got=%q\nwant=%q", got, want)
	}
}

func TestRenderNPTv6Empty(t *testing.T) {
	var b strings.Builder
	RenderNPTv6(&b, &config.Config{})
	if got, want := b.String(), "No NPTv6 rules configured.\n"; got != want {
		t.Fatalf("empty nptv6: got=%q want=%q", got, want)
	}
}

func TestRenderPersistentNilReader(t *testing.T) {
	var b strings.Builder
	RenderPersistent(&b, nil)
	if got, want := b.String(), "Persistent NAT table not available\n"; got != want {
		t.Fatalf("nil reader: got=%q want=%q", got, want)
	}
}

func TestRenderPersistentEmpty(t *testing.T) {
	dp := dataplane.New()
	var b strings.Builder
	RenderPersistent(&b, dp)
	if got, want := b.String(), "No persistent NAT bindings\n"; got != want {
		t.Fatalf("empty persistent: got=%q want=%q", got, want)
	}
}

func TestRenderPersistentDetailNilReader(t *testing.T) {
	var b strings.Builder
	RenderPersistentDetail(&b, nil)
	if got, want := b.String(), "Persistent NAT table not available\n"; got != want {
		t.Fatalf("nil reader: got=%q want=%q", got, want)
	}
}

// dataplane.New() returns *dataplane.Manager, which satisfies the
// natshow.Reader interface — compile-time assertion so a method-set
// drift breaks the build, not just a test.
var _ Reader = (*dataplane.Manager)(nil)
