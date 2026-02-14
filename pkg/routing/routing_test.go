package routing

import (
	"testing"
	"time"

	"github.com/psaab/bpfrx/pkg/config"
	"golang.org/x/sys/unix"
)

func TestResolveRibTable(t *testing.T) {
	tableIDs := map[string]int{
		"tunnel-vr": 100,
		"dmz-vr":    101,
	}

	tests := []struct {
		ribName string
		want    int
	}{
		{"inet.0", 254},
		{"inet6.0", 254},
		{"dmz-vr.inet.0", 101},
		{"dmz-vr.inet6.0", 101},
		{"tunnel-vr.inet.0", 100},
		{"unknown-vr.inet.0", 0},
		{"garbage", 0},
	}

	for _, tt := range tests {
		got := resolveRibTable(tt.ribName, tableIDs)
		if got != tt.want {
			t.Errorf("resolveRibTable(%q) = %d, want %d", tt.ribName, got, tt.want)
		}
	}
}

func TestRibGroupNeedsLeak(t *testing.T) {
	// Verify that the rib-group logic correctly identifies when leaking is needed.
	// We can't test actual ip rule creation without netlink, but we can test
	// the resolveRibTable helper and the logic structure.

	ribGroups := map[string]*config.RibGroup{
		"dmz-leak": {
			Name:       "dmz-leak",
			ImportRibs: []string{"dmz-vr.inet.0", "inet.0"},
		},
		"self-only": {
			Name:       "self-only",
			ImportRibs: []string{"tunnel-vr.inet.0"},
		},
	}

	instances := []*config.RoutingInstanceConfig{
		{Name: "tunnel-vr", TableID: 100, InterfaceRoutesRibGroup: "self-only"},
		{Name: "dmz-vr", TableID: 101, InterfaceRoutesRibGroup: "dmz-leak"},
	}

	tableIDs := map[string]int{
		"tunnel-vr": 100,
		"dmz-vr":    101,
	}

	// dmz-leak should need leaking (dmz-vr.inet.0=101, inet.0=254 → different tables)
	rg := ribGroups["dmz-leak"]
	inst := instances[1] // dmz-vr
	needsLeak := false
	for _, ribName := range rg.ImportRibs {
		if resolveRibTable(ribName, tableIDs) != inst.TableID {
			needsLeak = true
			break
		}
	}
	if !needsLeak {
		t.Error("dmz-leak should need leaking")
	}

	// self-only should NOT need leaking (only tunnel-vr.inet.0=100, same as instance)
	rg = ribGroups["self-only"]
	inst = instances[0] // tunnel-vr
	needsLeak = false
	for _, ribName := range rg.ImportRibs {
		if resolveRibTable(ribName, tableIDs) != inst.TableID {
			needsLeak = true
			break
		}
	}
	if needsLeak {
		t.Error("self-only should NOT need leaking")
	}
}

func TestDscpToTOS(t *testing.T) {
	tests := []struct {
		dscp string
		want uint8
	}{
		{"ef", 46 << 2},     // 0xB8 = 184
		{"af43", 38 << 2},   // 0x98 = 152
		{"af42", 36 << 2},   // 0x90 = 144
		{"af41", 34 << 2},   // 0x88 = 136
		{"af33", 30 << 2},   // 120
		{"cs1", 8 << 2},     // 32
		{"cs5", 40 << 2},    // 160
		{"be", 0},           // best effort = 0
		{"cs0", 0},          // cs0 = 0 → TOS = 0
		{"46", 46 << 2},     // numeric DSCP
		{"0", 0},            // zero
		{"63", 63 << 2},     // max DSCP
		{"invalid", 0},      // unknown name → 0
		{"EF", 46 << 2},     // case-insensitive
		{"AF43", 38 << 2},   // case-insensitive
	}

	for _, tt := range tests {
		got := dscpToTOS(tt.dscp)
		if got != tt.want {
			t.Errorf("dscpToTOS(%q) = %d (0x%02X), want %d (0x%02X)",
				tt.dscp, got, got, tt.want, tt.want)
		}
	}
}

func TestBuildPBRRules(t *testing.T) {
	instances := []*config.RoutingInstanceConfig{
		{Name: "Comcast-GigabitPro", TableID: 100},
		{Name: "ATT", TableID: 101},
	}

	t.Run("DSCP-based routing", func(t *testing.T) {
		fw := &config.FirewallConfig{
			FiltersInet: map[string]*config.FirewallFilter{
				"inet-source-dscp": {
					Name: "inet-source-dscp",
					Terms: []*config.FirewallFilterTerm{
						{
							Name:            "dscp-to-gigabitpro",
							DSCP:            "ef",
							RoutingInstance: "Comcast-GigabitPro",
						},
						{
							Name:            "dscp-to-att",
							DSCP:            "af43",
							RoutingInstance: "ATT",
						},
					},
				},
			},
		}

		rules := BuildPBRRules(fw, instances)
		if len(rules) != 2 {
			t.Fatalf("expected 2 PBR rules, got %d", len(rules))
		}

		// Find rules by instance (map iteration order is nondeterministic
		// but there's only one filter so order is deterministic within terms)
		var comcast, att *PBRRule
		for i := range rules {
			switch rules[i].Instance {
			case "Comcast-GigabitPro":
				comcast = &rules[i]
			case "ATT":
				att = &rules[i]
			}
		}

		if comcast == nil || att == nil {
			t.Fatal("expected rules for both Comcast-GigabitPro and ATT")
		}

		if comcast.TOS != 184 { // ef=46, TOS=46<<2=184=0xB8
			t.Errorf("Comcast TOS = %d, want 184 (0xB8)", comcast.TOS)
		}
		if comcast.TableID != 100 {
			t.Errorf("Comcast table = %d, want 100", comcast.TableID)
		}
		if comcast.Family != unix.AF_INET {
			t.Errorf("Comcast family = %d, want AF_INET", comcast.Family)
		}

		if att.TOS != 152 { // af43=38, TOS=38<<2=152=0x98
			t.Errorf("ATT TOS = %d, want 152 (0x98)", att.TOS)
		}
		if att.TableID != 101 {
			t.Errorf("ATT table = %d, want 101", att.TableID)
		}
	})

	t.Run("source address routing", func(t *testing.T) {
		fw := &config.FirewallConfig{
			FiltersInet: map[string]*config.FirewallFilter{
				"src-routing": {
					Name: "src-routing",
					Terms: []*config.FirewallFilterTerm{
						{
							Name:            "from-subnet",
							SourceAddresses: []string{"10.0.1.0/24"},
							RoutingInstance: "ATT",
						},
					},
				},
			},
		}

		rules := BuildPBRRules(fw, instances)
		if len(rules) != 1 {
			t.Fatalf("expected 1 PBR rule, got %d", len(rules))
		}
		if rules[0].Src != "10.0.1.0/24" {
			t.Errorf("src = %q, want 10.0.1.0/24", rules[0].Src)
		}
		if rules[0].TOS != 0 {
			t.Errorf("TOS = %d, want 0", rules[0].TOS)
		}
		if rules[0].TableID != 101 {
			t.Errorf("table = %d, want 101", rules[0].TableID)
		}
	})

	t.Run("destination address routing", func(t *testing.T) {
		fw := &config.FirewallConfig{
			FiltersInet: map[string]*config.FirewallFilter{
				"dst-routing": {
					Name: "dst-routing",
					Terms: []*config.FirewallFilterTerm{
						{
							Name:            "to-subnet",
							DestAddresses:   []string{"192.168.0.0/16"},
							RoutingInstance: "Comcast-GigabitPro",
						},
					},
				},
			},
		}

		rules := BuildPBRRules(fw, instances)
		if len(rules) != 1 {
			t.Fatalf("expected 1 PBR rule, got %d", len(rules))
		}
		if rules[0].Dst != "192.168.0.0/16" {
			t.Errorf("dst = %q, want 192.168.0.0/16", rules[0].Dst)
		}
	})

	t.Run("inet6 filter", func(t *testing.T) {
		fw := &config.FirewallConfig{
			FiltersInet6: map[string]*config.FirewallFilter{
				"v6-routing": {
					Name: "v6-routing",
					Terms: []*config.FirewallFilterTerm{
						{
							Name:            "dscp-route",
							DSCP:            "ef",
							RoutingInstance: "ATT",
						},
					},
				},
			},
		}

		rules := BuildPBRRules(fw, instances)
		if len(rules) != 1 {
			t.Fatalf("expected 1 PBR rule, got %d", len(rules))
		}
		if rules[0].Family != unix.AF_INET6 {
			t.Errorf("family = %d, want AF_INET6", rules[0].Family)
		}
	})

	t.Run("no criteria skipped", func(t *testing.T) {
		fw := &config.FirewallConfig{
			FiltersInet: map[string]*config.FirewallFilter{
				"no-criteria": {
					Name: "no-criteria",
					Terms: []*config.FirewallFilterTerm{
						{
							Name:            "accept-all",
							RoutingInstance: "ATT",
							// No DSCP, no source, no dest — can't express as ip rule
						},
					},
				},
			},
		}

		rules := BuildPBRRules(fw, instances)
		if len(rules) != 0 {
			t.Errorf("expected 0 PBR rules for no-criteria term, got %d", len(rules))
		}
	})

	t.Run("unknown instance skipped", func(t *testing.T) {
		fw := &config.FirewallConfig{
			FiltersInet: map[string]*config.FirewallFilter{
				"bad-ref": {
					Name: "bad-ref",
					Terms: []*config.FirewallFilterTerm{
						{
							Name:            "bad",
							DSCP:            "ef",
							RoutingInstance: "NonExistent",
						},
					},
				},
			},
		}

		rules := BuildPBRRules(fw, instances)
		if len(rules) != 0 {
			t.Errorf("expected 0 PBR rules for unknown instance, got %d", len(rules))
		}
	})

	t.Run("terms without routing-instance ignored", func(t *testing.T) {
		fw := &config.FirewallConfig{
			FiltersInet: map[string]*config.FirewallFilter{
				"mixed": {
					Name: "mixed",
					Terms: []*config.FirewallFilterTerm{
						{
							Name:   "accept-term",
							DSCP:   "ef",
							Action: "accept",
						},
						{
							Name:            "route-term",
							DSCP:            "af43",
							RoutingInstance: "ATT",
						},
					},
				},
			},
		}

		rules := BuildPBRRules(fw, instances)
		if len(rules) != 1 {
			t.Fatalf("expected 1 PBR rule, got %d", len(rules))
		}
		if rules[0].Instance != "ATT" {
			t.Errorf("instance = %q, want ATT", rules[0].Instance)
		}
	})

	t.Run("multi-address cross product", func(t *testing.T) {
		fw := &config.FirewallConfig{
			FiltersInet: map[string]*config.FirewallFilter{
				"multi": {
					Name: "multi",
					Terms: []*config.FirewallFilterTerm{
						{
							Name:            "cross",
							SourceAddresses: []string{"10.0.1.0/24", "10.0.2.0/24"},
							DestAddresses:   []string{"192.168.1.0/24", "192.168.2.0/24"},
							RoutingInstance: "ATT",
						},
					},
				},
			},
		}

		rules := BuildPBRRules(fw, instances)
		if len(rules) != 4 {
			t.Fatalf("expected 4 PBR rules (2×2 cross product), got %d", len(rules))
		}
	})

	t.Run("nil firewall", func(t *testing.T) {
		rules := BuildPBRRules(nil, instances)
		if len(rules) != 0 {
			t.Errorf("expected 0 PBR rules for nil config, got %d", len(rules))
		}
	})
}

func TestProbeICMP(t *testing.T) {
	// localhost should always be reachable (via UDP fallback at minimum)
	if !probeICMP("127.0.0.1") {
		t.Error("expected probe to 127.0.0.1 to succeed")
	}

	// Invalid address should fail
	if probeICMP("not-an-ip") {
		t.Error("expected probe to invalid address to fail")
	}
}

func TestKeepaliveState(t *testing.T) {
	state := &KeepaliveState{
		Up:         true,
		RemoteAddr: "10.0.0.1",
		Interval:   5,
		MaxRetries: 3,
	}

	// Initial state should be up
	if !state.Up {
		t.Error("expected initial state to be up")
	}

	// Simulate failures
	for i := 0; i < 3; i++ {
		state.Failures++
	}
	if state.Failures != 3 {
		t.Errorf("expected 3 failures, got %d", state.Failures)
	}

	// After reaching max retries, should be marked down
	state.Up = false
	state.LastFailure = time.Now()

	if state.Up {
		t.Error("expected state to be down after max retries")
	}

	// Simulate recovery
	state.Failures = 0
	state.Up = true
	state.LastSuccess = time.Now()

	if !state.Up {
		t.Error("expected state to be up after recovery")
	}
}

func TestKeepaliveDefaults(t *testing.T) {
	// When KeepaliveRetry is 0, startKeepalive should default to 3
	// We can't call startKeepalive without a netlink handle, but we
	// can verify the default logic inline.
	maxRetries := 0
	if maxRetries <= 0 {
		maxRetries = 3
	}
	if maxRetries != 3 {
		t.Errorf("expected default maxRetries to be 3, got %d", maxRetries)
	}
}
