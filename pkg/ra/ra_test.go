package ra

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/mdlayher/ndp"

	"github.com/psaab/bpfrx/pkg/config"
)

func TestBuildRA_Basic(t *testing.T) {
	s := &sender{
		cfg: &config.RAInterfaceConfig{
			Interface: "trust0",
			Prefixes: []*config.RAPrefix{
				{
					Prefix:     "2001:db8:1::/64",
					OnLink:     true,
					Autonomous: true,
				},
			},
		},
		iface: &net.Interface{
			Name:         "trust0",
			HardwareAddr: net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		},
	}

	ra := s.buildRA()

	if ra.RouterLifetime != 1800*time.Second {
		t.Errorf("RouterLifetime = %v, want 1800s", ra.RouterLifetime)
	}
	if ra.CurrentHopLimit != 64 {
		t.Errorf("CurrentHopLimit = %d, want 64", ra.CurrentHopLimit)
	}
	if ra.ManagedConfiguration {
		t.Error("ManagedConfiguration should be false")
	}
	if ra.OtherConfiguration {
		t.Error("OtherConfiguration should be false")
	}
	if ra.RouterSelectionPreference != ndp.Medium {
		t.Errorf("Preference = %v, want Medium", ra.RouterSelectionPreference)
	}

	// Check source LLA option.
	var foundSLLA bool
	for _, opt := range ra.Options {
		if lla, ok := opt.(*ndp.LinkLayerAddress); ok && lla.Direction == ndp.Source {
			foundSLLA = true
			if lla.Addr.String() != "00:11:22:33:44:55" {
				t.Errorf("SLLA = %s, want 00:11:22:33:44:55", lla.Addr)
			}
		}
	}
	if !foundSLLA {
		t.Error("missing source link-layer address option")
	}

	// Check prefix.
	var foundPrefix bool
	for _, opt := range ra.Options {
		if pi, ok := opt.(*ndp.PrefixInformation); ok {
			foundPrefix = true
			if pi.PrefixLength != 64 {
				t.Errorf("PrefixLength = %d, want 64", pi.PrefixLength)
			}
			wantPrefix := netip.MustParseAddr("2001:db8:1::")
			if pi.Prefix != wantPrefix {
				t.Errorf("Prefix = %s, want %s", pi.Prefix, wantPrefix)
			}
			if !pi.OnLink {
				t.Error("OnLink should be true")
			}
			if !pi.AutonomousAddressConfiguration {
				t.Error("Autonomous should be true")
			}
			if pi.ValidLifetime != time.Duration(defaultValidLifetime)*time.Second {
				t.Errorf("ValidLifetime = %v, want %ds", pi.ValidLifetime, defaultValidLifetime)
			}
			if pi.PreferredLifetime != time.Duration(defaultPreferredLifetime)*time.Second {
				t.Errorf("PreferredLifetime = %v, want %ds", pi.PreferredLifetime, defaultPreferredLifetime)
			}
		}
	}
	if !foundPrefix {
		t.Error("missing prefix information option")
	}
}

func TestBuildRA_ManagedStateful(t *testing.T) {
	s := &sender{
		cfg: &config.RAInterfaceConfig{
			Interface:     "trust0",
			ManagedConfig: true,
			OtherStateful: true,
		},
		iface: &net.Interface{
			Name:         "trust0",
			HardwareAddr: net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		},
	}

	ra := s.buildRA()
	if !ra.ManagedConfiguration {
		t.Error("ManagedConfiguration should be true")
	}
	if !ra.OtherConfiguration {
		t.Error("OtherConfiguration should be true")
	}
}

func TestBuildRA_DNSServers(t *testing.T) {
	s := &sender{
		cfg: &config.RAInterfaceConfig{
			Interface:  "trust0",
			DNSServers: []string{"2001:4860:4860::8888", "2001:4860:4860::8844"},
		},
		iface: &net.Interface{
			Name:         "trust0",
			HardwareAddr: net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		},
	}

	ra := s.buildRA()

	var found bool
	for _, opt := range ra.Options {
		if rdnss, ok := opt.(*ndp.RecursiveDNSServer); ok {
			found = true
			if len(rdnss.Servers) != 2 {
				t.Fatalf("got %d DNS servers, want 2", len(rdnss.Servers))
			}
			want1 := netip.MustParseAddr("2001:4860:4860::8888")
			want2 := netip.MustParseAddr("2001:4860:4860::8844")
			if rdnss.Servers[0] != want1 {
				t.Errorf("DNS[0] = %s, want %s", rdnss.Servers[0], want1)
			}
			if rdnss.Servers[1] != want2 {
				t.Errorf("DNS[1] = %s, want %s", rdnss.Servers[1], want2)
			}
		}
	}
	if !found {
		t.Error("missing RDNSS option")
	}
}

func TestBuildRA_NAT64(t *testing.T) {
	s := &sender{
		cfg: &config.RAInterfaceConfig{
			Interface:   "trust0",
			NAT64Prefix: "64:ff9b::/96",
		},
		iface: &net.Interface{
			Name:         "trust0",
			HardwareAddr: net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		},
	}

	ra := s.buildRA()

	var found bool
	for _, opt := range ra.Options {
		if pref64, ok := opt.(*ndp.PREF64); ok {
			found = true
			wantPrefix := netip.MustParsePrefix("64:ff9b::/96")
			if pref64.Prefix != wantPrefix {
				t.Errorf("PREF64 = %s, want %s", pref64.Prefix, wantPrefix)
			}
		}
	}
	if !found {
		t.Error("missing PREF64 option")
	}
}

func TestBuildRA_NAT64WithLifetime(t *testing.T) {
	s := &sender{
		cfg: &config.RAInterfaceConfig{
			Interface:       "trust0",
			NAT64Prefix:     "64:ff9b::/96",
			NAT64PrefixLife: 1800,
		},
		iface: &net.Interface{
			Name:         "trust0",
			HardwareAddr: net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		},
	}

	ra := s.buildRA()

	for _, opt := range ra.Options {
		if pref64, ok := opt.(*ndp.PREF64); ok {
			// PREF64 lifetime is quantized to 8-second granularity.
			want := 1800 * time.Second
			// Allow rounding to nearest 8s.
			diff := pref64.Lifetime - want
			if diff < 0 {
				diff = -diff
			}
			if diff > 8*time.Second {
				t.Errorf("PREF64 Lifetime = %v, want ~%v", pref64.Lifetime, want)
			}
			return
		}
	}
	t.Error("missing PREF64 option")
}

func TestBuildRA_LifetimeAndMTU(t *testing.T) {
	s := &sender{
		cfg: &config.RAInterfaceConfig{
			Interface:       "trust0",
			DefaultLifetime: 1800,
			MaxAdvInterval:  600,
			MinAdvInterval:  200,
			LinkMTU:         1280,
			Prefixes: []*config.RAPrefix{
				{
					Prefix:        "2001:db8::/64",
					OnLink:        true,
					Autonomous:    true,
					ValidLifetime: 86400,
					PreferredLife: 14400,
				},
			},
		},
		iface: &net.Interface{
			Name:         "trust0",
			HardwareAddr: net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		},
	}

	ra := s.buildRA()

	if ra.RouterLifetime != 1800*time.Second {
		t.Errorf("RouterLifetime = %v, want 1800s", ra.RouterLifetime)
	}

	// Check MTU option.
	var foundMTU bool
	for _, opt := range ra.Options {
		if mtu, ok := opt.(*ndp.MTU); ok {
			foundMTU = true
			if mtu.MTU != 1280 {
				t.Errorf("MTU = %d, want 1280", mtu.MTU)
			}
		}
	}
	if !foundMTU {
		t.Error("missing MTU option")
	}

	// Check prefix lifetimes.
	for _, opt := range ra.Options {
		if pi, ok := opt.(*ndp.PrefixInformation); ok {
			if pi.ValidLifetime != 86400*time.Second {
				t.Errorf("ValidLifetime = %v, want 86400s", pi.ValidLifetime)
			}
			if pi.PreferredLifetime != 14400*time.Second {
				t.Errorf("PreferredLifetime = %v, want 14400s", pi.PreferredLifetime)
			}
		}
	}
}

func TestBuildRA_MultipleInterfaces(t *testing.T) {
	m := New()
	// Verify manager starts empty.
	if len(m.senders) != 0 {
		t.Fatalf("new manager has %d senders, want 0", len(m.senders))
	}
}

func TestBuildRA_PrefixFlags(t *testing.T) {
	s := &sender{
		cfg: &config.RAInterfaceConfig{
			Interface: "trust0",
			Prefixes: []*config.RAPrefix{
				{Prefix: "2001:db8:1::/64", OnLink: false, Autonomous: false},
			},
		},
		iface: &net.Interface{
			Name:         "trust0",
			HardwareAddr: net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		},
	}

	ra := s.buildRA()

	for _, opt := range ra.Options {
		if pi, ok := opt.(*ndp.PrefixInformation); ok {
			if pi.OnLink {
				t.Error("OnLink should be false")
			}
			if pi.AutonomousAddressConfiguration {
				t.Error("Autonomous should be false")
			}
			return
		}
	}
	t.Error("missing prefix information option")
}

func TestBuildRA_Preference(t *testing.T) {
	tests := []struct {
		pref string
		want ndp.Preference
	}{
		{"high", ndp.High},
		{"low", ndp.Low},
		{"medium", ndp.Medium},
		{"", ndp.Medium},
	}

	for _, tt := range tests {
		s := &sender{
			cfg: &config.RAInterfaceConfig{
				Interface:  "trust0",
				Preference: tt.pref,
			},
			iface: &net.Interface{
				Name:         "trust0",
				HardwareAddr: net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
			},
		}

		ra := s.buildRA()
		if ra.RouterSelectionPreference != tt.want {
			t.Errorf("pref=%q: got %v, want %v", tt.pref, ra.RouterSelectionPreference, tt.want)
		}
	}
}

func TestConfigEqual_Same(t *testing.T) {
	a := &config.RAInterfaceConfig{
		Interface:     "trust0",
		ManagedConfig: true,
		Prefixes: []*config.RAPrefix{
			{Prefix: "2001:db8::/64", OnLink: true, Autonomous: true},
		},
		DNSServers: []string{"2001:4860:4860::8888"},
	}
	b := &config.RAInterfaceConfig{
		Interface:     "trust0",
		ManagedConfig: true,
		Prefixes: []*config.RAPrefix{
			{Prefix: "2001:db8::/64", OnLink: true, Autonomous: true},
		},
		DNSServers: []string{"2001:4860:4860::8888"},
	}

	if !configEqual(a, b) {
		t.Error("identical configs should be equal")
	}
}

func TestConfigEqual_Different(t *testing.T) {
	a := &config.RAInterfaceConfig{
		Interface: "trust0",
		Prefixes: []*config.RAPrefix{
			{Prefix: "2001:db8::/64", OnLink: true, Autonomous: true},
		},
	}
	b := &config.RAInterfaceConfig{
		Interface: "trust0",
		Prefixes: []*config.RAPrefix{
			{Prefix: "2001:db8:1::/64", OnLink: true, Autonomous: true},
		},
	}

	if configEqual(a, b) {
		t.Error("different prefixes should not be equal")
	}
}

func TestConfigEqual_DifferentDNS(t *testing.T) {
	a := &config.RAInterfaceConfig{
		Interface:  "trust0",
		DNSServers: []string{"2001:4860:4860::8888"},
	}
	b := &config.RAInterfaceConfig{
		Interface:  "trust0",
		DNSServers: []string{"2001:4860:4860::8844"},
	}

	if configEqual(a, b) {
		t.Error("different DNS should not be equal")
	}
}

func TestConfigEqual_DifferentFlags(t *testing.T) {
	a := &config.RAInterfaceConfig{Interface: "trust0", ManagedConfig: true}
	b := &config.RAInterfaceConfig{Interface: "trust0", ManagedConfig: false}

	if configEqual(a, b) {
		t.Error("different ManagedConfig should not be equal")
	}
}

func TestRandomAdvInterval(t *testing.T) {
	s := &sender{
		cfg: &config.RAInterfaceConfig{
			MaxAdvInterval: 600,
			MinAdvInterval: 200,
		},
	}

	for i := 0; i < 100; i++ {
		d := s.randomAdvInterval()
		if d < 200*time.Second || d > 600*time.Second {
			t.Errorf("interval %v out of [200s, 600s]", d)
		}
	}
}

func TestRandomAdvInterval_Defaults(t *testing.T) {
	s := &sender{
		cfg: &config.RAInterfaceConfig{},
	}

	for i := 0; i < 100; i++ {
		d := s.randomAdvInterval()
		// Default max=600, min=200 (600/3)
		if d < 200*time.Second || d > 600*time.Second {
			t.Errorf("interval %v out of [200s, 600s]", d)
		}
	}
}

func TestBuildRA_RethVirtualMAC(t *testing.T) {
	// RETH virtual MAC pattern: 02:bf:72:CC:RR:00
	rethMAC := net.HardwareAddr{0x02, 0xbf, 0x72, 0x01, 0x01, 0x00}
	s := &sender{
		cfg: &config.RAInterfaceConfig{
			Interface: "trust0",
			Prefixes: []*config.RAPrefix{
				{Prefix: "2001:db8::/64", OnLink: true, Autonomous: true},
			},
		},
		iface: &net.Interface{
			Name:         "trust0",
			HardwareAddr: rethMAC,
		},
	}

	ra := s.buildRA()

	// Verify SLLA uses the RETH virtual MAC.
	for _, opt := range ra.Options {
		if lla, ok := opt.(*ndp.LinkLayerAddress); ok && lla.Direction == ndp.Source {
			if lla.Addr.String() != rethMAC.String() {
				t.Errorf("SLLA = %s, want RETH MAC %s", lla.Addr, rethMAC)
			}
			return
		}
	}
	t.Error("missing source link-layer address option")
}

func TestManagerDiff_AddRemove(t *testing.T) {
	m := New()

	// Start with no senders.
	if len(m.senders) != 0 {
		t.Fatalf("new manager has %d senders", len(m.senders))
	}

	// Calling Clear on empty manager should not error.
	if err := m.Clear(); err != nil {
		t.Fatalf("Clear on empty: %v", err)
	}

	// Calling Withdraw on empty manager should not error.
	if err := m.Withdraw(); err != nil {
		t.Fatalf("Withdraw on empty: %v", err)
	}
}

// TestBuildRA_MarshalRoundtrip verifies the built RA can be marshaled
// to binary and parsed back by the ndp library.
func TestBuildRA_MarshalRoundtrip(t *testing.T) {
	s := &sender{
		cfg: &config.RAInterfaceConfig{
			Interface:       "trust0",
			ManagedConfig:   true,
			OtherStateful:   true,
			DefaultLifetime: 1800,
			Preference:      "high",
			LinkMTU:         1280,
			Prefixes: []*config.RAPrefix{
				{
					Prefix:        "2001:db8::/64",
					OnLink:        true,
					Autonomous:    true,
					ValidLifetime: 86400,
					PreferredLife: 14400,
				},
			},
			DNSServers: []string{"2001:4860:4860::8888"},
		},
		iface: &net.Interface{
			Name:         "trust0",
			HardwareAddr: net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		},
	}

	ra := s.buildRA()

	// Marshal to binary.
	b, err := ndp.MarshalMessage(ra)
	if err != nil {
		t.Fatalf("MarshalMessage: %v", err)
	}

	// Parse back.
	msg, err := ndp.ParseMessage(b)
	if err != nil {
		t.Fatalf("ParseMessage: %v", err)
	}

	parsed, ok := msg.(*ndp.RouterAdvertisement)
	if !ok {
		t.Fatal("parsed message is not RouterAdvertisement")
	}

	if parsed.RouterLifetime != 1800*time.Second {
		t.Errorf("parsed RouterLifetime = %v, want 1800s", parsed.RouterLifetime)
	}
	if !parsed.ManagedConfiguration {
		t.Error("parsed ManagedConfiguration should be true")
	}
	if !parsed.OtherConfiguration {
		t.Error("parsed OtherConfiguration should be true")
	}
	if parsed.RouterSelectionPreference != ndp.High {
		t.Errorf("parsed Preference = %v, want High", parsed.RouterSelectionPreference)
	}
}

// TestBuildRA_PREF64MarshalRoundtrip verifies that the PREF64 option
// survives marshal+parse roundtrip and appears in the raw bytes.
func TestBuildRA_PREF64MarshalRoundtrip(t *testing.T) {
	s := &sender{
		cfg: &config.RAInterfaceConfig{
			Interface:       "trust0",
			NAT64Prefix:     "64:ff9b::/96",
			NAT64PrefixLife: 1800,
			Prefixes: []*config.RAPrefix{
				{
					Prefix:     "2001:db8::/64",
					OnLink:     true,
					Autonomous: true,
				},
			},
			DNSServers: []string{"2001:4860:4860::8888"},
		},
		iface: &net.Interface{
			Name:         "trust0",
			HardwareAddr: net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		},
	}

	ra := s.buildRA()

	// Verify PREF64 option is in the RA struct.
	var foundInStruct bool
	for _, opt := range ra.Options {
		if _, ok := opt.(*ndp.PREF64); ok {
			foundInStruct = true
		}
	}
	if !foundInStruct {
		t.Fatal("PREF64 option not in RA struct before marshal")
	}

	// Marshal to binary.
	b, err := ndp.MarshalMessage(ra)
	if err != nil {
		t.Fatalf("MarshalMessage: %v", err)
	}

	// Scan raw bytes for option type 38 (PREF64).
	// RA header is 4 (ICMPv6) + 12 (RA body) = 16 bytes.
	// Options start at offset 16.
	var foundRaw bool
	off := 16
	for off+2 <= len(b) {
		optType := b[off]
		optLen := int(b[off+1]) * 8
		if optLen == 0 {
			break
		}
		t.Logf("raw option: type=%d len=%d at offset %d", optType, optLen, off)
		if optType == 38 {
			foundRaw = true
		}
		off += optLen
	}
	if !foundRaw {
		t.Fatalf("PREF64 (type 38) not found in raw marshaled bytes (len=%d): %x", len(b), b)
	}

	// Parse back.
	msg, err := ndp.ParseMessage(b)
	if err != nil {
		t.Fatalf("ParseMessage: %v", err)
	}

	parsed, ok := msg.(*ndp.RouterAdvertisement)
	if !ok {
		t.Fatal("parsed message is not RouterAdvertisement")
	}

	var foundParsed bool
	for _, opt := range parsed.Options {
		if pref64, ok := opt.(*ndp.PREF64); ok {
			foundParsed = true
			wantPrefix := netip.MustParsePrefix("64:ff9b::/96")
			if pref64.Prefix != wantPrefix {
				t.Errorf("parsed PREF64 prefix = %s, want %s", pref64.Prefix, wantPrefix)
			}
			// 1800s / 8 = 225, so roundtrip should be 225*8 = 1800s
			if pref64.Lifetime != 1800*time.Second {
				t.Errorf("parsed PREF64 lifetime = %v, want 1800s", pref64.Lifetime)
			}
		}
	}
	if !foundParsed {
		t.Error("PREF64 option not found after parse roundtrip")
	}
}
