package config

import (
	"net"
	"testing"
)

func TestSourceNATPoolNets(t *testing.T) {
	nat := &NATConfig{
		SourcePools: map[string]*NATPool{
			"isp-a": {
				Name:      "isp-a",
				Addresses: []string{"203.0.113.10", "203.0.113.11", "198.51.100.0/29"},
			},
			"isp-b-v6": {
				Name:    "isp-b-v6",
				Address: "2001:db8:b::/64",
			},
			"junk": {
				Name:      "junk",
				Addresses: []string{"not-an-ip"},
			},
		},
	}

	nets, ok := SourceNATPoolNets(nat, "isp-a")
	if !ok {
		t.Fatalf("isp-a: expected ok")
	}
	if len(nets) != 3 {
		t.Fatalf("isp-a: expected 3 nets, got %d", len(nets))
	}
	for _, tc := range []struct {
		ip   string
		want bool
	}{
		{"203.0.113.10", true},
		{"203.0.113.11", true},
		{"203.0.113.12", false}, // bare IPs are host routes, not ranges
		{"198.51.100.3", true},
		{"198.51.100.9", false},
	} {
		if got := IPInNets(net.ParseIP(tc.ip), nets); got != tc.want {
			t.Errorf("isp-a contains %s = %v, want %v", tc.ip, got, tc.want)
		}
	}

	nets, ok = SourceNATPoolNets(nat, "isp-b-v6")
	if !ok || len(nets) != 1 {
		t.Fatalf("isp-b-v6: ok=%v len=%d", ok, len(nets))
	}
	if !IPInNets(net.ParseIP("2001:db8:b::1234"), nets) {
		t.Errorf("isp-b-v6 should contain 2001:db8:b::1234")
	}
	if IPInNets(net.ParseIP("2001:db8:c::1"), nets) {
		t.Errorf("isp-b-v6 should not contain 2001:db8:c::1")
	}

	// Unknown pool: ok=false — callers must error, never fall through
	// to an unfiltered clear.
	if _, ok := SourceNATPoolNets(nat, "missing"); ok {
		t.Errorf("missing pool: expected ok=false")
	}
	if _, ok := SourceNATPoolNets(nil, "isp-a"); ok {
		t.Errorf("nil NATConfig: expected ok=false")
	}

	// Pool with only unparseable entries still reports ok=true with
	// zero nets (exists, matches nothing).
	nets, ok = SourceNATPoolNets(nat, "junk")
	if !ok || len(nets) != 0 {
		t.Errorf("junk pool: ok=%v len=%d, want ok=true len=0", ok, len(nets))
	}
}
