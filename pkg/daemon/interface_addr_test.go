package daemon

import (
	"net"
	"testing"
)

func mustIPNet(t *testing.T, cidr string) *net.IPNet {
	t.Helper()
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("ParseCIDR(%q): %v", cidr, err)
	}
	ipNet.IP = ip
	return ipNet
}

func TestSelectClusterBindAddr(t *testing.T) {
	addrs := []net.Addr{
		mustIPNet(t, "fe80::1266:6aff:fe30:ad1c/64"),
		mustIPNet(t, "10.99.12.1/30"),
		mustIPNet(t, "2001:db8::1/64"),
	}

	tests := []struct {
		name     string
		peerAddr string
		fallback string
		want     string
	}{
		{
			name:     "ipv4 peer waits for ipv4 instead of link local",
			peerAddr: "10.99.12.2",
			want:     "10.99.12.1",
		},
		{
			name:     "ipv6 peer prefers global ipv6",
			peerAddr: "2001:db8::2",
			want:     "2001:db8::1",
		},
		{
			name:     "unknown peer prefers ipv4 then global ipv6",
			peerAddr: "",
			want:     "10.99.12.1",
		},
		{
			name:     "hostport peer is parsed",
			peerAddr: "[2001:db8::2]:4785",
			want:     "2001:db8::1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := selectClusterBindAddr(addrs, tt.peerAddr, tt.fallback); got != tt.want {
				t.Fatalf("selectClusterBindAddr(%q) = %q, want %q", tt.peerAddr, got, tt.want)
			}
		})
	}
}

func TestSelectClusterBindAddrSkipsLinkLocalIPv6Fallback(t *testing.T) {
	addrs := []net.Addr{
		mustIPNet(t, "fe80::1266:6aff:fe30:ad1c/64"),
	}
	if got := selectClusterBindAddr(addrs, "10.99.12.2", ""); got != "" {
		t.Fatalf("selectClusterBindAddr returned %q, want empty string", got)
	}
}
