package ddns

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestParseCheckIPBodyValidV4(t *testing.T) {
	// 93.184.216.34 is a real, non-reserved public address (not in any
	// private/CGNAT/TEST-NET range the validity gate rejects).
	a, ok := parseCheckIPBody("Your IP is 93.184.216.34 today", true, nil)
	if !ok || a.String() != "93.184.216.34" {
		t.Fatalf("expected 93.184.216.34, got %v ok=%v", a, ok)
	}
}

func TestParseCheckIPBodyRejectsTestNet(t *testing.T) {
	// The TEST-NET ranges (192.0.2/198.51.100/203.0.113) used throughout the
	// other tests as stand-in "public" addresses are reserved-documentation and
	// must be rejected by the checkip gate (they can never be a real public IP).
	for _, ip := range []string{"192.0.2.5", "198.51.100.7", "203.0.113.9"} {
		if _, ok := parseCheckIPBody("ip="+ip, true, nil); ok {
			t.Fatalf("TEST-NET address %s must be rejected by the checkip gate", ip)
		}
	}
}

func TestParseCheckIPBodyRejectsPrivate(t *testing.T) {
	// Only a private address present → no usable public address.
	if _, ok := parseCheckIPBody("ip=192.168.1.1", true, nil); ok {
		t.Fatal("a private address must not be accepted as the public IP")
	}
	if _, ok := parseCheckIPBody("ip=10.0.0.5", true, nil); ok {
		t.Fatal("a 10/8 address must be rejected")
	}
	if _, ok := parseCheckIPBody("ip=100.64.0.1", true, nil); ok {
		t.Fatal("a CGNAT address must be rejected")
	}
}

func TestParseCheckIPBodyAllowlistSkipsEmbeddedResolver(t *testing.T) {
	// A /cdn-cgi/trace-style body that embeds the anycast resolver (1.1.1.1)
	// before the real client IP must skip the allowlisted address.
	body := "fl=1\nip=1.1.1.1\nclient=93.184.216.34\n"
	allow := []netip.Addr{netip.MustParseAddr("1.1.1.1")}
	a, ok := parseCheckIPBody(body, true, allow)
	if !ok || a.String() != "93.184.216.34" {
		t.Fatalf("allowlist must skip 1.1.1.1 and pick the client IP, got %v ok=%v", a, ok)
	}
}

func TestParseCheckIPBodyV6First(t *testing.T) {
	a, ok := parseCheckIPBody("addr 2606:4700:4700::1111", false, nil)
	if !ok || !a.Is6() {
		t.Fatalf("expected a v6 address, got %v ok=%v", a, ok)
	}
	// Reject ULA + documentation v6.
	if _, ok := parseCheckIPBody("fd00::1", false, nil); ok {
		t.Fatal("ULA fd00::/8 must be rejected")
	}
	if _, ok := parseCheckIPBody("2001:db8::1", false, nil); ok {
		t.Fatal("2001:db8::/32 documentation must be rejected")
	}
}

func TestCheckIPThroughMockServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("93.184.216.34\n"))
	}))
	defer srv.Close()
	a, ok := CheckIP(context.Background(), srv.Client(), srv.URL, true, nil)
	if !ok || a.String() != "93.184.216.34" {
		t.Fatalf("CheckIP returned %v ok=%v", a, ok)
	}
}

func TestParseAllowlist(t *testing.T) {
	got := ParseAllowlist("1.1.1.1, 8.8.8.8 garbage 2606:4700::1")
	if len(got) != 3 {
		t.Fatalf("expected 3 parsed addresses, got %d (%v)", len(got), got)
	}
}
