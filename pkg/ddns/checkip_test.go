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

// TestIsPublicAddrSpecialPurpose is the #2774 fail-on-revert gate for the
// public-address gate. Every IANA special-purpose range the checkip endpoint
// could return must be REJECTED (isPublicAddr == false), and a genuine
// globally-routable unicast address must be ACCEPTED. This goes RED if the
// specialPurposeV4/V6 prefix tables (or the stdlib predicate guards) are
// removed from isPublicAddr: each rejected entry below would then be accepted.
func TestIsPublicAddrSpecialPurpose(t *testing.T) {
	reject := []string{
		// IPv4 special-purpose (IANA registry).
		"0.0.0.0",         // 0.0.0.0/8 this-network / unspecified
		"0.1.2.3",         // 0.0.0.0/8 this-network (non-unspecified)
		"10.0.0.5",        // 10/8 private
		"100.64.0.1",      // 100.64/10 CGNAT
		"127.0.0.1",       // 127/8 loopback
		"169.254.1.1",     // 169.254/16 link-local
		"172.16.5.5",      // 172.16/12 private
		"192.0.0.8",       // 192.0.0/24 IETF protocol assignments
		"192.0.2.5",       // 192.0.2/24 TEST-NET-1
		"192.88.99.1",     // 192.88.99/24 6to4 relay anycast
		"192.168.1.1",     // 192.168/16 private
		"198.18.0.1",      // 198.18/15 benchmarking
		"198.19.255.255",  // 198.18/15 benchmarking (upper half)
		"198.51.100.7",    // 198.51.100/24 TEST-NET-2
		"203.0.113.9",     // 203.0.113/24 TEST-NET-3
		"224.0.0.1",       // 224/4 multicast
		"240.0.0.1",       // 240/4 reserved
		"255.255.255.255", // limited broadcast
		// IPv6 special-purpose (IANA registry).
		"::",           // ::/128 unspecified
		"::1",          // ::1/128 loopback
		"64:ff9b::1",   // 64:ff9b::/96 NAT64 well-known
		"100::1",       // 100::/64 discard-only
		"100:0:0:1::1", // 100:0:0:1::/64 dummy prefix (RFC 9780) — outside 100::/64
		"2001:db8::1",  // 2001:db8::/32 documentation
		"2002::1",      // 2002::/16 6to4
		"3fff::1",      // 3fff::/20 documentation (RFC 9637)
		"5f00::1",      // 5f00::/16 SRv6 SIDs (RFC 9602)
		"fc00::1",      // fc00::/7 ULA
		"fd00::1",      // fc00::/7 ULA
		"fe80::1",      // fe80::/10 link-local
		"ff02::1",      // ff00::/8 multicast
	}
	for _, s := range reject {
		a := netip.MustParseAddr(s).Unmap()
		if isPublicAddr(a) {
			t.Errorf("isPublicAddr(%s) = true, want false (special-purpose range)", s)
		}
	}
	accept := []string{
		"8.8.8.8",              // Google public DNS
		"93.184.216.34",        // example.com
		"1.0.0.1",              // public unicast
		"203.0.114.1",          // adjacent to TEST-NET-3 but routable
		"198.20.0.1",           // adjacent to 198.18/15 but routable
		"2606:4700:4700::1111", // Cloudflare public DNS
		"2001:4860:4860::8888", // Google public DNS v6
	}
	for _, s := range accept {
		a := netip.MustParseAddr(s).Unmap()
		if !isPublicAddr(a) {
			t.Errorf("isPublicAddr(%s) = false, want true (globally-routable unicast)", s)
		}
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

// TestValidateCheckIPURL is the #2773 validator gate: http(s) scheme + a host.
// validateCheckIPURL was dead code (no callers) before #2773 wired it into
// CheckIP and (mirrored) into the commit-time warning.
func TestValidateCheckIPURL(t *testing.T) {
	for _, ok := range []string{
		"http://checkip.example/",
		"https://checkip.example:8443/cdn-cgi/trace",
		"https://192.0.2.1/",
	} {
		if err := validateCheckIPURL(ok); err != nil {
			t.Fatalf("validateCheckIPURL(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{
		"",                // empty
		"ftp://host/",     // non-http scheme
		"not a url",       // no scheme
		"http://",         // scheme but no host
		"https:///path",   // empty host
		"javascript:0",    // non-http scheme
		"checkip.example", // bare host, no scheme
	} {
		if err := validateCheckIPURL(bad); err == nil {
			t.Fatalf("validateCheckIPURL(%q) = nil, want error", bad)
		}
	}
}

// TestCheckIPRejectsMalformedURL is the #2773 runtime fail-on-revert gate: a
// malformed checkip-url must be rejected by CheckIP itself (fail closed), not
// fall through to a fetch and masquerade as a transient failure. Before the
// wiring, http.NewRequest accepted these strings and CheckIP returned ok=false
// only because the *fetch* failed — indistinguishable from a real transient.
// This goes RED if the validateCheckIPURL gate is removed from CheckIP: the
// requests would then reach the transport, which fails the test on contact.
func TestCheckIPRejectsMalformedURL(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		t.Fatalf("CheckIP attempted a request for a malformed URL: %s", r.URL)
		return nil, nil
	})}
	for _, bad := range []string{"ftp://checkip.example/", "http://", "not a url"} {
		if _, ok := CheckIP(context.Background(), client, bad, true, nil); ok {
			t.Fatalf("CheckIP(%q) ok=true, want false (malformed URL must fail closed)", bad)
		}
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
