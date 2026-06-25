package ddns

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"regexp"
	"strings"
)

// checkip.go: the optional external check-IP address source (#2691 P3, plan
// §3.2/§5.3). For a firewall that sits BEHIND another NAT (so its own interface
// address is an RFC 1918 / private address, not the public one DNS should point
// at), the public address must be discovered from an external "what is my IP"
// endpoint. This is OPT-IN per provider (`checkip-url`); the default Surface A
// observation is the interface / DHCP-lease read (the firewall is usually the
// router and knows its own public address directly — plan §7 fork 4).
//
// inadyn idea #6 adopted (plan §3.7): the response is run through a validity
// gate + a bogus-IP allowlist so a checkip page that EMBEDS a resolver/anycast
// IP (e.g. Cloudflare's 1.1.1.1 in /cdn-cgi/trace) is not mistaken for the
// client address. v6 is tried first, then v4 (inadyn parse_my_address order).

// ipAddrRe matches an IPv4 or IPv6 address literal embedded in a checkip body.
// Deliberately permissive (a byte-scan, like inadyn) — the validity gate below
// is what rejects junk, loopback, link-local, multicast, and unspecified.
var ipAddrRe = regexp.MustCompile(
	`([0-9a-fA-F:]{2,}:[0-9a-fA-F:]*|(?:[0-9]{1,3}\.){3}[0-9]{1,3})`)

// CheckIP fetches the public address from a checkip endpoint and returns the
// first VALID address of the requested family. wantV4 selects A (true) vs AAAA
// (false). allowlist is the operator's bogus-IP allowlist (addresses to ignore
// even if otherwise valid — the embedded-resolver case). The shared hardened
// HTTP client (TLS-verified, bounded timeout, capped body) is used.
//
// Returns (addr, true) on success; (zero, false) when no usable address of the
// requested family is found (the engine then treats it as a transient
// observation failure and leaves the scope untouched — never a withdraw).
func CheckIP(ctx context.Context, client *http.Client, urlStr string, wantV4 bool, allowlist []netip.Addr) (netip.Addr, bool) {
	if client == nil {
		client = newHTTPClient()
	}
	req, err := http.NewRequest(http.MethodGet, urlStr, nil)
	if err != nil {
		return netip.Addr{}, false
	}
	req.Header.Set("User-Agent", "xpf-ddns/1.0")
	code, body, err := doRequest(ctx, client, req)
	if err != nil || classifyHTTPStatus(code) != nil {
		return netip.Addr{}, false
	}
	return parseCheckIPBody(string(body), wantV4, allowlist)
}

// parseCheckIPBody scans a checkip response body for the first valid address of
// the requested family, skipping bogus and allowlisted addresses. Exposed
// (unexported but separately testable) so the validity gate is unit-tested
// without a network.
func parseCheckIPBody(body string, wantV4 bool, allowlist []netip.Addr) (netip.Addr, bool) {
	for _, m := range ipAddrRe.FindAllString(body, -1) {
		a, err := netip.ParseAddr(strings.TrimSpace(m))
		if err != nil {
			continue
		}
		a = a.Unmap()
		if a.Is4() != wantV4 {
			continue
		}
		if !isPublicAddr(a) {
			continue
		}
		if isAllowlisted(a, allowlist) {
			continue
		}
		return a, true
	}
	return netip.Addr{}, false
}

// isPublicAddr is the inadyn validity gate: reject loopback, link-local,
// multicast, unspecified, and (for v4) private/CGNAT/documentation ranges that
// can never be the public address a checkip endpoint should report. A private
// result usually means the request never left the NAT — not a usable answer.
func isPublicAddr(a netip.Addr) bool {
	if !a.IsValid() || a.IsUnspecified() || a.IsLoopback() ||
		a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsMulticast() {
		return false
	}
	if a.Is4() {
		o := a.As4()
		switch {
		case o[0] == 10: // 10.0.0.0/8
			return false
		case o[0] == 172 && o[1] >= 16 && o[1] <= 31: // 172.16.0.0/12
			return false
		case o[0] == 192 && o[1] == 168: // 192.168.0.0/16
			return false
		case o[0] == 100 && o[1] >= 64 && o[1] <= 127: // 100.64.0.0/10 CGNAT
			return false
		case o[0] == 192 && o[1] == 0 && o[2] == 2: // 192.0.2.0/24 TEST-NET-1
			return false
		case o[0] == 198 && o[1] == 51 && o[2] == 100: // 198.51.100.0/24 TEST-NET-2
			return false
		case o[0] == 203 && o[1] == 0 && o[2] == 113: // 203.0.113.0/24 TEST-NET-3
			return false
		case o[0] == 169 && o[1] == 254: // 169.254.0.0/16 (also IsLinkLocal)
			return false
		}
		return true
	}
	// IPv6: reject ULA (fc00::/7) and the documentation prefix (2001:db8::/32).
	if a.Is6() {
		b := a.As16()
		if b[0]&0xfe == 0xfc { // fc00::/7
			return false
		}
		if b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0d && b[3] == 0xb8 { // 2001:db8::/32
			return false
		}
	}
	return true
}

// isAllowlisted reports whether a matches an operator bogus-IP allowlist entry
// (the embedded-resolver case — inadyn `except[]`).
func isAllowlisted(a netip.Addr, allowlist []netip.Addr) bool {
	for _, x := range allowlist {
		if a == x.Unmap() {
			return true
		}
	}
	return false
}

// ParseAllowlist parses a comma/space-separated list of bogus addresses into a
// slice for CheckIP. Unparseable entries are skipped. Convenience for the daemon
// wiring (the provider/global config carries the allowlist as a string).
func ParseAllowlist(s string) []netip.Addr {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	fields := strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' })
	out := make([]netip.Addr, 0, len(fields))
	for _, f := range fields {
		if a, err := netip.ParseAddr(strings.TrimSpace(f)); err == nil {
			out = append(out, a.Unmap())
		}
	}
	return out
}

// AddressSourceCheckIP is the per-scope selection for the external checkip source
// (#2691 P3, opt-in). Declared here next to the implementation; the other
// AddressSource values live in surface_a.go.
const AddressSourceCheckIP AddressSource = "checkip"

// checkIPAllowlistConfigError is returned for an obviously malformed checkip URL
// at construction so the daemon can degrade the scope rather than spin on it.
func validateCheckIPURL(u string) error {
	if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
		return fmt.Errorf("ddns checkip: url %q must be http(s)", u)
	}
	return nil
}
