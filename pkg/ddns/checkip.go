package ddns

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strings"

	"github.com/psaab/xpf/pkg/config"
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
	// Fail-closed on an obviously malformed checkip-url (#2773). http.NewRequest
	// accepts ftp://, "not a url", and http:// (no host), so without this gate a
	// bad URL would fall through to a fetch failure and masquerade forever as a
	// transient observation failure (ok=false), silently suppressing publishing.
	// A malformed URL is a configuration error, not a transient — reject it here
	// (the commit-time validateSurfaceADDNSWarnings warning is the operator-facing
	// half; this is the runtime backstop for a URL that slipped past commit).
	if err := validateCheckIPURL(urlStr); err != nil {
		return netip.Addr{}, false
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

// NewCheckIPClient builds the HTTP client a checkip probe should use, bound to
// the provider's configured source-address / destination-interface / routing-
// instance (#2846) so the external "what is my IP" query egresses from the SAME
// source as the DDNS updates do — not the kernel default route. A malformed
// source-address returns the unbound default client plus the error so the caller
// can log it and degrade gracefully (a checkip miss is a transient observation,
// never a withdraw). A nil provider yields the unbound default client, no error.
func NewCheckIPClient(p *config.DDNSProvider) (*http.Client, error) {
	return newProviderHTTPClient(p)
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
		if !IsPublicAddr(a) {
			continue
		}
		if isAllowlisted(a, allowlist) {
			continue
		}
		return a, true
	}
	return netip.Addr{}, false
}

// specialPurposeV4 enumerates the IANA IPv4 Special-Purpose Address Registry
// ranges (RFC 6890 and successors) that are NOT globally-routable unicast and
// therefore can never be the public address a checkip endpoint should report.
// stdlib netip predicates already cover the unspecified address, loopback
// (127/8), link-local (169.254/16), and multicast (224/4); the prefixes below
// are the ranges those predicates miss — notably CGNAT (100.64/10), the
// benchmarking range (198.18/15), the IETF-protocol/documentation/6to4-relay
// /24s, the 0/8 "this network", the reserved 240/4 block, and the limited
// broadcast 255.255.255.255/32. netip.Addr.IsPrivate() covers 10/8, 172.16/12,
// and 192.168/16 but does NOT cover any of these, hence the explicit list.
var specialPurposeV4 = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),          // "this network" (RFC 1122)
	netip.MustParsePrefix("100.64.0.0/10"),      // CGNAT (RFC 6598)
	netip.MustParsePrefix("192.0.0.0/24"),       // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),       // TEST-NET-1 (documentation)
	netip.MustParsePrefix("192.88.99.0/24"),     // 6to4 relay anycast (deprecated)
	netip.MustParsePrefix("198.18.0.0/15"),      // benchmarking (RFC 2544)
	netip.MustParsePrefix("198.51.100.0/24"),    // TEST-NET-2 (documentation)
	netip.MustParsePrefix("203.0.113.0/24"),     // TEST-NET-3 (documentation)
	netip.MustParsePrefix("240.0.0.0/4"),        // reserved for future use
	netip.MustParsePrefix("255.255.255.255/32"), // limited broadcast
}

// specialPurposeV6 enumerates the IANA IPv6 Special-Purpose Address Registry
// ranges not covered by the stdlib netip predicates used in IsPublicAddr.
// IsUnspecified (::/128), IsLoopback (::1/128), IsLinkLocalUnicast (fe80::/10),
// and IsMulticast (ff00::/8) are handled by predicates; the prefixes below add
// ULA (fc00::/7), the documentation prefixes (2001:db8::/32, 3fff::/20), the
// IPv4-mapped and IPv4/IPv6 translation ranges, the discard-only and dummy
// prefixes, the SRv6 SID block, and the deprecated 6to4 block. Inputs are
// already Unmap()'d before this gate, so an IPv4-mapped literal cannot reach
// the v6 path, but ::ffff:0:0/96 is listed for completeness against a raw v6
// caller. Every entry has Globally-Reachable=False in the IANA registry.
var specialPurposeV6 = []netip.Prefix{
	netip.MustParsePrefix("::ffff:0:0/96"),  // IPv4-mapped (RFC 4291)
	netip.MustParsePrefix("64:ff9b::/96"),   // NAT64 well-known prefix (RFC 6052)
	netip.MustParsePrefix("64:ff9b:1::/48"), // NAT64 local-use (RFC 8215)
	netip.MustParsePrefix("100::/64"),       // discard-only (RFC 6666)
	netip.MustParsePrefix("100:0:0:1::/64"), // dummy IPv6 prefix (RFC 9780)
	netip.MustParsePrefix("2001::/23"),      // IETF protocol assignments
	netip.MustParsePrefix("2001:db8::/32"),  // documentation (RFC 3849)
	netip.MustParsePrefix("2002::/16"),      // 6to4 (RFC 3056, deprecated)
	netip.MustParsePrefix("3fff::/20"),      // documentation (RFC 9637)
	netip.MustParsePrefix("5f00::/16"),      // SRv6 SIDs (RFC 9602)
	netip.MustParsePrefix("fc00::/7"),       // unique-local / ULA (RFC 4193)
}

// IsPublicAddr is the inadyn validity gate: it accepts only a globally-routable
// unicast address (the public address a checkip endpoint should report) and
// rejects every IANA special-purpose range. A private/reserved/benchmark result
// usually means the request never left the NAT, or the endpoint is hostile or
// misconfigured — never a usable answer to publish as the router's A/AAAA
// record (#2774). stdlib predicates cover the loopback/link-local/multicast/
// unspecified/RFC-1918 cases; the specialPurposeV4/V6 tables cover the rest of
// the registry (CGNAT, benchmarking, documentation, ULA, translation, etc.).
//
// Exported (#2776) so the daemon's Surface A static-address fallback
// (pkg/daemon/daemon_ddns_surface_a.go staticUnitAddr) gates a configured
// static address through the SAME predicate the netlink and checkip address
// sources use — a mis-scoped static address must not publish a martian.
func IsPublicAddr(a netip.Addr) bool {
	if !a.IsValid() || a.IsUnspecified() || a.IsLoopback() ||
		a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsMulticast() ||
		a.IsPrivate() || a.IsInterfaceLocalMulticast() {
		return false
	}
	if a.Is4() {
		for _, p := range specialPurposeV4 {
			if p.Contains(a) {
				return false
			}
		}
		return true
	}
	for _, p := range specialPurposeV6 {
		if p.Contains(a) {
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

// validateCheckIPURL rejects an obviously malformed checkip URL so a typo is
// caught at commit (validateSurfaceADDNSWarnings mirrors this) and fails closed
// at runtime construction (CheckIP) rather than spinning forever as a phantom
// "transient" observation failure (#2773). It requires an http(s) scheme AND a
// host: http.NewRequest accepts ftp://, "not a url", and a host-less "http://",
// none of which can ever fetch a public address. The scheme check is
// case-INSENSITIVE per RFC 3986 §3.1 ("HTTPS://host" is valid), so it parses
// first and compares the parsed scheme with EqualFold rather than a
// case-sensitive HasPrefix on the raw string (#2842).
func validateCheckIPURL(u string) error {
	parsed, err := url.Parse(u)
	if err != nil {
		return fmt.Errorf("ddns checkip: url %q is not a valid URL: %w", u, err)
	}
	if !strings.EqualFold(parsed.Scheme, "http") && !strings.EqualFold(parsed.Scheme, "https") {
		return fmt.Errorf("ddns checkip: url %q must be http(s)", u)
	}
	if parsed.Host == "" {
		return fmt.Errorf("ddns checkip: url %q has no host", u)
	}
	return nil
}
