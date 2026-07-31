package grpcapi

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	ddnspkg "github.com/psaab/xpf/pkg/ddns"
)

// #6468 D1, remote-cli half. The Surface A DDNS "Last error" column can carry a
// PROVIDER response body: Cloudflare (backend_cloudflare.go) and Route 53
// (backend_route53.go) embed the provider's own message with %s, so a hostile
// or compromised provider — or an operator pointed at an attacker-run endpoint
// — controls those bytes. They land in the gRPC ShowText buffer the remote
// `cli` prints verbatim.
//
// This is the fail-on-revert guard for that surface: dropping the
// termsafe.SanitizeForDisplay call in server_show_dhcp_lldp_snmp.go makes the
// raw OSC/ESC reappear, and swapping in the BLOCK sanitizer lets the embedded
// newline through and forges a scope row.

// evilProviderError6468 is a provider error body carrying an OSC 52
// clipboard-write AND an embedded newline. The newline is the reason this
// surface takes the SINGLE-LINE sanitizer: LastError is rendered into one
// %s-formatted cell of a fixed-width table, so a raw LF fakes a whole scope row.
const evilProviderError6468 = "cloudflare 1004: \x1b]52;c;YWFhYWFh\x07bad zone\n" +
	"    forged.example.com               inet   OK              203.0.113.9"

// evilLastErrorStatusFn returns one Surface A scope view whose LastError is the
// hostile provider body.
func evilLastErrorStatusFn() []ddnspkg.SurfaceAStatusView {
	return []ddnspkg.SurfaceAStatusView{{
		Interface: "ge-0-0-0",
		Family:    4,
		FQDN:      "wan.example.com",
		Provider:  "cf",
		State:     "published",
		Published: "198.51.100.7",
		LastError: evilProviderError6468,
	}}
}

func TestShowServicesDynamicDNS_RemoteCLIEscapesLastError_6468(t *testing.T) {
	cfg := &config.Config{}

	s := &Server{
		surfaceADDNSStatsFn:  func() *ddnspkg.SurfaceAStats { return &ddnspkg.SurfaceAStats{Scopes: 1} },
		surfaceADDNSStatusFn: evilLastErrorStatusFn,
	}
	var buf strings.Builder
	s.showServicesDynamicDNS(cfg, &buf, true)
	out := buf.String()

	if !strings.Contains(out, "wan.example.com") {
		t.Fatalf("the scope row must render (else the guard is vacuous):\n%q", out)
	}
	if hasRawTermControl6468(out) {
		t.Fatalf("remote-cli DDNS renderer emitted raw terminal control bytes — an unsanitized "+
			"PROVIDER response body reaches the operator terminal (#6468 D1):\n%q", out)
	}
	if !strings.Contains(out, `\x1b`) {
		t.Fatalf("expected the escaped ESC (\\x1b) to render, proving LastError was sanitized "+
			"rather than dropped:\n%q", out)
	}
	// The embedded LF must render as an escape, not as a real line break: this
	// column is one cell of a fixed-width table, so a surviving newline forges a
	// scope row. It is also the discriminator against the BLOCK sanitizer, which
	// preserves LF by design and would let the forged row through.
	if !strings.Contains(out, `\x0a`) {
		t.Fatalf("expected the embedded newline to render as \\x0a — LastError is a single-line "+
			"FIELD and must take termsafe.SanitizeForDisplay, not the block variant "+
			"(a surviving LF forges a scope row):\n%q", out)
	}
	if strings.Contains(out, "forged.example.com\n") || strings.Contains(out, "\n    forged") {
		t.Fatalf("the provider body forged a table row — the embedded newline survived:\n%q", out)
	}
}
