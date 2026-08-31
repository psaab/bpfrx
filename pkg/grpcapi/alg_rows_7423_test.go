package grpcapi

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #7423 row 6, gRPC surface.
//
// The CLI was the surface with the twelve fabricated rows, but `enabled` was
// on all three. Nothing in the userspace dataplane pinholes a data channel —
// the ALG bits reach `alg_type_for_session`, which tags the conntrack row —
// so "enabled" overstates what any of them do.
//
// This binds the gRPC renderer itself, not the shared pkg/config helper it
// calls. A helper being shared is not evidence that a caller reaches it; the
// row-4 work in this same change had tests that drove only the source-NAT
// renderer while dest.go carried the identical fix untested.
func TestShowAlgDoesNotClaimEnabled_7423(t *testing.T) {
	var buf strings.Builder
	(&Server{}).showAlg(&config.Config{}, &buf)
	out := buf.String()

	if strings.Contains(out, "enabled") {
		t.Errorf("gRPC show alg still reports an ALG as enabled:\n%s", out)
	}
	for _, want := range []string{"DNS:", "FTP:", "SIP:", "TFTP:"} {
		if !strings.Contains(out, want) {
			t.Errorf("gRPC show alg is missing %q:\n%s", want, out)
		}
	}
	if !strings.Contains(out, config.ALGStatusSessionTagged) {
		t.Errorf("DNS/FTP/SIP should report session tagging:\n%s", out)
	}
	if !strings.Contains(out, "TFTP: "+config.ALGStatusRecordedOnly) {
		t.Errorf("TFTP has no dataplane consumer at all and must say so:\n%s", out)
	}
}

// A disabled ALG must still read as disabled: a fix that rendered everything
// as inert would pass the test above while destroying the surface's value.
func TestShowAlgStillReportsDisable_7423(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.ALG = config.ALGConfig{
		DNSDisable: true, FTPDisable: true, SIPDisable: true, TFTPDisable: true,
	}
	var buf strings.Builder
	(&Server{}).showAlg(cfg, &buf)
	if n := strings.Count(buf.String(), config.ALGStatusDisabled); n != 4 {
		t.Errorf("want 4 disabled rows, got %d:\n%s", n, buf.String())
	}
}

// A `security alg <proto>` outside the modeled four is accepted at commit and
// recorded in UnsupportedProtos (#4232). It must be visible here, marked, or
// an operator's configured stanza is invisible on the surface they check.
func TestShowAlgRendersConfiguredUnmodeledProtos_7423(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.ALG = config.ALGConfig{UnsupportedProtos: []string{"h323", "h323", "msrpc"}}
	var buf strings.Builder
	(&Server{}).showAlg(cfg, &buf)
	out := buf.String()

	if n := strings.Count(out, "H323"); n != 1 {
		t.Errorf("configured alg h323 should render exactly one deduped row, got %d:\n%s", n, out)
	}
	if !strings.Contains(out, "H323: "+config.ALGStatusNotImplemented) {
		t.Errorf("unmodeled proto must be marked not implemented:\n%s", out)
	}
	if !strings.Contains(out, "MSRPC: "+config.ALGStatusNotImplemented) {
		t.Errorf("every unmodeled proto must render, not just the first:\n%s", out)
	}
}
