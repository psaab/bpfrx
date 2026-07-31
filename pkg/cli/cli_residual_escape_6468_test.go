package cli

import (
	"context"
	"io"
	"path/filepath"
	"strings"
	"testing"

	ddnspkg "github.com/psaab/xpf/pkg/ddns"
	"github.com/psaab/xpf/pkg/frr"
)

// #6468 residual surfaces, local-CLI half. Two device- or remote-supplied
// strings still reached the in-process operator terminal raw after the DHCP
// lease-field fix:
//
//   - D1, the Surface A DDNS "Last error" column, which can carry a PROVIDER
//     response body — Cloudflare (backend_cloudflare.go) and Route 53
//     (backend_route53.go) embed the provider's own message with %s;
//   - D2, captured `vtysh` stdout, which carries text a REMOTE PEER
//     advertised: the BGP hostname capability, IS-IS dynamic hostname TLVs,
//     OSPF router IDs.
//
// These are the fail-on-revert guards. Dropping a sanitize call in
// cli_show_routing.go / show_services_ddns.go / cli_request.go makes the raw
// ESC reappear on stdout; using the WRONG variant is caught too — see the
// per-assertion notes. The remote-cli mirror of every case below lives in
// pkg/grpcapi (server_routing_escape_6468_test.go,
// server_show_ddns_escape_6468_test.go); both renderers are in scope for this
// class, and fixing one alone is what left the class half-open.
//
// hasRawTermControl6468 and captureStdout are shared with sibling test files.

// evilVtyshBlock6468 is a realistic multi-line vtysh table with a CSI
// erase-line escape buried in the peer-advertised hostname cell. The
// surrounding rows are clean so a test can assert BOTH that the escape was
// neutralized AND that the block's line structure survived.
const evilVtyshBlock6468 = "BGP neighbor is 10.0.0.1, remote AS 65001\n" +
	"  Hostname: rtr1\x1b[2Kforged-peer\n" +
	"  BGP state = Established, up for 00:12:34\n"

// vtyshEscapeExecutor6468 is an frr executor double whose Vtysh returns the
// hostile block for every command. It satisfies pkg/frr's package-private
// frrExecutor (all four methods are exported names, so an out-of-package type
// can implement it) and is handed to frr.NewForTest, which is the seam that
// lets a show handler run its real wiring without shelling out to vtysh.
type vtyshEscapeExecutor6468 struct{}

func (vtyshEscapeExecutor6468) Vtysh(string) (string, error) {
	return evilVtyshBlock6468, nil
}

func (vtyshEscapeExecutor6468) FrrReloadPy(context.Context, string) error { return nil }

func (vtyshEscapeExecutor6468) VtyshLoad(context.Context, string) ([]byte, error) {
	return nil, nil
}

func (vtyshEscapeExecutor6468) VtyshStream(context.Context, string) (io.ReadCloser, func() error, error) {
	return io.NopCloser(strings.NewReader("")), func() error { return nil }, nil
}

// escapeVtyshCLI6468 wires a CLI whose FRR manager returns the hostile block
// from every vtysh call.
func escapeVtyshCLI6468(t *testing.T) *CLI {
	t.Helper()
	m := frr.NewForTest(filepath.Join(t.TempDir(), "frr.conf"), vtyshEscapeExecutor6468{})
	return &CLI{frr: m}
}

// assertVtyshOutputSanitized6468 is the shared verdict for a printed block. It
// binds THREE distinct failure modes:
//
//	(1) non-vacuous — the fixture actually rendered;
//	(2) no raw terminal control byte survived — the revert signal for dropping
//	    the sanitize call entirely;
//	(3) the escape is VISIBLE and the LINE COUNT is unchanged — the revert
//	    signal for swapping in the single-line sanitizer, which escapes every
//	    LF and would collapse the table into one \x0a-laden row.
func assertVtyshOutputSanitized6468(t *testing.T, surface, out string) {
	t.Helper()
	if !strings.Contains(out, "BGP neighbor is 10.0.0.1") {
		t.Fatalf("%s: the vtysh block must render (else the guard is vacuous):\n%q", surface, out)
	}
	if hasRawTermControl6468(out) {
		t.Fatalf("%s: printed raw terminal control bytes — unsanitized vtysh stdout carrying "+
			"peer-advertised text reaches the operator terminal (#6468 D2):\n%q", surface, out)
	}
	if !strings.Contains(out, `\x1b`) {
		t.Fatalf("%s: expected the escaped ESC (\\x1b) to render, proving the peer hostname was "+
			"sanitized rather than dropped:\n%q", surface, out)
	}
	if want, have := strings.Count(evilVtyshBlock6468, "\n"), strings.Count(out, "\n"); want != have {
		t.Fatalf("%s: the block's line structure must survive — want %d newlines, got %d. "+
			"The single-line termsafe.SanitizeForDisplay escapes LF and would collapse this "+
			"table; these surfaces need SanitizeBlockForDisplay:\n%q", surface, want, have, out)
	}
}

func TestShowOSPF_LocalCLIEscapesVtyshOutput_6468(t *testing.T) {
	// Every raw-vtysh branch of showOSPF. The bare "neighbor" branch builds a
	// structured table instead of printing vtysh stdout and is not in scope.
	for _, args := range [][]string{
		{"neighbor", "detail"},
		{"database"},
		{"interface"},
		{"routes"},
	} {
		c := escapeVtyshCLI6468(t)
		out := captureStdout(t, func() {
			if err := c.showOSPF(args); err != nil {
				t.Fatalf("showOSPF(%v): %v", args, err)
			}
		})
		assertVtyshOutputSanitized6468(t, "showOSPF "+strings.Join(args, " "), out)
	}
}

func TestShowBGP_LocalCLIEscapesVtyshOutput_6468(t *testing.T) {
	for _, args := range [][]string{
		{"neighbor", "10.0.0.1", "received-routes"},
		{"neighbor", "10.0.0.1", "advertised-routes"},
		{"neighbor", "10.0.0.1"},
		{"neighbor"},
	} {
		c := escapeVtyshCLI6468(t)
		out := captureStdout(t, func() {
			if err := c.showBGP(args); err != nil {
				t.Fatalf("showBGP(%v): %v", args, err)
			}
		})
		assertVtyshOutputSanitized6468(t, "showBGP "+strings.Join(args, " "), out)
	}
}

func TestShowISIS_LocalCLIEscapesVtyshOutput_6468(t *testing.T) {
	for _, args := range [][]string{
		{"adjacency", "detail"},
		{"database"},
		{"routes"},
	} {
		c := escapeVtyshCLI6468(t)
		out := captureStdout(t, func() {
			if err := c.showISIS(args); err != nil {
				t.Fatalf("showISIS(%v): %v", args, err)
			}
		})
		assertVtyshOutputSanitized6468(t, "showISIS "+strings.Join(args, " "), out)
	}
}

func TestShowBFD_LocalCLIEscapesVtyshOutput_6468(t *testing.T) {
	c := escapeVtyshCLI6468(t)
	out := captureStdout(t, func() {
		if err := c.showBFD([]string{"peers"}); err != nil {
			t.Fatalf("showBFD: %v", err)
		}
	})
	assertVtyshOutputSanitized6468(t, "showBFD peers", out)
}

func TestShowRouteMap_LocalCLIEscapesVtyshOutput_6468(t *testing.T) {
	c := escapeVtyshCLI6468(t)
	out := captureStdout(t, func() {
		if err := c.showRouteMap(); err != nil {
			t.Fatalf("showRouteMap: %v", err)
		}
	})
	assertVtyshOutputSanitized6468(t, "showRouteMap", out)
}

func TestRequestProtocolsClear_LocalCLIEscapesVtyshOutput_6468(t *testing.T) {
	// `request protocols {ospf,bgp} clear` prints whatever the clear emitted,
	// then its own confirmation line. FRR normally emits nothing here, so the
	// payload likelihood is low — but the guard belongs on the print, not on an
	// assumption about what FRR chooses to emit.
	for _, tc := range []struct {
		args    []string
		confirm string
	}{
		{[]string{"ospf", "clear"}, "OSPF process cleared\n"},
		{[]string{"bgp", "clear"}, "BGP sessions cleared (soft reset)\n"},
	} {
		c := escapeVtyshCLI6468(t)
		out := captureStdout(t, func() {
			if err := c.handleRequestProtocols(tc.args); err != nil {
				t.Fatalf("handleRequestProtocols(%v): %v", tc.args, err)
			}
		})
		surface := "request protocols " + strings.Join(tc.args, " ")
		// Strip the handler's own confirmation line so the shared line-count
		// assertion measures the vtysh block alone; its presence is asserted
		// here rather than dropped.
		trimmed, ok := strings.CutSuffix(out, tc.confirm)
		if !ok {
			t.Fatalf("%s: expected the confirmation line %q to terminate the output:\n%q",
				surface, tc.confirm, out)
		}
		assertVtyshOutputSanitized6468(t, surface, trimmed)
	}
}

// evilProviderError6468 is a provider error body carrying an OSC 52
// clipboard-write AND an embedded newline. The newline is the reason this
// surface takes the SINGLE-LINE sanitizer: LastError is rendered into one
// %s-formatted cell of a fixed-width table, so a raw LF fakes a whole scope row.
const evilProviderError6468 = "cloudflare 1004: \x1b]52;c;YWFhYWFh\x07bad zone\n" +
	"    forged.example.com               inet   OK              203.0.113.9"

func TestShowServicesDynamicDNS_LocalCLIEscapesLastError_6468(t *testing.T) {
	dir := t.TempDir()
	store := newConfigStore(t, filepath.Join(dir, "xpf.conf"))

	c := &CLI{
		store:               store,
		surfaceADDNSStatsFn: func() *ddnspkg.SurfaceAStats { return &ddnspkg.SurfaceAStats{Scopes: 1} },
		surfaceADDNSStatusFn: func() []ddnspkg.SurfaceAStatusView {
			return []ddnspkg.SurfaceAStatusView{{
				Interface: "ge-0-0-0",
				Family:    4,
				FQDN:      "wan.example.com",
				Provider:  "cf",
				State:     "published",
				Published: "198.51.100.7",
				LastError: evilProviderError6468,
			}}
		},
	}
	out := captureStdout(t, func() {
		if err := c.showServicesDynamicDNS(true); err != nil {
			t.Fatalf("showServicesDynamicDNS: %v", err)
		}
	})

	if !strings.Contains(out, "wan.example.com") {
		t.Fatalf("the scope row must render (else the guard is vacuous):\n%q", out)
	}
	if hasRawTermControl6468(out) {
		t.Fatalf("local DDNS renderer printed raw terminal control bytes — an unsanitized "+
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
	if strings.Contains(out, "\n    forged") {
		t.Fatalf("the provider body forged a table row — the embedded newline survived:\n%q", out)
	}
}
