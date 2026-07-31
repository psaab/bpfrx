package grpcapi

import (
	"context"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/frr"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #6468 D2, remote-cli half. The routing show RPCs return captured `vtysh`
// stdout and the remote `cli` prints resp.Output VERBATIM
// (cmd/cli/show_protocols.go, cmd/cli/show.go: fmt.Print(resp.Output)) — the
// same operator terminal the in-process CLI writes to, reached over gRPC
// instead of in-process. That stdout carries text a REMOTE PEER advertised:
// the BGP hostname capability, IS-IS dynamic hostname TLVs, OSPF router IDs.
//
// These are the fail-on-revert guards for that surface. Dropping a
// termsafe.SanitizeBlockForDisplay call in server_routing.go /
// server_show_routes_text.go makes the raw ESC reappear in the emitted text,
// and swapping in the single-line termsafe.SanitizeForDisplay collapses the
// table — each assertion below binds one of those two failure modes.
//
// hasRawTermControl6468 is shared with server_show_dhcp_escape_6468_test.go.

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
// lets a show RPC run its real wiring without shelling out to vtysh.
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

// escapeVtyshServer6468 wires a Server whose FRR manager returns the hostile
// block from every vtysh call.
func escapeVtyshServer6468(t *testing.T) *Server {
	t.Helper()
	m := frr.NewForTest(filepath.Join(t.TempDir(), "frr.conf"), vtyshEscapeExecutor6468{})
	return &Server{frr: m}
}

// assertVtyshOutputSanitized6468 is the shared verdict for a rendered block.
// It binds THREE distinct failure modes:
//
//	(1) non-vacuous — the fixture actually rendered, so the guard is not being
//	    asserted against an empty string;
//	(2) no raw terminal control byte survived — the revert signal for dropping
//	    the sanitize call entirely;
//	(3) the escape is VISIBLE and the LINE COUNT is unchanged — the revert
//	    signal for swapping in the single-line sanitizer, which would escape
//	    every LF and collapse the table into one \x0a-laden row.
func assertVtyshOutputSanitized6468(t *testing.T, surface, out string) {
	t.Helper()
	if !strings.Contains(out, "BGP neighbor is 10.0.0.1") {
		t.Fatalf("%s: the vtysh block must render (else the guard is vacuous):\n%q", surface, out)
	}
	if hasRawTermControl6468(out) {
		t.Fatalf("%s: emitted raw terminal control bytes — unsanitized vtysh stdout reaches "+
			"the remote cli's verbatim fmt.Print(resp.Output) (#6468 D2):\n%q", surface, out)
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

func TestGetOSPFStatus_RemoteCLIEscapesVtyshOutput_6468(t *testing.T) {
	// Every raw-vtysh req.Type of the OSPF handler. "" (the structured
	// neighbor-summary default) is excluded: it does not return vtysh stdout.
	for _, typ := range []string{"neighbor-detail", "database", "interface", "routes"} {
		s := escapeVtyshServer6468(t)
		resp, err := s.GetOSPFStatus(context.Background(), &pb.GetOSPFStatusRequest{Type: typ})
		if err != nil {
			t.Fatalf("GetOSPFStatus(%q): %v", typ, err)
		}
		assertVtyshOutputSanitized6468(t, "GetOSPFStatus type="+typ, resp.Output)
	}
}

func TestGetBGPStatus_RemoteCLIEscapesVtyshOutput_6468(t *testing.T) {
	// The three neighbor sub-selectors that return raw vtysh stdout. "routes",
	// "groups" and the bare summary build structured tables instead.
	for _, typ := range []string{
		"received-routes:10.0.0.1",
		"advertised-routes:10.0.0.1",
		"neighbor:10.0.0.1",
		"neighbor",
	} {
		s := escapeVtyshServer6468(t)
		resp, err := s.GetBGPStatus(context.Background(), &pb.GetBGPStatusRequest{Type: typ})
		if err != nil {
			t.Fatalf("GetBGPStatus(%q): %v", typ, err)
		}
		assertVtyshOutputSanitized6468(t, "GetBGPStatus type="+typ, resp.Output)
	}
}

func TestGetISISStatus_RemoteCLIEscapesVtyshOutput_6468(t *testing.T) {
	for _, typ := range []string{"adjacency-detail", "routes", "database"} {
		s := escapeVtyshServer6468(t)
		resp, err := s.GetISISStatus(context.Background(), &pb.GetISISStatusRequest{Type: typ})
		if err != nil {
			t.Fatalf("GetISISStatus(%q): %v", typ, err)
		}
		assertVtyshOutputSanitized6468(t, "GetISISStatus type="+typ, resp.Output)
	}
}

func TestShowBFDPeers_RemoteCLIEscapesVtyshOutput_6468(t *testing.T) {
	s := escapeVtyshServer6468(t)
	var buf strings.Builder
	if err := s.showBFDPeers(&buf); err != nil {
		t.Fatalf("showBFDPeers: %v", err)
	}
	assertVtyshOutputSanitized6468(t, "showBFDPeers", buf.String())
}

func TestShowRouteMap_RemoteCLIEscapesVtyshOutput_6468(t *testing.T) {
	s := escapeVtyshServer6468(t)
	var buf strings.Builder
	if err := s.showRouteMap(nil, &buf); err != nil {
		t.Fatalf("showRouteMap: %v", err)
	}
	assertVtyshOutputSanitized6468(t, "showRouteMap", buf.String())
}
