package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/diagcmd"
	"github.com/psaab/xpf/pkg/grpcapi"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #6904 — THE AGREEMENT between the two diagnostic surfaces.
//
// gRPC bounded target/source/routing-instance at 512 (#5060); REST bounded
// nothing. One surface was hardened and the sibling was missed, so the
// guarantee the gRPC check was supposed to give was not a system property.
//
// WHY THIS TEST IS SHAPED THIS WAY. Adding a second `512` to REST would fix
// today and leave the two free to drift again — which is how this got here. So
// the bound lives once, in pkg/diagcmd next to MaxPingSize, and this table
// drives BOTH surfaces with the SAME inputs and requires the SAME verdict. A
// REST-only test would leave the asymmetry re-introducible from the gRPC side,
// and a test pinned to its own literal would keep passing while the surfaces
// diverged.
//
// The bound is CHOSEN, not derived from an external authority — a DNS name is
// capped at 253 (RFC 1035) and an IPv6 literal at ~45, so 512 is
// largest-legitimate-plus-headroom. That is why the two surfaces AGREEING is
// the whole property here: there is no third source of truth to pin them to.
//
// SCOPE, stated rather than implied: the gRPC surface is driven only on the
// REJECT rows. Its length check runs before the stream is touched, so a nil
// stream is safe there, but an ACCEPT row proceeds into streamDiag and would
// spawn a real ping child. The reject direction is the one that was asymmetric
// and is what this binds; the gRPC accept direction is covered by pkg/grpcapi's
// own tests.
//
// Fail-on-revert: drop diagcmd.CheckArgs from either handler and the rows for
// that surface go RED while the other surface's stay green — which is exactly
// the asymmetry this issue is about.
func TestDiagArgBoundAgreesAcrossSurfaces_6904(t *testing.T) {
	oversized := strings.Repeat("a", diagcmd.MaxArgLen+1)
	atLimit := strings.Repeat("a", diagcmd.MaxArgLen)

	rows := []struct {
		name            string
		target          string
		source          string
		routingInstance string
		wantReject      bool
	}{
		{"legitimate target", "192.0.2.1", "", "", false},
		{"target at the limit", atLimit, "", "", false},
		{"target one over", oversized, "", "", true},
		{"source one over", "192.0.2.1", oversized, "", true},
		{"routing-instance one over", "192.0.2.1", "", oversized, true},
	}

	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			ruleRejects := diagcmd.CheckArgs(row.target, row.source, row.routingInstance) != nil
			restRejected := restPingRejects6904(t, row.target, row.source, row.routingInstance)

			if ruleRejects != row.wantReject {
				t.Fatalf("the SHARED rule rejected=%v, want %v — the table's premise is "+
					"wrong before either surface is consulted", ruleRejects, row.wantReject)
			}
			if restRejected != row.wantReject {
				t.Errorf("REST rejected=%v, want %v — the REST surface must enforce the "+
					"same per-field bound as gRPC (#6904)", restRejected, row.wantReject)
			}
			if restRejected != ruleRejects {
				t.Errorf("REST DISAGREES WITH THE SHARED RULE: rest=%v rule=%v. Two entry "+
					"points to one operation must not differ about what input is "+
					"acceptable — that asymmetry IS the defect (#6904)",
					restRejected, ruleRejects)
			}

			// The gRPC surface is driven only on the REJECT rows. Its length
			// check runs before the stream is touched, so a nil stream is safe
			// there — but an ACCEPT row proceeds into streamDiag and would
			// spawn a real ping child, which a unit test must not do. The
			// accept direction on that surface is covered by pkg/grpcapi's own
			// tests; what this table exists to bind is that the two surfaces
			// REJECT the same inputs, which is the direction that was asymmetric.
			// REST traceroute is the sibling handler and takes the same three
			// fields; without this row a revert there would be invisible.
			if got := restTracerouteRejects6904(t, row.target, row.source, row.routingInstance); got != row.wantReject {
				t.Errorf("REST traceroute rejected=%v, want %v — both REST diagnostic "+
					"handlers must enforce the bound, not just ping", got, row.wantReject)
			}

			if row.wantReject {
				if !grpcPingRejects6904(row.target, row.source, row.routingInstance) {
					t.Errorf("gRPC accepted an input the shared rule rejects — the surfaces " +
						"have drifted apart again (#6904)")
				}
			}
		})
	}
}

// restPingRejects6904 drives the real REST ping handler and reports whether it
// refused the request before reaching exec. diagRun is stubbed so a request
// that PASSES validation cannot spawn a child in the test environment.
func restPingRejects6904(t *testing.T, target, source, ri string) bool {
	t.Helper()
	orig := diagRun
	t.Cleanup(func() { diagRun = orig })
	diagRun = func(ctx context.Context, argv []string) (string, error) { return "stubbed", nil }

	body, err := json.Marshal(PingRequest{Target: target, Source: source, RoutingInstance: ri})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest("POST", "/api/v1/diagnostics/ping", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	(&Server{}).pingHandler(w, req)
	return w.Code >= 400
}

// grpcPingRejects6904 drives the real gRPC Ping validation. The length check
// runs before the stream is touched, so a nil stream is safe — the same
// property TestDiagFieldLengthRejected relies on.
func grpcPingRejects6904(target, source, ri string) (rejected bool) {
	// PANIC-SAFE, and the reason is a real property of the thing under test.
	// The nil stream is safe only WHILE the length check rejects before the
	// stream is touched. Remove that check — the exact revert this table
	// exists to catch — and the call proceeds into streamDiag and dereferences
	// the nil stream, killing the whole package binary and taking ~1200
	// unrelated tests with it. A revert would then look like a mass failure
	// instead of a named one, and the collected count would drop to a third of
	// the control: the "did it RED or did it CRASH" tell.
	//
	// A panic here means validation did NOT reject, which is exactly the
	// verdict the caller needs, so recovering and reporting false is truthful
	// rather than a workaround.
	defer func() {
		if recover() != nil {
			rejected = false
		}
	}()
	err := (&grpcapi.Server{}).Ping(&pb.PingRequest{
		Target: target, Source: source, RoutingInstance: ri,
	}, nil)
	return err != nil
}

// restTracerouteRejects6904 is restPingRejects6904 for the sibling handler.
func restTracerouteRejects6904(t *testing.T, target, source, ri string) bool {
	t.Helper()
	orig := diagRun
	t.Cleanup(func() { diagRun = orig })
	diagRun = func(ctx context.Context, argv []string) (string, error) { return "stubbed", nil }

	body, err := json.Marshal(TracerouteRequest{Target: target, Source: source, RoutingInstance: ri})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest("POST", "/api/v1/diagnostics/traceroute", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	(&Server{}).tracerouteHandler(w, req)
	return w.Code >= 400
}
