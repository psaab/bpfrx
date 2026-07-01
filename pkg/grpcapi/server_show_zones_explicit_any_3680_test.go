package grpcapi

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #3680 (gRPC-text peer of the local-CLI guard): the zone-detail policy summary
// used config.GlobalPolicyAppliesToZone, which recognised only the empty
// (omitted) global scope as the all-zones wildcard — not the EXPLICIT Junos
// token "any". A global written `match from-zone any` / `match to-zone any` was
// therefore hidden from every affected zone's `show security zones detail`.
//
// Fail-on-revert: revert config.IsWildcardZone (or its GlobalPolicyAppliesToZone
// callers) to the "" -only test and the explicit-any assertions go RED.

func explicitAnyGlobalGRPCServer(t *testing.T) *Server {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
security {
    zones {
        security-zone trust;
        security-zone untrust;
        security-zone dmz;
    }
    policies {
        global {
            policy any-to-untrust {
                match {
                    from-zone any;
                    to-zone untrust;
                    source-address any;
                    destination-address any;
                    application any;
                }
                then { deny; }
            }
            policy trust-to-any {
                match {
                    from-zone trust;
                    to-zone any;
                    source-address any;
                    destination-address any;
                    application any;
                }
                then { deny; }
            }
            policy scoped-td {
                match {
                    from-zone trust;
                    to-zone dmz;
                    source-address any;
                    destination-address any;
                    application any;
                }
                then { deny; }
            }
        }
        default-policy deny-all;
    }
}
`); err != nil {
		t.Fatalf("LoadOverride() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	return &Server{store: store}
}

func TestShowTextZoneDetailExplicitAnyGlobal3680(t *testing.T) {
	s := explicitAnyGlobalGRPCServer(t)
	resp, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "zones-detail"})
	if err != nil {
		t.Fatalf("ShowText(zones-detail) error = %v", err)
	}
	out := resp.GetOutput()

	// dmz has no zone-pair rule; both explicit-any globals must still surface.
	dmz := zoneDetailBlock(t, out, "dmz")
	if !strings.Contains(dmz, "[global] any -> untrust: any-to-untrust (deny)") {
		t.Errorf("dmz detail missing explicit from-zone-any global (hidden — #3680):\n%s", dmz)
	}
	if !strings.Contains(dmz, "[global] trust -> any: trust-to-any (deny)") {
		t.Errorf("dmz detail missing explicit to-zone-any global (hidden — #3680):\n%s", dmz)
	}
	if !strings.Contains(dmz, "[global] trust -> dmz: scoped-td (deny)") {
		t.Errorf("dmz detail missing scoped trust->dmz global:\n%s", dmz)
	}
	if strings.Contains(dmz, "(no policies)") {
		t.Errorf("dmz detail still prints bare \"(no policies)\":\n%s", dmz)
	}

	// untrust: destination of both explicit-any globals; the scoped trust->dmz
	// global must NOT over-include here.
	untrust := zoneDetailBlock(t, out, "untrust")
	if !strings.Contains(untrust, "[global] any -> untrust: any-to-untrust (deny)") {
		t.Errorf("untrust detail missing explicit from-zone-any global:\n%s", untrust)
	}
	if !strings.Contains(untrust, "[global] trust -> any: trust-to-any (deny)") {
		t.Errorf("untrust detail missing explicit to-zone-any global:\n%s", untrust)
	}
	if strings.Contains(untrust, "scoped-td") {
		t.Errorf("untrust detail over-included scoped trust->dmz global:\n%s", untrust)
	}
}
