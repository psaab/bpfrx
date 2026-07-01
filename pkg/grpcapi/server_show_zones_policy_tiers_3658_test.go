package grpcapi

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #3658 (M04/M05): the gRPC-text `show security zones detail` policy summary
// (showZonesDetail) scanned only zone-pair policies and printed "(no policies)"
// for a zone with no zone-pair rule — hiding BOTH the applicable GLOBAL tier
// (M04) and the effective default-policy catch-all (M05). The summary now spans
// all three tiers in evaluation order (zone-pair -> global -> default-policy).
//
// This is the gRPC peer of the local-CLI fail-on-revert guard in
// pkg/cli/cli_show_security_zones_policy_tiers_3658_test.go.

func policyTierGRPCServer(t *testing.T) *Server {
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
        from-zone trust to-zone untrust {
            policy zone-allow {
                match { source-address any; destination-address any; application any; }
                then { permit; }
            }
        }
        global {
            policy scoped-block {
                match {
                    from-zone trust;
                    to-zone untrust;
                    source-address any;
                    destination-address any;
                    application any;
                }
                then { deny; }
            }
            policy open-global {
                match { source-address any; destination-address any; application any; }
                then { permit; }
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

// zoneDetailBlock isolates one "Security zone: <name>" block from the full
// zone-detail render so assertions do not cross-match another zone's lines.
func zoneDetailBlock(t *testing.T, out, zone string) string {
	t.Helper()
	marker := "Zone: " + zone + "\n"
	idx := strings.Index(out, marker)
	if idx < 0 {
		t.Fatalf("zone %q missing from zone-detail output:\n%s", zone, out)
	}
	rest := out[idx:]
	if end := strings.Index(rest[len(marker):], "\nZone: "); end >= 0 {
		rest = rest[:len(marker)+end]
	}
	return rest
}

// TestShowTextZonesDetailPolicyTiers3658 is the #3658 M04/M05 fail-on-revert
// guard for the gRPC-text zone-detail surface.
func TestShowTextZonesDetailPolicyTiers3658(t *testing.T) {
	s := policyTierGRPCServer(t)
	resp, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "zones-detail"})
	if err != nil {
		t.Fatalf("ShowText(zones-detail) error = %v", err)
	}
	out := resp.GetOutput()

	// dmz: no zone-pair, covered only by the unscoped global + default-policy.
	dmz := zoneDetailBlock(t, out, "dmz")
	if strings.Contains(dmz, "(no policies)") {
		t.Errorf("dmz still prints bare \"(no policies)\" (M05 not fixed):\n%s", dmz)
	}
	if !strings.Contains(dmz, "[global] any -> any: open-global (permit)") {
		t.Errorf("dmz missing unscoped global tier (M04 not fixed):\n%s", dmz)
	}
	if strings.Contains(dmz, "scoped-block") {
		t.Errorf("dmz leaked scoped trust->untrust global (applicability filter):\n%s", dmz)
	}
	if !strings.Contains(dmz, "[default] default-policy: deny") {
		t.Errorf("dmz missing effective default-policy line (M05 not fixed):\n%s", dmz)
	}

	// untrust: full precedence stack — zone-pair, scoped global, unscoped
	// global, default.
	untrust := zoneDetailBlock(t, out, "untrust")
	for _, want := range []string{
		"[zone-pair] trust -> untrust: zone-allow (permit)",
		"[global] trust -> untrust: scoped-block (deny)",
		"[global] any -> any: open-global (permit)",
		"[default] default-policy: deny",
	} {
		if !strings.Contains(untrust, want) {
			t.Errorf("untrust detail missing %q:\n%s", want, untrust)
		}
	}
}
