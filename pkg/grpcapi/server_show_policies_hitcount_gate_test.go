package grpcapi

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #2118: `show security policies hit-count` (and the structured /
// Prometheus surfaces) must honor `security policy-stats system-wide
// enable`. #2008 M4 gated only the Prometheus collector; the gRPC text +
// CLI + structured paths read counters unconditionally, so the four
// surfaces disagreed. These tests assert the gRPC text `hit-count` and
// `detail` tables show live counts when the knob is on and 0 when off,
// for the SAME populated dataplane.

// newHitCountGateStore builds a single permit policy with a known
// per-rule counter slot. `statsEnabled` toggles the policy-stats knob.
func newHitCountGateStore(t *testing.T, statsEnabled bool) *configstore.Store {
	t.Helper()

	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	cmds := []string{
		"security zones security-zone trust",
		"security zones security-zone untrust",
		"security policies from-zone trust to-zone untrust policy allow-web match source-address any",
		"security policies from-zone trust to-zone untrust policy allow-web match destination-address any",
		"security policies from-zone trust to-zone untrust policy allow-web match application any",
		"security policies from-zone trust to-zone untrust policy allow-web then permit",
	}
	if statsEnabled {
		cmds = append(cmds, "security policy-stats system-wide enable")
	}
	for _, cmd := range cmds {
		if err := store.SetFromInput(cmd); err != nil {
			t.Fatalf("SetFromInput(%q) error = %v", cmd, err)
		}
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	cfg := store.ActiveConfig()
	if cfg == nil {
		t.Fatal("ActiveConfig() = nil")
	}
	if cfg.Security.PolicyStatsEnabled != statsEnabled {
		t.Fatalf("PolicyStatsEnabled = %v, want %v", cfg.Security.PolicyStatsEnabled, statsEnabled)
	}
	return store
}

// allowWebPolicyID resolves the dataplane counter slot for the single
// trust->untrust allow-web rule so the fake dataplane can serve it.
func allowWebPolicyID(t *testing.T, store *configstore.Store) uint32 {
	t.Helper()
	cfg := store.ActiveConfig()
	for setID, zpp := range cfg.Security.Policies {
		for ruleIndex, pol := range zpp.Policies {
			if pol.Name == "allow-web" {
				return uint32(setID)*dataplane.MaxRulesPerPolicy + uint32(ruleIndex)
			}
		}
	}
	t.Fatal("allow-web policy not found")
	return 0
}

func TestShowPoliciesHitCountHonorsPolicyStats(t *testing.T) {
	for _, tc := range []struct {
		name        string
		statsOn     bool
		wantPackets string // substring that must / must-not appear
	}{
		{name: "enabled", statsOn: true, wantPackets: "42"},
		{name: "disabled", statsOn: false, wantPackets: "0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := newHitCountGateStore(t, tc.statsOn)
			ruleID := allowWebPolicyID(t, store)
			s := &Server{
				store: store,
				dp: &schedulerCounterGRPCDP{
					Manager: dataplane.New(),
					counters: map[uint32]dataplane.CounterValue{
						ruleID: {Packets: 42, Bytes: 4242},
					},
				},
			}

			resp, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "policies-hit-count"})
			if err != nil {
				t.Fatalf("ShowText(policies-hit-count) error = %v", err)
			}
			out := resp.GetOutput()

			// Locate the allow-web data row.
			var row string
			for _, line := range strings.Split(out, "\n") {
				if strings.Contains(line, "allow-web") {
					row = line
					break
				}
			}
			if row == "" {
				t.Fatalf("allow-web row not found in output:\n%s", out)
			}
			if tc.statsOn {
				if !strings.Contains(row, "42") || !strings.Contains(row, "4242") {
					t.Fatalf("policy-stats ON: allow-web row missing live counts (want 42/4242):\n%s", row)
				}
			} else {
				if strings.Contains(row, "42") || strings.Contains(row, "4242") {
					t.Fatalf("policy-stats OFF: allow-web row leaked live counts (must be 0):\n%s", row)
				}
				// The Packets/Bytes columns must read 0.
				fields := strings.Fields(row)
				if len(fields) < 2 {
					t.Fatalf("malformed row: %q", row)
				}
				if fields[len(fields)-1] != "0" || fields[len(fields)-2] != "0" {
					t.Fatalf("policy-stats OFF: trailing Packets/Bytes columns must be 0/0:\n%s", row)
				}
			}
		})
	}
}

func TestShowPoliciesDetailHonorsPolicyStats(t *testing.T) {
	// policy-stats OFF: the "Session statistics" block (per-policy hit
	// count) must be suppressed even though the dataplane has counts.
	store := newHitCountGateStore(t, false)
	ruleID := allowWebPolicyID(t, store)
	s := &Server{
		store: store,
		dp: &schedulerCounterGRPCDP{
			Manager: dataplane.New(),
			counters: map[uint32]dataplane.CounterValue{
				ruleID: {Packets: 42, Bytes: 4242},
			},
		},
	}

	resp, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "policies-detail"})
	if err != nil {
		t.Fatalf("ShowText(policies-detail) error = %v", err)
	}
	if strings.Contains(resp.GetOutput(), "Session statistics") {
		t.Fatalf("policy-stats OFF: detail leaked Session statistics block:\n%s", resp.GetOutput())
	}

	// policy-stats ON: the block appears with the live counts.
	store = newHitCountGateStore(t, true)
	ruleID = allowWebPolicyID(t, store)
	s = &Server{
		store: store,
		dp: &schedulerCounterGRPCDP{
			Manager: dataplane.New(),
			counters: map[uint32]dataplane.CounterValue{
				ruleID: {Packets: 42, Bytes: 4242},
			},
		},
	}
	resp, err = s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "policies-detail"})
	if err != nil {
		t.Fatalf("ShowText(policies-detail) error = %v", err)
	}
	if !strings.Contains(resp.GetOutput(), "Session statistics") ||
		!strings.Contains(resp.GetOutput(), "42 packets, 4242 bytes") {
		t.Fatalf("policy-stats ON: detail missing Session statistics with live counts:\n%s", resp.GetOutput())
	}
}
