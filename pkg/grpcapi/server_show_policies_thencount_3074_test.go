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

// #3074: the per-policy Junos `then count` modifier must surface a
// policy's packet/byte counter independent of the system-wide
// `security policy-stats system-wide enable` knob. Before #3074 the
// modifier was parsed/stored but inert at every display surface. These
// tests assert the gRPC text `policies-hit-count` and `policies-detail`
// surfaces show a `then count` policy's live counts with the global knob
// OFF, while a sibling without `then count` stays at 0 (pre-#3074
// behavior). Reverting the `|| pol.Count` display gate -> RED.
func newThenCountGRPCStore(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	cmds := []string{
		"security zones security-zone trust",
		"security zones security-zone untrust",
		"security policies from-zone trust to-zone untrust policy counted-web match source-address any",
		"security policies from-zone trust to-zone untrust policy counted-web match destination-address any",
		"security policies from-zone trust to-zone untrust policy counted-web match application any",
		"security policies from-zone trust to-zone untrust policy counted-web then permit",
		"security policies from-zone trust to-zone untrust policy counted-web then count",
		"security policies from-zone trust to-zone untrust policy plain-web match source-address any",
		"security policies from-zone trust to-zone untrust policy plain-web match destination-address any",
		"security policies from-zone trust to-zone untrust policy plain-web match application any",
		"security policies from-zone trust to-zone untrust policy plain-web then permit",
	}
	for _, cmd := range cmds {
		if err := store.SetFromInput(cmd); err != nil {
			t.Fatalf("SetFromInput(%q) error = %v", cmd, err)
		}
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	if cfg := store.ActiveConfig(); cfg == nil || cfg.Security.PolicyStatsEnabled {
		t.Fatal("precondition: active config present + PolicyStatsEnabled OFF")
	}
	return store
}

// thenCountSlots resolves the rule-counter slot for each named policy.
func thenCountSlots(t *testing.T, store *configstore.Store) (counted, plain uint32) {
	t.Helper()
	cfg := store.ActiveConfig()
	for setID, zpp := range cfg.Security.Policies {
		for i, pol := range zpp.Policies {
			id := uint32(setID)*dataplane.MaxRulesPerPolicy + uint32(i)
			switch pol.Name {
			case "counted-web":
				counted = id
			case "plain-web":
				plain = id
			}
		}
	}
	return counted, plain
}

func TestShowPoliciesHitCountThenCountOverridesStatsKnob(t *testing.T) {
	store := newThenCountGRPCStore(t)
	counted, plain := thenCountSlots(t, store)
	s := &Server{
		store: store,
		dp: &schedulerCounterGRPCDP{
			Manager: dataplane.New(),
			counters: map[uint32]dataplane.CounterValue{
				counted: {Packets: 42, Bytes: 4242},
				plain:   {Packets: 99, Bytes: 9999},
			},
		},
	}

	resp, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "policies-hit-count"})
	if err != nil {
		t.Fatalf("ShowText(policies-hit-count) error = %v", err)
	}
	out := resp.GetOutput()
	countedRow, plainRow := lineWith(out, "counted-web"), lineWith(out, "plain-web")
	if countedRow == "" || plainRow == "" {
		t.Fatalf("policy rows not found:\n%s", out)
	}
	// `then count` policy surfaces its counts with the global knob OFF.
	if !strings.Contains(countedRow, "42") || !strings.Contains(countedRow, "4242") {
		t.Fatalf("counted-web (then count) missing live counts with stats OFF:\n%s", countedRow)
	}
	// Sibling without `then count` keeps the pre-#3074 zero behavior.
	if strings.Contains(plainRow, "99") || strings.Contains(plainRow, "9999") {
		t.Fatalf("plain-web (no then count) leaked live counts with stats OFF:\n%s", plainRow)
	}
}

func TestShowPoliciesDetailThenCountOverridesStatsKnob(t *testing.T) {
	store := newThenCountGRPCStore(t)
	counted, plain := thenCountSlots(t, store)
	s := &Server{
		store: store,
		dp: &schedulerCounterGRPCDP{
			Manager: dataplane.New(),
			counters: map[uint32]dataplane.CounterValue{
				counted: {Packets: 42, Bytes: 4242},
				plain:   {Packets: 99, Bytes: 9999},
			},
		},
	}
	resp, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "policies-detail"})
	if err != nil {
		t.Fatalf("ShowText(policies-detail) error = %v", err)
	}
	out := resp.GetOutput()
	// The `then count` policy's Session statistics block appears with the
	// global knob OFF; the plain policy's does not (only counted-web's
	// 42/4242 should be present).
	if !strings.Contains(out, "42 packets, 4242 bytes") {
		t.Fatalf("counted-web (then count) detail missing Session statistics with stats OFF:\n%s", out)
	}
	if strings.Contains(out, "99 packets, 9999 bytes") {
		t.Fatalf("plain-web (no then count) detail leaked Session statistics with stats OFF:\n%s", out)
	}
}

func lineWith(out, name string) string {
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, name) {
			return line
		}
	}
	return ""
}
