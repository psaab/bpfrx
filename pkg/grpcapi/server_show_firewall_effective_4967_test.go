package grpcapi

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// newEffectiveFirewallServer builds a Server whose active config defines one
// inet firewall filter, for the #4967 effective-snapshot ShowText topics.
func newEffectiveFirewallServer(t *testing.T) *Server {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	for _, cmd := range []string{
		"firewall family inet filter f1 term t1 from destination-port 80",
		"firewall family inet filter f1 term t1 then accept",
	} {
		if err := store.SetFromInput(cmd); err != nil {
			t.Fatalf("SetFromInput(%q) error = %v", cmd, err)
		}
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	return &Server{store: store}
}

// TestShowTextFirewallEffectiveRendersCompiledSnapshot proves the #4967 server
// topics that the remote CLI now routes to actually render the compiled
// FirewallFilterSnapshot (the `[effective]` heading) rather than the raw
// config, for both the all-filters and single-filter forms. Without the server
// dispatch these topics would fall through to the default ShowText handler.
func TestShowTextFirewallEffectiveRendersCompiledSnapshot(t *testing.T) {
	s := newEffectiveFirewallServer(t)

	for _, topic := range []string{"firewall-effective", "firewall-effective:inet", "firewall-effective-filter:f1", "firewall-effective-filter:f1:inet"} {
		resp, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: topic})
		if err != nil {
			t.Fatalf("ShowText(%q) error = %v", topic, err)
		}
		out := resp.GetOutput()
		for _, want := range []string{"Filter: f1 (family inet) [effective]", "Term: t1", "then accept"} {
			if !strings.Contains(out, want) {
				t.Fatalf("ShowText(%q) output missing %q:\n%s", topic, want, out)
			}
		}
	}
}

// TestShowTextFirewallEffectiveNotFound covers the single-filter miss and the
// family-filtered empty set — the remote surface must render the same
// diagnostics the local CLI does, not silently empty output (#4967).
func TestShowTextFirewallEffectiveNotFound(t *testing.T) {
	s := newEffectiveFirewallServer(t)

	resp, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "firewall-effective-filter:nope"})
	if err != nil {
		t.Fatalf("ShowText error = %v", err)
	}
	if got := resp.GetOutput(); !strings.Contains(got, "Filter not found: nope") {
		t.Fatalf("missing not-found diagnostic: %q", got)
	}

	// f1 is inet-only; asking for inet6 must report the empty family set.
	resp, err = s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "firewall-effective:inet6"})
	if err != nil {
		t.Fatalf("ShowText error = %v", err)
	}
	if got := resp.GetOutput(); !strings.Contains(got, "No firewall filters configured (family inet6)") {
		t.Fatalf("missing empty-family diagnostic: %q", got)
	}
}
