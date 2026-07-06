package grpcapi

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// TestNoDirectPerPolicyReadInShowSurfaces is the #4344 L08 static canary for the
// gRPC policy display surfaces: they must NOT call dp.ReadPolicyCounters
// directly in a per-rule loop — every read goes through the #3965 bulk reader
// (dpuserspace.NewPolicyCounterReader). The permitted mention is the fallback
// method value passed to NewPolicyCounterReader (`s.dp.ReadPolicyCounters`, no
// trailing `(`), so a direct `.ReadPolicyCounters(` CALL fails the test.
func TestNoDirectPerPolicyReadInShowSurfaces(t *testing.T) {
	for _, f := range []string{"server_show_policies_text.go", "server_show_zones.go"} {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		if n := strings.Count(string(src), ".ReadPolicyCounters("); n != 0 {
			t.Errorf("%s makes %d direct .ReadPolicyCounters( call(s); policy display surfaces must read via dpuserspace.NewPolicyCounterReader (#4344)", f, n)
		}
	}
}

// #4344: the gRPC policy-counter display surfaces — structured GetPolicies, the
// `show security policies hit-count` text renderer, and the `... detail` text
// renderer — must read the whole policy set through the #3965 bulk reader
// (dpuserspace.NewPolicyCounterReader -> ReadAllPolicyCounters), NOT a
// per-policy ReadPolicyCounters loop.
//
// bulkReaderGRPCDP implements BOTH paths: the bulk map holds the authoritative
// values, the per-policy fallback returns a distinct poison value and records
// that it was called. A migrated surface renders the bulk value and leaves
// perPolicyCalls == 0.
type bulkReaderGRPCDP struct {
	*dataplane.Manager
	bulk           map[uint32]dataplane.CounterValue
	perPolicyVal   dataplane.CounterValue
	perPolicyCalls *int
}

func (d *bulkReaderGRPCDP) IsLoaded() bool { return true }

func (d *bulkReaderGRPCDP) ReadPolicyCounters(uint32) (dataplane.CounterValue, error) {
	*d.perPolicyCalls++
	return d.perPolicyVal, nil
}

func (d *bulkReaderGRPCDP) ReadAllPolicyCounters(*config.Config) (map[uint32]dataplane.CounterValue, error) {
	return d.bulk, nil
}

// fullPolicyBulk fills a bulk counter map for EVERY policy handle in cfg
// (zone-pair rules, global rules, default-policy sentinel), computing each
// handle the same way ReadAllPolicyCounters and the display surfaces do so no
// read signals "unpublished" (GetPolicies fails closed on an unpublished
// counter with policy-stats on). The scheduled-allow handle gets a distinctive
// value the canary asserts.
func fullPolicyBulk(cfg *config.Config, scheduledID uint32) map[uint32]dataplane.CounterValue {
	bulk := map[uint32]dataplane.CounterValue{}
	var setID uint32
	for _, zpp := range cfg.Security.Policies {
		if zpp == nil {
			setID++
			continue
		}
		for i, rule := range zpp.Policies {
			if rule == nil {
				continue
			}
			bulk[setID*dataplane.MaxRulesPerPolicy+uint32(i)] = dataplane.CounterValue{Packets: 1, Bytes: 10}
		}
		setID++
	}
	for i, rule := range cfg.Security.GlobalPolicies {
		if rule == nil {
			continue
		}
		bulk[setID*dataplane.MaxRulesPerPolicy+uint32(i)] = dataplane.CounterValue{Packets: 1, Bytes: 10}
	}
	bulk[dataplane.DefaultPolicySentinelID] = dataplane.CounterValue{Packets: 5, Bytes: 50}
	bulk[scheduledID] = dataplane.CounterValue{Packets: 23, Bytes: 2300}
	return bulk
}

func newBulkReaderGRPCServer(t *testing.T) (*Server, uint32, *int) {
	t.Helper()
	store := newSchedulerCounterGRPCStore(t)
	policyID := scheduledCounterGRPCPolicyID(t, store)
	calls := 0
	s := &Server{
		store: store,
		dp: &bulkReaderGRPCDP{
			Manager:        dataplane.New(),
			bulk:           fullPolicyBulk(store.ActiveConfig(), policyID),
			perPolicyVal:   dataplane.CounterValue{Packets: 7, Bytes: 700},
			perPolicyCalls: &calls,
		},
	}
	return s, policyID, &calls
}

func TestGetPoliciesUsesBulkReader(t *testing.T) {
	s, _, calls := newBulkReaderGRPCServer(t)

	resp, err := s.GetPolicies(context.Background(), &pb.GetPoliciesRequest{})
	if err != nil {
		t.Fatalf("GetPolicies() error = %v", err)
	}
	var found bool
	for _, policy := range resp.GetPolicies() {
		for _, rule := range policy.GetRules() {
			if rule.GetName() != "scheduled-allow" {
				continue
			}
			found = true
			if rule.GetHitPackets() != 23 || rule.GetHitBytes() != 2300 {
				t.Fatalf("scheduled-allow counters = %d/%d, want the bulk value 23/2300 (not the per-policy poison 7/700)",
					rule.GetHitPackets(), rule.GetHitBytes())
			}
		}
	}
	if !found {
		t.Fatal("scheduled-allow rule not found in GetPolicies response")
	}
	if *calls != 0 {
		t.Fatalf("per-policy ReadPolicyCounters called %d times; want 0 (GetPolicies must read the bulk snapshot)", *calls)
	}
}

func TestShowPoliciesHitCountTextUsesBulkReader(t *testing.T) {
	s, _, calls := newBulkReaderGRPCServer(t)

	var buf strings.Builder
	s.showPoliciesHitCount("", &buf)
	out := buf.String()

	if row := rowContaining(out, "scheduled-allow"); !strings.Contains(row, "23") {
		t.Fatalf("scheduled-allow hit-count row = %q, want the bulk value 23\nfull:\n%s", row, out)
	}
	if *calls != 0 {
		t.Fatalf("per-policy ReadPolicyCounters called %d times; want 0 (text hit-count must read the bulk snapshot)", *calls)
	}
}

func TestShowPoliciesDetailTextUsesBulkReader(t *testing.T) {
	s, _, calls := newBulkReaderGRPCServer(t)

	var buf strings.Builder
	s.showPoliciesDetail("", &buf)
	out := buf.String()

	// The Session statistics block for scheduled-allow must show the bulk value.
	if !strings.Contains(out, "23 packets, 2300 bytes") {
		t.Fatalf("detail Session statistics missing the bulk value 23 packets, 2300 bytes\nfull:\n%s", out)
	}
	if *calls != 0 {
		t.Fatalf("per-policy ReadPolicyCounters called %d times; want 0 (text detail must read the bulk snapshot)", *calls)
	}
}

func rowContaining(out, needle string) string {
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, needle) {
			return line
		}
	}
	return ""
}
