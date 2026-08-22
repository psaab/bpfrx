// #7016: GetPolicies must not answer codes.Internal for the WHOLE inventory
// because one policy's counter has not been published by the helper yet, and
// the two text renderers must not report that window as a counter read FAILURE.
//
// Same mechanism as the REST sibling (pkg/api/security_policy_counter_
// unpublished_7016_test.go): #6743 activated the #3965 bulk reader, whose
// unpublished-per-rule signal is ErrPolicyCounterUnpublished, and every one of
// these surfaces folded it into readErr. GetPolicies discarded the response;
// the text surfaces printed "policy counter read failed" naming a fault that
// does not exist. The window is reachable before the first 1 Hz status poll
// lands (the shim is loaded, so IsLoaded() is already true) and under config
// skew after a non-abort-class apply failure (#5679).
//
// FAIL-ON-REVERT: restoring `} else if readErr == nil { readErr = err }` at any
// read site makes GetPolicies error again / the text surfaces warn again, and
// the assertions below go RED. A genuine snapshot failure must still fail loud
// — the controls below.
package grpcapi

import (
	"context"
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// warmupPolicyGRPCDP is LOADED with an EMPTY bulk snapshot — the measured
// warm-up state of the real userspace Manager (pinned in
// pkg/dataplane/userspace TestWarmUpBulkSnapshotIsEmptyAndReadsUnpublished).
type warmupPolicyGRPCDP struct {
	*dataplane.Manager
}

func (d *warmupPolicyGRPCDP) IsLoaded() bool { return true }

func (d *warmupPolicyGRPCDP) ReadAllPolicyCounters(*config.Config) (map[uint32]dataplane.CounterValue, error) {
	return map[uint32]dataplane.CounterValue{}, nil
}

func (d *warmupPolicyGRPCDP) ReadPolicyCounters(uint32) (dataplane.CounterValue, error) {
	panic("per-policy fallback must not run: the bulk probe resolves")
}

// bulkFailPolicyGRPCDP is LOADED and its bulk snapshot read genuinely FAILS.
type bulkFailPolicyGRPCDP struct {
	*dataplane.Manager
}

func (d *bulkFailPolicyGRPCDP) IsLoaded() bool { return true }

func (d *bulkFailPolicyGRPCDP) ReadAllPolicyCounters(*config.Config) (map[uint32]dataplane.CounterValue, error) {
	return nil, errors.New("counter bridge degraded")
}

func (d *bulkFailPolicyGRPCDP) ReadPolicyCounters(uint32) (dataplane.CounterValue, error) {
	panic("per-policy fallback must not run: the bulk probe resolves")
}

// newSchedulerCounterGRPCStore carries policy-stats system-wide, two zone-pair
// rules, a global rule, and (implicitly) the default-policy row, so all three
// read sites in GetPolicies are exercised.
func warmupPolicyGRPCServer(t *testing.T) *Server {
	t.Helper()
	store := newSchedulerCounterGRPCStore(t)
	if cfg := store.ActiveConfig(); cfg == nil || len(cfg.Security.GlobalPolicies) == 0 {
		t.Fatal("global policy precondition not met: the global read site would not be exercised")
	}
	return &Server{store: store, dp: &warmupPolicyGRPCDP{Manager: dataplane.New()}}
}

func TestGetPoliciesUnpublishedCounterIsNotAnRPCError(t *testing.T) {
	s := warmupPolicyGRPCServer(t)

	resp, err := s.GetPolicies(context.Background(), &pb.GetPoliciesRequest{})
	if err != nil {
		t.Fatalf("GetPolicies() error = %v; an unpublished per-rule counter is a no-data window, not an RPC failure (#7016)", err)
	}

	want := map[string]bool{
		"plain-allow":               false,
		"scheduled-allow":           false,
		"global-scheduled":          false,
		dataplane.DefaultPolicyName: false,
	}
	for _, pi := range resp.GetPolicies() {
		for _, rule := range pi.GetRules() {
			if _, tracked := want[rule.GetName()]; !tracked {
				continue
			}
			want[rule.GetName()] = true
			if !rule.GetHitCountersUnavailable() {
				t.Errorf("%s: hit_counters_unavailable = false, want true — the counter is unpublished, so 0/0 is not authoritative",
					rule.GetName())
			}
			if rule.GetHitPackets() != 0 || rule.GetHitBytes() != 0 {
				t.Errorf("%s: counters = %d/%d, want 0/0 alongside the unavailable flag",
					rule.GetName(), rule.GetHitPackets(), rule.GetHitBytes())
			}
		}
	}
	for name, seen := range want {
		if !seen {
			t.Errorf("%s missing from the GetPolicies response", name)
		}
	}
}

// CONTROL: a genuine bulk-snapshot read failure must still be codes.Internal.
func TestGetPoliciesStillFailsLoudOnGenuineReadError(t *testing.T) {
	s := &Server{store: newSchedulerCounterGRPCStore(t), dp: &bulkFailPolicyGRPCDP{Manager: dataplane.New()}}

	_, err := s.GetPolicies(context.Background(), &pb.GetPoliciesRequest{})
	if err == nil {
		t.Fatal("GetPolicies() returned nil error on a genuine counter-bridge failure; the #7016 relaxation must apply ONLY to the unpublished signal (#3408)")
	}
	if got := status.Code(err); got != codes.Internal {
		t.Fatalf("GetPolicies() code = %v, want codes.Internal", got)
	}
}

func TestShowPoliciesHitCountTextMarksUnpublishedRatherThanWarning(t *testing.T) {
	s := warmupPolicyGRPCServer(t)

	var buf strings.Builder
	s.showPoliciesHitCount("", &buf)
	out := buf.String()

	if strings.Contains(out, "policy counter read failed") {
		t.Errorf("hit-count text claims a counter READ FAILED for an unpublished counter; nothing failed (#7016). got:\n%s", out)
	}
	if !strings.Contains(out, "not yet published") {
		t.Errorf("hit-count text lacks the unpublished note; an operator cannot tell n/a from a real zero. got:\n%s", out)
	}
	if row := rowContaining(out, "scheduled-allow"); !strings.Contains(row, "n/a") {
		t.Errorf("scheduled-allow row = %q, want an n/a cell rather than an authoritative 0\nfull:\n%s", row, out)
	}
}

func TestShowPoliciesDetailTextMarksUnpublishedRatherThanWarning(t *testing.T) {
	s := warmupPolicyGRPCServer(t)

	var buf strings.Builder
	s.showPoliciesDetail("", &buf)
	out := buf.String()

	if strings.Contains(out, "policy counter read failed") {
		t.Errorf("detail text claims a counter READ FAILED for an unpublished counter; nothing failed (#7016). got:\n%s", out)
	}
	if !strings.Contains(out, "Session statistics: not available") {
		t.Errorf("detail text silently omits the Session statistics block, which reads identically to policy-stats being off. got:\n%s", out)
	}
}

// CONTROL: the text surfaces must still warn on a genuine read failure.
func TestShowPoliciesTextStillWarnsOnGenuineReadError(t *testing.T) {
	s := &Server{store: newSchedulerCounterGRPCStore(t), dp: &bulkFailPolicyGRPCDP{Manager: dataplane.New()}}

	var hit, detail strings.Builder
	s.showPoliciesHitCount("", &hit)
	s.showPoliciesDetail("", &detail)

	if !strings.Contains(hit.String(), "policy counter read failed") {
		t.Errorf("hit-count text lost its #3408 read-failure warning; got:\n%s", hit.String())
	}
	if !strings.Contains(detail.String(), "policy counter read failed") {
		t.Errorf("detail text lost its #3408 read-failure warning; got:\n%s", detail.String())
	}
}
