package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// Codex PR #6743 r7-N2: the #3965 bulk policy-counter path was unreachable
// in production for TWO independent reasons, and BOTH had to be fixed:
//
//  1. NewPolicyCounterReader asserted the bulk interface on the raw handle,
//     but the daemon fills its consumers with the #2114 live indirection,
//     whose method set is exactly the mandatory management surface;
//  2. the bulk reader lived on *Manager only, and the daemon publishes the
//     ADAPTER, so even an unwrapped handle missed.
//
// Every one of the seven observability callers therefore took the
// O(P*(P+C)) per-policy fallback the bulk snapshot exists to replace — the
// same capability-erasure class as the missing Prometheus families, with a
// performance cliff instead of a missing metric as the symptom.

// liveIndirectionStub is the shape the daemon hands its consumers: a value
// whose OWN method set carries none of the optional capabilities, with the
// real backend reachable only through dataplane.Unwrap.
type liveIndirectionStub struct{ backend any }

func (s liveIndirectionStub) Unwrap() any { return s.backend }

var _ dataplane.LiveUnwrapper = liveIndirectionStub{}

// TestLegacyAdapterExposesBulkPolicyCounters pins reason 2.
//
// Fail-on-revert: delete LegacyDataPlaneAdapter.ReadAllPolicyCounters and
// this fails — the published backend stops offering the bulk snapshot at
// all, so no amount of unwrapping reaches it.
func TestLegacyAdapterExposesBulkPolicyCounters(t *testing.T) {
	var adapter any = NewLegacyDataPlaneAdapter(&Manager{})
	if _, ok := adapter.(interface {
		ReadAllPolicyCounters(*config.Config) (map[uint32]dataplane.CounterValue, error)
	}); !ok {
		t.Fatal("the PUBLISHED backend (*LegacyDataPlaneAdapter) does not expose " +
			"ReadAllPolicyCounters, so every observability caller silently falls back " +
			"to the O(P*(P+C)) per-policy read")
	}
}

// TestNewPolicyCounterReaderUnwrapsLiveIndirection pins reason 1.
//
// Fail-on-revert: drop the dataplane.Unwrap from NewPolicyCounterReader's
// probe and this fails — the reader returns the FALLBACK for a handle that
// resolves to a healthy bulk-capable backend, which is exactly what every
// production caller was getting.
func TestNewPolicyCounterReaderUnwrapsLiveIndirection(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.GlobalPolicies = []*config.Policy{{Name: "p0"}}

	mgr := &Manager{}
	mgr.lastStatus.PolicyRuleCounters = []PolicyRuleCounterStatus{{
		RuleID:  stablePolicyRuleID("junos-global", "junos-global", "p0"),
		Packets: 7,
		Bytes:   700,
	}}

	// Positive control: the backend really does publish the counter, so a
	// zero below means the probe missed, not that there was nothing to read.
	direct, err := mgr.ReadAllPolicyCounters(cfg)
	if err != nil {
		t.Fatalf("ReadAllPolicyCounters: %v", err)
	}
	if len(direct) == 0 {
		t.Fatal("fixture publishes no counters; the assertion below would be vacuous")
	}
	var id uint32
	for k := range direct {
		id = k
	}

	fallbackCalls := 0
	fallback := func(uint32) (dataplane.CounterValue, error) {
		fallbackCalls++
		return dataplane.CounterValue{}, nil
	}

	// The handle a consumer actually holds: the live indirection over the
	// published adapter.
	handle := liveIndirectionStub{backend: NewLegacyDataPlaneAdapter(mgr)}

	read := NewPolicyCounterReader(handle, cfg, fallback)
	got, err := read(id)
	if err != nil {
		t.Fatalf("read(%d): %v", id, err)
	}
	if fallbackCalls != 0 {
		t.Fatalf("the reader took the per-policy FALLBACK %d times for a handle that "+
			"resolves to a bulk-capable backend: the probe is not unwrapping the #2114 "+
			"live indirection", fallbackCalls)
	}
	if got.Packets != 7 || got.Bytes != 700 {
		t.Fatalf("bulk read = %+v, want the injected {7,700}", got)
	}

	// Negative control: once the daemon disowns the backend the indirection
	// resolves to nil, and the fallback IS the right answer.
	disowned := NewPolicyCounterReader(liveIndirectionStub{backend: nil}, cfg, fallback)
	if _, err := disowned(id); err != nil {
		t.Fatalf("disowned read: %v", err)
	}
	if fallbackCalls != 1 {
		t.Fatalf("disowned handle took the fallback %d times, want exactly 1", fallbackCalls)
	}
}
