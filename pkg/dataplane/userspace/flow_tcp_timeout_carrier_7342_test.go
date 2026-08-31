package userspace

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #7342: the claim the enforcement table rests on is now the opposite of
// #6539's — every `security flow tcp-session <kind>-timeout` leaf reaches the
// wire — and this test binds it where it is actually decided, in the lowering.
//
// It stays a PER-LEAF measurement rather than a whole-snapshot equality,
// because "all four differ from established-only" is also what a lowering that
// carried one field under three names would produce. Each leaf is set alone and
// must move the snapshot on its own, and the table must agree with what was
// measured — carrier and enforcement are equivalent by construction here, which
// is what makes "carry now, enforce later" impossible to land by accident.
func TestTCPSessionTimeoutsAllHaveWireCarriers_7342(t *testing.T) {
	marshal := func(ts *config.TCPSessionConfig) string {
		t.Helper()
		cfg := &config.Config{}
		cfg.Security.Flow.TCPSession = ts
		b, err := json.Marshal(buildFlowSnapshot(cfg))
		if err != nil {
			t.Fatalf("marshal flow snapshot: %v", err)
		}
		return string(b)
	}

	// The baseline every per-leaf case is compared against: a TCPSession with
	// nothing set. If this already carried something the cases below would
	// measure the wrong delta.
	base := marshal(&config.TCPSessionConfig{})

	cases := []struct {
		leaf string
		set  func(*config.TCPSessionConfig)
		// wireKey is the JSON name the leaf must appear under. Asserting the
		// NAME as well as the difference is what stops two leaves sharing one
		// carrier: without it, lowering both closing and time-wait into
		// `tcp_closing_timeout` would move the snapshot for each and pass.
		wireKey string
	}{
		{config.TCPSessionEstablishedTimeoutLeaf, func(c *config.TCPSessionConfig) { c.EstablishedTimeout = 600 }, "tcp_session_timeout"},
		{config.TCPSessionInitialTimeoutLeaf, func(c *config.TCPSessionConfig) { c.InitialTimeout = 45 }, "tcp_initial_timeout"},
		{config.TCPSessionClosingTimeoutLeaf, func(c *config.TCPSessionConfig) { c.ClosingTimeout = 15 }, "tcp_closing_timeout"},
		{config.TCPSessionTimeWaitTimeoutLeaf, func(c *config.TCPSessionConfig) { c.TimeWaitTimeout = 90 }, "tcp_time_wait_timeout"},
	}
	seen := map[string]string{}
	for _, tc := range cases {
		ts := &config.TCPSessionConfig{}
		tc.set(ts)
		got := marshal(ts)
		if got == base {
			t.Errorf("%s alone did not change the wire snapshot, so it has NO carrier — "+
				"the table marks it enforced and all three `show` surfaces render it "+
				"unannotated.\n got: %s\nbase: %s", tc.leaf, got, base)
			continue
		}
		if !strings.Contains(got, `"`+tc.wireKey+`":`) {
			t.Errorf("%s moved the snapshot but not under %q: %s", tc.leaf, tc.wireKey, got)
		}
		if prev, dup := seen[tc.wireKey]; dup {
			t.Errorf("%s and %s share the wire field %q", prev, tc.leaf, tc.wireKey)
		}
		seen[tc.wireKey] = tc.leaf
	}

	// The table must agree with what was just measured, in BOTH directions.
	for _, e := range config.TCPSessionTimeoutLeaves() {
		if !e.Enforced {
			t.Errorf("table marks %q unenforced, but #7342 gave every tcp-session timeout "+
				"a wire carrier and a live consumer", e.Leaf)
		}
	}
}

// A leaf left UNSET must not reach the wire at all, so a helper that predates
// #7342 (and a peer running one) sees the same snapshot it always did.
//
// This is the half that `omitempty` provides and that nothing else checks: the
// per-leaf cases above would all pass if every field were emitted as an
// explicit 0, which would still be a wire change for every existing config.
func TestUnsetTCPSessionTimeoutsStayOffTheWire_7342(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Flow.TCPSession = &config.TCPSessionConfig{EstablishedTimeout: 600}
	b, err := json.Marshal(buildFlowSnapshot(cfg))
	if err != nil {
		t.Fatalf("marshal flow snapshot: %v", err)
	}
	got := string(b)
	for _, key := range []string{"tcp_initial_timeout", "tcp_closing_timeout", "tcp_time_wait_timeout"} {
		if strings.Contains(got, `"`+key+`":`) {
			t.Errorf("unset leaf emitted %q on the wire; an existing config must produce a "+
				"byte-identical snapshot to pre-#7342: %s", key, got)
		}
	}
	// Liveness: the field that IS set must be present, or the absence above is
	// a marshalling failure rather than omitempty working.
	if !strings.Contains(got, `"tcp_session_timeout":600`) {
		t.Fatalf("established-timeout missing from the snapshot; the absences above are vacuous: %s", got)
	}
}
