package daemon

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/grpcapi"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #5275 PR2 — the facade must not NARROW the dynamic type below what consumers
// probe for.
//
// Every test here drives a REAL consumer through its REAL exported entry point
// with a REAL facade in the DP slot, and asserts on what the consumer PRODUCES.
// That distinction is the whole point: calling facade.AppliedNATView() directly
// proves only that the method exists. It does not prove that
// `s.dp.(appliedNATViewProvider)` at pkg/grpcapi/server_nat_deterministic.go:26
// succeeds, which is the thing that broke — and the two are different facts,
// because the probe asserts against the facade's DYNAMIC TYPE, not against a
// method someone can see in the source.
//
// pkg/daemon is the only package that can make these assertions. The probe
// interfaces are package-private to their consumers, and the facade is
// package-private here; pkg/daemon imports all three consumers, so it is the
// single point where a facade and a real consumer can meet. The surfaces
// exercised are gRPC's, because pkg/api's mux and pkg/cli's dispatcher are both
// package-private with no exported handler seam — noted in the report rather
// than papered over. gRPC carries all four of the lost capabilities.

// probeBindingBackend is a facadeBackend with controllable capability
// responses, plus counters that record WHICH iteration path a consumer chose.
type probeBindingBackend struct {
	*fakeFacadeBackend

	schedulerState map[string]bool
	natView        dpuserspace.AppliedNATView

	v4 []sessionRow
	v6 []sessionRowV6

	cursorCallsV4 int // IterateSessionsFrom   — the bounded O(N) path
	cursorCallsV6 int // IterateSessionsV6From
	rescanCallsV4 int // IterateSessions       — the O(N^2) fallback (#4719)
	rescanCallsV6 int // IterateSessionsV6
}

type sessionRow struct {
	key dataplane.SessionKey
	val dataplane.SessionValue
}

type sessionRowV6 struct {
	key dataplane.SessionKeyV6
	val dataplane.SessionValueV6
}

func (d *probeBindingBackend) PolicySchedulerActiveState() map[string]bool {
	return d.schedulerState
}

func (d *probeBindingBackend) AppliedNATView() dpuserspace.AppliedNATView { return d.natView }

func (d *probeBindingBackend) IterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	d.rescanCallsV4++
	for _, e := range d.v4 {
		if !fn(e.key, e.val) {
			return nil
		}
	}
	return nil
}

func (d *probeBindingBackend) IterateSessionsV6(fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	d.rescanCallsV6++
	for _, e := range d.v6 {
		if !fn(e.key, e.val) {
			return nil
		}
	}
	return nil
}

// IterateSessionsFrom resumes AFTER cursor, matching the dataplane Manager
// contract the real consumers rely on for stable paging.
func (d *probeBindingBackend) IterateSessionsFrom(cursor *dataplane.SessionKey, fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	d.cursorCallsV4++
	started := cursor == nil
	for _, e := range d.v4 {
		if !started {
			if e.key == *cursor {
				started = true
			}
			continue
		}
		if !fn(e.key, e.val) {
			return nil
		}
	}
	return nil
}

func (d *probeBindingBackend) IterateSessionsV6From(cursor *dataplane.SessionKeyV6, fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	d.cursorCallsV6++
	started := cursor == nil
	for _, e := range d.v6 {
		if !started {
			if e.key == *cursor {
				started = true
			}
			continue
		}
		if !fn(e.key, e.val) {
			return nil
		}
	}
	return nil
}

func newProbeBindingBackend() *probeBindingBackend {
	return &probeBindingBackend{fakeFacadeBackend: &fakeFacadeBackend{}}
}

// facadeOver wraps be and fails the test if the union rejects it — a nil facade
// here would make every assertion below vacuous for the wrong reason.
func facadeOver(t *testing.T, be facadeBackend) *dataplaneFacade {
	t.Helper()
	f := newDataplaneFacade(be)
	if f == nil {
		t.Fatal("precondition: the test backend does not satisfy facadeBackend, so no facade " +
			"was built and nothing below would be exercising the facade at all")
	}
	return f
}

// emptyConfigStore is a committed-but-minimal store for the surfaces that only
// need a non-nil Store to build their request filter.
func emptyConfigStore(t *testing.T) *configstore.Store {
	t.Helper()
	store, err := configstore.New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err != nil {
		t.Fatalf("configstore.New: %v", err)
	}
	return store
}

// schedulerConfigStore commits a config with one scheduler-bound policy and one
// plain policy, so the rendered output distinguishes "marked inactive" from
// "left alone".
func schedulerConfigStore(t *testing.T) *configstore.Store {
	t.Helper()
	store, err := configstore.New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err != nil {
		t.Fatalf("configstore.New: %v", err)
	}
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := store.LoadOverride(`
schedulers {
    scheduler workhours {
        daily;
    }
}
security {
    zones {
        security-zone trust;
        security-zone untrust;
    }
    policies {
        from-zone trust to-zone untrust {
            policy sched-off {
                match { source-address any; destination-address any; application any; }
                then { permit; }
                scheduler-name workhours;
            }
            policy plain-allow {
                match { source-address any; destination-address any; application any; }
                then { permit; }
            }
        }
    }
}
`); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	return store
}

// TestFacadeBindsPolicySchedulerStateAtTheRenderedDisplay is the sharpest of the
// four, because the probe's failure mode is FAIL-OPEN AT THE DISPLAY.
//
// pkg/grpcapi's policySchedulerActiveState() returns ok=false when the assertion
// fails, and policyDetailStateSuffix() renders NOTHING when ok is false — so a
// policy the dataplane is currently SKIPPING is reported to the operator with
// the same header as a live one. A test that asserted ok==true would pass even
// if the renderer then did the wrong thing with it, so this asserts the rendered
// STATE token instead.
func TestFacadeBindsPolicySchedulerStateAtTheRenderedDisplay(t *testing.T) {
	be := newProbeBindingBackend()
	be.schedulerState = map[string]bool{"workhours": false} // the dataplane is SKIPPING it

	srv := grpcapi.NewServer("", grpcapi.Config{
		Store: schedulerConfigStore(t),
		DP:    facadeOver(t, be),
	})

	resp, err := srv.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "policies-detail"})
	if err != nil {
		t.Fatalf("ShowText(policies-detail): %v", err)
	}
	out := resp.GetOutput()

	if !strings.Contains(out, "Policy: sched-off, action-type: Permit, State: inactive, Scheduler: workhours") {
		t.Fatalf("the policy-detail display does NOT report the scheduler-inactive policy as "+
			"inactive. The dataplane is skipping `sched-off`, but the operator is shown a header "+
			"indistinguishable from an active policy — the fail-open display #5275 PR2 introduced "+
			"by narrowing the facade below policySchedulerStateProvider.\nrendered:\n%s", out)
	}
}

// TestFacadeSchedulerStateLeavesUnscheduledPoliciesAlone is the OVER-REACH
// GUARD for the test above, and it lives in its own function on purpose: as a
// trailing assertion inside a t.Fatalf-ing test it would never execute in the
// case it is meant to constrain.
//
// It pins what the fold must NOT change. Restoring the scheduler-state probe
// widens what the display can say about SCHEDULER-BOUND policies and nothing
// else; a policy with no scheduler must keep its bit-identical header in the
// same render where a scheduled sibling is being marked inactive. The #3667
// Index column follows action-type directly, so matching
// "action-type: Permit, Index: " proves nothing was inserted between them.
//
// This stays GREEN with the probe present and with it reverted — which is what
// separates a guard from a restatement of the fix.
func TestFacadeSchedulerStateLeavesUnscheduledPoliciesAlone(t *testing.T) {
	be := newProbeBindingBackend()
	be.schedulerState = map[string]bool{"workhours": false}

	srv := grpcapi.NewServer("", grpcapi.Config{
		Store: schedulerConfigStore(t),
		DP:    facadeOver(t, be),
	})

	resp, err := srv.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "policies-detail"})
	if err != nil {
		t.Fatalf("ShowText(policies-detail): %v", err)
	}
	out := resp.GetOutput()

	if !strings.Contains(out, "Policy: plain-allow, action-type: Permit, Index: ") {
		t.Errorf("a policy with NO scheduler gained a State suffix — the change reached beyond "+
			"scheduler-bound policies:\n%s", out)
	}
	// The zone-pair header is not per-policy scheduler state and must be
	// untouched by anything this fold does.
	if !strings.Contains(out, "Policy: trust -> untrust, State: enabled") {
		t.Errorf("the zone-pair header changed — the fold reached outside the per-policy "+
			"State token:\n%s", out)
	}
}

// TestFacadeBindsPolicySchedulerStateActiveStaysEnabled is the polarity control
// for the test above. Without it, a "fix" that hardcoded the inactive suffix
// would satisfy the assertion that matters.
func TestFacadeBindsPolicySchedulerStateActiveStaysEnabled(t *testing.T) {
	be := newProbeBindingBackend()
	be.schedulerState = map[string]bool{"workhours": true} // the dataplane IS running it

	srv := grpcapi.NewServer("", grpcapi.Config{
		Store: schedulerConfigStore(t),
		DP:    facadeOver(t, be),
	})

	resp, err := srv.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "policies-detail"})
	if err != nil {
		t.Fatalf("ShowText(policies-detail): %v", err)
	}
	if out := resp.GetOutput(); strings.Contains(out, "State: inactive") {
		t.Fatalf("an ACTIVE scheduler-bound policy was rendered inactive — the display is not "+
			"reading live state, it is asserting a constant:\n%s", out)
	}
}

// TestFacadeBindsAppliedNATViewAtTheLookupResult binds the deterministic
// source-NAT probe (#5794) at pkg/grpcapi/server_nat_deterministic.go:26.
//
// A failed probe yields AppliedView{Available:false}, which the lookup turns
// into Found=false with a stable error code — the feature reports "unavailable"
// on a perfectly healthy dataplane. The assertion is on the RESOLVED MAPPING,
// not on the probe: the golden values come from the existing #5794 vectors, so a
// facade that satisfies the probe but returns a hollow view still fails.
func TestFacadeBindsAppliedNATViewAtTheLookupResult(t *testing.T) {
	pool := &config.NATPool{
		Name:      "cgn-pool",
		Addresses: []string{"203.0.113.1", "203.0.113.2", "203.0.113.3", "203.0.113.4"},
		PortLow:   1024,
		PortHigh:  65535,
		Deterministic: &config.DeterministicNATConfig{
			BlockSize:   512,
			HostAddress: "100.64.0.0/22",
		},
	}
	natCfg := &config.Config{}
	natCfg.Security.NAT.SourcePools = map[string]*config.NATPool{"cgn-pool": pool}

	be := newProbeBindingBackend()
	be.natView = dpuserspace.AppliedNATView{Config: natCfg, AppliedGeneration: 11, Available: true}

	srv := grpcapi.NewServer("", grpcapi.Config{Store: emptyConfigStore(t), DP: facadeOver(t, be)})

	resp, err := srv.GetNATDeterministic(context.Background(), &pb.GetNATDeterministicRequest{
		Direction:    pb.NATDeterministicDirection_NAT_DETERMINISTIC_DIRECTION_FORWARD,
		Pool:         "cgn-pool",
		InternalHost: "100.64.0.5",
	})
	if err != nil {
		t.Fatalf("GetNATDeterministic: %v", err)
	}
	if !resp.GetFound() {
		t.Fatalf("deterministic source-NAT lookup reports UNAVAILABLE through the facade "+
			"(error_code=%q detail=%q) while the dataplane has an applied view — the facade "+
			"narrowed the dynamic type below appliedNATViewProvider and #5794 is dead on this "+
			"surface", resp.GetErrorCode(), resp.GetErrorDetail())
	}
	if resp.GetExternalIp() != "203.0.113.1" || resp.GetPortLow() != 3584 ||
		resp.GetPortHigh() != 4095 || resp.GetAppliedGeneration() != 11 {
		t.Fatalf("lookup resolved through the facade but returned the wrong mapping: %+v", resp)
	}
}

// TestFacadeBindsSessionCursorAtThePageToken binds the cursor-iteration probe
// on the READ path (pkg/grpcapi/server_sessions.go:127). A failed probe silently
// drops to the legacy offset path, whose pages can skip or duplicate rows across
// map mutation. The observable is the emitted page token: only the cursor path
// produces one.
func TestFacadeBindsSessionCursorAtThePageToken(t *testing.T) {
	be := newProbeBindingBackend()
	for i, dport := range []uint16{80, 443, 8080} {
		be.v4 = append(be.v4, sessionRow{
			key: dataplane.SessionKey{
				SrcIP:    [4]byte{10, 0, 1, byte(5 + i)},
				DstIP:    [4]byte{10, 0, 2, 7},
				SrcPort:  htonsForTest(uint16(10000 + i)),
				DstPort:  htonsForTest(dport),
				Protocol: 6,
			},
			val: dataplane.SessionValue{State: dataplane.SessStateEstablished},
		})
	}

	srv := grpcapi.NewServer("", grpcapi.Config{Store: emptyConfigStore(t), DP: facadeOver(t, be)})

	resp, err := srv.GetSessions(context.Background(), &pb.GetSessionsRequest{PageSize: 2})
	if err != nil {
		t.Fatalf("GetSessions: %v", err)
	}
	if resp.GetNextPageToken() == "" {
		t.Fatalf("cursor paging returned NO page token over %d sessions with page_size=2 — the "+
			"probe for sessionCursorIterator failed and the request silently fell back to the "+
			"offset path, whose own doc says it can skip or duplicate rows across map mutation "+
			"(#3421 H4)", len(be.v4))
	}
	if be.cursorCallsV4 == 0 {
		t.Errorf("a page token was emitted but IterateSessionsFrom was never called — the token " +
			"is not coming from the cursor path")
	}
}

// TestFacadeBindsSessionCursorAtTheClearFallback binds the SAME probe on the
// path where the fallback is worst. pkg/grpcapi/server_sessions.go:1306-1315
// records why the cursor path exists: a per-chunk fresh re-scan is O(N^2) on a
// multi-million-entry table and "would trade the memory DoS for a CPU-stall DoS
// able to starve the HA watchdog (#4719)".
//
// The clear DELETES the same sessions either way, so the outcome cannot
// distinguish the paths. What distinguishes them is which iterator ran, so that
// is what this asserts — both families, because v4 and v6 probe independently
// (server_sessions.go:1317 and :1460).
func TestFacadeBindsSessionCursorAtTheClearFallback(t *testing.T) {
	be := newProbeBindingBackend()
	be.v4 = append(be.v4, sessionRow{
		key: dataplane.SessionKey{
			SrcIP: [4]byte{10, 0, 1, 5}, DstIP: [4]byte{10, 0, 2, 7},
			SrcPort: htonsForTest(10000), DstPort: htonsForTest(80), Protocol: 6,
		},
		val: dataplane.SessionValue{State: dataplane.SessStateEstablished},
	})
	be.v6 = append(be.v6, sessionRowV6{
		key: dataplane.SessionKeyV6{
			SrcIP: [16]byte{0x20, 0x01, 0x05, 0x59}, DstIP: [16]byte{0x20, 0x01, 0x05, 0x60},
			SrcPort: htonsForTest(20000), DstPort: htonsForTest(53), Protocol: 17,
		},
		val: dataplane.SessionValueV6{State: dataplane.SessStateEstablished},
	})

	srv := grpcapi.NewServer("", grpcapi.Config{Store: emptyConfigStore(t), DP: facadeOver(t, be)})

	// A filter (any filter) selects the filtered-clear path rather than
	// ClearAllSessions.
	if _, err := srv.ClearSessions(context.Background(), &pb.ClearSessionsRequest{
		Protocol: "tcp",
	}); err != nil {
		t.Fatalf("ClearSessions: %v", err)
	}

	if be.cursorCallsV4 == 0 || be.cursorCallsV6 == 0 {
		t.Fatalf("filtered clear did NOT use the cursor iterators (v4=%d v6=%d calls) — the "+
			"probe for sessionCursorIterator failed, so the clear fell back to the bounded "+
			"fresh-rescan that #4719 replaced precisely because it is an O(N^2) CPU-stall able "+
			"to starve the HA watchdog", be.cursorCallsV4, be.cursorCallsV6)
	}
	if be.rescanCallsV4 != 0 || be.rescanCallsV6 != 0 {
		t.Errorf("filtered clear ALSO ran the full-table rescan (v4=%d v6=%d) — the cursor path "+
			"is not replacing it", be.rescanCallsV4, be.rescanCallsV6)
	}
}

// htonsForTest converts a host-order port to the network order the session keys
// carry. Local to this file so it cannot collide with a package helper.
func htonsForTest(p uint16) uint16 { return p<<8 | p>>8 }
