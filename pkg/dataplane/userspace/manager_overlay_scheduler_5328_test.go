package userspace

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// schedPolicyInactive5328 returns the Inactive bit of the named policy rule in
// a published snapshot, failing the test if the rule is absent.
func schedPolicyInactive5328(t *testing.T, policies []PolicyRuleSnapshot, name string) bool {
	t.Helper()
	for _, p := range policies {
		if p.Name == name {
			return p.Inactive
		}
	}
	t.Fatalf("policy %q not found in published snapshot (%d policies)", name, len(policies))
	return false
}

// TestPublishRouteOverlaySnapshotRefreshesSchedulerPolicyBits5328 pins the
// #5328 (A6-b2-F4) fix: a route-overlay publish that is handed a policy-
// scheduler active-state map MUST rebuild the published snapshot's policy
// inactive bits from that map in the SAME publish, not merely cache the map
// and inherit the last-compiled (stale) policy sections.
//
// The daemon's ip-monitoring actuator calls PublishRouteOverlaySnapshot with a
// live scheduler.ActiveState() (pkg/daemon/daemon_ipmon.go). Here the seeded
// lastSnapshot was compiled with the "workhours" scheduler ACTIVE, so its
// "scheduled-allow" permit is Inactive=false. We then publish a routes-only
// overlay carrying the CLOSED window (workhours:false). The published snapshot
// must show the permit as Inactive=true — otherwise the Rust helper keeps
// enforcing a permit whose schedule window already closed, while this publish
// reports success.
//
// FAIL-ON-REVERT: dropping the `if schedulerState != nil { ... rebuild ... }`
// block from PublishRouteOverlaySnapshot leaves next.Policies inherited from
// lastSnapshot (Inactive=false), so the captured published snapshot reports the
// permit ACTIVE and this test goes RED on the "Inactive=false" assertion.
func TestPublishRouteOverlaySnapshotRefreshesSchedulerPolicyBits5328(t *testing.T) {
	// A SHORT temp-dir prefix (not t.TempDir(), whose long sub-test name would
	// push the AF_UNIX path past the 108-byte sun_path limit under a long
	// TMPDIR / GOTMPDIR=/dev/shm — "bind: invalid argument"). Run with
	// TMPDIR=/tmp if the default TMPDIR is long.
	dir, err := os.MkdirTemp("", "x5328")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	controlSock := filepath.Join(dir, "control.sock")

	cfg := &config.Config{}
	cfg.Security.Policies = []*config.ZonePairPolicies{{
		FromZone: "trust",
		ToZone:   "untrust",
		Policies: []*config.Policy{{
			Name:          "scheduled-allow",
			SchedulerName: "workhours",
			Match: config.PolicyMatch{
				SourceAddresses:      []string{"any"},
				DestinationAddresses: []string{"any"},
				Applications:         []string{"any"},
			},
			Action: config.PolicyPermit,
		}},
	}}
	cfg.Schedulers = map[string]*config.SchedulerConfig{
		"workhours": {Name: "workhours"},
	}

	m := New()
	m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	m.cfg.ControlSocket = controlSock
	m.generation = 5
	m.lastStatus.ConfigSnapshotProtocolVersion = ProtocolVersion

	// Seed lastSnapshot compiled with the scheduler window OPEN so the
	// permit is ACTIVE (Inactive=false). Reuse the SAME cfg pointer so the
	// #5680 route-only-hybrid guard's pointer fast path admits the publish.
	m.lastSnapshot, err = buildSnapshotWithSchedulerState(
		cfg, config.UserspaceConfig{ControlSocket: controlSock}, 5, 0,
		map[string]bool{"workhours": true}, nil, nil)
	if err != nil {
		t.Fatalf("build lastSnapshot: %v", err)
	}
	if schedPolicyInactive5328(t, m.lastSnapshot.Policies, "scheduled-allow") {
		t.Fatal("precondition: seeded lastSnapshot permit must be ACTIVE (Inactive=false)")
	}

	reqs := startArmControlServer(t, controlSock, 1)

	// Window CLOSED: publish a routes-only overlay carrying workhours:false.
	published, err := m.PublishRouteOverlaySnapshot(cfg, nil, map[string]bool{"workhours": false})
	if err != nil {
		t.Fatalf("PublishRouteOverlaySnapshot returned error: %v", err)
	}
	if !published {
		t.Fatal("expected a real publish (policy inactive bit changed), got duplicate-skip")
	}

	req := <-reqs
	if req.Snapshot == nil {
		t.Fatal("captured control request carried no snapshot")
	}
	if !schedPolicyInactive5328(t, req.Snapshot.Policies, "scheduled-allow") {
		t.Fatal("published snapshot reports the scheduled permit ACTIVE (Inactive=false): " +
			"the route-overlay publish did NOT refresh policy scheduler bits from schedulerState " +
			"(#5328 A6-b2-F4) — the helper would enforce a permit whose window already closed")
	}
}

// TestPublishRouteOverlaySnapshotSchedulerFlipDefeatsDuplicateSkip5328 pins the
// ORDERING half of the #5328 (A6-b2-F4) fix: the scheduler-state policy rebuild
// runs BEFORE the duplicate-publish content-hash skip, so a scheduler-only bit
// flip on UNCHANGED routes still publishes rather than being falsely deduped as
// "content unchanged".
//
// The seeded lastSnapshotHash equals the seeded snapshot's content hash and the
// overlay carries NO route change (nil), so the ONLY forwarding-content delta in
// this publish is the policy inactive bit. If the rebuild were placed AFTER the
// dedup check (line "Duplicate-publish skip" in manager_overlay.go), the
// routes-and-policies-still-unchanged snapshot would hash-match m.lastSnapshotHash
// and be skipped (published=false) — the helper would keep enforcing the stale
// OPEN-window permit while this publish silently reported nothing to do.
//
// FAIL-ON-REVERT / FAIL-ON-REORDER: neutralizing the rebuild block (or moving it
// below the content-hash skip) makes the publish hash-match the seed and return
// published=false, so the "expected a real publish" assertion goes RED.
func TestPublishRouteOverlaySnapshotSchedulerFlipDefeatsDuplicateSkip5328(t *testing.T) {
	dir, err := os.MkdirTemp("", "x5328o")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	controlSock := filepath.Join(dir, "control.sock")

	cfg := &config.Config{}
	cfg.Security.Policies = []*config.ZonePairPolicies{{
		FromZone: "trust",
		ToZone:   "untrust",
		Policies: []*config.Policy{{
			Name:          "scheduled-allow",
			SchedulerName: "workhours",
			Match: config.PolicyMatch{
				SourceAddresses:      []string{"any"},
				DestinationAddresses: []string{"any"},
				Applications:         []string{"any"},
			},
			Action: config.PolicyPermit,
		}},
	}}
	cfg.Schedulers = map[string]*config.SchedulerConfig{
		"workhours": {Name: "workhours"},
	}

	m := New()
	m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	m.cfg.ControlSocket = controlSock
	m.generation = 5
	m.lastStatus.ConfigSnapshotProtocolVersion = ProtocolVersion

	// Seed lastSnapshot compiled with the window OPEN (permit ACTIVE).
	m.lastSnapshot, err = buildSnapshotWithSchedulerState(
		cfg, config.UserspaceConfig{ControlSocket: controlSock}, 5, 0,
		map[string]bool{"workhours": true}, nil, nil)
	if err != nil {
		t.Fatalf("build lastSnapshot: %v", err)
	}
	// Seed the dedup baseline to the seeded snapshot's content hash so an
	// unchanged-content publish WOULD be skipped — the discriminator that
	// forces the rebuild to run before the dedup check.
	h, ok := snapshotContentHash(m.lastSnapshot)
	if !ok {
		t.Fatal("seed snapshot content hash failed")
	}
	m.lastSnapshotHash = h

	reqs := startArmControlServer(t, controlSock, 1)

	// Window CLOSED, routes UNCHANGED (nil overlay): the only content delta
	// is the scheduled permit's inactive bit.
	published, err := m.PublishRouteOverlaySnapshot(cfg, nil, map[string]bool{"workhours": false})
	if err != nil {
		t.Fatalf("PublishRouteOverlaySnapshot returned error: %v", err)
	}
	if !published {
		t.Fatal("scheduler-only inactive-bit flip on unchanged routes was deduped away " +
			"(published=false): the schedulerState policy rebuild must run BEFORE the " +
			"duplicate-publish content-hash skip (#5328 A6-b2-F4) — otherwise the helper " +
			"keeps enforcing the stale open-window permit")
	}

	req := <-reqs
	if req.Snapshot == nil {
		t.Fatal("captured control request carried no snapshot")
	}
	if !schedPolicyInactive5328(t, req.Snapshot.Policies, "scheduled-allow") {
		t.Fatal("published snapshot still reports the scheduled permit ACTIVE (Inactive=false) " +
			"after a closed-window scheduler flip (#5328 A6-b2-F4)")
	}
}
