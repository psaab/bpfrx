package userspace

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// stubRuleListHermetic makes buildRouteSnapshots hermetic by stubbing the
// netlink ip-rule enumerator (routes.go ruleListFn), which otherwise calls the
// real netlink.RuleList and fails "operation not permitted" in a restricted
// sandbox (both the seed full build and the route-overlay republish enumerate
// ip-rules). Restored on test cleanup.
func stubRuleListHermetic(t *testing.T) {
	t.Helper()
	orig := ruleListFn
	t.Cleanup(func() { ruleListFn = orig })
	ruleListFn = func(int) ([]netlink.Rule, error) { return nil, nil }
}

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

// schedPolicyPresent5328 reports whether the named policy rule is present in a
// published snapshot (unlike schedPolicyInactive5328 it does not fail on
// absence), so a test can assert a rule was dropped.
func schedPolicyPresent5328(policies []PolicyRuleSnapshot, name string) bool {
	for _, p := range policies {
		if p.Name == name {
			return true
		}
	}
	return false
}

// collidingSchedCfg5328 builds a config whose zone-name set carries a verified
// StableZoneID collision (z174/z214, later-sorting z214 quarantined) plus a
// non-colliding survivor zone "trust", with two scheduled zone-pair permits: one
// survivor (trust->z174) and one whose to-zone is the quarantined z214. A FULL
// build quarantines z214 and DROPS the trust->z214 permit; a partial republish
// that rebuilds policies from this cfg WITHOUT re-applying the quarantine would
// reintroduce the trust->z214 permit as a dangling reference (#6480).
func collidingSchedCfg5328(t *testing.T) *config.Config {
	t.Helper()
	if config.StableZoneID("z174") != config.StableZoneID("z214") {
		t.Fatalf("test premise broken: z174/z214 no longer collide under the frozen fold")
	}
	mkPol := func(name string) *config.Policy {
		return &config.Policy{
			Name:          name,
			SchedulerName: "workhours",
			Match: config.PolicyMatch{
				SourceAddresses:      []string{"any"},
				DestinationAddresses: []string{"any"},
				Applications:         []string{"any"},
			},
			Action: config.PolicyPermit,
		}
	}
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust"},
		"z174":  {Name: "z174"},
		"z214":  {Name: "z214"},
	}
	cfg.Security.Policies = []*config.ZonePairPolicies{
		{FromZone: "trust", ToZone: "z174", Policies: []*config.Policy{mkPol("survivor-allow")}},
		{FromZone: "trust", ToZone: "z214", Policies: []*config.Policy{mkPol("dangling-allow")}},
	}
	cfg.Schedulers = map[string]*config.SchedulerConfig{"workhours": {Name: "workhours"}}
	return cfg
}

// assertNoDanglingZoneRef5328 fails if any policy in the snapshot references a
// security zone absent from the snapshot's own Zones — the exact condition the
// Rust UnresolvableZoneReference preflight rejects the whole snapshot on (#6480).
// "" and "junos-global" are structural sentinels, not zone references. It also
// asserts Summary.PolicyCount == len(Policies), the bookkeeping invariant the
// full build maintains after quarantine.
func assertNoDanglingZoneRef5328(t *testing.T, snap *ConfigSnapshot) {
	t.Helper()
	published := map[string]bool{}
	for _, z := range snap.Zones {
		published[z.Name] = true
	}
	for _, p := range snap.Policies {
		slots := append([]string{p.FromZone, p.ToZone, p.MatchFromZone, p.MatchToZone},
			append(append([]string{}, p.MatchFromZones...), p.MatchToZones...)...)
		for _, z := range slots {
			if z == "" || z == "junos-global" {
				continue
			}
			if !published[z] {
				t.Fatalf("published policy %q references zone %q absent from snapshot Zones "+
					"(%d policies, %d zones) — the Rust UnresolvableZoneReference preflight "+
					"would reject the WHOLE snapshot (#6480)", p.Name, z, len(snap.Policies), len(snap.Zones))
			}
		}
	}
	if snap.Summary.PolicyCount != len(snap.Policies) {
		t.Fatalf("Summary.PolicyCount = %d, want %d (== len(Policies)) (#6480)",
			snap.Summary.PolicyCount, len(snap.Policies))
	}
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
	stubRuleListHermetic(t)
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
	stubRuleListHermetic(t)
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

// TestPublishRouteOverlaySnapshotReappliesZoneQuarantine6480 pins the #6480
// hostile-review MAJOR: the route-overlay publish rebuilds next.Policies from raw
// cfg under the scheduler map but inherits the already-reduced next.Zones (the
// full build quarantined the later-sorting colliding zone). Without re-applying
// the StableZoneID quarantine the rebuild reintroduces the trust->z214 permit,
// which references the quarantined zone z214 absent from next.Zones — a dangling
// reference the Rust UnresolvableZoneReference preflight rejects wholesale. On the
// supported ip-monitoring path FRR is updated BEFORE this publish
// (daemon_ipmon.go), so the reject strands the kernel/FRR on new routes while
// userspace keeps the old FIB, unable to converge.
//
// FAIL-ON-REVERT: dropping the scrubPoliciesForQuarantinedZones re-application
// from rebuildScheduledPolicySectionsLocked leaves the trust->z214 permit in the
// published snapshot, so assertNoDanglingZoneRef5328 goes RED (clean assertion).
func TestPublishRouteOverlaySnapshotReappliesZoneQuarantine6480(t *testing.T) {
	stubRuleListHermetic(t)
	dir, err := os.MkdirTemp("", "x6480")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	controlSock := filepath.Join(dir, "control.sock")

	cfg := collidingSchedCfg5328(t)

	m := New()
	m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	m.cfg.ControlSocket = controlSock
	m.generation = 5
	m.lastStatus.ConfigSnapshotProtocolVersion = ProtocolVersion

	// Seed lastSnapshot via the FULL build with the scheduler ACTIVE: the full
	// build quarantines z214 and drops the trust->z214 permit, so the seed carries
	// the reduced Zones {trust, z174} and only the survivor permit. Reuse the SAME
	// cfg pointer so the #5680 route-only-hybrid guard's pointer fast path admits
	// the publish.
	m.lastSnapshot, err = buildSnapshotWithSchedulerState(
		cfg, config.UserspaceConfig{ControlSocket: controlSock}, 5, 0,
		map[string]bool{"workhours": true}, nil, nil)
	if err != nil {
		t.Fatalf("build lastSnapshot: %v", err)
	}
	// Precondition: the seed is already quarantined (z214 gone, dangling permit gone).
	assertNoDanglingZoneRef5328(t, m.lastSnapshot)
	if len(m.lastSnapshot.zoneIDCollisions) != 1 {
		t.Fatalf("seed must record the z174/z214 collision, got %v", m.lastSnapshot.zoneIDCollisions)
	}
	if schedPolicyPresent5328(m.lastSnapshot.Policies, "dangling-allow") {
		t.Fatal("precondition: full-build seed must have dropped the trust->z214 permit")
	}

	reqs := startArmControlServer(t, controlSock, 1)

	// Route-overlay publish carrying the scheduler map: the rebuild reintroduces
	// the trust->z214 permit from raw cfg and MUST re-quarantine it.
	published, err := m.PublishRouteOverlaySnapshot(cfg, nil, map[string]bool{"workhours": true})
	if err != nil {
		t.Fatalf("PublishRouteOverlaySnapshot returned error: %v", err)
	}
	if !published {
		t.Fatal("expected a real publish")
	}

	req := <-reqs
	if req.Snapshot == nil {
		t.Fatal("captured control request carried no snapshot")
	}
	assertNoDanglingZoneRef5328(t, req.Snapshot)
	// The survivor permit must remain (the scrub must not over-drop).
	if !schedPolicyPresent5328(req.Snapshot.Policies, "survivor-allow") {
		t.Fatal("survivor permit trust->z174 was wrongly dropped by the re-quarantine")
	}
	// The dangling permit must be gone.
	if schedPolicyPresent5328(req.Snapshot.Policies, "dangling-allow") {
		t.Fatal("dangling permit trust->z214 survived the re-quarantine (references quarantined z214) (#6480)")
	}
}

// TestUpdatePolicyScheduleStateReappliesZoneQuarantine6480 is the mirror of the
// route-overlay test for the canonical scheduler-only republish path. It shares
// the SAME latent #6480 defect — UpdatePolicyScheduleState rebuilds next.Policies
// from raw cfg while inheriting the reduced next.Zones — and the SAME shared
// rebuildScheduledPolicySectionsLocked re-quarantine fixes both paths in lockstep.
func TestUpdatePolicyScheduleStateReappliesZoneQuarantine6480(t *testing.T) {
	stubRuleListHermetic(t)
	dir, err := os.MkdirTemp("", "x6480u")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	controlSock := filepath.Join(dir, "control.sock")

	cfg := collidingSchedCfg5328(t)

	m := New()
	m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	m.cfg.ControlSocket = controlSock
	m.generation = 5
	m.lastStatus.ConfigSnapshotProtocolVersion = ProtocolVersion

	m.lastSnapshot, err = buildSnapshotWithSchedulerState(
		cfg, config.UserspaceConfig{ControlSocket: controlSock}, 5, 0,
		map[string]bool{"workhours": true}, nil, nil)
	if err != nil {
		t.Fatalf("build lastSnapshot: %v", err)
	}
	assertNoDanglingZoneRef5328(t, m.lastSnapshot)

	reqs := startArmControlServer(t, controlSock, 1)

	// A CLOSED-window scheduler republish: rebuilds policies from raw cfg (which
	// reintroduces the trust->z214 permit) and MUST re-quarantine it.
	if err := m.UpdatePolicyScheduleState(cfg, map[string]bool{"workhours": false}); err != nil {
		t.Fatalf("UpdatePolicyScheduleState returned error: %v", err)
	}

	req := <-reqs
	if req.Snapshot == nil {
		t.Fatal("captured control request carried no snapshot")
	}
	assertNoDanglingZoneRef5328(t, req.Snapshot)
	if !schedPolicyPresent5328(req.Snapshot.Policies, "survivor-allow") {
		t.Fatal("survivor permit trust->z174 was wrongly dropped by the re-quarantine")
	}
	if schedPolicyPresent5328(req.Snapshot.Policies, "dangling-allow") {
		t.Fatal("dangling permit trust->z214 survived the re-quarantine (references quarantined z214) (#6480)")
	}
}

// TestPublishRouteOverlaySnapshotReadsFreshSchedulerStateNotStale5328 strengthens
// the freshness coverage (Codex nit): the existing OPEN->CLOSED tests seed
// m.policySchedulerActive nil, and since a nil/absent scheduler read is
// fail-closed (Inactive=true) a rebuild that IGNORED the passed schedulerState
// would still land on Inactive=true and pass. This drives the CLOSED->OPEN
// direction with the cache PRE-SEEDED to the STALE closed state, so only a rebuild
// that reads the FRESH open state can make the permit ACTIVE (Inactive=false).
//
// FAIL-ON-REVERT: neutralizing the rebuild (or the schedulerState cache update
// before it) leaves the inherited/stale CLOSED bit (Inactive=true), so the
// "Inactive=false" assertion goes RED — binding that the publish uses the
// freshly-passed {workhours:true}, not a stale cache.
func TestPublishRouteOverlaySnapshotReadsFreshSchedulerStateNotStale5328(t *testing.T) {
	stubRuleListHermetic(t)
	dir, err := os.MkdirTemp("", "x5328f")
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
	cfg.Schedulers = map[string]*config.SchedulerConfig{"workhours": {Name: "workhours"}}

	m := New()
	m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	m.cfg.ControlSocket = controlSock
	m.generation = 5
	m.lastStatus.ConfigSnapshotProtocolVersion = ProtocolVersion

	// Seed lastSnapshot with the window CLOSED so the permit is INACTIVE.
	m.lastSnapshot, err = buildSnapshotWithSchedulerState(
		cfg, config.UserspaceConfig{ControlSocket: controlSock}, 5, 0,
		map[string]bool{"workhours": false}, nil, nil)
	if err != nil {
		t.Fatalf("build lastSnapshot: %v", err)
	}
	if !schedPolicyInactive5328(t, m.lastSnapshot.Policies, "scheduled-allow") {
		t.Fatal("precondition: seeded permit must be INACTIVE (window CLOSED)")
	}
	// Pre-seed the scheduler cache to the STALE closed state: a rebuild that fails
	// to read the freshly-passed OPEN map would keep the permit INACTIVE.
	m.policySchedulerActive = map[string]bool{"workhours": false}

	reqs := startArmControlServer(t, controlSock, 1)

	// Publish the OPEN window: only a rebuild reading the FRESH map makes it ACTIVE.
	published, err := m.PublishRouteOverlaySnapshot(cfg, nil, map[string]bool{"workhours": true})
	if err != nil {
		t.Fatalf("PublishRouteOverlaySnapshot returned error: %v", err)
	}
	if !published {
		t.Fatal("expected a real publish (permit inactive bit changed CLOSED->OPEN)")
	}

	req := <-reqs
	if req.Snapshot == nil {
		t.Fatal("captured control request carried no snapshot")
	}
	if schedPolicyInactive5328(t, req.Snapshot.Policies, "scheduled-allow") {
		t.Fatal("published permit still INACTIVE after a fresh OPEN-window publish: the " +
			"route-overlay rebuild read a STALE scheduler state instead of the freshly-passed " +
			"{workhours:true} (#5328 A6-b2-F4 / #6480)")
	}
}
