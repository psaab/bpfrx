package userspace

import (
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

func overlayTestConfig() *config.Config {
	cfg := &config.Config{}
	cfg.RoutingOptions.StaticRoutes = []*config.StaticRoute{
		// ECMP default: two next-hops in ONE route entry.
		{Destination: "0.0.0.0/0", NextHops: []config.NextHopEntry{
			{Address: "172.16.50.1"}, {Address: "172.16.50.2"},
		}},
		{Destination: "10.20.0.0/16", NextHops: []config.NextHopEntry{{Address: "172.16.50.1"}}},
	}
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{
		{Name: "ISP-B", StaticRoutes: []*config.StaticRoute{
			{Destination: "0.0.0.0/0", NextHops: []config.NextHopEntry{{Address: "10.9.0.1"}}},
		}},
	}
	return cfg
}

// TestRouteOverlayWholeEntryReplacement: an overlay winner replaces the
// ENTIRE (table, family, prefix) entry set — the ECMP next-hop set is
// gone, not half-merged (#1827 plan §4.3, named ECMP test).
func TestRouteOverlayWholeEntryReplacement(t *testing.T) {
	cfg := overlayTestConfig()
	overlay := []config.RouteOverlayEntry{
		{Destination: "0.0.0.0/0", NextHop: "172.16.80.1", Policy: "wan-failover"},
	}
	routes := buildRouteSnapshots(cfg, nil, overlay)

	var defaults []RouteSnapshot
	for _, r := range routes {
		if r.Table == "inet.0" && r.Destination == "0.0.0.0/0" {
			defaults = append(defaults, r)
		}
	}
	if len(defaults) != 1 {
		t.Fatalf("inet.0 default entries = %+v, want exactly one (whole-entry replacement)", defaults)
	}
	if len(defaults[0].NextHops) != 1 || defaults[0].NextHops[0] != "172.16.80.1" {
		t.Fatalf("default next-hops = %+v, want only the overlay next-hop (no ECMP merge)", defaults[0].NextHops)
	}

	// Untouched entries survive: the non-default static and the
	// ISP-B instance default.
	foundOther, foundRI := false, false
	for _, r := range routes {
		if r.Table == "inet.0" && r.Destination == "10.20.0.0/16" {
			foundOther = true
		}
		if r.Table == "ISP-B.inet.0" && r.Destination == "0.0.0.0/0" &&
			len(r.NextHops) == 1 && r.NextHops[0] == "10.9.0.1" {
			foundRI = true
		}
	}
	if !foundOther || !foundRI {
		t.Fatalf("unrelated routes disturbed by overlay: %+v", routes)
	}

	// Routing-instance overlay replaces only that instance's table.
	riOverlay := []config.RouteOverlayEntry{
		{RoutingInstance: "ISP-B", Destination: "0.0.0.0/0", NextHop: "10.9.99.1", Policy: "p"},
	}
	routes = buildRouteSnapshots(cfg, nil, riOverlay)
	for _, r := range routes {
		if r.Table == "ISP-B.inet.0" && r.Destination == "0.0.0.0/0" {
			if len(r.NextHops) != 1 || r.NextHops[0] != "10.9.99.1" {
				t.Fatalf("ISP-B default = %+v, want overlay next-hop", r)
			}
		}
		if r.Table == "inet.0" && r.Destination == "0.0.0.0/0" && len(r.NextHops) != 2 {
			t.Fatalf("master default = %+v, must be untouched by instance overlay", r)
		}
	}

	// Withdrawal (nil overlay) restores the config routes.
	routes = buildRouteSnapshots(cfg, nil, nil)
	for _, r := range routes {
		if r.Table == "inet.0" && r.Destination == "0.0.0.0/0" && len(r.NextHops) != 2 {
			t.Fatalf("withdrawn overlay left residue: %+v", r)
		}
	}
}

// TestRouteOverlayContentHashDelta: an overlay-only change shifts the
// snapshot content hash (invariant 6 — a silently-skipped transition
// would be a failover-doesn't-happen bug).
func TestRouteOverlayContentHashDelta(t *testing.T) {
	cfg := overlayTestConfig()
	base, _ := buildSnapshotWithSchedulerState(cfg, config.UserspaceConfig{}, 1, 0, nil, nil, nil)
	withOverlay, _ := buildSnapshotWithSchedulerState(cfg, config.UserspaceConfig{}, 1, 0, nil,
		[]config.RouteOverlayEntry{{Destination: "0.0.0.0/0", NextHop: "172.16.80.1", Policy: "p"}}, nil)

	h1, ok1 := snapshotContentHash(base)
	h2, ok2 := snapshotContentHash(withOverlay)
	if !ok1 || !ok2 {
		t.Fatal("content hash unavailable")
	}
	if h1 == h2 {
		t.Fatal("overlay-only change did not move the snapshot content hash")
	}

	// Same overlay again ⇒ identical hash (duplicate-publish basis).
	again, _ := buildSnapshotWithSchedulerState(cfg, config.UserspaceConfig{}, 2, 7, nil,
		[]config.RouteOverlayEntry{{Destination: "0.0.0.0/0", NextHop: "172.16.80.1", Policy: "p"}}, nil)
	h3, _ := snapshotContentHash(again)
	if h2 != h3 {
		t.Fatal("identical overlay produced different content hash (generation must be excluded)")
	}
}

// overlayControlServer accepts apply_snapshot requests and records them.
func overlayControlServer(t *testing.T, dir string) (string, chan ControlRequest) {
	t.Helper()
	controlSock := filepath.Join(dir, "control.sock")
	ln, err := net.Listen("unix", controlSock)
	if err != nil {
		t.Fatalf("listen control socket: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	reqCh := make(chan ControlRequest, 8)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			var req ControlRequest
			if err := json.NewDecoder(conn).Decode(&req); err == nil {
				reqCh <- req
				gen := uint64(0)
				fib := uint32(0)
				if req.Snapshot != nil {
					gen = req.Snapshot.Generation
					fib = req.Snapshot.FIBGeneration
				}
				_ = json.NewEncoder(conn).Encode(ControlResponse{
					OK: true,
					Status: &ProcessStatus{
						Enabled:                true,
						LastSnapshotGeneration: gen,
						LastFIBGeneration:      fib,
					},
				})
			}
			conn.Close()
		}
	}()
	return controlSock, reqCh
}

// TestPublishRouteOverlaySnapshot covers the named manager API (#1827
// Codex r2-2): overlay publish via apply_snapshot with a generation
// bump and overlay routes, duplicate-publish skip, and full-apply
// overlay preservation through the cached overlay.
func TestPublishRouteOverlaySnapshot(t *testing.T) {
	dir := t.TempDir()
	controlSock, reqCh := overlayControlServer(t, dir)

	cfg := overlayTestConfig()
	m := New()
	m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	m.cfg.ControlSocket = controlSock
	m.generation = 7
	m.lastSnapshot, _ = buildSnapshot(cfg, config.UserspaceConfig{ControlSocket: controlSock}, 7, 0)
	if h, ok := snapshotContentHash(m.lastSnapshot); ok {
		m.lastSnapshotHash = h
	}
	m.lastStatus.ConfigSnapshotProtocolVersion = ProtocolVersion

	overlay := []config.RouteOverlayEntry{
		{Destination: "0.0.0.0/0", NextHop: "172.16.80.1", Policy: "wan-failover"},
	}
	published, err := m.PublishRouteOverlaySnapshot(cfg, overlay, nil)
	if err != nil {
		t.Fatalf("PublishRouteOverlaySnapshot: %v", err)
	}
	if !published {
		t.Fatal("first publish reported published=false")
	}

	var req ControlRequest
	select {
	case req = <-reqCh:
	case <-time.After(2 * time.Second):
		t.Fatal("no apply_snapshot published")
	}
	if req.Type != "apply_snapshot" || req.Snapshot == nil {
		t.Fatalf("request = %+v, want apply_snapshot", req.Type)
	}
	if req.Snapshot.Generation <= 7 {
		t.Fatalf("generation = %d, want > 7", req.Snapshot.Generation)
	}
	found := false
	for _, r := range req.Snapshot.Routes {
		if r.Table == "inet.0" && r.Destination == "0.0.0.0/0" {
			if len(r.NextHops) == 1 && r.NextHops[0] == "172.16.80.1" {
				found = true
			} else {
				t.Fatalf("published default = %+v, want overlay next-hop only", r)
			}
		}
	}
	if !found {
		t.Fatalf("published snapshot missing overlay route: %+v", req.Snapshot.Routes)
	}

	// Duplicate publish (same overlay, same content) is skipped and
	// reports published=false so the actuator does not bump the FIB
	// generation (Codex PR #1843 MED).
	published, err = m.PublishRouteOverlaySnapshot(cfg, overlay, nil)
	if err != nil {
		t.Fatalf("duplicate PublishRouteOverlaySnapshot: %v", err)
	}
	if published {
		t.Fatal("duplicate publish reported published=true")
	}
	select {
	case extra := <-reqCh:
		t.Fatalf("duplicate publish was not skipped: %+v", extra.Type)
	case <-time.After(100 * time.Millisecond):
	}

	// Overlay change publishes again (content delta).
	overlay2 := []config.RouteOverlayEntry{
		{Destination: "0.0.0.0/0", NextHop: "172.16.80.2", Policy: "wan-failover"},
	}
	published, err = m.PublishRouteOverlaySnapshot(cfg, overlay2, nil)
	if err != nil {
		t.Fatalf("PublishRouteOverlaySnapshot(overlay2): %v", err)
	}
	if !published {
		t.Fatal("changed overlay reported published=false")
	}
	select {
	case req = <-reqCh:
	case <-time.After(2 * time.Second):
		t.Fatal("changed overlay not published")
	}

	// Full-apply preservation (AGY r2-2): the cached overlay feeds the
	// full snapshot build, so an operator commit while a policy is
	// FAILED keeps the injected route.
	snap, _ := buildSnapshotWithSchedulerState(cfg, config.UserspaceConfig{}, 9, 0, nil, m.routeOverlaySnapshot(), m.feedSnapshotOverlay())
	kept := false
	for _, r := range snap.Routes {
		if r.Table == "inet.0" && r.Destination == "0.0.0.0/0" &&
			len(r.NextHops) == 1 && r.NextHops[0] == "172.16.80.2" {
			kept = true
		}
	}
	if !kept {
		t.Fatalf("full apply did not preserve the active overlay: %+v", snap.Routes)
	}
}

// TestPublishRouteOverlaySnapshotWithoutHelper: an overlay arriving
// before any snapshot/helper exists is cached (not an error) and rides
// the next full apply.
func TestPublishRouteOverlaySnapshotWithoutHelper(t *testing.T) {
	m := New()
	overlay := []config.RouteOverlayEntry{
		{Destination: "0.0.0.0/0", NextHop: "172.16.80.1", Policy: "p"},
	}
	published, err := m.PublishRouteOverlaySnapshot(nil, overlay, nil)
	if err != nil {
		t.Fatalf("PublishRouteOverlaySnapshot without helper: %v", err)
	}
	if published {
		t.Fatal("helperless caching reported published=true")
	}
	got := m.routeOverlaySnapshot()
	if len(got) != 1 || got[0].NextHop != "172.16.80.1" {
		t.Fatalf("overlay not cached: %+v", got)
	}
}

// overlayControlServerToggle behaves like overlayControlServer but its
// apply_snapshot handling can be flipped to fail (OK:false) via the
// returned setter, so a publish failure can be exercised. All requests
// are still forwarded on the returned channel.
func overlayControlServerToggle(t *testing.T, dir string) (string, chan ControlRequest, func(bool)) {
	t.Helper()
	controlSock := filepath.Join(dir, "control.sock")
	ln, err := net.Listen("unix", controlSock)
	if err != nil {
		t.Fatalf("listen control socket: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	reqCh := make(chan ControlRequest, 8)
	var mu sync.Mutex
	fail := false
	setFail := func(f bool) {
		mu.Lock()
		fail = f
		mu.Unlock()
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			var req ControlRequest
			if err := json.NewDecoder(conn).Decode(&req); err == nil {
				reqCh <- req
				mu.Lock()
				failNow := fail
				mu.Unlock()
				if failNow && req.Type == "apply_snapshot" {
					_ = json.NewEncoder(conn).Encode(ControlResponse{
						OK:    false,
						Error: "simulated apply_snapshot failure",
					})
				} else {
					gen := uint64(0)
					fib := uint32(0)
					if req.Snapshot != nil {
						gen = req.Snapshot.Generation
						fib = req.Snapshot.FIBGeneration
					}
					_ = json.NewEncoder(conn).Encode(ControlResponse{
						OK: true,
						Status: &ProcessStatus{
							Enabled:                true,
							LastSnapshotGeneration: gen,
							LastFIBGeneration:      fib,
						},
					})
				}
			}
			conn.Close()
		}
	}()
	return controlSock, reqCh, setFail
}

// TestPublishRouteOverlaySnapshotFailureKeepsBaseline is the #3760
// regression: a failed apply_snapshot must NOT advance the cached
// desired overlay. Before the fix, m.routeOverlay was assigned at the
// top of PublishRouteOverlaySnapshot, so a helper rejection left the
// cache recording an overlay the dataplane never accepted. A later full
// apply reads that cache (routeOverlaySnapshot) and rebuilds routes
// against the never-published overlay — the cache lies about what is
// live, and the desired-vs-applied observability is defeated.
//
// RED-on-revert: reverting the mutate-after-success fix makes the cache
// advance to the failed overlay B, so assertions (a)/(b) below fail.
func TestPublishRouteOverlaySnapshotFailureKeepsBaseline(t *testing.T) {
	dir := t.TempDir()
	controlSock, reqCh, setFail := overlayControlServerToggle(t, dir)

	cfg := overlayTestConfig()
	m := New()
	m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	m.cfg.ControlSocket = controlSock
	m.generation = 7
	m.lastSnapshot, _ = buildSnapshot(cfg, config.UserspaceConfig{ControlSocket: controlSock}, 7, 0)
	if h, ok := snapshotContentHash(m.lastSnapshot); ok {
		m.lastSnapshotHash = h
	}
	m.lastStatus.ConfigSnapshotProtocolVersion = ProtocolVersion

	// Establish a real applied baseline: publish overlay A successfully.
	overlayA := []config.RouteOverlayEntry{
		{Destination: "0.0.0.0/0", NextHop: "172.16.80.1", Policy: "wan-failover"},
	}
	published, err := m.PublishRouteOverlaySnapshot(cfg, overlayA, nil)
	if err != nil || !published {
		t.Fatalf("baseline publish: published=%v err=%v", published, err)
	}
	<-reqCh // drain the baseline apply_snapshot
	genAfterBaseline := m.generation

	// The helper now rejects the next apply_snapshot. Publishing overlay B
	// must fail AND leave the cache at the last-applied baseline A.
	setFail(true)
	overlayB := []config.RouteOverlayEntry{
		{Destination: "0.0.0.0/0", NextHop: "172.16.80.2", Policy: "wan-failover"},
	}
	published, err = m.PublishRouteOverlaySnapshot(cfg, overlayB, nil)
	if err == nil {
		t.Fatal("expected publish failure, got nil error")
	}
	if published {
		t.Fatal("failed publish reported published=true")
	}
	<-reqCh // drain the rejected apply_snapshot attempt

	// (a) The cached desired overlay must still be A: the never-applied B
	//     must not have advanced the cache (the #3760 divergence).
	got := m.routeOverlaySnapshot()
	if len(got) != 1 || got[0].NextHop != "172.16.80.1" {
		t.Fatalf("cache advanced to the unpublished overlay after a failed publish: %+v (want last-applied A 172.16.80.1)", got)
	}
	// The generation must not have advanced on a failed publish.
	if m.generation != genAfterBaseline {
		t.Fatalf("generation advanced on a failed publish: %d -> %d", genAfterBaseline, m.generation)
	}

	// (b) A full apply reads the cached overlay; it must rebuild A's route,
	//     matching what the dataplane actually has — NOT the failed B.
	snap, _ := buildSnapshotWithSchedulerState(cfg, config.UserspaceConfig{}, 9, 0, nil, m.routeOverlaySnapshot(), m.feedSnapshotOverlay())
	for _, r := range snap.Routes {
		if r.Table == "inet.0" && r.Destination == "0.0.0.0/0" {
			if len(r.NextHops) != 1 || r.NextHops[0] != "172.16.80.1" {
				t.Fatalf("full apply rebuilt routes from the unpublished overlay: %+v (want A 172.16.80.1)", r.NextHops)
			}
		}
	}

	// (c) With the helper healthy again, the next attempt re-publishes the
	//     change B, because the cache is still at baseline A and the
	//     content hash differs from the last-published snapshot. If the
	//     failed publish had advanced the cache, a full-apply diff could
	//     suppress B as "already published".
	setFail(false)
	published, err = m.PublishRouteOverlaySnapshot(cfg, overlayB, nil)
	if err != nil {
		t.Fatalf("retry publish after recovery: %v", err)
	}
	if !published {
		t.Fatal("retry after recovery did not re-publish the change")
	}
	select {
	case req := <-reqCh:
		if req.Type != "apply_snapshot" {
			t.Fatalf("retry request = %q, want apply_snapshot", req.Type)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("retry did not publish an apply_snapshot")
	}
	// The cache has now advanced exactly once, to B.
	got = m.routeOverlaySnapshot()
	if len(got) != 1 || got[0].NextHop != "172.16.80.2" {
		t.Fatalf("cache did not advance to B after a successful retry: %+v", got)
	}
}
