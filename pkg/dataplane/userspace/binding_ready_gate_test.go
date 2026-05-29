package userspace

import "testing"

// #1666: the binding-array READY write is gated on bindingForwardingLive,
// which requires the helper-derived binding.Ready AND the worker not being
// Dead. These tests pin the gate logic directly (no BPF map / memlock
// needed, so they run in every environment, unlike the map-touching
// applyHelperStatusLocked / verifyBindingsMapLocked tests which require
// privilege). They are the always-runnable guard for the gate semantics.

func TestBindingForwardingLiveRequiresReady(t *testing.T) {
	cases := []struct {
		name    string
		binding BindingStatus
		dead    map[uint32]bool
		want    bool
	}{
		{
			name: "registered+armed but not ready (e.g. XSK not registered) is withheld",
			// The historical (Registered && Armed) predicate would have
			// marked this READY — the crash-blind blackhole. The gate now
			// withholds it.
			binding: BindingStatus{Registered: true, Armed: true, Bound: true, XSKRegistered: false, Ready: false},
			want:    false,
		},
		{
			name:    "ready, worker not dead is forwarding-live",
			binding: BindingStatus{WorkerID: 2, Registered: true, Armed: true, Bound: true, XSKRegistered: true, Ready: true},
			want:    true,
		},
		{
			name: "ready but disarmed is withheld",
			// The Rust Ready derivation does NOT include Armed, so a
			// Ready:true / Armed:false binding (disarmed by the control
			// plane while otherwise live) must NOT forward — the gate keeps
			// the Registered && Armed admission alongside Ready.
			binding: BindingStatus{WorkerID: 2, Registered: true, Armed: false, Bound: true, XSKRegistered: true, Ready: true},
			want:    false,
		},
		{
			name: "ready but unregistered is withheld",
			binding: BindingStatus{WorkerID: 2, Registered: false, Armed: true, Bound: true, XSKRegistered: true, Ready: true},
			want:    false,
		},
		{
			name: "ready but worker dead is withheld (fast panic clear)",
			// Ready is still true in this snapshot (heartbeat not yet
			// stale), but the supervisor flagged the worker dead — the
			// !Dead leg withholds READY immediately rather than waiting
			// ~5s for heartbeat staleness to flip Ready false.
			binding: BindingStatus{WorkerID: 4, Registered: true, Armed: true, Bound: true, XSKRegistered: true, Ready: true},
			dead:    map[uint32]bool{4: true},
			want:    false,
		},
		{
			name:    "ready, a different worker is dead does not affect this binding",
			binding: BindingStatus{WorkerID: 4, Registered: true, Armed: true, Ready: true},
			dead:    map[uint32]bool{9: true},
			want:    true,
		},
		{
			name:    "not ready and not dead is withheld",
			binding: BindingStatus{WorkerID: 1, Registered: true, Armed: true, Ready: false},
			want:    false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := bindingForwardingLive(tc.binding, tc.dead); got != tc.want {
				t.Fatalf("bindingForwardingLive(%+v, %v) = %v, want %v",
					tc.binding, tc.dead, got, tc.want)
			}
		})
	}
}

func TestDeadWorkerIDSet(t *testing.T) {
	if got := deadWorkerIDSet(nil); got != nil {
		t.Fatalf("deadWorkerIDSet(nil) = %v, want nil", got)
	}
	runtime := []WorkerRuntimeStatus{
		{WorkerID: 0, Dead: false},
		{WorkerID: 1, Dead: true},
		{WorkerID: 2, Dead: false},
		{WorkerID: 3, Dead: true},
	}
	dead := deadWorkerIDSet(runtime)
	if !dead[1] || !dead[3] {
		t.Fatalf("deadWorkerIDSet did not flag dead workers 1 and 3: %v", dead)
	}
	if dead[0] || dead[2] {
		t.Fatalf("deadWorkerIDSet flagged live workers: %v", dead)
	}
	// No dead workers -> nil set (so the gate degenerates to
	// Registered && Armed && Ready).
	if got := deadWorkerIDSet([]WorkerRuntimeStatus{{WorkerID: 5, Dead: false}}); got != nil {
		t.Fatalf("deadWorkerIDSet with no dead workers = %v, want nil", got)
	}
}

// A nil dead-set (the common case: no panics) must never withhold READY
// from an otherwise-Ready binding. Guards against a nil-map regression in
// bindingForwardingLive.
func TestBindingForwardingLiveNilDeadSetHonoursReady(t *testing.T) {
	if !bindingForwardingLive(BindingStatus{WorkerID: 7, Registered: true, Armed: true, Ready: true}, nil) {
		t.Fatal("a Ready+armed binding with a nil dead-set must be forwarding-live")
	}
	if bindingForwardingLive(BindingStatus{WorkerID: 7, Registered: true, Armed: true, Ready: false}, nil) {
		t.Fatal("a non-Ready binding must not be forwarding-live")
	}
}
