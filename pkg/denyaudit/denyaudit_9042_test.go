package denyaudit

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func withClock(t *testing.T, at *int64) {
	t.Helper()
	prev := nowNanos
	nowNanos = func() int64 { return *at }
	t.Cleanup(func() { nowNanos = prev })
}

// #9042 acceptance: a burst of N denials from ONE principal produces O(1) log
// records and increments the counter by N.
func TestBurstIsBoundedButCounted9042(t *testing.T) {
	now := int64(1)
	withClock(t, &now)
	before := Total(SurfaceGRPCLoginClass)

	emitted, suppressedSeen := 0, uint64(0)
	const burst = 500
	for i := 0; i < burst; i++ {
		if emit, sup := Note(SurfaceGRPCLoginClass, "uid:1234"); emit {
			emitted++
			suppressedSeen += sup
		}
	}
	if emitted != 1 {
		t.Errorf("#9042: a %d-denial burst from one principal emitted %d log records, want 1. "+
			"The line ships at Warn to remote syslog, so an unbounded burst is off-box "+
			"traffic per denied RPC and pushes xpfd's other lines past journald's cap.",
			burst, emitted)
	}
	if got := Total(SurfaceGRPCLoginClass) - before; got != burst {
		t.Errorf("#9042: counter advanced by %d, want %d. Bounding the log must NOT hide the "+
			"volume — the counter is the only signal a denial happened at all, since there "+
			"is no authorization event in the audit journal.", got, burst)
	}

	// ...and the suppressed count is reported with the NEXT emission, so an
	// operator sees both that it is ongoing and how fast.
	now += int64(Interval) + 1
	emit, sup := Note(SurfaceGRPCLoginClass, "uid:1234")
	if !emit {
		t.Fatal("#9042: no emission after the window elapsed")
	}
	if sup != uint64(burst-1) {
		t.Errorf("#9042: next emission reported %d suppressed, want %d — a bounded line that "+
			"does not say how much it hid is not observable", sup, burst-1)
	}
}

// A denial from a NEW principal must still log promptly: bounding one noisy
// caller must not blind the operator to a different one.
// A denial from a NEW principal logs promptly while buckets remain free --
// bounding one noisy caller must not blind the operator to a different one.
//
// THE GUARANTEE IS STATED AT ITS REAL STRENGTH. It holds while free buckets
// remain; under an attacker occupying every bucket a new principal's first
// denial may be suppressed. That is the deliberate trade (see the buckets
// comment): guaranteeing otherwise means the line count grows with an
// attacker-controlled key count, which is the flood being fixed. This asserts
// the guarantee that IS made, rather than one the design cannot keep.
func TestNewPrincipalStillLogsPromptly9042(t *testing.T) {
	resetForTest()
	now := int64(1)
	withClock(t, &now)
	promptly, distinct := 0, 0
	seen := map[uint32]bool{}
	for i := 0; i < 4*buckets; i++ {
		key := fmt.Sprintf("uid:new-%d", i)
		b := bucketIndexForTest(SurfaceGRPCLoginClass, key)
		fresh := !seen[b]
		seen[b] = true
		emit, _ := Note(SurfaceGRPCLoginClass, key)
		if fresh {
			distinct++
			if emit {
				promptly++
			}
		}
	}
	if distinct == 0 {
		t.Fatal("#9042: no fresh buckets were exercised, so this proves nothing")
	}
	if promptly != distinct {
		t.Errorf("#9042: %d of %d principals reaching a FREE bucket failed to log promptly. "+
			"A first denial from a new principal must not be swallowed while capacity "+
			"remains — that is the half of the trade the design does guarantee.",
			promptly, distinct)
	}
}

// THE KEY SPACE IS FIXED, and that is a security property rather than an
// optimisation. A per-principal map keyed by attacker-supplied identity grows
// without bound — the same defect class this package fixes, one level down.
func TestKeySpaceIsBounded9042(t *testing.T) {
	now := int64(1)
	withClock(t, &now)
	for i := 0; i < 100000; i++ {
		Note(SurfaceFabricAuth, fmt.Sprintf("attacker-chosen-%d", i))
	}
	if got := len(state); got != buckets {
		t.Errorf("#9042: bucket array grew to %d; it must stay fixed at %d, or an attacker "+
			"varying the key exhausts memory through the very limiter meant to bound them",
			got, buckets)
	}
}

// Every surface must be enumerable, because the collector reads Surfaces()
// rather than restating the list — a second enumeration of the same fact is the
// drift #8312 called out.
func TestEverySurfaceIsEnumerated9042(t *testing.T) {
	seen := map[Surface]bool{}
	for _, s := range Surfaces() {
		if seen[s] {
			t.Errorf("#9042: surface %q listed twice", s)
		}
		seen[s] = true
		if _, ok := totals[s]; !ok {
			t.Errorf("#9042: surface %q is enumerated but has no counter, so its denials are "+
				"logged-and-lost", s)
		}
	}
	if len(seen) != len(totals) {
		t.Errorf("#9042: %d surfaces enumerated but %d counters exist — a counter nothing "+
			"enumerates is never exported", len(seen), len(totals))
	}
}

func TestConcurrentNoteIsRaceFree9042(t *testing.T) {
	now := int64(1)
	withClock(t, &now)
	before := Total(SurfaceRESTCrossSite)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				Note(SurfaceRESTCrossSite, fmt.Sprintf("k%d", i))
			}
		}(i)
	}
	wg.Wait()
	if got := Total(SurfaceRESTCrossSite) - before; got != 5000 {
		t.Errorf("#9042: concurrent counter advanced by %d, want 5000", got)
	}
	_ = time.Second
}
