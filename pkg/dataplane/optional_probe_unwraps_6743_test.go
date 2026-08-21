package dataplane

import "testing"

// #6743 r8: the ...Of optional-capability probes must resolve through Unwrap
// BEFORE their type switch, and nothing bound that.
//
// WHAT WAS UNBOUND, measured at b9be179a6. Deleting the `Unwrap(...)` call
// from TelemetryOf — leaving `switch p := provider.(type)`, which is exactly
// the pre-#6743 shape the fix exists to replace — left pkg/dataplane,
// pkg/daemon, pkg/api AND pkg/cli all green. So the behaviour the fix is
// *about* had no guard.
//
// A coarser mutation DOES red something (forcing TelemetryOf to return the
// null object outright reds a CLI fabric-counters test), which is why the
// distinction matters: a test that only proves "TelemetryOf returns something
// non-null" does not prove it resolved the PUBLISHED BACKEND rather than the
// live indirection wrapped around it. Those two differ only when an
// indirection is present — and an indirection is present on every deployment
// (pkg/daemon's liveDataPlane, #2114).
//
// THE FIXTURE IS THE PRODUCTION SHAPE, not a convenient one. liveDataPlane
// declares only the MANDATORY management surface and implements
// LiveUnwrapper; the backend behind it carries the OPTIONAL capability. So
// the indirection here deliberately does NOT implement Telemetry or
// TelemetryProvider — if it did, probing the indirection would succeed and
// the mutation would be invisible, which is precisely how this stayed
// unbound.

// probeBackend6743 is the published backend: it carries the optional
// capability. MapStats returns a one-element slice so the bound path is
// distinguishable from the null object BEHAVIOURALLY, not just by identity —
// the null object reports zero maps.
type probeBackend6743 struct{ Telemetry }

func (p *probeBackend6743) MapStats() []MapStats { return []MapStats{{Name: "probe6743"}} }

// probeIndirection6743 is the live adapter: mandatory surface only, plus
// LiveUnwrapper. It must NOT satisfy Telemetry or TelemetryProvider.
type probeIndirection6743 struct{ backend any }

func (p *probeIndirection6743) Unwrap() any { return p.backend }

// probeNilIndirection6743 models a DISOWNED cell: the adapter is still held by
// the caller, but its owner has published nothing.
type probeNilIndirection6743 struct{}

func (probeNilIndirection6743) Unwrap() any { return nil }

// TestTelemetryOfResolvesThroughTheIndirection_6743 is the fail-on-revert guard
// for the Unwrap in TelemetryOf.
//
// RED-on-revert: change `switch p := Unwrap(provider).(type)` to
// `switch p := provider.(type)` in TelemetryOf (pkg/dataplane/apply.go).
func TestTelemetryOfResolvesThroughTheIndirection_6743(t *testing.T) {
	backend := &probeBackend6743{Telemetry: NewDataPlaneTelemetry(nil)}
	live := &probeIndirection6743{backend: backend}

	// PRECONDITION, asserted rather than assumed: the indirection must not
	// itself expose the capability, or this test cannot distinguish probing
	// the adapter from probing the backend and would pass under the mutation.
	if _, ok := any(live).(Telemetry); ok {
		t.Fatal("fixture broken: the indirection satisfies Telemetry, so probing it directly " +
			"would succeed and the Unwrap would be unobservable")
	}
	if _, ok := any(live).(TelemetryProvider); ok {
		t.Fatal("fixture broken: the indirection satisfies TelemetryProvider")
	}

	got := TelemetryOf(live)
	// Behavioural, not identity: the backend reports one map, the null object
	// reports none. Under the revert the probe sees an adapter that satisfies
	// none of the arms and falls through to the null object, so this reads 0.
	if stats := got.MapStats(); len(stats) != 1 || stats[0].Name != "probe6743" {
		t.Fatalf("TelemetryOf(live indirection).MapStats() = %v (probe returned %T), want the "+
			"PUBLISHED BACKEND's single \"probe6743\" map. Probing the adapter instead of "+
			"unwrapping to the backend erases every optional capability on a HEALTHY "+
			"deployment — NAT-pool and userspace Prometheus families stop being emitted and "+
			"NAT statistics report healthy zeros (#2114/#6743).", stats, got)
	}
}

// TestTelemetryOfOnADisownedCellIsNull_6743 is the over-reach control, and a
// SEPARATE test on purpose: sharing a body with the binder would put it behind
// that body's t.Fatalf, where it could never be observed running under the
// mutation it exists to bound.
//
// Unwrap must not become "return the adapter when the cell is empty". A
// disowned cell yields nil, and the probe must degrade to the null object so
// the consumer takes its capability-unavailable branch. This stays GREEN under
// the revert above — that contrast is what makes it a control.
func TestTelemetryOfOnADisownedCellIsNull_6743(t *testing.T) {
	got := TelemetryOf(probeNilIndirection6743{})
	if got == nil {
		t.Fatal("TelemetryOf must return a null object, never a nil interface — callers " +
			"invoke methods on it without a nil check")
	}
	// The null object reports no maps; a live backend's would not be consulted
	// at all here. This asserts the DEGRADE, not merely non-nil.
	if stats := got.MapStats(); len(stats) != 0 {
		t.Fatalf("a disowned cell produced %d map stats; the probe resolved something other "+
			"than the empty publication", len(stats))
	}
}
