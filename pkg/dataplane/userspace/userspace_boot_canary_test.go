package userspace

import (
	"fmt"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// TestUserspaceBootReturnsAdapter asserts that Boot() returns an
// adapter-wrapped userspace runtime that satisfies both
// dataplane.DataPlane (the legacy compatibility surface still consumed
// by pkg/cli, pkg/api, pkg/conntrack, pkg/fwdstatus) and
// dataplane.RuntimeDataPlane (the daemon-facing runtime surface).
//
// This is the load-bearing invariant for #1520 (sub-#1451 S5): the
// daemon's legacyDP() helper depends on the runtime dataplane being
// type-assertable to dataplane.DataPlane. Without the adapter,
// legacyDP() returns nil and CLI / API status paths silently degrade.
func TestUserspaceBootReturnsAdapter(t *testing.T) {
	t.Parallel()

	dp := Boot()
	if dp == nil {
		t.Fatal("Boot() returned nil")
	}

	if _, ok := any(dp).(*LegacyDataPlaneAdapter); !ok {
		t.Fatalf("Boot() = %T, want *LegacyDataPlaneAdapter", dp)
	}
	if _, ok := any(dp).(dataplane.RuntimeDataPlane); !ok {
		t.Fatalf("Boot() = %T, does not implement dataplane.RuntimeDataPlane", dp)
	}
	if _, ok := any(dp).(dataplane.DataPlane); !ok {
		t.Fatalf("Boot() = %T, does not implement dataplane.DataPlane (legacy adapter surface lost)", dp)
	}
}

// TestUserspaceBootMatchesRegistryShape asserts that the value returned
// by Boot() has the same concrete type as the value returned by the
// runtime backend registry round-trip
// (dataplane.NewRuntimeDataPlane(TypeUserspace)). #1520 retains the
// registry entry as a compatibility / test seam, and the two paths must
// produce indistinguishable concrete types.
func TestUserspaceBootMatchesRegistryShape(t *testing.T) {
	t.Parallel()

	direct := Boot()
	registry, err := dataplane.NewRuntimeDataPlane(dataplane.TypeUserspace)
	if err != nil {
		t.Fatalf("NewRuntimeDataPlane(userspace): %v", err)
	}

	if _, ok := any(registry).(*LegacyDataPlaneAdapter); !ok {
		t.Fatalf("NewRuntimeDataPlane(userspace) = %T, want *LegacyDataPlaneAdapter", registry)
	}
	if _, ok := any(direct).(*LegacyDataPlaneAdapter); !ok {
		t.Fatalf("Boot() = %T, want *LegacyDataPlaneAdapter", direct)
	}

	// Same concrete type for both paths.
	if dt := fmtType(direct); dt != fmtType(registry) {
		t.Fatalf("Boot() and NewRuntimeDataPlane(userspace) returned different concrete types: %s vs %s", dt, fmtType(registry))
	}
}

func fmtType(v any) string {
	if v == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%T", v)
}
