package daemon

import (
	"errors"
	"fmt"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// TestBuildRuntimeDataPlaneDefaultUsesUserspaceBoot asserts that the
// empty default dataplane type ("" → userspace per
// dataplane.EffectiveType) routes through userspace.Boot(), not through
// the runtime backend registry. This is the load-bearing structural
// delta of #1520 (sub-#1451 S5).
func TestBuildRuntimeDataPlaneDefaultUsesUserspaceBoot(t *testing.T) {
	t.Parallel()

	dp, err := buildRuntimeDataPlane("")
	if err != nil {
		t.Fatalf("buildRuntimeDataPlane(\"\"): %v", err)
	}
	if _, ok := any(dp).(*dpuserspace.LegacyDataPlaneAdapter); !ok {
		t.Fatalf("buildRuntimeDataPlane(\"\") = %T, want *userspace.LegacyDataPlaneAdapter", dp)
	}
}

// TestBuildRuntimeDataPlaneUserspaceUsesUserspaceBoot asserts the same
// invariant for the explicit "userspace" selection.
func TestBuildRuntimeDataPlaneUserspaceUsesUserspaceBoot(t *testing.T) {
	t.Parallel()

	dp, err := buildRuntimeDataPlane(dataplane.TypeUserspace)
	if err != nil {
		t.Fatalf("buildRuntimeDataPlane(userspace): %v", err)
	}
	if _, ok := any(dp).(*dpuserspace.LegacyDataPlaneAdapter); !ok {
		t.Fatalf("buildRuntimeDataPlane(userspace) = %T, want *userspace.LegacyDataPlaneAdapter", dp)
	}
}

// TestBuildRuntimeDataPlaneEBPFRoutesToLegacyManager asserts that the
// explicit "ebpf" rollback selection still constructs the legacy
// *dataplane.Manager via the dataplane factory, NOT the userspace
// adapter. The rollback path must not silently land on the userspace
// runtime.
func TestBuildRuntimeDataPlaneEBPFRoutesToLegacyManager(t *testing.T) {
	t.Parallel()

	dp, err := buildRuntimeDataPlane(dataplane.TypeEBPF)
	if err != nil {
		t.Fatalf("buildRuntimeDataPlane(ebpf): %v", err)
	}
	if _, ok := any(dp).(*dataplane.Manager); !ok {
		t.Fatalf("buildRuntimeDataPlane(ebpf) = %T, want *dataplane.Manager (legacy rollback)", dp)
	}
	if _, ok := any(dp).(*dpuserspace.LegacyDataPlaneAdapter); ok {
		t.Fatal("buildRuntimeDataPlane(ebpf) returned userspace adapter; rollback path is broken")
	}
}

// TestBuildRuntimeDataPlaneDPDKReturnsRetired asserts that the helper
// propagates dataplane.ErrDPDKBackendRetired unchanged for the retired
// DPDK selection. The daemon outer loop has an errors.Is branch that
// depends on this sentinel.
func TestBuildRuntimeDataPlaneDPDKReturnsRetired(t *testing.T) {
	t.Parallel()

	dp, err := buildRuntimeDataPlane(dataplane.TypeDPDK)
	if err == nil {
		t.Fatalf("buildRuntimeDataPlane(dpdk) = %T, nil; want ErrDPDKBackendRetired", dp)
	}
	if !errors.Is(err, dataplane.ErrDPDKBackendRetired) {
		t.Fatalf("buildRuntimeDataPlane(dpdk) err = %v; want errors.Is(ErrDPDKBackendRetired)", err)
	}
	if dp != nil {
		t.Fatalf("buildRuntimeDataPlane(dpdk) returned non-nil dp = %T", dp)
	}
}

// TestBuildRuntimeDataPlaneMatchesBootShape sanity-checks that the
// userspace branch returns the same concrete type as userspace.Boot()
// directly. Guards against a future refactor that silently re-introduces
// the runtime backend registry wrapper.
func TestBuildRuntimeDataPlaneMatchesBootShape(t *testing.T) {
	t.Parallel()

	helper, err := buildRuntimeDataPlane(dataplane.TypeUserspace)
	if err != nil {
		t.Fatalf("buildRuntimeDataPlane(userspace): %v", err)
	}
	direct := dpuserspace.Boot()

	if hType, dType := fmt.Sprintf("%T", helper), fmt.Sprintf("%T", direct); hType != dType {
		t.Fatalf("buildRuntimeDataPlane(userspace) = %s, want %s (Boot() shape)", hType, dType)
	}
}
