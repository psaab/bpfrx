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

// TestBuildRuntimeDataPlaneEBPFReturnsRetired asserts that the helper
// propagates dataplane.ErrEBPFBackendRetired unchanged for the retired
// legacy eBPF selection after #1476 mechanical source removal. The
// daemon outer loop has an errors.Is branch that depends on this
// sentinel (the soft-fallback at daemon_run.go that mirrors the DPDK
// path). Pre-#1476 the same shape constructed a legacy *dataplane.Manager
// for the explicit-rollback path; the rollback path is now retired in
// lockstep with the source deletion.
func TestBuildRuntimeDataPlaneEBPFReturnsRetired(t *testing.T) {
	t.Parallel()

	dp, err := buildRuntimeDataPlane(dataplane.TypeEBPF)
	if err == nil {
		t.Fatalf("buildRuntimeDataPlane(ebpf) = %T, nil; want ErrEBPFBackendRetired", dp)
	}
	if !errors.Is(err, dataplane.ErrEBPFBackendRetired) {
		t.Fatalf("buildRuntimeDataPlane(ebpf) err = %v; want errors.Is(ErrEBPFBackendRetired)", err)
	}
	if dp != nil {
		t.Fatalf("buildRuntimeDataPlane(ebpf) returned non-nil dp = %T", dp)
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

// TestBuildRuntimeDataPlaneUnknownTypePropagatesError asserts that the
// helper does not silently swallow an unknown dataplane type (e.g., an
// operator typo). The error must be surfaced from the legacy factory so
// daemon startup logs it via the existing slog.Error("failed to create
// dataplane", ...) branch. Also asserts the unknown-type error is NOT
// the DPDK retirement sentinel (sentinel reserved for "dpdk" only).
func TestBuildRuntimeDataPlaneUnknownTypePropagatesError(t *testing.T) {
	t.Parallel()

	dp, err := buildRuntimeDataPlane("totally-unknown-type")
	if err == nil {
		t.Fatalf("buildRuntimeDataPlane(unknown) = %T, nil; want error", dp)
	}
	if dp != nil {
		t.Fatalf("buildRuntimeDataPlane(unknown) returned non-nil dp = %T", dp)
	}
	if errors.Is(err, dataplane.ErrDPDKBackendRetired) {
		t.Fatalf("buildRuntimeDataPlane(unknown) returned ErrDPDKBackendRetired; sentinel must be reserved for dpdk")
	}
	if errors.Is(err, dataplane.ErrEBPFBackendRetired) {
		t.Fatalf("buildRuntimeDataPlane(unknown) returned ErrEBPFBackendRetired; sentinel must be reserved for ebpf")
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
