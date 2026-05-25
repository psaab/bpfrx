//go:build !dpdk

package dpdk

import (
	"context"
	"errors"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// TestDPDKConstructorsReturnRetirementError pins the post-#1527
// behavior: both NewDataPlane(TypeDPDK) and
// NewRuntimeDataPlane(TypeDPDK) must return
// dataplane.ErrDPDKBackendRetired rather than the generic
// "unknown dataplane type" error or — worse — a working stub
// Manager.  The test guards against silent registry resurrection
// (someone re-adding the init() block in manager.go) and against
// the retirement error being weakened to a non-sentinel message.
func TestDPDKConstructorsReturnRetirementError(t *testing.T) {
	legacy, err := dataplane.NewDataPlane(dataplane.TypeDPDK)
	if !errors.Is(err, dataplane.ErrDPDKBackendRetired) {
		t.Fatalf("NewDataPlane(dpdk) error = %v, want errors.Is(ErrDPDKBackendRetired)", err)
	}
	if legacy != nil {
		t.Fatalf("NewDataPlane(dpdk) = %T, want nil", legacy)
	}

	runtime, err := dataplane.NewRuntimeDataPlane(dataplane.TypeDPDK)
	if !errors.Is(err, dataplane.ErrDPDKBackendRetired) {
		t.Fatalf("NewRuntimeDataPlane(dpdk) error = %v, want errors.Is(ErrDPDKBackendRetired)", err)
	}
	if runtime != nil {
		t.Fatalf("NewRuntimeDataPlane(dpdk) = %T, want nil", runtime)
	}
}

// TestRegisterDPDKBackendPanics guards against silent resurrection of
// the DPDK backend via RegisterBackend or RegisterRuntimeBackend.
// NewDataPlane and NewRuntimeDataPlane intercept TypeDPDK before
// reaching the registry, so any successfully-registered DPDK
// constructor would be permanently unreachable.  The panic makes the
// programming error visible at init() time rather than silently at
// runtime.
func TestRegisterDPDKBackendPanics(t *testing.T) {
	assertPanics := func(name string, fn func()) {
		t.Helper()
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("%s: expected panic, got none", name)
			}
		}()
		fn()
	}

	assertPanics("RegisterBackend(TypeDPDK)", func() {
		dataplane.RegisterBackend(dataplane.TypeDPDK, func() dataplane.DataPlane { return nil })
	})
	assertPanics("RegisterRuntimeBackend(TypeDPDK)", func() {
		dataplane.RegisterRuntimeBackend(dataplane.TypeDPDK, func() dataplane.RuntimeDataPlane { return nil })
	})
}

// TestDPDKStubRequiresDPDKBuildTag still covers the direct stub
// path (Load/Start/Compile/ApplyConfig on a Manager constructed via
// New()) so that any caller that gets a *Manager through a
// non-registry path still sees the build-tag rejection.  After
// #1527 the registry path is gone, so this test is the only place
// errDPDKBuildTagRequired is exercised — that is intentional until
// Phase 3 (#1528) deletes the package.
func TestDPDKStubRequiresDPDKBuildTag(t *testing.T) {
	m := New()

	if err := m.Load(); !errors.Is(err, errDPDKBuildTagRequired) {
		t.Fatalf("Load() error = %v, want %v", err, errDPDKBuildTagRequired)
	}
	if m.IsLoaded() {
		t.Fatal("stub Load marked DPDK loaded without the dpdk build tag")
	}

	if err := m.Start(context.Background()); !errors.Is(err, errDPDKBuildTagRequired) {
		t.Fatalf("Start() error = %v, want %v", err, errDPDKBuildTagRequired)
	}

	if _, err := m.Compile(nil); !errors.Is(err, errDPDKBuildTagRequired) {
		t.Fatalf("Compile() error = %v, want %v", err, errDPDKBuildTagRequired)
	}

	if _, err := m.ApplyConfig(context.Background(), nil); !errors.Is(err, errDPDKBuildTagRequired) {
		t.Fatalf("ApplyConfig() error = %v, want %v", err, errDPDKBuildTagRequired)
	}
}
