//go:build !dpdk

package dpdk

import (
	"context"
	"errors"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

func TestDPDKConstructorsRemainRegistered(t *testing.T) {
	legacy, err := dataplane.NewDataPlane(dataplane.TypeDPDK)
	if err != nil {
		t.Fatalf("NewDataPlane(dpdk): %v", err)
	}
	if _, ok := legacy.(*Manager); !ok {
		t.Fatalf("NewDataPlane(dpdk) = %T, want *dpdk.Manager", legacy)
	}

	runtime, err := dataplane.NewRuntimeDataPlane(dataplane.TypeDPDK)
	if err != nil {
		t.Fatalf("NewRuntimeDataPlane(dpdk): %v", err)
	}
	if _, ok := runtime.(*Manager); !ok {
		t.Fatalf("NewRuntimeDataPlane(dpdk) = %T, want *dpdk.Manager", runtime)
	}
}

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
}
