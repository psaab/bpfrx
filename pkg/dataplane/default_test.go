package dataplane

import (
	"strings"
	"testing"
)

func TestEffectiveTypeDefaultsToUserspace(t *testing.T) {
	t.Parallel()

	if got := EffectiveType(""); got != TypeUserspace {
		t.Fatalf("EffectiveType(\"\") = %q, want %q", got, TypeUserspace)
	}
	if got := EffectiveType(TypeEBPF); got != TypeEBPF {
		t.Fatalf("EffectiveType(%q) = %q, want %q", TypeEBPF, got, TypeEBPF)
	}
}

func TestNewDataPlaneRejectsEmptyDefault(t *testing.T) {
	t.Parallel()

	dp, err := NewDataPlane("")
	if err == nil {
		t.Fatalf("NewDataPlane(\"\") = %T, nil error; want explicit default rejection", dp)
	}
	if !strings.Contains(err.Error(), "defaults to \"userspace\"") {
		t.Fatalf("NewDataPlane(\"\") error = %q, want userspace default hint", err)
	}
}

func TestNewRuntimeDataPlaneMissingUserspaceBackendDoesNotUseEBPF(t *testing.T) {
	t.Parallel()

	dp, err := NewRuntimeDataPlane("")
	if err == nil {
		t.Fatalf("NewRuntimeDataPlane(\"\") = %T, nil error; want missing userspace backend", dp)
	}
	if !strings.Contains(err.Error(), "userspace") {
		t.Fatalf("NewRuntimeDataPlane(\"\") error = %q, want userspace backend error", err)
	}
}
