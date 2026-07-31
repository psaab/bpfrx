package upgrade

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// #6601 r5 MINOR-1: the kernel promotion gate derives the live xpfd from ONE
// pinned systemd unit and deliberately does not infer which unit is the xpf
// one. `xpfd upgrade cut --unit <name>` is a supported standalone selector, so
// a host can legitimately not have that unit — and there the boot-time gate
// cannot run at all. Arming is refused up front rather than letting a candidate
// boot UNVERIFIED and never get promoted.

func withLoadStateProbe(t *testing.T, fn func(context.Context, string) (string, error)) {
	t.Helper()
	orig := unitLoadStateProbeCtx
	t.Cleanup(func() { unitLoadStateProbeCtx = orig })
	unitLoadStateProbeCtx = fn
}

// TestCheckKernelPromotionUnitTriState pins the whole decision table. The
// asymmetry is the point: only a DEFINITE not-found refuses. `systemctl show`
// exits 0 and prints "not-found" for an unknown unit, so a probe ERROR means
// systemctl could not be consulted — which is not evidence of absence, and
// collapsing the two would block arming whenever systemd was briefly
// unreachable.
func TestCheckKernelPromotionUnitTriState(t *testing.T) {
	for _, tc := range []struct {
		name      string
		state     string
		probeErr  error
		wantRefus bool
	}{
		{"loaded", "loaded", nil, false},
		// EXISTS but unusable as a service — still fine here: the gate only
		// needs to read the unit's ExecStart, and a masked/bad unit still has
		// one. Refusing would block arming on a host the gate can handle.
		{"masked", "masked", nil, false},
		{"bad-setting", "bad-setting", nil, false},
		{"error", "error", nil, false},

		// The one refusal.
		{"not-found", "not-found", nil, true},

		// Indeterminate: never refuse on nothing.
		{"probe error", "", errProbe, false},
		{"empty output", "", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withLoadStateProbe(t, func(context.Context, string) (string, error) {
				return tc.state, tc.probeErr
			})
			err := CheckKernelPromotionUnit(context.Background())
			gotRefusal := err != nil
			if gotRefusal != tc.wantRefus {
				t.Fatalf("LoadState=%q err=%v -> refusal=%v, want %v (err=%v)",
					tc.state, tc.probeErr, gotRefusal, tc.wantRefus, err)
			}
			if tc.wantRefus && !errors.Is(err, ErrKernelPromotionUnitAbsent) {
				t.Fatalf("refusal does not wrap ErrKernelPromotionUnitAbsent: %v", err)
			}
		})
	}
}

var errProbe = errors.New("systemctl unavailable")

// TestCheckKernelPromotionUnitProbesTheDefaultUnit: the guard must ask about
// the SAME unit the boot-time gate pins, or it would clear an arm the gate then
// cannot service.
func TestCheckKernelPromotionUnitProbesTheDefaultUnit(t *testing.T) {
	var asked string
	withLoadStateProbe(t, func(_ context.Context, unit string) (string, error) {
		asked = unit
		return "loaded", nil
	})
	if err := CheckKernelPromotionUnit(context.Background()); err != nil {
		t.Fatalf("CheckKernelPromotionUnit: %v", err)
	}
	if asked != DefaultUnit {
		t.Fatalf("probed unit %q, want DefaultUnit %q", asked, DefaultUnit)
	}
}

// TestCheckKernelPromotionUnitRefusalIsActionable: the refusal is what an
// operator sees instead of a silently-unverifiable candidate, so it has to name
// the unit and point at a way forward.
func TestCheckKernelPromotionUnitRefusalIsActionable(t *testing.T) {
	withLoadStateProbe(t, func(context.Context, string) (string, error) {
		return "not-found", nil
	})
	err := CheckKernelPromotionUnit(context.Background())
	if err == nil {
		t.Fatal("want a refusal")
	}
	msg := err.Error()
	for _, want := range []string{DefaultUnit + ".service", "--unit", "UNVERIFIED", "image-replace"} {
		if !strings.Contains(msg, want) {
			t.Errorf("refusal does not mention %q: %s", want, msg)
		}
	}
}

// promoteScriptPath locates the boot-time gate from this package's directory.
func promoteScriptPath(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	// pkg/upgrade -> repo root -> scripts/image/xpf-kernel-promote
	p := filepath.Join(wd, "..", "..", "scripts", "image", "xpf-kernel-promote")
	if _, err := os.Stat(p); err != nil {
		t.Skipf("promote script not found at %s: %v", p, err)
	}
	return p
}

var promoteUnitAssignRE = regexp.MustCompile(`(?m)^PROMOTE_UNIT="([^"]+)"`)

// TestPromoteScriptUnitMatchesDefaultUnit is the CROSS-LANGUAGE drift canary.
//
// The pinning only works if both ends pin the SAME unit. The shell gate
// hardcodes it (it has no way to import a Go constant) and CheckKernelPromotionUnit
// probes DefaultUnit; if those ever diverge, arming would be cleared against one
// unit while the boot-time gate queried another — reintroducing exactly the
// silent non-verification this closes, with the arm-time guard giving false
// assurance. Nothing else in the build couples them, so assert it.
func TestPromoteScriptUnitMatchesDefaultUnit(t *testing.T) {
	data, err := os.ReadFile(promoteScriptPath(t))
	if err != nil {
		t.Fatalf("read promote script: %v", err)
	}
	m := promoteUnitAssignRE.FindSubmatch(data)
	if m == nil {
		t.Fatalf("no `PROMOTE_UNIT=\"...\"` assignment in the promote script; the " +
			"unit pinning is no longer assertable from Go, so the two ends can " +
			"drift silently")
	}
	got := string(m[1])
	want := DefaultUnit + ".service"
	if got != want {
		t.Fatalf("promote script pins PROMOTE_UNIT=%q but Go pins DefaultUnit=%q "+
			"(=> %q). The arm-time guard would clear a host the boot-time gate "+
			"cannot service, or vice versa.", got, DefaultUnit, want)
	}
}

// TestPromoteScriptQueriesOnlyThePinnedUnit: a stray literal unit name in a
// systemctl query would escape the drift canary above, so require every
// systemctl invocation to go through "$PROMOTE_UNIT".
func TestPromoteScriptQueriesOnlyThePinnedUnit(t *testing.T) {
	data, err := os.ReadFile(promoteScriptPath(t))
	if err != nil {
		t.Fatalf("read promote script: %v", err)
	}
	for i, line := range strings.Split(string(data), "\n") {
		code := line
		if idx := strings.Index(code, "#"); idx >= 0 {
			code = code[:idx] // strip comments; prose names the unit freely
		}
		if !strings.Contains(code, "systemctl show") {
			continue
		}
		// The property is that the unit comes from the VARIABLE, never a
		// literal — any spelling of the expansion is fine, including inside an
		// operator-facing advice string that quotes the command back.
		if !strings.Contains(code, `"$PROMOTE_UNIT"`) &&
			!strings.Contains(code, "${PROMOTE_UNIT}") {
			t.Errorf("xpf-kernel-promote:%d names a systemd unit literally rather "+
				"than expanding PROMOTE_UNIT, so the Go drift canary cannot see "+
				"it: %s", i+1, strings.TrimSpace(line))
		}
	}
}
