package lldp

import (
	"context"
	"errors"
	"net"
	"slices"
	"testing"
)

// resolveOnly installs an interface lookup that resolves exactly the given
// KERNEL names and fails everything else, and makes socket setup fail so no
// real socket is opened. It restores both seams on cleanup.
func resolveOnly(t *testing.T, kernelNames ...string) {
	t.Helper()
	ok := make(map[string]bool, len(kernelNames))
	for _, n := range kernelNames {
		ok[n] = true
	}
	SetInterfaceByNameForTesting(func(name string) (*net.Interface, error) {
		if ok[name] {
			return &net.Interface{Index: 1, Name: name}, nil
		}
		return nil, errors.New("no such interface: " + name)
	})
	FailIfSessionForTesting(errors.New("injected: no CAP_NET_RAW in test"))
	t.Cleanup(func() {
		SetInterfaceByNameForTesting(nil)
		FailIfSessionForTesting(nil)
	})
}

func cfgFor(names ...string) *LLDPConfig {
	c := &LLDPConfig{}
	for _, n := range names {
		c.Interfaces = append(c.Interfaces, LLDPInterface{Name: n})
	}
	return c
}

// TestApplyReportsUnresolvedInterfaces6794 pins the producer half of #6794.
//
// Manager.Apply brings each configured interface up INDEPENDENTLY and a lookup
// failure skips just that one, so a call that "succeeded" can leave part of the
// generation dark. It used to return nothing at all, which is what let the
// caller's unchanged-config guard treat an incomplete generation as converged.
//
// The table has one row per branch, because a fixture that never enters a
// branch cannot see that branch's guard: all-resolvable, none-resolvable, and
// the MIXED row — the mixed row is the one that fails a "fix" that reports
// all-or-nothing instead of naming the actual failures.
func TestApplyReportsUnresolvedInterfaces6794(t *testing.T) {
	tests := []struct {
		name    string
		present []string
		cfg     []string
		want    []string
	}{
		{"all-resolvable", []string{"ge-0-0-0", "ge-0-0-1"}, []string{"ge-0/0/0", "ge-0/0/1"}, nil},
		{"none-resolvable", nil, []string{"ge-0/0/0", "ge-0/0/1"}, []string{"ge-0/0/0", "ge-0/0/1"}},
		{"mixed-partial", []string{"ge-0-0-0"}, []string{"ge-0/0/0", "ge-0/0/1"}, []string{"ge-0/0/1"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resolveOnly(t, tc.present...)
			m := New()
			t.Cleanup(m.Stop)

			got := m.Apply(context.Background(), cfgFor(tc.cfg...))
			if !slices.Equal(got, tc.want) {
				t.Errorf("Apply unresolved = %v, want %v. A partial apply that reports nothing is "+
					"indistinguishable from a converged one, so the caller's unchanged-config "+
					"guard skips the reconcile that would have recovered it (#6794)", got, tc.want)
			}
		})
	}
}

// TestApplyReturnsNothingForADisabledConfig6794 covers the early-return branch:
// a nil/disabled/empty config stops the service and has no interfaces to fail,
// so there is no retry debt to report. Without this row the nil branch's return
// is unbound.
func TestApplyReturnsNothingForADisabledConfig6794(t *testing.T) {
	resolveOnly(t)
	m := New()
	t.Cleanup(m.Stop)

	for _, cfg := range []*LLDPConfig{nil, {Disable: true}, {}} {
		if got := m.Apply(context.Background(), cfg); got != nil {
			t.Errorf("Apply(%v) unresolved = %v, want nil: a disabled config has no interfaces to "+
				"fail and must not manufacture retry debt", cfg, got)
		}
	}
}

// TestInterfaceResolvableAgreesWithApply6794 binds the AGREEMENT between the
// two places that decide whether a configured interface exists, rather than
// pinning either one.
//
// Apply resolves `config.LinuxIfName(name)`; InterfaceResolvable is what the
// daemon's recovery guard consults to decide whether a previously-unresolved
// interface has appeared. If those two ever disagreed — a different name form,
// a different seam — the guard would either never fire (no recovery, the
// original bug) or fire forever (churn). The Junos slash form is the case that
// would expose a divergence, since a slash never appears in a kernel ifname.
func TestInterfaceResolvableAgreesWithApply6794(t *testing.T) {
	for _, tc := range []struct {
		name    string
		present []string
		iface   string
		want    bool
	}{
		{"slash-form-resolves-via-kernel-dash-name", []string{"ge-0-0-0"}, "ge-0/0/0", true},
		{"slash-form-absent", nil, "ge-0/0/0", false},
		{"already-kernel-form", []string{"em0"}, "em0", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolveOnly(t, tc.present...)

			if got := InterfaceResolvable(tc.iface); got != tc.want {
				t.Errorf("InterfaceResolvable(%q) = %v, want %v", tc.iface, got, tc.want)
			}

			// The agreement: Apply must report it unresolved exactly when
			// InterfaceResolvable says it is not resolvable.
			m := New()
			t.Cleanup(m.Stop)
			unresolved := m.Apply(context.Background(), cfgFor(tc.iface))
			applySaysResolvable := !slices.Contains(unresolved, tc.iface)
			if applySaysResolvable != tc.want {
				t.Errorf("Apply and InterfaceResolvable disagree for %q: Apply resolvable=%v, "+
					"InterfaceResolvable=%v. The daemon's recovery guard reads one and the apply "+
					"acts on the other, so a divergence means either no recovery or endless "+
					"re-apply (#6794)", tc.iface, applySaysResolvable, tc.want)
			}
		})
	}
}
