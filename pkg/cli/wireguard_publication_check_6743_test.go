package cli

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #6743 r2 B4 (pkg/cli half): an operator-facing render must not report
// the backend KIND for a daemon that has no backend.
//
// MEASURED at 710a87569, before the fix, driving an EMPTY cell:
//
//	EMPTY-CELL showSecurityWireguard          => "WireGuard telemetry requires the userspace dataplane"
//	EMPTY-CELL showSecurityWireguardPublicKey => "WireGuard telemetry requires the userspace dataplane"
//	EMPTY-CELL showSystemBuffers              => "Dataplane not loaded"   <- the site the PR DID fix
//
// `c.dp == nil` is permanently false under the daemon's live indirection,
// so the render fell into the "not the userspace backend" arm. See the
// gRPC peer, pkg/grpcapi/wireguard_publication_check_6743_test.go, for the
// full argument; these are the same two renders behind the local console.

// cliWireguardRenders enumerates the renders under test so a third one
// added later is a compile-time addition here rather than a silent
// omission.
func cliWireguardRenders() []struct {
	name   string
	render func(*CLI) error
} {
	return []struct {
		name   string
		render func(*CLI) error
	}{
		{"showSecurityWireguard", func(c *CLI) error { return c.showSecurityWireguard(false) }},
		{"showSecurityWireguardDetail", func(c *CLI) error { return c.showSecurityWireguard(true) }},
		{"showSecurityWireguardPublicKey", (*CLI).showSecurityWireguardPublicKey},
	}
}

// TestCLIWireguardRendersReportAbsenceNotKindOnAnEmptyCell_6743 is the
// fail-on-revert guard.
//
// RED-on-revert: restore `if c.dp == nil` in front of the probe in either
// showSecurityWireguard or showSecurityWireguardPublicKey
// (pkg/cli/cli_show_security_wireguard.go).
func TestCLIWireguardRendersReportAbsenceNotKindOnAnEmptyCell_6743(t *testing.T) {
	for _, tc := range cliWireguardRenders() {
		t.Run(tc.name, func(t *testing.T) {
			// The daemon's live indirection with an EMPTY cell: the
			// interface value is non-nil, the published backend is not.
			// cliLiveIndirection is the shared #2114 fixture from
			// cli_capability_probe_2114_test.go.
			adapter := cliLiveIndirection{Manager: dataplane.New(), backend: nil}
			c := &CLI{dp: adapter}
			if c.dp == nil {
				t.Fatal("fixture broken: c.dp is nil, so the old `dp == nil` check would " +
					"already answer correctly and this test proves nothing")
			}

			got := captureStdout(t, func() {
				if err := tc.render(c); err != nil {
					t.Errorf("%s: %v", tc.name, err)
				}
			})

			if strings.Contains(got, "requires the userspace dataplane") {
				t.Fatalf("%s on an EMPTY cell = %q; want the ABSENCE answer. The render "+
					"reported the backend KIND for a daemon that has no backend at all — "+
					"the #6743 r6-F3 defect, at a site the conversion to dpProbe() left "+
					"behind", tc.name, strings.TrimSpace(got))
			}
			if !strings.Contains(got, "Dataplane not loaded") {
				t.Fatalf("%s on an EMPTY cell = %q; want %q", tc.name,
					strings.TrimSpace(got), "Dataplane not loaded")
			}
		})
	}
}

// TestCLIWireguardRendersStillReportKindForANonUserspaceBackend_6743 is
// the over-reach control, in a SEPARATE body: the fix must not collapse
// the two answers into one. A backend that IS published but carries no
// Status() must still get the capability answer.
func TestCLIWireguardRendersStillReportKindForANonUserspaceBackend_6743(t *testing.T) {
	for _, tc := range cliWireguardRenders() {
		t.Run(tc.name, func(t *testing.T) {
			published := dataplane.New() // PUBLISHED, but no Status()
			if _, ok := any(published).(cliUserspaceStatusProvider); ok {
				t.Fatal("fixture broken: the published backend carries Status(), so the " +
					"capability arm is unreachable")
			}
			c := &CLI{dp: cliLiveIndirection{Manager: dataplane.New(), backend: published}}

			got := captureStdout(t, func() {
				if err := tc.render(c); err != nil {
					t.Errorf("%s: %v", tc.name, err)
				}
			})

			if !strings.Contains(got, "requires the userspace dataplane") {
				t.Fatalf("%s with a PUBLISHED non-userspace backend = %q; want the "+
					"capability answer. Collapsing this into \"Dataplane not loaded\" would "+
					"trade one wrong answer for another", tc.name, strings.TrimSpace(got))
			}
		})
	}
}
