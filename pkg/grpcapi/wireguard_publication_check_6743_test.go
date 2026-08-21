package grpcapi

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// grpcMandatoryOnlyBackend6743 is a PUBLISHED backend that carries the
// mandatory surface and no optional capability, and is deliberately not a
// dataplane.LiveUnwrapper so Unwrap stops at it.
type grpcMandatoryOnlyBackend6743 struct{ grpcRuntime }

// #6743 r2 B4: an operator-facing render must not report the backend KIND
// for a daemon that has no backend.
//
// This is the PR's own r6-F3 argument — "`dp != nil` no longer means a
// dataplane exists", so a render keyed on the field makes "a claim about a
// LOADED backend's maps for a daemon that had just lost its backend" —
// applied to the two WireGuard renders, which the PR converted to
// dpProbe() and left with the old `s.dp == nil` publication check.
//
// MEASURED at 710a87569, before the fix, driving an EMPTY cell (the
// bootstrap-exit re-arm failure at daemon_run_naming.go clears it):
//
//	EMPTY-CELL showWireguard       => "WireGuard telemetry requires the userspace dataplane"
//	EMPTY-CELL showWireguardPubKey => "WireGuard telemetry requires the userspace dataplane"
//	EMPTY-CELL showBuffers         => "Dataplane not loaded"   <- the site the PR DID fix
//	NIL-DP     showWireguard       => "Dataplane not loaded"   <- the control
//
// `s.dp == nil` is permanently false under the live indirection, so the
// render fell into the "not the userspace backend" arm and told the
// operator their firewall is running a non-userspace dataplane. The only
// runtime forwarding path is the userspace helper (#1373), so that answer
// is not merely imprecise — it names a backend class that cannot exist,
// and it sends the operator looking at `system dataplane-type` instead of
// at the daemon that failed to arm.
//
// The peer guard for pkg/cli's two identical renders is
// pkg/cli/wireguard_publication_check_6743_test.go.

// wireguardRenders enumerates the renders under test so a third one added
// later is a compile-time addition here rather than a silent omission.
func wireguardRenders() []struct {
	name   string
	render func(*Server, *strings.Builder)
} {
	return []struct {
		name   string
		render func(*Server, *strings.Builder)
	}{
		{"showWireguard", func(s *Server, buf *strings.Builder) { s.showWireguard(buf, false) }},
		{"showWireguardDetail", func(s *Server, buf *strings.Builder) { s.showWireguard(buf, true) }},
		{"showWireguardPublicKey", func(s *Server, buf *strings.Builder) { s.showWireguardPublicKey(buf) }},
	}
}

// TestWireguardRendersReportAbsenceNotKindOnAnEmptyCell_6743 is the
// fail-on-revert guard.
//
// RED-on-revert: restore `if s.dp == nil` in front of the probe in either
// showWireguard or showWireguardPublicKey
// (pkg/grpcapi/server_show_security_text.go).
func TestWireguardRendersReportAbsenceNotKindOnAnEmptyCell_6743(t *testing.T) {
	for _, tc := range wireguardRenders() {
		t.Run(tc.name, func(t *testing.T) {
			// The daemon's live indirection with an EMPTY cell: the
			// interface value is non-nil, the published backend is not.
			s := &Server{dp: &grpcIndirection6743{backend: nil}}

			// PRECONDITION: the shape under test is exactly "the field is
			// non-nil but nothing is published". Without this a nil-dp
			// fixture would pass for the wrong reason.
			if s.dp == nil {
				t.Fatal("fixture broken: s.dp is nil, so the old `dp == nil` check would " +
					"already answer correctly and this test proves nothing")
			}

			var buf strings.Builder
			tc.render(s, &buf)
			got := buf.String()

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

// TestWireguardRendersStillReportKindForANonUserspaceBackend_6743 is the
// over-reach control, in a SEPARATE body: the fix must not collapse the
// two answers into one. A backend that IS published but does not carry the
// optional Status() capability must still get the capability answer, not
// "Dataplane not loaded".
//
// The published value must satisfy the MANDATORY surface and nothing
// else, and — measured, not assumed — must NOT itself be a
// dataplane.LiveUnwrapper: an earlier revision of this test published a
// second grpcIndirection6743, whose own Unwrap() resolved on through to a
// nil backend, so the "published" arm was really the empty-cell arm and
// the control failed for a fixture reason. grpcMandatoryOnlyBackend6743
// exists to have no Unwrap method at all.
func TestWireguardRendersStillReportKindForANonUserspaceBackend_6743(t *testing.T) {
	for _, tc := range wireguardRenders() {
		t.Run(tc.name, func(t *testing.T) {
			published := &grpcMandatoryOnlyBackend6743{} // no Status(), but PUBLISHED
			if _, ok := any(published).(userspaceStatusProvider); ok {
				t.Fatal("fixture broken: the published backend carries Status(), so the " +
					"capability arm is unreachable")
			}
			if _, ok := any(published).(dataplane.LiveUnwrapper); ok {
				t.Fatal("fixture broken: the published backend is itself an unwrapper, so " +
					"dataplane.Unwrap resolves PAST it and this is the empty-cell arm")
			}
			s := &Server{dp: &grpcIndirection6743{backend: published}}

			var buf strings.Builder
			tc.render(s, &buf)
			got := buf.String()

			if !strings.Contains(got, "requires the userspace dataplane") {
				t.Fatalf("%s with a PUBLISHED non-userspace backend = %q; want the "+
					"capability answer. Collapsing this into \"Dataplane not loaded\" would "+
					"trade one wrong answer for another", tc.name, strings.TrimSpace(got))
			}
		})
	}
}
