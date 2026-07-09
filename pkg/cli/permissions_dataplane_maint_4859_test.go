package cli

import (
	"strings"
	"testing"
)

// TestCheckPermission_DestructiveDataplaneRequiresMaint pins #4859: the
// destructive userspace-dataplane control verbs — `request chassis cluster
// data-plane userspace forwarding disarm`, `queue N {unregister|disarm}`,
// `binding slot N {unregister|disarm}`, `inject-packet ...` — and the ISSU
// ownership drain `request system software in-service-upgrade` take forwarding
// / redirect ownership out of service or force RGs secondary. They must require
// the super-user-only PermMaint, not the plain PermControl that the predefined
// operator class holds.
//
// RED on revert: the pre-fix requestSubcommandIsMaintenance classified only
// system reboot/halt/power-off/zeroize + cluster failover, so these leaves fell
// through to PermControl and operator was ALLOWED — every operator subtest here
// goes RED.
func TestCheckPermission_DestructiveDataplaneRequiresMaint(t *testing.T) {
	destructive := [][]string{
		{"request", "chassis", "cluster", "data-plane", "userspace", "forwarding", "disarm"},
		{"request", "chassis", "cluster", "data-plane", "userspace", "queue", "3", "unregister"},
		{"request", "chassis", "cluster", "data-plane", "userspace", "queue", "3", "disarm"},
		{"request", "chassis", "cluster", "data-plane", "userspace", "binding", "slot", "2", "unregister"},
		{"request", "chassis", "cluster", "data-plane", "userspace", "binding", "slot", "2", "disarm"},
		{"request", "chassis", "cluster", "data-plane", "userspace", "inject-packet", "slot", "0", "valid"},
		{"request", "system", "software", "in-service-upgrade"},
	}

	tests := []struct {
		class string
		allow bool
	}{
		{"super-user", true},
		{"operator", false},
		{"read-only", false},
		{"config-viewer", false},
	}
	for _, tc := range tests {
		t.Run(tc.class, func(t *testing.T) {
			c := &CLI{userClass: tc.class}
			for _, parts := range destructive {
				err := c.checkPermission(parts)
				cmd := strings.Join(parts, " ")
				if tc.allow && err != nil {
					t.Errorf("%q denied for %q: %v (want allowed)", cmd, tc.class, err)
				}
				if !tc.allow && err == nil {
					t.Errorf("%q ALLOWED for %q (want denied — destructive maintenance)", cmd, tc.class)
				}
			}
		})
	}
}

// TestCheckPermission_RestorativeDataplaneStaysControl asserts the gate is
// surgical: the RESTORATIVE dataplane verbs (arm / register) stay at
// PermControl so operator keeps its benign live-dataplane control. RED if the
// gate over-classifies arm|register as maintenance.
func TestCheckPermission_RestorativeDataplaneStaysControl(t *testing.T) {
	op := &CLI{userClass: "operator"}
	restorative := [][]string{
		{"request", "chassis", "cluster", "data-plane", "userspace", "forwarding", "arm"},
		{"request", "chassis", "cluster", "data-plane", "userspace", "queue", "3", "register"},
		{"request", "chassis", "cluster", "data-plane", "userspace", "queue", "3", "arm"},
		{"request", "chassis", "cluster", "data-plane", "userspace", "binding", "slot", "2", "register"},
		{"request", "chassis", "cluster", "data-plane", "userspace", "binding", "slot", "2", "arm"},
	}
	for _, parts := range restorative {
		if err := op.checkPermission(parts); err != nil {
			t.Errorf("operator DENIED restorative %q: %v (want allowed — control-level)", strings.Join(parts, " "), err)
		}
	}
}

// TestCheckPermission_DataplaneMaintAbbreviationCannotBypass asserts the gate
// resolves prefix abbreviations the same way the dispatcher does, so an
// abbreviated destructive verb cannot slip past as plain control. operator must
// stay DENIED; super-user allowed.
func TestCheckPermission_DataplaneMaintAbbreviationCannotBypass(t *testing.T) {
	abbrev := [][]string{
		// data-plane / userspace / forwarding abbreviated; the operation token
		// "disarm" is spelled in full (the dispatcher exact-matches it).
		{"request", "chassis", "cluster", "data-p", "user", "forw", "disarm"},
		{"request", "sys", "soft", "in-service-upgrade"},
	}
	op := &CLI{userClass: "operator"}
	su := &CLI{userClass: "super-user"}
	for _, parts := range abbrev {
		if err := op.checkPermission(parts); err == nil {
			t.Errorf("operator ALLOWED %q (abbreviation bypassed the maintenance gate)", strings.Join(parts, " "))
		}
		if err := su.checkPermission(parts); err != nil {
			t.Errorf("super-user denied %q: %v (want allowed)", strings.Join(parts, " "), err)
		}
	}
}
