package config_test

import (
	"strings"
	"testing"
)

// C179-046 (codex-179): the `security log stream <name> severity` schema
// validator must accept exactly the logging.ParseSeverity domain the runtime
// applies (pkg/daemon/daemon_system.go sets SyslogClient.MinSeverity =
// logging.ParseSeverity(stream.Severity)). Before the fix the leaf carried a
// truncated {error, warning, info} enum that REJECTED critical / notice /
// debug / emergency / alert / any / none at commit — every one of which the
// runtime honors — so a valid vSRX severity floor could not be configured
// (commit-rejects-valid). The fix aliases the leaf's enum to the shared
// junosSyslogSeverities SSOT already used by the sibling `system syslog
// <facility> <severity>` leaf.
//
// FAIL-ON-REVERT: restoring syslogSeverities = {"error","info","warning"}
// makes the accept loop below fail — critical/notice/debug/emergency/alert/
// any/none are rejected again.
func TestLogStreamSeverity_FullSSOT_Accepted_5523(t *testing.T) {
	// The whole ParseSeverity domain the runtime maps to a MinSeverity floor.
	accept := []string{
		"any", "none", "emergency", "alert", "critical",
		"error", "warning", "notice", "info", "debug",
	}
	for _, sev := range accept {
		cmd := "set security log stream s severity " + sev
		if err := flatSchemaCheck(t, cmd); err != nil {
			t.Errorf("severity %q must be accepted (runtime ParseSeverity honors it): %v", sev, err)
		}
	}
}

// A genuinely bogus severity is still rejected (no over-accept regression),
// and the error names the offending leaf.
func TestLogStreamSeverity_BogusStillRejected_5523(t *testing.T) {
	for _, sev := range []string{"wraning", "crit", "informational", "asd"} {
		cmd := "set security log stream s severity " + sev
		err := flatSchemaCheck(t, cmd)
		if err == nil {
			t.Errorf("bogus severity %q must be rejected", sev)
			continue
		}
		if !strings.Contains(err.Error(), "severity") {
			t.Errorf("reject %q: error should reference the severity leaf: %v", sev, err)
		}
	}
}
