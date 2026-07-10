package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/logging"
)

// TestSyslogHostMinSeverity_AnyCritical is the daemon-side #5314 regression.
// `set system syslog host H any critical` parses to facility=any,
// severity=critical. The old guard tested `if sev > 0`, but ParseSeverity only
// mapped error/warning/info, so ParseSeverity("critical") returned 0 and the
// guard left MinSeverity at the 0 send-all sentinel — the host then received
// info/warning/error records it was never authorized for.
//
// This asserts the computed client filter is the critical threshold, and that a
// SyslogClient carrying it forwards critical/alert/emergency but NOT
// error/warning/info. On revert (3-severity ParseSeverity), MinSeverity == 0
// and every "must NOT forward" assertion goes RED.
func TestSyslogHostMinSeverity_AnyCritical(t *testing.T) {
	facilities := []config.SyslogFacility{{Facility: "any", Severity: "critical"}}

	min := syslogHostMinSeverity(facilities)
	if min != logging.SyslogCritical {
		t.Fatalf("syslogHostMinSeverity(any critical) = %d, want %d (critical)", min, logging.SyslogCritical)
	}

	c := &logging.SyslogClient{MinSeverity: min}
	for _, sev := range []int{logging.SyslogEmergency, logging.SyslogAlert, logging.SyslogCritical} {
		if !c.ShouldSend(sev) {
			t.Errorf("host `any critical` should forward severity %d", sev)
		}
	}
	for _, sev := range []int{logging.SyslogError, logging.SyslogWarning, logging.SyslogNotice, logging.SyslogInfo} {
		if c.ShouldSend(sev) {
			t.Errorf("host `any critical` MUST NOT forward severity %d — #5314 over-forward", sev)
		}
	}
}

// TestSyslogHostMinSeverity_EmergencyNotSendAll proves the guard no longer
// drops emergency: `host H any emergency` must yield the emergency-only filter,
// NOT the send-all sentinel. The old `if sev > 0` guard would also have dropped
// emergency (its threshold code is negative), leaving MinSeverity at 0.
func TestSyslogHostMinSeverity_EmergencyNotSendAll(t *testing.T) {
	min := syslogHostMinSeverity([]config.SyslogFacility{{Facility: "any", Severity: "emergency"}})
	if min != logging.SeverityEmergency {
		t.Fatalf("syslogHostMinSeverity(any emergency) = %d, want %d (emergency)", min, logging.SeverityEmergency)
	}
	c := &logging.SyslogClient{MinSeverity: min}
	if !c.ShouldSend(logging.SyslogEmergency) {
		t.Error("host `any emergency` should forward emergency")
	}
	if c.ShouldSend(logging.SyslogAlert) {
		t.Error("host `any emergency` MUST NOT forward alert (emergency != send-all)")
	}
}

// TestSyslogHostMinSeverity_Merge folds several facility pairs into the most
// restrictive client filter, and confirms an unspecified severity defaults to
// send-all.
func TestSyslogHostMinSeverity_Merge(t *testing.T) {
	// Most restrictive of {info, critical, warning} is critical.
	min := syslogHostMinSeverity([]config.SyslogFacility{
		{Facility: "daemon", Severity: "info"},
		{Facility: "kern", Severity: "critical"},
		{Facility: "auth", Severity: "warning"},
	})
	if min != logging.SyslogCritical {
		t.Errorf("merge = %d, want %d (critical, most restrictive)", min, logging.SyslogCritical)
	}

	// No facilities / no severity => 0 (send-all) default.
	if got := syslogHostMinSeverity(nil); got != 0 {
		t.Errorf("syslogHostMinSeverity(nil) = %d, want 0 (send-all)", got)
	}
	if got := syslogHostMinSeverity([]config.SyslogFacility{{Facility: "daemon"}}); got != 0 {
		t.Errorf("syslogHostMinSeverity(no severity) = %d, want 0 (send-all)", got)
	}
}
