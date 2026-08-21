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

	// `any` is the wildcard: it applies whatever facility the client stamps.
	min := syslogHostMinSeverity(facilities, logging.FacilityDaemon)
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
	min := syslogHostMinSeverity([]config.SyslogFacility{{Facility: "any", Severity: "emergency"}}, logging.FacilityDaemon)
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

// TestSyslogHostMinSeverity_SameFacilityMerge folds several pairs naming the
// SAME facility into the most restrictive client filter, and confirms an
// unspecified severity defaults to send-all.
//
// #5797 retarget: this test previously asserted a cross-FACILITY fold —
// {daemon info, kern critical, auth warning} => critical — which is the defect
// #5797 names, not a contract. `MoreRestrictiveMinSeverity` is still the merge
// rule; what changed is the POPULATION it merges, which is now only the
// selectors that can match a record this client emits. Two selectors naming one
// facility remain a genuine conflict on that facility and still fold.
func TestSyslogHostMinSeverity_SameFacilityMerge(t *testing.T) {
	// Most restrictive of {info, critical, warning} on ONE facility is critical.
	min := syslogHostMinSeverity([]config.SyslogFacility{
		{Facility: "daemon", Severity: "info"},
		{Facility: "daemon", Severity: "critical"},
		{Facility: "daemon", Severity: "warning"},
	}, logging.FacilityDaemon)
	if min != logging.SyslogCritical {
		t.Errorf("same-facility merge = %d, want %d (critical, most restrictive)", min, logging.SyslogCritical)
	}

	// No facilities / no severity => 0 (send-all) default.
	if got := syslogHostMinSeverity(nil, logging.FacilityDaemon); got != 0 {
		t.Errorf("syslogHostMinSeverity(nil) = %d, want 0 (send-all)", got)
	}
	if got := syslogHostMinSeverity([]config.SyslogFacility{{Facility: "daemon"}}, logging.FacilityDaemon); got != 0 {
		t.Errorf("syslogHostMinSeverity(no severity) = %d, want 0 (send-all)", got)
	}
}
