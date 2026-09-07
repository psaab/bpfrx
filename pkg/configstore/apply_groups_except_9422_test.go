package configstore

import (
	"testing"
)

// #9422, the OPERATOR channel. `apply-groups-except` is absent from setSchema,
// so all four channels accepted it; the defect was that none CONSULTED it. The
// remedy keeps it accepted and makes it effective, so this asserts the commit
// path both accepts the statement and honours it.
//
// The control is the whole measurement: before the fix, compiling the same
// config with the `-except` line removed produced an IDENTICAL result.
func TestApplyGroupsExceptHonouredAtCommit9422(t *testing.T) {
	const withExcept = `system { host-name p; }
groups { G { system { domain-name FROM-GROUP; } } }
apply-groups G;
system { apply-groups-except G; time-zone UTC; }`
	const control = `system { host-name p; }
groups { G { system { domain-name FROM-GROUP; } } }
apply-groups G;
system { time-zone UTC; }`

	ctrl, err := CheckText(control, -1)
	if err != nil {
		t.Fatalf("control rejected by the operator commit path: %v", err)
	}
	if ctrl.System.DomainName != "FROM-GROUP" {
		t.Fatalf("POSITIVE CONTROL broken: without the `-except` line the group must be "+
			"inherited, got DomainName=%q", ctrl.System.DomainName)
	}

	got, err := CheckText(withExcept, -1)
	if err != nil {
		t.Fatalf("`apply-groups-except` rejected by the operator commit path: %v", err)
	}
	if got.System.DomainName != "" {
		t.Fatalf("`apply-groups-except G` was accepted and ignored at commit: DomainName=%q "+
			"— the operator got configuration they explicitly excluded (#9422)",
			got.System.DomainName)
	}
	if got.System.TimeZone != "UTC" {
		t.Fatalf("the excluding stanza lost its own inline statement: TimeZone=%q", got.System.TimeZone)
	}
	if len(got.Warnings) != 0 {
		t.Errorf("unexpected warnings: %v", got.Warnings)
	}
}
