package cli

import (
	"strings"
	"testing"
)

// TestPrintISSUDrainReportConfirmed: the interactive `request system software
// in-service-upgrade` command certifies the drain and prints the stop/swap
// instruction only when the peer takeover was observed.
func TestPrintISSUDrainReportConfirmed(t *testing.T) {
	out := captureStdout(t, func() { printISSUDrainReport(true) })
	if !strings.Contains(out, "traffic drained to peer") {
		t.Errorf("confirmed ISSU output missing drain confirmation:\n%s", out)
	}
	if !strings.Contains(out, "systemctl stop xpfd") {
		t.Errorf("confirmed ISSU output missing stop/swap instruction:\n%s", out)
	}
	if strings.Contains(out, "Do NOT stop xpfd") {
		t.Errorf("confirmed ISSU output must not warn against stopping:\n%s", out)
	}
}

// TestPrintISSUDrainReportUnconfirmedWithholdsStopCertification is the #5039
// fail-on-revert guard for the CLI surface: an unconfirmed handoff must not
// certify the drain nor unconditionally instruct the operator to stop the only
// forwarding owner.
func TestPrintISSUDrainReportUnconfirmedWithholdsStopCertification(t *testing.T) {
	out := captureStdout(t, func() { printISSUDrainReport(false) })
	if strings.Contains(out, "has been drained to peer") ||
		strings.Contains(out, "traffic drained to peer") {
		t.Errorf("unconfirmed ISSU output must NOT certify the drain:\n%s", out)
	}
	if !strings.Contains(out, "Do NOT stop xpfd yet") {
		t.Errorf("unconfirmed ISSU output must warn against stopping xpfd:\n%s", out)
	}
	if !strings.Contains(out, "show chassis cluster status") {
		t.Errorf("unconfirmed ISSU output must direct the operator to verify handoff:\n%s", out)
	}
	// No copy-pasteable stop command on the unconfirmed path (#5039 review).
	if strings.Contains(out, "systemctl stop") {
		t.Errorf("unconfirmed ISSU output must NOT include a systemctl stop command:\n%s", out)
	}
}
