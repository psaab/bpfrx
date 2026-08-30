package cluster

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// ip_monitoring_status_7338_test.go — #7338.
//
// `show chassis cluster ip-monitoring status` printed "No IP monitoring
// failures" for a redundancy group that ip-monitoring had actively DEMOTED.
//
// The renderer filtered failures by the raw `"ip:"` prefix. Global-threshold
// mode installs a SINGLE aggregate debt under `ipAggregateMonitorName`, which
// deliberately does not carry that prefix, and installs NO per-target debts by
// design — so the filter matched nothing and the renderer fell through to the
// all-clear line. The screen was blank in BOTH dimensions.
//
// That is a false negative on a diagnostic, which is worse than a wrong number:
// an operator reads it as EVIDENCE and rules ip-monitoring out, during the
// post-mortem of the very failover its global-weight demotion may have caused.
// And global-threshold mode is the vSRX-parity mode — the one an operator
// following Junos documentation configures.
//
// The discriminator (`isIPMonitorName`) already existed, and its own doc says
// any code reconciling ONE class must use it. This renderer was such code.

// newIPMonStatusManager7338 builds a manager whose RG 1 is in the requested
// ip-monitoring mode, with `failed` installed as current monitor failures.
func newIPMonStatusManager7338(t *testing.T, globalThreshold int, failed ...string) *Manager {
	t.Helper()
	m := NewManager(0, 1)
	rg := makeRG(1, false, map[int]int{0: 200})
	rg.IPMonitoring = &config.IPMonitoring{
		GlobalWeight:    120,
		GlobalThreshold: globalThreshold,
		Targets: []*config.IPMonitorTarget{
			{Address: "10.9.9.9", Weight: 60},
			{Address: "10.9.9.10", Weight: 60},
		},
	}
	cfg := makeConfig(rg)
	m.UpdateConfig(cfg)
	m.monitor = NewMonitor(m, cfg.RedundancyGroups)

	m.mu.Lock()
	for _, st := range m.groups {
		if st.GroupID == 1 {
			st.MonitorFails = append([]string(nil), failed...)
		}
	}
	m.mu.Unlock()
	return m
}

// THE DEFECT. A global-threshold demotion must not render as "no failures".
func TestGlobalThresholdDemotionIsNotReportedAsNoFailures7338(t *testing.T) {
	m := newIPMonStatusManager7338(t, 100, ipAggregateMonitorName)
	out := m.FormatIPMonitoringStatus()

	if strings.Contains(out, "No IP monitoring failures") {
		t.Errorf("an RG that ip-monitoring DEMOTED via the global threshold still "+
			"prints the all-clear line. An operator reads that as evidence and rules "+
			"ip-monitoring out during the post-mortem of the failover it caused "+
			"(#7338):\n%s", out)
	}
}

// The rendered row must name the CROSSING and the applied weight — not an
// address, because in this mode no per-address debt exists to name.
func TestGlobalThresholdRowNamesThresholdAndWeight7338(t *testing.T) {
	m := newIPMonStatusManager7338(t, 100, ipAggregateMonitorName)
	out := m.FormatIPMonitoringStatus()

	for _, want := range []string{"global threshold crossed", "threshold 100", "weight 120"} {
		if !strings.Contains(out, want) {
			t.Errorf("the global-threshold row does not surface %q; an operator cannot "+
				"tell WHY the group demoted or by how much (#7338):\n%s", want, out)
		}
	}
	// It must not invent a target address. In global-threshold mode
	// desiredRGIPDebts installs one aggregate debt and returns, so there is no
	// per-address debt — rendering one would be a fabricated fact on a
	// diagnostic that just stopped lying.
	if strings.Contains(out, "10.9.9.9    ") || strings.Contains(out, "Status: unreachable") {
		t.Errorf("the global-threshold row named a target address as unreachable. No "+
			"per-target debt exists in this mode, so that is invented (#7338):\n%s", out)
	}
}

// CONTROL 1 — independent (per-target) mode output is UNCHANGED.
//
// This is the cell that stops the fix being "print something for every RG":
// restoring the old prefix filter must leave THIS green while the two above go
// red, which is what makes the fix attributable to the aggregate class.
func TestPerTargetModeOutputIsUnchanged7338(t *testing.T) {
	m := newIPMonStatusManager7338(t, 0, "ip:10.9.9.9")
	out := m.FormatIPMonitoringStatus()

	if !strings.Contains(out, "10.9.9.9") || !strings.Contains(out, "Status: unreachable") {
		t.Errorf("per-target mode no longer renders the unreachable target:\n%s", out)
	}
	if strings.Contains(out, "global threshold crossed") {
		t.Errorf("per-target mode rendered a global-threshold row; the two classes are "+
			"distinct and must not bleed:\n%s", out)
	}
	if strings.Contains(out, "No IP monitoring failures") {
		t.Errorf("per-target mode with a failed target printed the all-clear line:\n%s", out)
	}
}

// CONTROL 2 — a genuinely healthy RG must STILL print the all-clear line.
//
// Without this, a "fix" that simply deleted the all-clear branch would satisfy
// every cell above while destroying the only positive signal the command has.
func TestHealthyRGStillReportsNoFailures7338(t *testing.T) {
	m := newIPMonStatusManager7338(t, 100)
	out := m.FormatIPMonitoringStatus()

	if !strings.Contains(out, "No IP monitoring failures") {
		t.Errorf("an RG with no ip-monitoring failures must still say so; removing the "+
			"all-clear line would leave the operator unable to distinguish healthy from "+
			"unrendered:\n%s", out)
	}
}

// The accessor must report ok=false for independent mode, so a caller cannot
// mistake a zero threshold for a configured one.
func TestIPGlobalThresholdReportsModeNotJustNumbers7338(t *testing.T) {
	m := newIPMonStatusManager7338(t, 0)
	if _, _, ok := m.monitor.IPGlobalThreshold(1); ok {
		t.Error("IPGlobalThreshold reported ok for an RG in independent mode; a caller " +
			"would then render a global-threshold row for a per-target configuration")
	}
	m2 := newIPMonStatusManager7338(t, 100)
	th, w, ok := m2.monitor.IPGlobalThreshold(1)
	if !ok || th != 100 || w != 120 {
		t.Errorf("IPGlobalThreshold(1) = (%d, %d, %v), want (100, 120, true)", th, w, ok)
	}
	if _, _, ok := m2.monitor.IPGlobalThreshold(99); ok {
		t.Error("IPGlobalThreshold reported ok for an RG that does not exist")
	}
}
