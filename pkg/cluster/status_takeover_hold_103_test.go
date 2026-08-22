package cluster

import (
	"strings"
	"testing"
	"time"
)

// #103 item 5: "CLI/status should show RG readiness reasons and remaining hold
// timer." The reasons were rendered; the hold was not. Ready and
// takeover-ELIGIBLE are different properties — election gates on
// IsReadyForTakeover (Ready AND ReadySince+holdTime elapsed) — so between
// SetRGReady(ready) and the end of the hold window an RG is Ready while every
// election gate declines to promote it. The status line reported that as a bare
// "Takeover ready: yes", contradicting the election with nothing naming the
// hold.

func holdManager(t *testing.T, holdMS int) *Manager {
	t.Helper()
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, false, map[int]int{0: 200, 1: 100}))
	cfg.ControlInterface = "em0" // cluster mode: the election gates are armed
	cfg.TakeoverHoldTime = holdMS
	m.UpdateConfig(cfg)
	return m
}

// takeoverReadyLine returns the "Takeover ready:" line from a status render.
func takeoverReadyLine(t *testing.T, out string) string {
	t.Helper()
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "Takeover ready:") {
			return strings.TrimSpace(l)
		}
	}
	t.Fatalf("no 'Takeover ready:' line in:\n%s", out)
	return ""
}

// The core defect: inside the hold window the RG is Ready, election refuses to
// promote it, and the status must say so.
func TestFormatStatus_InsideHoldWindowIsNotTakeoverReady(t *testing.T) {
	m := holdManager(t, 5000)
	m.SetRGReady(0, true, nil)

	// The election agrees the RG is not promotable.
	m.mu.Lock()
	m.peerAlive = true
	m.peerEverSeen = true
	m.electSingleNode()
	state := m.groups[0].State
	m.mu.Unlock()
	if state == StatePrimary {
		t.Fatalf("precondition broken: election promoted inside the hold window (state=%v)", state)
	}

	line := takeoverReadyLine(t, m.FormatStatus())
	if !strings.HasPrefix(line, "Takeover ready: no") {
		t.Errorf("FormatStatus reports %q while election declines to promote; want a 'no'", line)
	}
	if !strings.Contains(line, "takeover hold") {
		t.Errorf("FormatStatus line %q does not name the takeover hold", line)
	}
	if !strings.Contains(line, "remaining") {
		t.Errorf("FormatStatus line %q does not report the remaining hold", line)
	}
}

// Same property on the `information` render, which additionally must report the
// configured hold so the remaining value can be read in context.
func TestFormatInformation_InsideHoldWindowNamesHold(t *testing.T) {
	m := holdManager(t, 5000)
	m.SetRGReady(0, true, nil)

	out := m.FormatInformation()
	if !strings.Contains(out, "Takeover hold time: 5s") {
		t.Errorf("FormatInformation lacks the configured 'Takeover hold time: 5s':\n%s", out)
	}
	line := takeoverReadyLine(t, out)
	if !strings.HasPrefix(line, "Takeover ready: no") {
		t.Errorf("FormatInformation reports %q inside the hold window; want a 'no'", line)
	}
	if !strings.Contains(line, "takeover hold") || !strings.Contains(line, "remaining") {
		t.Errorf("FormatInformation line %q does not report the remaining hold", line)
	}
	// The ready-since instant stays visible: it is what the hold counts from.
	if !strings.Contains(line, "ready since") {
		t.Errorf("FormatInformation line %q dropped the ready-since instant", line)
	}
}

// Once the hold has elapsed, IsReadyForTakeover is true and the render must go
// back to a plain "yes" — otherwise the fix would just move the lie.
func TestFormatStatus_ElapsedHoldIsTakeoverReady(t *testing.T) {
	m := holdManager(t, 5000)
	m.SetRGReady(0, true, nil)

	// Backdate ReadySince past the hold instead of sleeping.
	m.mu.Lock()
	m.groups[0].ReadySince = time.Now().Add(-6 * time.Second)
	rg := *m.groups[0]
	hold := m.takeoverHoldTime
	m.mu.Unlock()
	if !rg.IsReadyForTakeover(hold) {
		t.Fatalf("precondition broken: RG not takeover-ready after backdating ReadySince")
	}

	for name, out := range map[string]string{
		"status":      m.FormatStatus(),
		"information": m.FormatInformation(),
	} {
		line := takeoverReadyLine(t, out)
		if !strings.HasPrefix(line, "Takeover ready: yes") {
			t.Errorf("%s reports %q after the hold elapsed; want 'yes'", name, line)
		}
		if strings.Contains(line, "takeover hold") {
			t.Errorf("%s still names the hold after it elapsed: %q", name, line)
		}
	}
}

// A NOT-ready RG must keep reporting its real readiness reasons. The hold is
// not what is blocking it, so naming the hold there would bury the actual
// cause.
func TestFormatStatus_NotReadyReportsReasonsNotHold(t *testing.T) {
	m := holdManager(t, 5000)
	m.SetRGReady(0, false, []string{"interface ge-0/0/1 missing"})

	for name, out := range map[string]string{
		"status":      m.FormatStatus(),
		"information": m.FormatInformation(),
	} {
		line := takeoverReadyLine(t, out)
		if !strings.Contains(line, "interface ge-0/0/1 missing") {
			t.Errorf("%s dropped the readiness reason: %q", name, line)
		}
		if strings.Contains(line, "takeover hold") {
			t.Errorf("%s names the hold on a NOT-ready RG, burying the real cause: %q", name, line)
		}
	}
}

// With takeover-hold-time unset — the default — the hold contributes nothing
// and neither render may change. This is what bounds the blast radius of the
// change onto clusters that actually configured a hold, including the
// pkg/upgrade precheck that parses the first token after "Takeover ready:".
func TestFormatRenders_DefaultHoldIsUnchanged(t *testing.T) {
	m := holdManager(t, 0)
	if got := m.TakeoverHoldTime(); got != DefaultTakeoverHoldTime {
		t.Fatalf("TakeoverHoldTime() = %v, want the default %v", got, DefaultTakeoverHoldTime)
	}
	m.SetRGReady(0, true, nil)

	if line := takeoverReadyLine(t, m.FormatStatus()); line != "Takeover ready: yes" {
		t.Errorf("FormatStatus line = %q, want an unchanged bare 'Takeover ready: yes'", line)
	}
	info := m.FormatInformation()
	if strings.Contains(info, "Takeover hold time:") {
		t.Errorf("FormatInformation emits a hold-time line at the default 0:\n%s", info)
	}
	if line := takeoverReadyLine(t, info); !strings.HasPrefix(line, "Takeover ready: yes (since ") {
		t.Errorf("FormatInformation line = %q, want the unchanged 'yes (since ...)' form", line)
	}
}

// TakeoverHoldRemaining must return 0 for every case that is NOT "ready and
// still inside the hold", so no caller can read a positive remaining off an RG
// the hold is not gating.
func TestTakeoverHoldRemaining_ZeroCases(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name string
		rg   RedundancyGroupState
		hold time.Duration
	}{
		{"not ready", RedundancyGroupState{Ready: false, ReadySince: now}, 5 * time.Second},
		{"ready but zero ReadySince", RedundancyGroupState{Ready: true}, 5 * time.Second},
		{"no hold configured", RedundancyGroupState{Ready: true, ReadySince: now}, 0},
		{"negative hold", RedundancyGroupState{Ready: true, ReadySince: now}, -time.Second},
		{"hold elapsed", RedundancyGroupState{Ready: true, ReadySince: now.Add(-time.Minute)}, 5 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.rg.TakeoverHoldRemaining(tt.hold); got != 0 {
				t.Errorf("TakeoverHoldRemaining = %v, want 0", got)
			}
		})
	}

	rg := RedundancyGroupState{Ready: true, ReadySince: now}
	got := rg.TakeoverHoldRemaining(5 * time.Second)
	if got <= 0 || got > 5*time.Second {
		t.Errorf("TakeoverHoldRemaining = %v, want a positive value <= 5s", got)
	}
}
