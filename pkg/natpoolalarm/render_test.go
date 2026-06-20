package natpoolalarm

import (
	"strings"
	"testing"
	"time"
)

func TestRenderAlarmsDetail(t *testing.T) {
	alarms := []ActiveAlarm{
		{PoolName: "p1", CurrentPct: 85, RaiseThreshold: 80, FirstSeen: time.Date(2026, 6, 20, 1, 2, 3, 0, time.UTC)},
		{PoolName: "p2", CurrentPct: 95, RaiseThreshold: 90},
	}
	var b strings.Builder
	// Start after two pre-existing alarms (e.g. screen alarms numbered 1,2).
	got := RenderAlarms(&b, alarms, 2, true)
	if got != 4 {
		t.Fatalf("count = %d, want 4", got)
	}
	out := b.String()
	if !strings.Contains(out, "Alarm 3:") || !strings.Contains(out, "Alarm 4:") {
		t.Fatalf("numbering wrong:\n%s", out)
	}
	if !strings.Contains(out, "Class: NAT") || !strings.Contains(out, "Severity: Minor") {
		t.Fatalf("class/severity wrong:\n%s", out)
	}
	if !strings.Contains(out, "NAT source pool p1 utilization 85% exceeds raise-threshold 80%") {
		t.Fatalf("p1 description wrong:\n%s", out)
	}
	if !strings.Contains(out, "First seen: 2026-06-20 01:02:03") {
		t.Fatalf("first-seen line missing:\n%s", out)
	}
	// p2 has a zero FirstSeen → no first-seen line for it.
	if strings.Count(out, "First seen:") != 1 {
		t.Fatalf("zero FirstSeen must omit the first-seen line:\n%s", out)
	}
}

func TestRenderAlarmsSummary(t *testing.T) {
	alarms := []ActiveAlarm{{PoolName: "p1", CurrentPct: 85, RaiseThreshold: 80}}
	var b strings.Builder
	got := RenderAlarms(&b, alarms, 0, false)
	if got != 1 {
		t.Fatalf("summary count = %d, want 1", got)
	}
	if b.String() != "" {
		t.Fatalf("summary mode must write no body, got %q", b.String())
	}
}

func TestRenderAlarmsEmpty(t *testing.T) {
	var b strings.Builder
	got := RenderAlarms(&b, nil, 3, true)
	if got != 3 || b.String() != "" {
		t.Fatalf("empty alarms must not change count or write: count=%d out=%q", got, b.String())
	}
}
