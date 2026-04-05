package main

import (
	"testing"

	pb "github.com/psaab/bpfrx/pkg/grpcapi/bpfrxv1"
)

func TestRemoteMonitorSummaryModeFromKey(t *testing.T) {
	tests := []struct {
		key  byte
		want pb.MonitorInterfaceSummaryMode
	}{
		{'c', pb.MonitorInterfaceSummaryMode_MONITOR_INTERFACE_SUMMARY_MODE_COMBINED},
		{'C', pb.MonitorInterfaceSummaryMode_MONITOR_INTERFACE_SUMMARY_MODE_COMBINED},
		{'p', pb.MonitorInterfaceSummaryMode_MONITOR_INTERFACE_SUMMARY_MODE_PACKETS},
		{'b', pb.MonitorInterfaceSummaryMode_MONITOR_INTERFACE_SUMMARY_MODE_BYTES},
		{'d', pb.MonitorInterfaceSummaryMode_MONITOR_INTERFACE_SUMMARY_MODE_DELTA},
		{'r', pb.MonitorInterfaceSummaryMode_MONITOR_INTERFACE_SUMMARY_MODE_RATE},
	}
	for _, tt := range tests {
		got, ok := remoteMonitorSummaryModeFromKey(tt.key)
		if !ok {
			t.Fatalf("remoteMonitorSummaryModeFromKey(%q) unexpectedly rejected", tt.key)
		}
		if got != tt.want {
			t.Fatalf("remoteMonitorSummaryModeFromKey(%q) = %v, want %v", tt.key, got, tt.want)
		}
	}
}

func TestRemoteMonitorSummaryModeFromKeyRejectsUnknownKeys(t *testing.T) {
	if _, ok := remoteMonitorSummaryModeFromKey('x'); ok {
		t.Fatal("remoteMonitorSummaryModeFromKey accepted unsupported key")
	}
}

func TestIsMonitorQuitKey(t *testing.T) {
	for _, key := range []byte{'q', 'Q', 0x1b, 0x03} {
		if !isMonitorQuitKey(key) {
			t.Fatalf("isMonitorQuitKey(%q) = false, want true", key)
		}
	}
	if isMonitorQuitKey('p') {
		t.Fatal("isMonitorQuitKey('p') = true, want false")
	}
}
