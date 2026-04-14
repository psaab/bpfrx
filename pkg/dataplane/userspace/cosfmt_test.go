package userspace

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func testCoSConfig() *config.Config {
	return &config.Config{
		ClassOfService: &config.ClassOfServiceConfig{
			ForwardingClasses: map[string]*config.CoSForwardingClass{
				"best-effort":    {Name: "best-effort", Queue: 0},
				"bandwidth-10mb": {Name: "bandwidth-10mb", Queue: 4},
			},
			Schedulers: map[string]*config.CoSScheduler{
				"be":   {Name: "be", TransmitRateBytes: 1_875_000},
				"10mb": {Name: "10mb", TransmitRateBytes: 1_250_000, TransmitRateExact: true},
			},
			SchedulerMaps: map[string]*config.CoSSchedulerMap{
				"bandwidth-limit": {
					Name: "bandwidth-limit",
					Entries: map[string]*config.CoSSchedulerMapEntry{
						"best-effort":    {ForwardingClass: "best-effort", Scheduler: "be"},
						"bandwidth-10mb": {ForwardingClass: "bandwidth-10mb", Scheduler: "10mb"},
					},
				},
			},
			Interfaces: map[string]*config.CoSInterface{
				"reth0": {
					Name: "reth0",
					Units: map[int]*config.CoSInterfaceUnit{
						80: {
							Unit:             80,
							ShapingRateBytes: 1_875_000,
							BurstSizeBytes:   65_536,
							SchedulerMap:     "bandwidth-limit",
							DSCPClassifier:   "wan-classifier",
						},
					},
				},
			},
		},
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"reth0": {
					Name: "reth0",
					Units: map[int]*config.InterfaceUnit{
						80: {
							Number:         80,
							FilterOutputV4: "bandwidth-output",
						},
					},
				},
			},
		},
	}
}

func TestFormatCoSInterfaceSummaryShowsConfigOnlyInterface(t *testing.T) {
	out := FormatCoSInterfaceSummary(testCoSConfig(), nil, "reth0.80")
	for _, want := range []string{
		"Interface: reth0.80",
		"Scheduler map:            bandwidth-limit",
		"DSCP classifier:          wan-classifier",
		"Output filter (inet):     bandwidth-output",
		"Runtime:                  unavailable",
		"best-effort",
		"bandwidth-10mb",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestFormatCoSInterfaceSummaryIncludesRuntimeQueueState(t *testing.T) {
	owner := uint32(7)
	status := &ProcessStatus{
		CoSInterfaces: []CoSInterfaceStatus{
			{
				InterfaceName:       "reth0.80",
				OwnerWorkerID:       &owner,
				WorkerInstances:     2,
				NonemptyQueues:      1,
				RunnableQueues:      1,
				TimerLevel0Sleepers: 1,
				TimerLevel1Sleepers: 0,
				Queues: []CoSQueueStatus{
					{
						QueueID:             4,
						ForwardingClass:     "bandwidth-10mb",
						Priority:            1,
						Exact:               true,
						TransmitRateBytes:   1_250_000,
						BufferBytes:         32 * 1024,
						QueuedPackets:       3,
						QueuedBytes:         4096,
						RunnableInstances:   1,
						ParkedInstances:     1,
						NextWakeupTick:      77,
						SurplusDeficitBytes: 2048,
					},
				},
			},
		},
	}
	out := FormatCoSInterfaceSummary(testCoSConfig(), status, "")
	for _, want := range []string{
		"Owner worker:             7",
		"Runtime workers:          2",
		"Runtime queues:           nonempty=1 runnable=1",
		"Timer wheel sleepers:     level0=1 level1=0",
		"Queue  Class           Priority",
		"bandwidth-10mb",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
	if !strings.Contains(out, "77") || !strings.Contains(out, "4.00 KiB") {
		t.Fatalf("expected runtime queue metrics in output:\n%s", out)
	}
}

func TestFormatCoSInterfaceSummaryShowsUnknownOwnerAsDash(t *testing.T) {
	status := &ProcessStatus{
		CoSInterfaces: []CoSInterfaceStatus{
			{
				InterfaceName:   "reth0.80",
				WorkerInstances: 1,
			},
		},
	}
	out := FormatCoSInterfaceSummary(testCoSConfig(), status, "reth0.80")
	if !strings.Contains(out, "Owner worker:             -") {
		t.Fatalf("expected unknown owner to render as dash:\n%s", out)
	}
}

func TestFormatCoSInterfaceSummaryFiltersByBaseInterface(t *testing.T) {
	out := FormatCoSInterfaceSummary(testCoSConfig(), nil, "reth0")
	if !strings.Contains(out, "Interface: reth0.80") {
		t.Fatalf("expected base selector to include logical unit:\n%s", out)
	}
}
