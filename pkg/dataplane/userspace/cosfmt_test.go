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
							Unit:               80,
							ShapingRateBytes:   1_875_000,
							BurstSizeBytes:     65_536,
							SchedulerMap:       "bandwidth-limit",
							DSCPClassifier:     "wan-classifier",
							IEEE8021Classifier: "wan-pcp",
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
		"IEEE 802.1 classifier:    wan-pcp",
		"DSCP rewrite-rule:        -",
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
						OwnerWorkerID:       &owner,
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
		"Queue  Owner  Class",
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

// #710/#718: admission-drop counters must render under each queue row
// with real values. Without this line, operators debugging the
// admission path (SFQ flow-share cap, buffer cap, ECN threshold) have
// no way to tell which admission decision is firing on the live system.
func TestFormatCoSInterfaceSummaryRendersAdmissionDropCounters(t *testing.T) {
	owner := uint32(1)
	status := &ProcessStatus{
		CoSInterfaces: []CoSInterfaceStatus{
			{
				InterfaceName:   "reth0.80",
				OwnerWorkerID:   &owner,
				WorkerInstances: 1,
				Queues: []CoSQueueStatus{
					{
						QueueID:                 4,
						OwnerWorkerID:           &owner,
						ForwardingClass:         "bandwidth-10mb",
						Priority:                5,
						Exact:                   true,
						TransmitRateBytes:       1_250_000,
						BufferBytes:             32 * 1024,
						AdmissionFlowShareDrops: 12345,
						AdmissionBufferDrops:    0,
						AdmissionEcnMarked:      4567,
					},
				},
			},
		},
	}
	out := FormatCoSInterfaceSummary(testCoSConfig(), status, "reth0.80")
	want := "Drops: flow_share=12345  buffer=0  ecn_marked=4567"
	if !strings.Contains(out, want) {
		t.Fatalf("missing %q in output:\n%s", want, out)
	}
}

// The formatter renders queues via tabwriter into a scratch buffer and
// interleaves the per-queue Drops line on a second pass. That second
// pass relies on a strict 1:1 mapping between the i-th table data line
// and the i-th element of `queues` (sorted by queue_id ascending).
// This test pins that invariant — a future refactor that, say, adds a
// blank separator line, re-orders queues, or attaches one queue's
// Drops row under another's data row would break this assertion while
// the single-queue tests above would still pass.
func TestFormatCoSInterfaceSummaryInterleavesPerQueueDropsInOrder(t *testing.T) {
	owner := uint32(1)
	status := &ProcessStatus{
		CoSInterfaces: []CoSInterfaceStatus{
			{
				InterfaceName:   "reth0.80",
				OwnerWorkerID:   &owner,
				WorkerInstances: 1,
				Queues: []CoSQueueStatus{
					{
						QueueID:                 0,
						OwnerWorkerID:           &owner,
						ForwardingClass:         "best-effort",
						Priority:                5,
						Exact:                   true,
						TransmitRateBytes:       1_875_000,
						BufferBytes:             16 * 1024,
						AdmissionFlowShareDrops: 11,
						AdmissionBufferDrops:    22,
						AdmissionEcnMarked:      33,
					},
					{
						QueueID:                 4,
						OwnerWorkerID:           &owner,
						ForwardingClass:         "bandwidth-10mb",
						Priority:                5,
						Exact:                   true,
						TransmitRateBytes:       1_250_000,
						BufferBytes:             32 * 1024,
						AdmissionFlowShareDrops: 44,
						AdmissionBufferDrops:    55,
						AdmissionEcnMarked:      66,
					},
				},
			},
		},
	}
	out := FormatCoSInterfaceSummary(testCoSConfig(), status, "reth0.80")

	// Use content-unique markers rather than full row-text substrings
	// because tabwriter's column widths depend on cell content across
	// all rows — a new queue with a longer forwarding-class name in
	// the fixture would shift spacing and break a literal-row match
	// without actually breaking the invariant this test pins.
	//
	// The invariant: queue rows emit in queue_id ascending order, and
	// each queue's Drops line sits directly under its own data row
	// (not under the next queue's). We pin that with unique counter
	// values per queue (33 vs 66) so a misaligned interleave would be
	// detectable.
	q0Drops := "Drops: flow_share=11  buffer=22  ecn_marked=33"
	q4Drops := "Drops: flow_share=44  buffer=55  ecn_marked=66"
	// The word "best-effort" anchors queue 0's row. "bandwidth-10mb"
	// anchors queue 4's. Both strings appear exactly once in the
	// output (once in the data row).
	q0RowIdx := strings.Index(out, "best-effort")
	q0DropsIdx := strings.Index(out, q0Drops)
	q4RowIdx := strings.Index(out, "bandwidth-10mb")
	q4DropsIdx := strings.Index(out, q4Drops)

	if q0RowIdx < 0 || q0DropsIdx < 0 || q4RowIdx < 0 || q4DropsIdx < 0 {
		t.Fatalf("missing queue row anchor or drops line:\n%s", out)
	}
	// Strict order: q0 row, q0 drops, q4 row, q4 drops. A swap would
	// mean queue 0's row is followed by queue 4's Drops line (or
	// similar) — exactly the pathology this test guards against.
	if !(q0RowIdx < q0DropsIdx && q0DropsIdx < q4RowIdx && q4RowIdx < q4DropsIdx) {
		t.Fatalf(
			"drops-line interleave broken: q0Row=%d q0Drops=%d q4Row=%d q4Drops=%d\n%s",
			q0RowIdx, q0DropsIdx, q4RowIdx, q4DropsIdx, out,
		)
	}
}

// Zero-valued counters MUST still render — operators need to see the
// counter is wired, otherwise "no output" is indistinguishable from
// "counter missing from the pipeline" when chasing #718 / #722.
func TestFormatCoSInterfaceSummaryRendersZeroAdmissionCounters(t *testing.T) {
	owner := uint32(1)
	status := &ProcessStatus{
		CoSInterfaces: []CoSInterfaceStatus{
			{
				InterfaceName:   "reth0.80",
				OwnerWorkerID:   &owner,
				WorkerInstances: 1,
				Queues: []CoSQueueStatus{
					{
						QueueID:         4,
						OwnerWorkerID:   &owner,
						ForwardingClass: "bandwidth-10mb",
						// all admission counters default to 0
					},
				},
			},
		},
	}
	out := FormatCoSInterfaceSummary(testCoSConfig(), status, "reth0.80")
	want := "Drops: flow_share=0  buffer=0  ecn_marked=0"
	if !strings.Contains(out, want) {
		t.Fatalf("missing %q in output (zero-valued drops must still render):\n%s", want, out)
	}
}
