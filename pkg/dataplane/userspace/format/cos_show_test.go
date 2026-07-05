package format

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	userspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// testCoSShowConfig extends the shared CoS fixture with classifiers and
// rewrite rules so the show-command formatters have data to render.
func testCoSShowConfig() *config.Config {
	cfg := testCoSConfig()
	cfg.ClassOfService.DSCPClassifiers = map[string]*config.CoSDSCPClassifier{
		"wan-classifier": {
			Name: "wan-classifier",
			Entries: []*config.CoSDSCPClassifierEntry{
				// Expedited-forwarding: DSCP 46 = 101110b.
				{ForwardingClass: "bandwidth-10mb", LossPriority: "low", DSCPValues: []uint8{46}},
				// Best-effort: DSCP 0 = 000000b, no explicit loss-priority.
				{ForwardingClass: "best-effort", DSCPValues: []uint8{0}},
			},
		},
	}
	cfg.ClassOfService.IEEE8021Classifiers = map[string]*config.CoSIEEE8021Classifier{
		"wan-pcp": {
			Name: "wan-pcp",
			Entries: []*config.CoSIEEE8021ClassifierEntry{
				{ForwardingClass: "bandwidth-10mb", LossPriority: "high", CodePoints: []uint8{5}},
			},
		},
	}
	return cfg
}

func TestFormatInterfacesQueue(t *testing.T) {
	status := &userspace.ProcessStatus{
		CoSInterfaces: []userspace.CoSInterfaceStatus{
			{
				InterfaceName: "reth0.80",
				Queues: []userspace.CoSQueueStatus{
					{
						QueueID:              4,
						ForwardingClass:      "bandwidth-10mb",
						QueuedPackets:        12,
						QueuedBytes:          6000,
						DrainSentBytes:       48000,
						AdmissionBufferDrops: 3,
						AdmissionEcnMarked:   1,
					},
					{
						QueueID:         0,
						ForwardingClass: "best-effort",
						QueuedPackets:   1,
					},
				},
			},
		},
	}

	out := FormatInterfacesQueue(status, "")
	for _, want := range []string{
		"Physical interface: reth0.80",
		"Egress queues: 8 supported, 2 in use",
		"Queue: 0, Forwarding classes: best-effort",
		"Queue: 4, Forwarding classes: bandwidth-10mb",
		"Buffer-drop packets  :                    3",
		"ECN-marked packets   :                    1",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
	// Queues must render in ascending queue-id order (0 before 4).
	if strings.Index(out, "Queue: 0,") > strings.Index(out, "Queue: 4,") {
		t.Fatalf("queues rendered out of order:\n%s", out)
	}
}

func TestFormatInterfacesQueueSelectorFilter(t *testing.T) {
	status := &userspace.ProcessStatus{
		CoSInterfaces: []userspace.CoSInterfaceStatus{
			{InterfaceName: "reth0.80", Queues: []userspace.CoSQueueStatus{{QueueID: 0}}},
			{InterfaceName: "reth1.0", Queues: []userspace.CoSQueueStatus{{QueueID: 0}}},
		},
	}
	// Physical-name selector matches the unit-qualified runtime interface.
	out := FormatInterfacesQueue(status, "reth0")
	if !strings.Contains(out, "reth0.80") || strings.Contains(out, "reth1.0") {
		t.Fatalf("selector reth0 did not filter correctly:\n%s", out)
	}
	// No matching interface reports a scoped no-data message.
	out = FormatInterfacesQueue(status, "ge-9-9-9")
	if !strings.Contains(out, "No class-of-service queues active on ge-9-9-9") {
		t.Fatalf("unexpected no-match output:\n%s", out)
	}
}

func TestFormatInterfacesQueueNoStatus(t *testing.T) {
	if got := FormatInterfacesQueue(nil, ""); !strings.Contains(got, "No class-of-service queues active") {
		t.Fatalf("nil status: %q", got)
	}
}

func TestFormatCoSClassifiers(t *testing.T) {
	out := FormatCoSClassifiers(testCoSShowConfig(), "", "")
	for _, want := range []string{
		"Classifier: wan-classifier, Code point type: dscp",
		"Classifier: wan-pcp, Code point type: ieee-802.1",
		"Code point", "Forwarding class", "Loss priority",
		"101110", // DSCP 46 as 6-bit binary
		"000000", // DSCP 0 as 6-bit binary
		"101",    // PCP 5 as 3-bit binary
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
	// DSCP rows must sort by code-point value (0 before 46).
	if strings.Index(out, "000000") > strings.Index(out, "101110") {
		t.Fatalf("DSCP code points rendered out of order:\n%s", out)
	}
	// Missing loss-priority defaults to "low".
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "000000") {
			if !strings.Contains(line, "low") {
				t.Fatalf("best-effort row missing default loss-priority low: %q", line)
			}
		}
	}
}

func TestFormatCoSClassifiersFilters(t *testing.T) {
	cfg := testCoSShowConfig()

	// type dscp excludes the ieee-802.1 classifier.
	out := FormatCoSClassifiers(cfg, "", "dscp")
	if !strings.Contains(out, "wan-classifier") || strings.Contains(out, "wan-pcp") {
		t.Fatalf("type=dscp filter wrong:\n%s", out)
	}

	// name filter selects a single classifier.
	out = FormatCoSClassifiers(cfg, "wan-pcp", "")
	if strings.Contains(out, "wan-classifier") || !strings.Contains(out, "wan-pcp") {
		t.Fatalf("name=wan-pcp filter wrong:\n%s", out)
	}

	// No match reports the filter message.
	out = FormatCoSClassifiers(cfg, "nope", "")
	if !strings.Contains(out, "No class-of-service classifier matches") {
		t.Fatalf("expected no-match message, got:\n%s", out)
	}
}

func TestFormatCoSSchedulerMaps(t *testing.T) {
	out := FormatCoSSchedulerMaps(testCoSShowConfig(), "")
	for _, want := range []string{
		"Scheduler map: bandwidth-limit",
		"Forwarding class", "Scheduler", "Queue", "Transmit rate", "Exact",
		"best-effort", "bandwidth-10mb",
		"10.00 Mb/s", // exact scheduler transmit rate
		"yes",        // exact column for the 10mb scheduler
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
	// Entries sort by queue id: best-effort (queue 0) before bandwidth-10mb (queue 4).
	if strings.Index(out, "best-effort") > strings.Index(out, "bandwidth-10mb") {
		t.Fatalf("scheduler-map rows out of order:\n%s", out)
	}
}

func TestFormatCoSSchedulerMapsNameFilter(t *testing.T) {
	cfg := testCoSShowConfig()
	if got := FormatCoSSchedulerMaps(cfg, "missing"); !strings.Contains(got, "No class-of-service scheduler-map matches missing") {
		t.Fatalf("name filter miss: %q", got)
	}
	if got := FormatCoSSchedulerMaps(&config.Config{}, ""); !strings.Contains(got, "No class-of-service scheduler-maps configured") {
		t.Fatalf("empty cfg: %q", got)
	}
}

func TestFormatCoSForwardingClasses(t *testing.T) {
	out := FormatCoSForwardingClasses(testCoSShowConfig())
	for _, want := range []string{
		"Forwarding class", "ID", "Queue",
		"best-effort", "bandwidth-10mb",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
	// Sorted by queue: best-effort (0) before bandwidth-10mb (4).
	if strings.Index(out, "best-effort") > strings.Index(out, "bandwidth-10mb") {
		t.Fatalf("forwarding-class rows out of order:\n%s", out)
	}
	if got := FormatCoSForwardingClasses(&config.Config{}); !strings.Contains(got, "No class-of-service forwarding-classes configured") {
		t.Fatalf("empty cfg: %q", got)
	}
}
