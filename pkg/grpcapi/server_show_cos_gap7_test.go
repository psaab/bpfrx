package grpcapi

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #4228 Gap 7: the four vSRX CoS show commands dispatch through ShowText over
// the compiled config (classifier/scheduler-map/forwarding-class) and the live
// userspace status (interfaces queue).
func newCoSGap7Server(t *testing.T) *Server {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	for _, cmd := range []string{
		"class-of-service forwarding-classes queue 0 best-effort",
		"class-of-service forwarding-classes queue 1 premium",
		"class-of-service schedulers scheduler-be transmit-rate 1m",
		"class-of-service schedulers scheduler-prem transmit-rate 100m exact",
		"class-of-service scheduler-maps bandwidth-limit forwarding-class best-effort scheduler scheduler-be",
		"class-of-service scheduler-maps bandwidth-limit forwarding-class premium scheduler scheduler-prem",
		"class-of-service classifiers dscp wan-classifier forwarding-class premium loss-priority low code-points ef",
		"class-of-service classifiers dscp wan-classifier forwarding-class best-effort loss-priority low code-points be",
		"class-of-service classifiers ieee-802.1 wan-pcp forwarding-class premium loss-priority high code-points 5",
	} {
		if err := store.SetFromInput(cmd); err != nil {
			t.Fatalf("SetFromInput(%q) error = %v", cmd, err)
		}
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	return &Server{
		store: store,
		dp: &firewallFilterShowUserspaceDP{
			Manager: dataplane.New(),
			status: dpuserspace.ProcessStatus{
				CoSInterfaces: []dpuserspace.CoSInterfaceStatus{
					{
						InterfaceName: "reth0.80",
						Queues: []dpuserspace.CoSQueueStatus{
							{QueueID: 1, ForwardingClass: "premium", QueuedPackets: 9, DrainSentBytes: 4096, AdmissionBufferDrops: 2},
							{QueueID: 0, ForwardingClass: "best-effort", QueuedPackets: 3},
						},
					},
				},
			},
		},
	}
}

func TestShowTextCoSForwardingClassGap7(t *testing.T) {
	s := newCoSGap7Server(t)
	resp, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "cos-forwarding-class"})
	if err != nil {
		t.Fatalf("ShowText() error = %v", err)
	}
	out := resp.GetOutput()
	for _, want := range []string{"Forwarding class", "best-effort", "premium"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output = %q, want %q", out, want)
		}
	}
}

func TestShowTextCoSSchedulerMapGap7(t *testing.T) {
	s := newCoSGap7Server(t)
	resp, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "cos-scheduler-map"})
	if err != nil {
		t.Fatalf("ShowText() error = %v", err)
	}
	out := resp.GetOutput()
	for _, want := range []string{"Scheduler map: bandwidth-limit", "scheduler-be", "scheduler-prem", "100.00 Mb/s"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output = %q, want %q", out, want)
		}
	}
	// Name filter.
	resp, err = s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "cos-scheduler-map:missing"})
	if err != nil {
		t.Fatalf("ShowText() error = %v", err)
	}
	if !strings.Contains(resp.GetOutput(), "No class-of-service scheduler-map matches missing") {
		t.Fatalf("name filter output = %q", resp.GetOutput())
	}
}

func TestShowTextCoSClassifierGap7(t *testing.T) {
	s := newCoSGap7Server(t)
	resp, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "cos-classifier"})
	if err != nil {
		t.Fatalf("ShowText() error = %v", err)
	}
	out := resp.GetOutput()
	for _, want := range []string{
		"Classifier: wan-classifier, Code point type: dscp",
		"Classifier: wan-pcp, Code point type: ieee-802.1",
		"101110", // ef = DSCP 46
		"101",    // PCP 5
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("output = %q, want %q", out, want)
		}
	}

	// type filter excludes the 802.1 classifier.
	resp, err = s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "cos-classifier:type=dscp"})
	if err != nil {
		t.Fatalf("ShowText() error = %v", err)
	}
	if out := resp.GetOutput(); !strings.Contains(out, "wan-classifier") || strings.Contains(out, "wan-pcp") {
		t.Fatalf("type=dscp output = %q", out)
	}

	// name filter selects a single classifier.
	resp, err = s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "cos-classifier:name=wan-pcp"})
	if err != nil {
		t.Fatalf("ShowText() error = %v", err)
	}
	if out := resp.GetOutput(); strings.Contains(out, "wan-classifier,") || !strings.Contains(out, "wan-pcp") {
		t.Fatalf("name=wan-pcp output = %q", out)
	}
}

func TestShowTextInterfacesQueueGap7(t *testing.T) {
	s := newCoSGap7Server(t)
	resp, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "interfaces-queue"})
	if err != nil {
		t.Fatalf("ShowText() error = %v", err)
	}
	out := resp.GetOutput()
	for _, want := range []string{
		"Physical interface: reth0.80",
		"Queue: 0, Forwarding classes: best-effort",
		"Queue: 1, Forwarding classes: premium",
		"Egress queues: 8 supported, 2 in use",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("output = %q, want %q", out, want)
		}
	}

	// Filter carries the selector.
	resp, err = s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "interfaces-queue", Filter: "reth9"})
	if err != nil {
		t.Fatalf("ShowText() error = %v", err)
	}
	if !strings.Contains(resp.GetOutput(), "No class-of-service queues active on reth9") {
		t.Fatalf("selector filter output = %q", resp.GetOutput())
	}
}
