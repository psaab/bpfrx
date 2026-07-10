package cli

import (
	"errors"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// queueStatusCLIUserspaceDP is a fake userspace dataplane whose Status() can be
// made to fail, exercising the #5326 error-vs-empty distinction end to end
// through the CLI `show interfaces queue` path.
type queueStatusCLIUserspaceDP struct {
	*dataplane.Manager
	status dpuserspace.ProcessStatus
	err    error
}

func (f *queueStatusCLIUserspaceDP) Status() (dpuserspace.ProcessStatus, error) {
	return f.status, f.err
}

// TestShowInterfacesQueueStatusErrorNotEmpty is #5326 state (1): when the
// userspace status retrieval FAILS the CLI must surface the error, NOT report
// "No class-of-service queues active" (which would falsely claim there is no
// CoS during exactly the window when the truth is UNKNOWN). RED on revert to
// the discarded-error behavior (status stays nil → empty-snapshot message).
func TestShowInterfacesQueueStatusErrorNotEmpty(t *testing.T) {
	c := &CLI{
		dp: &queueStatusCLIUserspaceDP{
			Manager: dataplane.New(),
			err:     errors.New("control socket unavailable"),
		},
	}

	var callErr error
	out := captureStdout(t, func() {
		callErr = c.showInterfacesQueue("")
	})
	if callErr != nil {
		t.Fatalf("showInterfacesQueue() error = %v", callErr)
	}
	if !strings.Contains(out, "error retrieving class-of-service queue status") {
		t.Fatalf("status error not surfaced:\n%s", out)
	}
	if !strings.Contains(out, "control socket unavailable") {
		t.Fatalf("underlying error text missing:\n%s", out)
	}
	if strings.Contains(out, "No class-of-service queues active") {
		t.Fatalf("fetch error rendered as empty snapshot (the #5326 bug):\n%s", out)
	}
}

// TestShowInterfacesQueueEmptySnapshot is #5326 state (2): a successful but
// empty CoS snapshot is the legitimate "No class-of-service queues active"
// case and must render unchanged (no regression for a genuinely-empty CoS).
func TestShowInterfacesQueueEmptySnapshot(t *testing.T) {
	c := &CLI{
		dp: &queueStatusCLIUserspaceDP{
			Manager: dataplane.New(),
			status:  dpuserspace.ProcessStatus{},
		},
	}

	out := captureStdout(t, func() {
		if err := c.showInterfacesQueue(""); err != nil {
			t.Fatalf("showInterfacesQueue() error = %v", err)
		}
	})
	if !strings.Contains(out, "No class-of-service queues active") {
		t.Fatalf("empty snapshot did not render the no-queues message:\n%s", out)
	}
	if strings.Contains(out, "error retrieving") {
		t.Fatalf("empty snapshot must not render an error:\n%s", out)
	}
}

// TestShowInterfacesQueueNonEmpty is #5326 state (3): a successful non-empty
// snapshot renders the per-queue counters.
func TestShowInterfacesQueueNonEmpty(t *testing.T) {
	c := &CLI{
		dp: &queueStatusCLIUserspaceDP{
			Manager: dataplane.New(),
			status: dpuserspace.ProcessStatus{
				CoSInterfaces: []dpuserspace.CoSInterfaceStatus{
					{
						InterfaceName: "reth0.80",
						Queues: []dpuserspace.CoSQueueStatus{
							{QueueID: 4, ForwardingClass: "bandwidth-10mb", QueuedPackets: 12},
						},
					},
				},
			},
		},
	}

	out := captureStdout(t, func() {
		if err := c.showInterfacesQueue(""); err != nil {
			t.Fatalf("showInterfacesQueue() error = %v", err)
		}
	})
	for _, want := range []string{
		"Physical interface: reth0.80",
		"Queue: 4, Forwarding classes: bandwidth-10mb",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
	if strings.Contains(out, "No class-of-service queues active") || strings.Contains(out, "error retrieving") {
		t.Fatalf("non-empty snapshot rendered a fallback message:\n%s", out)
	}
}
