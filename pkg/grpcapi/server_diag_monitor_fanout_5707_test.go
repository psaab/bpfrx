package grpcapi

import (
	"context"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc/metadata"
)

// fanoutStatusDP is a grpcRuntime that counts Status() control-socket queries so
// the #5707 fan-out test can assert how many backend status reads a burst of
// MonitorInterface streams issues.
type fanoutStatusDP struct {
	dataplane.DataPlane
	statusCalls atomic.Int64
}

func (d *fanoutStatusDP) IsLoaded() bool { return true }

func (d *fanoutStatusDP) ReadInterfaceCounters(int) (dataplane.InterfaceCounterValue, error) {
	return dataplane.InterfaceCounterValue{}, nil
}

func (d *fanoutStatusDP) Status() (dpuserspace.ProcessStatus, error) {
	d.statusCalls.Add(1)
	return dpuserspace.ProcessStatus{Enabled: true}, nil
}

// oneTickMonitorStream is a MonitorInterface server stream that records one
// frame and then cancels its own context, so the handler's per-tick loop emits
// exactly one frame (one tick) before returning. That makes each stream issue a
// single per-tick status read, which is the unit the fan-out test counts.
type oneTickMonitorStream struct {
	ctx    context.Context
	cancel context.CancelFunc
	frames int
}

func newOneTickMonitorStream() *oneTickMonitorStream {
	ctx, cancel := context.WithCancel(context.Background())
	return &oneTickMonitorStream{ctx: ctx, cancel: cancel}
}

func (m *oneTickMonitorStream) Send(*pb.MonitorInterfaceResponse) error {
	m.frames++
	m.cancel() // end the stream after this single tick
	return nil
}
func (m *oneTickMonitorStream) Context() context.Context     { return m.ctx }
func (m *oneTickMonitorStream) SetHeader(metadata.MD) error  { return nil }
func (m *oneTickMonitorStream) SendHeader(metadata.MD) error { return nil }
func (m *oneTickMonitorStream) SetTrailer(metadata.MD)       {}
func (m *oneTickMonitorStream) SendMsg(any) error            { return nil }
func (m *oneTickMonitorStream) RecvMsg(any) error            { return nil }

// TestMonitorInterfaceSharesStatusAcrossStreams_5707 is the fail-on-revert guard
// for the O(interfaces*streams) status fan-out fix. K concurrent
// MonitorInterface streams each run one tick against a single "lo" interface.
// With the shared per-Server status cache, all K ticks coalesce into ONE backend
// Status() control-socket query. Reverting the fix — binding readSnap back to
// the raw s.userspaceDataplaneStatus per stream — makes each stream fetch
// independently, so the count becomes K and this test fails.
func TestMonitorInterfaceSharesStatusAcrossStreams_5707(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := store.LoadOverride("system { host-name fw; }"); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	dp := &fanoutStatusDP{}
	s := &Server{store: store, dp: dp}

	// Pre-seed the shared status cache with a FIXED clock so the whole burst
	// falls inside one freshness window deterministically — the coalescing then
	// hinges on the sharing, not on wall-clock timing.
	fixed := time.Unix(1_700_000_000, 0)
	s.monitorStatusCache = newMonitorStatusCache(
		s.userspaceDataplaneStatus, monitorStatusTTL, func() time.Time { return fixed })

	const streams = 6
	var wg sync.WaitGroup
	sinks := make([]*oneTickMonitorStream, streams)
	for i := range sinks {
		sinks[i] = newOneTickMonitorStream()
		wg.Add(1)
		go func(st *oneTickMonitorStream) {
			defer wg.Done()
			// context.Canceled is the expected return once the single tick ends.
			_ = s.MonitorInterface(&pb.MonitorInterfaceRequest{InterfaceName: "lo"}, st)
		}(sinks[i])
	}
	wg.Wait()

	for i, st := range sinks {
		if st.frames != 1 {
			t.Fatalf("stream %d emitted %d frames, want exactly 1 tick", i, st.frames)
		}
	}

	if got := dp.statusCalls.Load(); got != 1 {
		t.Fatalf("Status() backend calls across %d streams = %d, want 1 "+
			"(streams must not multiply status reads — #5707 fan-out regressed)", streams, got)
	}
}
