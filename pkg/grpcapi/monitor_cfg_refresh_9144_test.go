package grpcapi

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"github.com/psaab/xpf/pkg/monitoriface"
	"google.golang.org/grpc/metadata"
)

// #9144: MonitorInterface pinned `cfg := s.store.ActiveConfig()` at stream open
// and its 1s tick loop used that snapshot for the life of the stream. The
// interface SET and the COUNTERS were never stale — TrafficSummaryInterfaces
// walks netlink fresh every tick and reads counters by live kernel name. What was
// stale is the config-derived DISPLAY NAME, so a commit that re-points an alias
// left LIVE counters rendered under a name that now belongs to something else.
//
// Measured through the real store and a real commit, before the fix:
//
//	BEFORE commit:                  kernel lo is displayed as "reth0"
//	AFTER commit, PINNED snapshot:  kernel lo is displayed as "reth0"   <-- stale label
//	AFTER commit, RE-READ:          kernel lo is displayed as "reth9"
//
// THE FIXTURE, and why it is not vacuous. The summary path only consults the
// config for interfaces that resolve to a LIVE kernel device, so a config full of
// names with no live counterpart would exercise nothing and the cell would pass
// identically with and without the fix. These configs alias `lo` — live on every
// host — as a RETH member, so the config-derived label is genuinely in play.
// TestSummaryLabelFixtureIsLoadBearing9144 asserts exactly that.
//
// FAIL-ON-REVERT: change monitorSummaryInterfaces back to taking the pinned
// snapshot and TestSummaryInterfacesFollowsAConfigCommit9144 goes RED.

const monitorCfgRethA9144 = `
system {
    host-name monitor-9144;
}
interfaces {
    lo {
        gigether-options {
            redundant-parent reth0;
        }
    }
    reth0 {
        redundant-ether-options {
            redundancy-group 1;
        }
        unit 0 {
            family inet {
                address 10.9.9.1/24;
            }
        }
    }
}
`

const monitorCfgRethB9144 = `
system {
    host-name monitor-9144;
}
interfaces {
    lo {
        gigether-options {
            redundant-parent reth9;
        }
    }
    reth9 {
        redundant-ether-options {
            redundancy-group 1;
        }
        unit 0 {
            family inet {
                address 10.9.9.1/24;
            }
        }
    }
}
`

func monitorStore9144(t *testing.T, text string) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	commitMonitorCfg9144(t, store, text)
	return store
}

func commitMonitorCfg9144(t *testing.T, store *configstore.Store, text string) {
	t.Helper()
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := store.LoadOverride(text); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	store.ExitConfigure()
}

// labelForKernel9144 returns the display name the summary mapping attaches to a
// given live kernel device, or "<none>".
func labelForKernel9144(names []string, kernels map[string]string, kernel string) string {
	for _, n := range names {
		if kernels[n] == kernel {
			return n
		}
	}
	return "<none>"
}

// The core assertion: the mapping follows a commit that lands mid-stream.
func TestSummaryInterfacesFollowsAConfigCommit9144(t *testing.T) {
	store := monitorStore9144(t, monitorCfgRethA9144)
	s := &Server{store: store}

	// The snapshot the stream opens with — exactly what MonitorInterface pins.
	openCfg := store.ActiveConfig()
	if openCfg == nil {
		t.Fatal("no active config after the first commit")
	}

	names, kernels := s.monitorSummaryInterfaces(openCfg)
	if got := labelForKernel9144(names, kernels, "lo"); got != "reth0" {
		t.Fatalf("before the commit, kernel lo is labelled %q, want %q — the fixture is not exercising "+
			"the config-derived label at all", got, "reth0")
	}

	// A commit lands while the stream is open.
	commitMonitorCfg9144(t, store, monitorCfgRethB9144)

	names, kernels = s.monitorSummaryInterfaces(openCfg)
	if got := labelForKernel9144(names, kernels, "lo"); got != "reth9" {
		t.Fatalf("after the commit, live kernel lo is still labelled %q, want %q — the stream is "+
			"rendering live counters under a display name the config no longer assigns (#9144)", got, "reth9")
	}
}

// The fixture control. If `lo` were not aliased by the config, the summary path
// would label it "lo" regardless of what was committed, and the cell above would
// pass with OR without the fix — evidence about the fixture, not the code.
func TestSummaryLabelFixtureIsLoadBearing9144(t *testing.T) {
	store := monitorStore9144(t, monitorCfgRethA9144)
	s := &Server{store: store}
	cfg := store.ActiveConfig()

	// With the aliasing config, the label is config-derived.
	names, kernels := s.monitorSummaryInterfaces(cfg)
	if got := labelForKernel9144(names, kernels, "lo"); got == "lo" {
		t.Fatal("kernel lo is labelled with its own name — the config alias is NOT reaching the " +
			"summary mapping, so every other cell in this file is vacuous")
	}

	// And a config with no alias for lo labels it with the kernel name, which is
	// the state the cell above would be stuck in if the fixture were wrong.
	bare := &config.Config{}
	names, kernels = monitoriface.TrafficSummaryInterfaces(bare)
	if got := labelForKernel9144(names, kernels, "lo"); got != "lo" {
		t.Fatalf("with no config alias, kernel lo is labelled %q, want %q", got, "lo")
	}
}

// A re-read that returns nil must degrade to the frame the stream opened with,
// not blank the summary: a monitor stream that empties on a transient store
// state is a worse failure than one stale label.
func TestSummaryInterfacesDegradesToOpenFrameOnNilReread9144(t *testing.T) {
	store := monitorStore9144(t, monitorCfgRethA9144)
	openCfg := store.ActiveConfig()

	// A Server whose store has no active config at all models the nil re-read.
	empty := &Server{store: newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))}
	if empty.store.ActiveConfig() != nil {
		t.Skip("a fresh store already has an active config; the nil-re-read path is not reachable here")
	}

	names, kernels := empty.monitorSummaryInterfaces(openCfg)
	if len(names) == 0 {
		t.Fatal("a nil re-read blanked the summary instead of degrading to the opening frame")
	}
	if got := labelForKernel9144(names, kernels, "lo"); got != "reth0" {
		t.Fatalf("the degraded frame labelled kernel lo %q, want the opening frame's %q", got, "reth0")
	}
}

// Both nil is the only case that may legitimately return nothing, and it must
// not panic.
func TestSummaryInterfacesBothNil9144(t *testing.T) {
	s := &Server{store: newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))}
	if s.store.ActiveConfig() == nil {
		if names, _ := s.monitorSummaryInterfaces(nil); names != nil {
			t.Fatalf("no config anywhere should yield no names, got %v", names)
		}
	}
}

// monitorResolveToKernel must resolve against the config it is HANDED, not any
// captured one — that parameterization is the whole point of the split.
func TestMonitorResolveToKernelUsesTheConfigItIsGiven9144(t *testing.T) {
	storeA := monitorStore9144(t, monitorCfgRethA9144)
	cfgA := storeA.ActiveConfig()
	storeB := monitorStore9144(t, monitorCfgRethB9144)
	cfgB := storeB.ActiveConfig()

	if got := monitorResolveToKernel(cfgA, "reth0"); got != "lo" {
		t.Errorf("cfgA reth0 -> %q, want lo", got)
	}
	if got := monitorResolveToKernel(cfgB, "reth9"); got != "lo" {
		t.Errorf("cfgB reth9 -> %q, want lo", got)
	}
	// reth0 does not exist in cfgB, so it must NOT resolve to lo there.
	if got := monitorResolveToKernel(cfgB, "reth0"); got == "lo" {
		t.Error("cfgB resolved reth0 to lo — the resolver is not using the config it was handed")
	}
	// A nil config must not panic.
	if got := monitorResolveToKernel(nil, "ge-0/0/0"); got != "ge-0-0-0" {
		t.Errorf("nil config: ge-0/0/0 -> %q, want ge-0-0-0", got)
	}
}

// WIRING BIND. Every cell above calls monitorSummaryInterfaces DIRECTLY, so all
// of them stay green if the tick loop stops calling it — the helper would be
// correct and unreached. This drives the real MonitorInterface handler across a
// real commit and asserts the RENDERED FRAMES change, which is the only
// assertion that can see the call site.
type twoTickMonitorStream9144 struct {
	ctx     context.Context
	cancel  context.CancelFunc
	frames  []string
	onFrame func(n int)
}

func newTwoTickMonitorStream9144(onFrame func(n int)) *twoTickMonitorStream9144 {
	ctx, cancel := context.WithCancel(context.Background())
	return &twoTickMonitorStream9144{ctx: ctx, cancel: cancel, onFrame: onFrame}
}

func (m *twoTickMonitorStream9144) Send(resp *pb.MonitorInterfaceResponse) error {
	m.frames = append(m.frames, resp.GetFrame())
	if m.onFrame != nil {
		m.onFrame(len(m.frames))
	}
	if len(m.frames) >= 2 {
		m.cancel()
	}
	return nil
}
func (m *twoTickMonitorStream9144) Context() context.Context     { return m.ctx }
func (m *twoTickMonitorStream9144) SetHeader(metadata.MD) error  { return nil }
func (m *twoTickMonitorStream9144) SendHeader(metadata.MD) error { return nil }
func (m *twoTickMonitorStream9144) SetTrailer(metadata.MD)       {}
func (m *twoTickMonitorStream9144) SendMsg(any) error            { return nil }
func (m *twoTickMonitorStream9144) RecvMsg(any) error            { return nil }

type monitorDP9144 struct{ dataplane.DataPlane }

func (monitorDP9144) IsLoaded() bool { return true }
func (monitorDP9144) ReadInterfaceCounters(int) (dataplane.InterfaceCounterValue, error) {
	return dataplane.InterfaceCounterValue{}, nil
}
func (monitorDP9144) Status() (dpuserspace.ProcessStatus, error) {
	return dpuserspace.ProcessStatus{Enabled: true}, nil
}

func TestMonitorInterfaceFramesFollowAConfigCommit9144(t *testing.T) {
	store := monitorStore9144(t, monitorCfgRethA9144)
	s := &Server{store: store, dp: monitorDP9144{}}

	// Commit the rename BETWEEN the first and second frame — a commit landing
	// while the operator's `monitor interface` stream is open.
	stream := newTwoTickMonitorStream9144(func(n int) {
		if n == 1 {
			commitMonitorCfg9144(t, store, monitorCfgRethB9144)
		}
	})

	done := make(chan error, 1)
	go func() { done <- s.MonitorInterface(&pb.MonitorInterfaceRequest{}, stream) }()

	select {
	case <-done:
	case <-time.After(20 * time.Second):
		stream.cancel()
		t.Fatal("MonitorInterface did not emit two frames")
	}

	if len(stream.frames) < 2 {
		t.Fatalf("got %d frames, want 2", len(stream.frames))
	}
	if !strings.Contains(stream.frames[0], "reth0") {
		t.Fatalf("frame 1 does not mention reth0 — the fixture is not exercising the label:\n%s", stream.frames[0])
	}
	if !strings.Contains(stream.frames[1], "reth9") {
		t.Fatalf("frame 2 still renders the pre-commit label; the stream is pinned to the config "+
			"snapshot taken at open (#9144):\n%s", stream.frames[1])
	}
	if strings.Contains(stream.frames[1], "reth0") {
		t.Errorf("frame 2 still contains the stale name reth0:\n%s", stream.frames[1])
	}
}
