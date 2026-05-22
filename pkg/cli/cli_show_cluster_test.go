package cli

import (
	"reflect"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

type fabricStatsCLIDP struct {
	dataplane.DataPlane

	loaded  bool
	reads   []uint32
	counter map[uint32]uint64
}

func (f *fabricStatsCLIDP) IsLoaded() bool {
	return f.loaded
}

func (f *fabricStatsCLIDP) ReadGlobalCounter(index uint32) (uint64, error) {
	f.reads = append(f.reads, index)
	return f.counter[index], nil
}

func TestShowChassisClusterFabricStatisticsReadsTelemetryCounters(t *testing.T) {
	dp := &fabricStatsCLIDP{
		loaded: true,
		counter: map[uint32]uint64{
			dataplane.GlobalCtrFabricRedirect:     100,
			dataplane.GlobalCtrFabricRedirectFab0: 40,
			dataplane.GlobalCtrFabricRedirectFab1: 50,
			dataplane.GlobalCtrFabricRedirectZone: 10,
			dataplane.GlobalCtrFabricFwdDrop:      3,
		},
	}
	c := &CLI{dp: dp}

	out := captureStdout(t, func() {
		if err := c.showChassisClusterFabricStatistics(); err != nil {
			t.Fatalf("showChassisClusterFabricStatistics() error = %v", err)
		}
	})

	wantReads := []uint32{
		dataplane.GlobalCtrFabricRedirect,
		dataplane.GlobalCtrFabricRedirectFab0,
		dataplane.GlobalCtrFabricRedirectFab1,
		dataplane.GlobalCtrFabricRedirectZone,
		dataplane.GlobalCtrFabricFwdDrop,
	}
	if !reflect.DeepEqual(dp.reads, wantReads) {
		t.Fatalf("counter reads = %#v, want %#v", dp.reads, wantReads)
	}
	for _, want := range []string{
		"Total redirects:          100",
		"fab0 redirects:           40",
		"fab1 redirects:           50",
		"Zone-encoded redirects:   10",
		"Redirect drops:           3",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}
}

func TestShowChassisClusterFabricStatisticsSkipsUnloadedDataplane(t *testing.T) {
	dp := &fabricStatsCLIDP{loaded: false}
	c := &CLI{dp: dp}

	out := captureStdout(t, func() {
		if err := c.showChassisClusterFabricStatistics(); err != nil {
			t.Fatalf("showChassisClusterFabricStatistics() error = %v", err)
		}
	})

	if strings.TrimSpace(out) != "Dataplane not loaded" {
		t.Fatalf("output = %q, want unloaded message", out)
	}
	if len(dp.reads) != 0 {
		t.Fatalf("counter reads = %#v, want none", dp.reads)
	}
}
