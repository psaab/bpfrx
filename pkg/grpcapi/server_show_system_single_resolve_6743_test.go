package grpcapi

import (
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// Codex PR #6743 r7-F3: the buffer renders must take exactly ONE resolution.
//
// Before this round they took three — dataplane.Published(s.dp), then
// s.dpProbe(), then s.dp.GetMapStats() — each an independent load of the
// #2114 cell. A setDataplane(nil) landing between them re-created the exact
// confusion Published() was introduced to prevent: the publication check
// passed against a live backend, the later loads resolved nil, and the
// render printed "No BPF maps available" — a statement about a LOADED
// backend's maps — for a daemon that no longer had a backend at all.
//
// This is deterministic, not a race: the fake below is a live indirection
// that resolves ONCE and is empty from then on, which is the observable
// consequence of that schedule with the timing removed.

// oneShotIndirection is a live indirection whose cell empties immediately
// after the first resolution. It also satisfies grpcDataPlane by embedding
// the root Manager, so it can be stored in Server.dp exactly as the daemon's
// liveDataPlane is.
type oneShotIndirection struct {
	*dataplane.Manager
	backend  any
	resolves atomic.Int32
}

func (o *oneShotIndirection) Unwrap() any {
	if o.resolves.Add(1) == 1 {
		return o.backend
	}
	return nil
}

var _ dataplane.LiveUnwrapper = (*oneShotIndirection)(nil)

// mapStatsBackend is the published backend: no userspace Status() probe, so
// the render takes the map-stats arm, and a non-empty map list so "No BPF
// maps available" can only mean the render lost the backend.
type mapStatsBackend struct {
	*dataplane.Manager
}

func (*mapStatsBackend) IsLoaded() bool { return true }
func (*mapStatsBackend) SessionCount() (int, int) {
	return 0, 0
}

func (*mapStatsBackend) GetMapStats() []dataplane.MapStats {
	return []dataplane.MapStats{{
		Name:       "sessions_v4",
		Type:       "Hash",
		MaxEntries: 1024,
		UsedCount:  4,
	}}
}

// TestShowBuffersResolvesBackendOnce is the fail-on-revert guard.
//
// Revert either render to `if dataplane.Published(s.dp)` + `s.dpProbe()` +
// `s.dp.GetMapStats()` and the second and third loads see the emptied cell:
// the output becomes "No BPF maps available" and these assertions go RED.
func TestShowBuffersResolvesBackendOnce(t *testing.T) {
	for _, tc := range []struct {
		name   string
		render func(*Server, *config.Config, *strings.Builder) error
	}{
		{"showBuffers", (*Server).showBuffers},
		{"showBuffersDetail", (*Server).showBuffersDetail},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dp := &oneShotIndirection{
				Manager: dataplane.New(),
				backend: &mapStatsBackend{Manager: dataplane.New()},
			}
			s := &Server{
				dp:    dp,
				store: newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf")),
			}

			var buf strings.Builder
			if err := tc.render(s, &config.Config{}, &buf); err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			out := buf.String()

			if strings.Contains(out, "No BPF maps available") {
				t.Fatalf("%s reported \"No BPF maps available\" after resolving the "+
					"backend more than once (resolves=%d): the render must take ONE "+
					"resolution and describe that instant.\n%s",
					tc.name, dp.resolves.Load(), out)
			}
			if !strings.Contains(out, "sessions_v4") {
				t.Fatalf("%s did not render the published backend's maps (resolves=%d)\n%s",
					tc.name, dp.resolves.Load(), out)
			}
			if got := dp.resolves.Load(); got != 1 {
				t.Fatalf("%s resolved the cell %d times, want exactly 1", tc.name, got)
			}
		})
	}
}

// TestShowBuffersEmptyCellSaysNotLoaded is the negative control: with NO
// backend at all the render must still say "Dataplane not loaded", so the
// test above cannot pass merely because the "No BPF maps available" string
// was deleted.
func TestShowBuffersEmptyCellSaysNotLoaded(t *testing.T) {
	dp := &oneShotIndirection{Manager: dataplane.New(), backend: nil}
	s := &Server{
		dp:    dp,
		store: newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf")),
	}
	var buf strings.Builder
	if err := s.showBuffers(&config.Config{}, &buf); err != nil {
		t.Fatalf("showBuffers: %v", err)
	}
	if !strings.Contains(buf.String(), "Dataplane not loaded") {
		t.Fatalf("empty cell must render \"Dataplane not loaded\", got:\n%s", buf.String())
	}
}
