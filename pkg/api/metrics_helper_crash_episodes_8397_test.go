package api

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// #8397: xpf_dataplane_helper_crash_episodes_total.
//
// A COUNTER, and the counter shape is the point. `restartHelperAfterCrash`
// wipes the helper crash record on success, so every gauge-shaped view of crash
// state reads clean the moment the helper is healthy again — a helper that
// crashed four times in the last hour and is running now presents a spotless
// surface to every other signal in this collector. This is the one that does
// not forget.

func collectCrashEpisodes8397(t *testing.T, c *xpfCollector) (float64, bool) {
	t.Helper()
	ch := make(chan prometheus.Metric, 64)
	go func() {
		c.collectHelperCrashEpisodes(ch)
		close(ch)
	}()
	for m := range ch {
		if m.Desc() != c.helperCrashEpisodesTotal {
			continue
		}
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			t.Fatalf("metric.Write: %v", err)
		}
		if pb.GetCounter() == nil {
			t.Fatalf("xpf_dataplane_helper_crash_episodes_total must be a COUNTER, "+
				"not a gauge: a gauge invites a dashboard to show the CURRENT value, "+
				"and the current value of a recovered helper is what #8397 is about. "+
				"got %+v", &pb)
		}
		return pb.GetCounter().GetValue(), true
	}
	return 0, false
}

func TestHelperCrashEpisodesMetricIsEmitted8397(t *testing.T) {
	c := newCollector(&Server{helperCrashEpisodesFn: func() int { return 4 }})
	got, ok := collectCrashEpisodes8397(t, c)
	if !ok {
		t.Fatal("xpf_dataplane_helper_crash_episodes_total was not emitted")
	}
	if got != 4 {
		t.Errorf("value = %v, want 4", got)
	}
}

func TestHelperCrashEpisodesMetricEmitsZeroNotNothing8397(t *testing.T) {
	// A daemon whose helper has never crashed must emit 0, not omit the series.
	// An ABSENT series reads as healthy to an alert in exactly the same way a
	// zero does, right up until the series is absent for a different reason —
	// a collector change, a gate — and then the alert stays silent because
	// there is nothing to evaluate.
	c := newCollector(&Server{helperCrashEpisodesFn: func() int { return 0 }})
	got, ok := collectCrashEpisodes8397(t, c)
	if !ok {
		t.Fatal("the series must be emitted at 0, not omitted")
	}
	if got != 0 {
		t.Errorf("value = %v, want 0", got)
	}
}

func TestHelperCrashEpisodesMetricIsSkippedWithoutASource8397(t *testing.T) {
	// CONTROL. With no source wired the series is absent rather than a
	// fabricated 0 — a daemon that cannot see the helper must not assert that
	// it has never crashed. Without this cell, emitting an unconditional 0
	// would satisfy both cells above.
	c := newCollector(&Server{})
	if _, ok := collectCrashEpisodes8397(t, c); ok {
		t.Error("with no HelperCrashEpisodesFn the series must be absent, not 0: " +
			"absence means 'unknown', 0 means 'never crashed', and a daemon with " +
			"no dataplane accessor knows the former, not the latter")
	}
}
