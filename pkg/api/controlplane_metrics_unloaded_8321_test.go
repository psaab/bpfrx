package api

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	dto "github.com/prometheus/client_model/go"
	"github.com/psaab/xpf/pkg/dataplane"
)

// #8321 finding 14: control-plane metrics must survive an unloaded or degraded
// dataplane.
//
// `collectDHCPMetrics`, `collectDDNSMetrics`, `collectSurfaceADDNSMetrics` and
// `collectSystemMetrics` sat AFTER `if dp == nil || !dp.IsLoaded() { return }`,
// so on a config-only boot or a degraded dataplane the daemon's uptime, DHCP
// lease and DDNS metrics vanished from monitoring — at exactly the moment an
// operator is trying to work out what happened.
//
// A metric that disappears during the incident it would explain is worse than
// one that was never added: its absence reads as "nothing to report" rather
// than "I cannot see".

// collectedNames8321 drives a full Collect with NO dataplane and returns every
// metric name emitted.
func collectedNames8321(t *testing.T, srv *Server) map[string]bool {
	t.Helper()
	c := newCollector(srv)
	ch := make(chan prometheus.Metric, 4096)
	go func() {
		c.Collect(ch)
		close(ch)
	}()
	names := map[string]bool{}
	for m := range ch {
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			continue
		}
		// Desc().String() carries `fqName: "..."`; take the name out of it.
		d := m.Desc().String()
		const key = `fqName: "`
		if i := strings.Index(d, key); i >= 0 {
			rest := d[i+len(key):]
			if j := strings.Index(rest, `"`); j > 0 {
				names[rest[:j]] = true
			}
		}
	}
	return names
}

func TestSystemMetricsSurviveAnUnloadedDataplane8321(t *testing.T) {
	// dp is nil — the config-only / degraded-boot case.
	names := collectedNames8321(t, &Server{})

	// POSITIVE CONTROL on the harness: a scrape with no dataplane must still
	// emit SOMETHING, or this cell passes vacuously against a Collect that
	// returned immediately.
	if len(names) == 0 {
		t.Fatal("a scrape with no dataplane emitted nothing at all — the harness " +
			"is not reaching Collect, so every assertion below would be vacuous")
	}

	// xpf_daemon_uptime_seconds is the sharpest case: daemon uptime is a pure
	// control-plane fact and is the first thing an operator looks at when a
	// box is misbehaving.
	if !names["xpf_daemon_uptime_seconds"] {
		t.Errorf("xpf_daemon_uptime_seconds is absent with no dataplane loaded.\n\n"+
			"Daemon uptime does not depend on the dataplane, and it is most "+
			"needed exactly when the dataplane is not loaded. Emitted %d metrics; "+
			"the control-plane collectors must run BEFORE the "+
			"`dp == nil || !dp.IsLoaded()` gate.", len(names))
	}
}

// unloadedAPIDP8321 is a NON-NIL dataplane that reports itself unloaded — the
// degraded case, as opposed to the config-only `dp == nil` one. It is what
// makes the control below discriminating: with `dp == nil` the downstream
// collectors nil-guard themselves, so deleting the gate changes nothing and a
// control built on nil cannot fail.
type unloadedAPIDP8321 struct {
	*dataplane.Manager
}

func (d *unloadedAPIDP8321) IsLoaded() bool { return false }

// TestControlPlaneMetricsSurviveADegradedDataplane8321 is the SECOND
// configuration of the same property, not a control — and the difference is
// worth stating because I tried to write it as a control and it could not be
// one.
//
// `dp == nil` is the config-only boot; a NON-NIL dataplane reporting
// !IsLoaded() is the degraded one, and they take different paths to the same
// early return. Both must keep the control-plane families.
//
// WHAT I COULD NOT WRITE, measured rather than assumed: a control asserting
// that the gate still SUPPRESSES something. Deleting
// `if dp == nil || !dp.IsLoaded() { return }` outright changes the emitted set
// by ZERO families in either configuration — every downstream collector already
// guards itself against an absent or unloaded dataplane. So the gate is a COST
// boundary (it skips a control-socket status round-trip and a good deal of
// wasted work per scrape), not a correctness boundary for the metric set, and
// no cell can distinguish its presence from its absence by looking at output.
//
// That is why this file has no "the gate still gates" assertion: one would have
// looked like a control and been incapable of failing.
func TestControlPlaneMetricsSurviveADegradedDataplane8321(t *testing.T) {
	srv := &Server{dp: &unloadedAPIDP8321{Manager: dataplane.New()}}
	names := collectedNames8321(t, srv)

	if len(names) == 0 {
		t.Fatal("a scrape with an unloaded dataplane emitted nothing at all — " +
			"the harness is not reaching Collect")
	}
	if !names["xpf_daemon_uptime_seconds"] {
		t.Errorf("xpf_daemon_uptime_seconds is absent with a DEGRADED (non-nil, "+
			"unloaded) dataplane. That is the second path to the early return, "+
			"and the one an operator hits when the helper is wedged rather than "+
			"absent. Emitted %d families.", len(names))
	}
}
