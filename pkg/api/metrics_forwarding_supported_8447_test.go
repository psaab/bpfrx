package api

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// #8447: xpf_dataplane_forwarding_supported.
//
// A capability gate can disarm every binding, taking rx to 0 while the
// interfaces stay up and the config commits cleanly. The documented case is
// persistent-NAT on a chassis cluster (#1449). What was missing is any signal
// an ALERT could key on: the only surface was a line inside a `show` nobody
// runs when the symptom is "the link went down".

func collectForwardingSupported8447(t *testing.T, c *xpfCollector) (float64, bool) {
	t.Helper()
	ch := make(chan prometheus.Metric, 16)
	go func() {
		c.collectForwardingSupported(ch)
		close(ch)
	}()
	for m := range ch {
		if m.Desc() != c.forwardingSupported {
			continue
		}
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			t.Fatalf("metric.Write: %v", err)
		}
		return pb.GetGauge().GetValue(), true
	}
	return 0, false
}

func TestForwardingSupportedEmitsOneWhenForwarding8447(t *testing.T) {
	c := newCollector(&Server{forwardingSupportedFn: func() bool { return true }})
	got, ok := collectForwardingSupported8447(t, c)
	if !ok {
		t.Fatal("xpf_dataplane_forwarding_supported was not emitted")
	}
	if got != 1 {
		t.Errorf("value = %v, want 1", got)
	}
}

func TestForwardingSupportedEmitsZeroWhenDisarmed8447(t *testing.T) {
	// The case the metric exists for. A 0 here is a transit outage on a box
	// whose interfaces are up and whose config committed cleanly.
	c := newCollector(&Server{forwardingSupportedFn: func() bool { return false }})
	got, ok := collectForwardingSupported8447(t, c)
	if !ok {
		t.Fatal("the series must be emitted at 0 — an ABSENT series and a healthy " +
			"one are the same thing to an alert, and 0 is the alerting condition")
	}
	if got != 0 {
		t.Errorf("value = %v, want 0", got)
	}
}

func TestForwardingSupportedIsAbsentWithoutASource8447(t *testing.T) {
	// CONTROL, and the reason the fn is nil-checked rather than defaulted.
	// A daemon with no dataplane accessor does not KNOW whether forwarding is
	// live. Emitting 1 there would assert that it is — turning "we cannot see"
	// into "everything is fine", which is the exact reading #8447 is about.
	// Without this cell, an unconditional 1 would satisfy the first test and
	// mute the second in production.
	c := newCollector(&Server{})
	if _, ok := collectForwardingSupported8447(t, c); ok {
		t.Error("with no ForwardingSupportedFn the series must be absent, not 1")
	}
}
