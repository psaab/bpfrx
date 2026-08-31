package grpcapi

import (
	"sort"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #7357: `show forwarding-options` must list its instances in a STABLE order.
//
// Every renderer iterated its instance map with a bare `range`, which Go
// randomises per run, so two calls with identical config produced different
// orderings. An operator diffing captures sees churn that is not there, and
// any golden or transcript over these surfaces is unstable for a reason
// unrelated to the config.
//
// The assertion is that the rendered order EQUALS the sorted order, not that
// two runs agree. Comparing two runs is a weaker and flakier test: with a
// small map two randomised iterations can coincide, so it passes by luck at a
// rate that depends on the fixture size. Comparing against sorted order fails
// deterministically the moment the fix is reverted.
//
// The fixture names are deliberately inserted in REVERSE order so insertion
// order and sorted order disagree — a fixture whose natural order already
// matches sorted order cannot distinguish a sort from a no-op.
func renderedInstanceOrder(t *testing.T, out, prefix string) []string {
	t.Helper()
	var got []string
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if name, ok := strings.CutPrefix(trimmed, prefix); ok {
			got = append(got, strings.TrimSpace(name))
		}
	}
	return got
}

func assertSorted(t *testing.T, got []string, what string) {
	t.Helper()
	if len(got) == 0 {
		t.Fatalf("%s: rendered NO instance lines — the assertion below would "+
			"pass vacuously over an empty slice", what)
	}
	want := append([]string(nil), got...)
	sort.Strings(want)
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("%s: rendered order %v is not sorted (want %v) — a bare "+
				"`range` over a Go map is randomised per run (#7357)", what, got, want)
			return
		}
	}
}

func TestPortMirroringRenderOrderIsStable_7357(t *testing.T) {
	cfg := &config.Config{}
	cfg.ForwardingOptions.PortMirroring = &config.PortMirroringConfig{
		Instances: map[string]*config.PortMirrorInstance{
			// EIGHT names, not three or four. The subject is a RANDOMISED map
			// iteration, so an unsorted render coincides with sorted order with
			// probability 1/n!. At n=4 that is 1/24 — a mutation cell would
			// escape about 4% of the time and the test would be quietly flaky
			// in the direction of passing. At n=8 it is 1/40320.
			"zulu":     {Name: "zulu", Output: "ge-0/0/9"},
			"november": {Name: "november", Output: "ge-0/0/8"},
			"mike":     {Name: "mike", Output: "ge-0/0/5"},
			"kilo":     {Name: "kilo", Output: "ge-0/0/4"},
			"golf":     {Name: "golf", Output: "ge-0/0/7"},
			"echo":     {Name: "echo", Output: "ge-0/0/6"},
			"delta":    {Name: "delta", Output: "ge-0/0/2"},
			"alpha":    {Name: "alpha", Output: "ge-0/0/1"},
		},
	}
	var buf strings.Builder
	s := &Server{}
	s.showForwardingOptionsPortMirroring(cfg, &buf)
	assertSorted(t, renderedInstanceOrder(t, buf.String(), "Instance:"), "port-mirroring")
}

func TestSamplingRenderOrderIsStable_7357(t *testing.T) {
	cfg := &config.Config{}
	cfg.ForwardingOptions.Sampling = &config.SamplingConfig{
		Instances: map[string]*config.SamplingInstance{
			// Eight names for the same 1/n! reason as above.
			"zulu":     {Name: "zulu"},
			"november": {Name: "november"},
			"mike":     {Name: "mike"},
			"kilo":     {Name: "kilo"},
			"golf":     {Name: "golf"},
			"echo":     {Name: "echo"},
			"delta":    {Name: "delta"},
			"alpha":    {Name: "alpha"},
		},
	}
	var buf strings.Builder
	s := &Server{}
	s.showForwardingOptions(cfg, &buf)
	assertSorted(t, renderedInstanceOrder(t, buf.String(), "Instance:"), "sampling")
}
