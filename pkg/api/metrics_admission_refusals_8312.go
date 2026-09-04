package api

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/psaab/xpf/pkg/diagcmd"
)

// #8312: export the admission limiters' refusal counts.
//
// THE NUMBER THIS EXISTS TO PROVIDE. #7294 item 2 asks for a WEIGHTED cost
// model on diagcmd.SessionWalkLimiter — charge a full table walk more slots
// than a cursor page — with the acceptance criterion that the model be "stated
// with a measurement, not asserted". Two attempts measured the wrong quantity:
// a cluster REST sweep whose ~80ms of HTTP + JSON fixed cost buried the walk
// and produced five NEGATIVE per-session slopes, and a proposed Go benchmark
// that needs BPF_MAP_CREATE and could not be run.
//
// A weighting is only observable if some request is refused today that a
// weighted budget would admit. Nothing counted refusals, so no per-item cost —
// however precisely measured — could have decided it. This is the instrument
// that can: if these stay at 0 on real deployments the weighting buys nothing
// and the issue is answered; if they climb, the labels say which budget and
// the case is made from a running box rather than from a benchmark.
//
// ALWAYS EMITTED, INCLUDING AT ZERO, per the #3464 convention: a counter that
// appears only once it fires cannot be alerted on and cannot distinguish
// "never refused" from "not scraped". Zero is the answer this issue most needs
// to be able to see.
//
// Cumulative and process-lifetime, so a restart resets it — which is the
// ordinary Prometheus counter contract and is handled by rate() at query time.
func (c *xpfCollector) describeAdmissionRefusals(ch chan<- *prometheus.Desc) {
	ch <- c.admissionRefusalsTotal
}

// admissionLimiters is the set sampled, with the label each carries.
//
// It is a function rather than a package var so a test can observe the SAME
// mapping the collector uses instead of restating it — a second list of the
// same fact is the drift this codebase has been bitten by, and the limiters
// themselves are process-wide singletons whose identity is the thing under
// test.
func admissionLimiters() []struct {
	name    string
	limiter *diagcmd.Limiter
} {
	return []struct {
		name    string
		limiter *diagcmd.Limiter
	}{
		{"session_walk", diagcmd.SessionWalkLimiter},
		{"remote_walk", diagcmd.RemoteWalkLimiter},
		{"diagnostic", diagcmd.DefaultLimiter},
	}
}

func (c *xpfCollector) emitAdmissionRefusals(ch chan<- prometheus.Metric) {
	for _, l := range admissionLimiters() {
		if l.limiter == nil {
			continue
		}
		ch <- prometheus.MustNewConstMetric(c.admissionRefusalsTotal,
			prometheus.CounterValue, float64(l.limiter.Refusals()), l.name)
	}
}
