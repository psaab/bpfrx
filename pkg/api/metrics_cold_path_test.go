package api

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #1621: Prometheus emission test for the cold-path histogram surface.
//
// Per plan v2 (§4.5 + claude-smr-plan-r1.md F2/F4/F5 + agy-r1.md F3/F5/F6 +
// codex-r1.md F3/F4/F5):
//
//   - Bucket counter uses `le` label (PromQL histogram_quantile-
//     compatible).
//   - clock_source gauge ALWAYS emitted, even when uncalibrated
//     (source="unset"), so dashboards distinguish "tsc active" from
//     "no data this scrape".
//   - snapshot_failed counter ALWAYS emitted so operators can detect
//     publish-contention starvation.
//   - ns_per_tsc_q32 gauge emitted so operators can validate
//     calibration sanity.
//   - All scalars (sample_phase, wrapper_underflow_count,
//     wrapper_ns_baseline) emitted.

func TestEmitWorkerColdPath_EmptyStatus_AlwaysEmittedMetrics(t *testing.T) {
	c := newCollectorWithWorkerDescsOnly()
	status := dpuserspace.ProcessStatus{
		WorkerRuntime: []dpuserspace.WorkerRuntimeStatus{
			{WorkerID: 0}, // empty cold-path fields
		},
	}
	got := collectFromEmitWorkerRuntime(t, c, status)

	want := map[string]bool{
		"xpf_userspace_worker_cold_path_sample_phase_total":            false,
		"xpf_userspace_worker_cold_path_wrapper_underflow_count_total": false,
		"xpf_userspace_worker_cold_path_wrapper_ns_baseline":           false,
		"xpf_userspace_worker_cold_path_ns_per_tsc_q32":                false,
		"xpf_userspace_worker_cold_path_clock_source":                  false,
		"xpf_userspace_worker_cold_path_snapshot_failed_total":         false,
	}
	for _, m := range got {
		name := descName(m.Desc())
		if _, ok := want[name]; ok {
			want[name] = true
		}
	}
	for name, seen := range want {
		if !seen {
			t.Errorf("cold-path metric not emitted on empty status: %s", name)
		}
	}
}

func TestEmitWorkerColdPath_ClockSourceGaugeAlwaysOne(t *testing.T) {
	c := newCollectorWithWorkerDescsOnly()
	cases := []struct {
		name        string
		source      string
		labelExpect string
	}{
		{"unset", "", "unset"},
		{"tsc", "tsc", "tsc"},
		{"clock_gettime", "clock_gettime", "clock_gettime"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status := dpuserspace.ProcessStatus{
				WorkerRuntime: []dpuserspace.WorkerRuntimeStatus{
					{WorkerID: 0, ColdPathClockSource: tc.source},
				},
			}
			got := collectFromEmitWorkerRuntime(t, c, status)
			var foundClockSource bool
			for _, m := range got {
				if m.Desc() != c.workerColdPathClockSource {
					continue
				}
				foundClockSource = true
				var pb dto.Metric
				if err := m.Write(&pb); err != nil {
					t.Fatalf("metric.Write: %v", err)
				}
				if v := pb.Gauge.GetValue(); v != 1.0 {
					t.Errorf("clock_source gauge value: want 1.0 got %v", v)
				}
				var srcLabel string
				for _, l := range pb.Label {
					if l.GetName() == "source" {
						srcLabel = l.GetValue()
					}
				}
				if srcLabel != tc.labelExpect {
					t.Errorf("clock_source label: want %q got %q",
						tc.labelExpect, srcLabel)
				}
			}
			if !foundClockSource {
				t.Errorf("clock_source gauge missing for %s", tc.name)
			}
		})
	}
}

func TestEmitWorkerColdPath_BucketLabelIsLE(t *testing.T) {
	c := newCollectorWithWorkerDescsOnly()
	// Build a synthetic histogram with 1 bucket entry in slot 3.
	hist := make([][]uint64, 16)
	for i := range hist {
		hist[i] = make([]uint64, 24)
	}
	hist[3][5] = 42 // slot 3, bucket 5 (le = 2^(10+5)-1 = 32767)

	status := dpuserspace.ProcessStatus{
		WorkerRuntime: []dpuserspace.WorkerRuntimeStatus{
			{
				WorkerID:        0,
				ColdPathHist:    hist,
				ColdPathSamples: make([]uint64, 16),
			},
		},
	}
	got := collectFromEmitWorkerRuntime(t, c, status)
	var foundBucket bool
	for _, m := range got {
		if m.Desc() != c.workerColdPathBucket {
			continue
		}
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			t.Fatalf("metric.Write: %v", err)
		}
		labels := map[string]string{}
		for _, l := range pb.Label {
			labels[l.GetName()] = l.GetValue()
		}
		// Verify the bucket metric has the `le` label (NOT
		// `bucket_hi_ns`) per Prometheus histogram_quantile()
		// convention.
		if _, ok := labels["le"]; !ok {
			t.Errorf("bucket metric missing `le` label: labels=%v", labels)
		}
		if _, ok := labels["bucket_hi_ns"]; ok {
			t.Errorf("bucket metric must not use legacy `bucket_hi_ns` label: labels=%v", labels)
		}
		// Sanity: slot 3 + bucket 5 + value 42.
		if labels["zone_pair_slot"] == "3" && labels["le"] == "32767" {
			if pb.Counter.GetValue() == 42 {
				foundBucket = true
			}
		}
	}
	if !foundBucket {
		t.Errorf("expected bucket {worker=0,slot=3,le=32767}=42 not found in emission")
	}
}

func TestEmitWorkerColdPath_PopulatedSlot(t *testing.T) {
	c := newCollectorWithWorkerDescsOnly()
	samples := make([]uint64, 16)
	sumNS := make([]uint64, 16)
	aliasSeen := make([]bool, 16)
	samples[7] = 100
	sumNS[7] = 12345
	aliasSeen[7] = true

	status := dpuserspace.ProcessStatus{
		WorkerRuntime: []dpuserspace.WorkerRuntimeStatus{
			{
				WorkerID:                      2,
				ColdPathSamples:               samples,
				ColdPathSumNS:                 sumNS,
				ColdPathAliasSeen:             aliasSeen,
				ColdPathSamplePhase:           50000,
				ColdPathWrapperUnderflowCount: 3,
				ColdPathWrapperNSBaseline:     45,
				ColdPathNSPerTSCQ32:           1871674289,
				ColdPathClockSource:           "tsc",
				ColdPathSnapshotFailed:        2,
			},
		},
	}
	got := collectFromEmitWorkerRuntime(t, c, status)

	type key struct {
		desc *prometheus.Desc
		slot string
	}
	seen := map[key]float64{}
	for _, m := range got {
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			t.Fatalf("metric.Write: %v", err)
		}
		var slot string
		for _, l := range pb.Label {
			if l.GetName() == "zone_pair_slot" {
				slot = l.GetValue()
			}
		}
		v := 0.0
		if pb.Counter != nil {
			v = pb.Counter.GetValue()
		} else if pb.Gauge != nil {
			v = pb.Gauge.GetValue()
		}
		seen[key{m.Desc(), slot}] = v
	}
	if seen[key{c.workerColdPathSamples, "7"}] != 100 {
		t.Errorf("samples slot 7: want 100 got %v",
			seen[key{c.workerColdPathSamples, "7"}])
	}
	if seen[key{c.workerColdPathSumNS, "7"}] != 12345 {
		t.Errorf("sum_ns slot 7: want 12345 got %v",
			seen[key{c.workerColdPathSumNS, "7"}])
	}
	if seen[key{c.workerColdPathAliasSeen, "7"}] != 1 {
		t.Errorf("alias_seen slot 7: want 1.0 got %v",
			seen[key{c.workerColdPathAliasSeen, "7"}])
	}
	if seen[key{c.workerColdPathSamplePhase, ""}] != 50000 {
		t.Errorf("sample_phase: want 50000 got %v",
			seen[key{c.workerColdPathSamplePhase, ""}])
	}
	if seen[key{c.workerColdPathWrapperUnderflow, ""}] != 3 {
		t.Errorf("wrapper_underflow: want 3 got %v",
			seen[key{c.workerColdPathWrapperUnderflow, ""}])
	}
	if seen[key{c.workerColdPathWrapperNSBaseline, ""}] != 45 {
		t.Errorf("wrapper_ns_baseline: want 45 got %v",
			seen[key{c.workerColdPathWrapperNSBaseline, ""}])
	}
	if seen[key{c.workerColdPathNSPerTSCQ32, ""}] != 1871674289 {
		t.Errorf("ns_per_tsc_q32: want 1871674289 got %v",
			seen[key{c.workerColdPathNSPerTSCQ32, ""}])
	}
	if seen[key{c.workerColdPathSnapshotFailedTotal, ""}] != 2 {
		t.Errorf("snapshot_failed: want 2 got %v",
			seen[key{c.workerColdPathSnapshotFailedTotal, ""}])
	}
}

// descName extracts the metric name from a *prometheus.Desc by parsing
// the Desc's `String()` representation. Prometheus client_golang
// stores the name internally but doesn't expose an accessor; the
// String() form is "Desc{fqName: \"<NAME>\", ...}".
func descName(d *prometheus.Desc) string {
	s := d.String()
	const prefix = `fqName: "`
	idx := strings.Index(s, prefix)
	if idx < 0 {
		return s
	}
	rest := s[idx+len(prefix):]
	end := strings.Index(rest, `"`)
	if end < 0 {
		return rest
	}
	return rest[:end]
}
