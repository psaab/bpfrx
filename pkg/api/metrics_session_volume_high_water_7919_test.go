package api

import (
	"testing"

	dto "github.com/prometheus/client_model/go"

	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #7919: the per-worker session-volume high-water metric, and specifically the
// property that makes it usable as evidence — ABSENT and ZERO are different
// answers and must not collapse into one series.
//
// WHY THAT MATTERS HERE rather than as a style point. Every worker holds a copy
// of every session (measured on the reference cluster: `session_table_entries`
// reads 6 on all six workers for three flows), but only the worker whose
// packets land accounts for one. So "which workers' tables ever hold volume" is
// the axis that separates an accounting defect from a mirroring defect. An old
// helper that cannot answer, decoded as 0, would assert that a worker has never
// carried traffic — manufacturing precisely the evidence this field exists to
// gather.

func workerVolumeSeries(t *testing.T, w dpuserspace.WorkerRuntimeStatus) (float64, bool) {
	t.Helper()
	c := newCollectorWithWorkerDescsOnly()
	status := dpuserspace.ProcessStatus{WorkerRuntime: []dpuserspace.WorkerRuntimeStatus{w}}
	for _, m := range collectFromEmitWorkerRuntime(t, c, status) {
		if descName(m.Desc()) == "xpf_userspace_worker_session_volume_high_water" {
			var pb dto.Metric
			if err := m.Write(&pb); err != nil {
				t.Fatalf("metric.Write: %v", err)
			}
			return pb.GetGauge().GetValue(), true
		}
	}
	return 0, false
}

// A helper that REPORTS the high-water gets a series carrying it.
func TestSessionVolumeHighWaterIsEmittedWhenReported7919(t *testing.T) {
	v := uint64(117280)
	got, ok := workerVolumeSeries(t, dpuserspace.WorkerRuntimeStatus{
		WorkerID: 2, SessionVolumeHighWater: &v,
	})
	if !ok {
		t.Fatalf("no xpf_userspace_worker_session_volume_high_water series for a worker that reported one")
	}
	if got != 117280 {
		t.Errorf("high-water = %v, want 117280 — the value must reach the series, "+
			"not just its presence", got)
	}
}

// THE DEFECT GUARD. A helper that does NOT report it (an older one, which omits
// the wire key) must produce NO series — not a 0.
func TestSessionVolumeHighWaterIsAbsentWhenUnreported7919(t *testing.T) {
	if _, ok := workerVolumeSeries(t, dpuserspace.WorkerRuntimeStatus{WorkerID: 2}); ok {
		t.Fatalf("a helper that does not report the high-water produced a series; " +
			"absent must stay absent. A 0 here reads as 'this worker has never " +
			"carried traffic', which is a measurement the helper never made")
	}
}

// POSITIVE CONTROL for the assertion above. `ok == false` would also be the
// answer if the collector emitted no worker series at all, or if the metric
// name were misspelled in the test — both of which would make the guard pass
// while checking nothing. A sibling metric on the SAME status must be present.
func TestWorkerSeriesAreEmittedAtAllForTheAbsentCase7919(t *testing.T) {
	c := newCollectorWithWorkerDescsOnly()
	status := dpuserspace.ProcessStatus{
		WorkerRuntime: []dpuserspace.WorkerRuntimeStatus{{WorkerID: 2, WorkLoops: 5}},
	}
	seen := false
	for _, m := range collectFromEmitWorkerRuntime(t, c, status) {
		if descName(m.Desc()) == "xpf_userspace_worker_work_loops_total" {
			seen = true
		}
	}
	if !seen {
		t.Fatalf("control: no xpf_userspace_worker_work_loops_total series for the " +
			"same status the absence test uses — that test would pass vacuously")
	}
}

// A reported ZERO is indistinguishable from unreported, and that is deliberate:
// the helper omits the key while the value is 0, so both encode "no positive
// evidence of volume". Pinned so nobody later "fixes" it into a measured 0.
func TestReportedZeroHighWaterIsStillASeries7919(t *testing.T) {
	z := uint64(0)
	got, ok := workerVolumeSeries(t, dpuserspace.WorkerRuntimeStatus{
		WorkerID: 2, SessionVolumeHighWater: &z,
	})
	if !ok || got != 0 {
		t.Fatalf("an EXPLICIT zero from the helper must still be a series carrying 0 "+
			"(got ok=%v value=%v); the pointer, not the value, is what encodes "+
			"'cannot answer'", ok, got)
	}
}
