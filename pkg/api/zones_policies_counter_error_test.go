// #3408: per-zone / per-policy counter read failures must be surfaced, not
// reported as clean zeros — the same contract as the global counters (#3345).
// REST returns HTTP 500; the Prometheus collector SKIPS the affected sample
// and bumps xpf_counter_read_errors_total.
//
// FAIL-ON-REVERT: restoring the `err == nil` swallow (dropping the readErr
// capture / the counterReadErrors bump) makes REST return 200 with clean-zero
// counts and the collector emit policy samples without an error count — the
// want-assertions below go RED.
package api

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/psaab/xpf/pkg/dataplane"
)

// policyZoneErrAPIDP is a loaded apiRuntimeDataPlane whose per-zone and
// per-policy counter reads fail. It supplies a LastApplyResult so the zone
// handler reaches the read (zone IDs must resolve).
type policyZoneErrAPIDP struct {
	*dataplane.Manager
	apply *dataplane.ApplyResult
}

func (d *policyZoneErrAPIDP) IsLoaded() bool { return true }

func (d *policyZoneErrAPIDP) LastApplyResult() *dataplane.ApplyResult { return d.apply }

func (d *policyZoneErrAPIDP) ReadPolicyCounters(uint32) (dataplane.CounterValue, error) {
	return dataplane.CounterValue{}, errors.New("counter bridge degraded")
}

func (d *policyZoneErrAPIDP) ReadZoneCounters(uint16, int) (dataplane.CounterValue, error) {
	return dataplane.CounterValue{}, errors.New("counter bridge degraded")
}

func TestPoliciesHandlerSurfacesReadError(t *testing.T) {
	s := &Server{
		store: newDescriptorCoverageStore(t),
		dp:    &policyZoneErrAPIDP{Manager: dataplane.New()},
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/security/policies", nil)
	s.policiesHandler(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("policiesHandler status = %d, want %d on policy counter read failure. body=%s",
			rr.Code, http.StatusInternalServerError, rr.Body.String())
	}
}

func TestZonesHandlerSurfacesReadError(t *testing.T) {
	s := &Server{
		store: newDescriptorCoverageStore(t),
		dp: &policyZoneErrAPIDP{
			Manager: dataplane.New(),
			apply:   &dataplane.ApplyResult{ZoneIDs: map[string]uint16{"trust": 1, "untrust": 2}},
		},
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/security/zones", nil)
	s.zonesHandler(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("zonesHandler status = %d, want %d on zone counter read failure. body=%s",
			rr.Code, http.StatusInternalServerError, rr.Body.String())
	}
}

func TestCollectPolicyCountersCountsReadErrors(t *testing.T) {
	srv := &Server{store: newDescriptorCoverageStore(t)}
	c := newCollector(srv)
	dp := &policyZoneErrAPIDP{Manager: dataplane.New()}

	ch := make(chan prometheus.Metric, 64)
	c.collectPolicyCounters(ch, dp)
	close(ch)

	var policyEmitted int
	for m := range ch {
		if strings.Contains(m.Desc().String(), "xpf_policy_hits_total") {
			policyEmitted++
		}
	}
	if policyEmitted != 0 {
		t.Errorf("collectPolicyCounters emitted %d policy samples on an all-failing DP; want 0", policyEmitted)
	}
	if c.counterReadErrors.Load() == 0 {
		t.Error("counterReadErrors not bumped on a per-policy read failure")
	}
}

func TestCollectZoneCountersCountsReadErrors(t *testing.T) {
	srv := &Server{store: newDescriptorCoverageStore(t)}
	c := newCollector(srv)
	dp := &policyZoneErrAPIDP{
		Manager: dataplane.New(),
		apply:   &dataplane.ApplyResult{ZoneIDs: map[string]uint16{"trust": 1, "untrust": 2}},
	}

	ch := make(chan prometheus.Metric, 64)
	c.collectZoneCounters(ch, dp)
	close(ch)

	var zoneEmitted int
	for m := range ch {
		if strings.Contains(m.Desc().String(), "xpf_zone_") {
			zoneEmitted++
		}
	}
	if zoneEmitted != 0 {
		t.Errorf("collectZoneCounters emitted %d zone samples on an all-failing DP; want 0", zoneEmitted)
	}
	if c.counterReadErrors.Load() == 0 {
		t.Error("counterReadErrors not bumped on a per-zone read failure")
	}
}
