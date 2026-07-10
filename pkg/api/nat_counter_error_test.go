// #5046: NAT-stats telemetry read failures must fail CLOSED as unavailable,
// not render as a healthy zero-usage / zero-hit reading with HTTP 200. This
// mirrors the #3345/#3408 counter-error contract already enforced on the
// zone/policy/filter surfaces.
//
// FAIL-ON-REVERT: restoring any `if err == nil` swallow (or the bare `nil`
// return from runtimeSourceNATPools) makes the affected handler return 200 with
// a clean zero and the collector emit a used-ports sample with no error bump —
// the want-assertions below go RED.
package api

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// natStatusErrAPIDP is a loaded DP whose userspace Status() read FAILS. Because
// it exposes a Status() method, runtimeSourceNATPools takes the runtime path
// and must propagate the read failure (not swallow it to a config fallback).
type natStatusErrAPIDP struct {
	*dataplane.Manager
}

func (d *natStatusErrAPIDP) IsLoaded() bool { return true }

func (d *natStatusErrAPIDP) Status() (dpuserspace.ProcessStatus, error) {
	return dpuserspace.ProcessStatus{}, errors.New("nat status bridge degraded")
}

// natPortCtrErrAPIDP is a loaded DP with NO Status() surface (so the handler
// falls back to the legacy port counter) whose ReadNATPortCounter FAILS.
type natPortCtrErrAPIDP struct {
	*dataplane.Manager
	result *dataplane.ApplyResult
}

func (d *natPortCtrErrAPIDP) IsLoaded() bool                          { return true }
func (d *natPortCtrErrAPIDP) LastApplyResult() *dataplane.ApplyResult { return d.result.Clone() }
func (d *natPortCtrErrAPIDP) ReadNATPortCounter(uint32) (uint64, error) {
	return 0, errors.New("nat port counter bridge degraded")
}

// natRuleCtrErrAPIDP is a loaded DP whose ReadNATRuleCounter FAILS.
type natRuleCtrErrAPIDP struct {
	*dataplane.Manager
	result *dataplane.ApplyResult
}

func (d *natRuleCtrErrAPIDP) IsLoaded() bool                          { return true }
func (d *natRuleCtrErrAPIDP) LastApplyResult() *dataplane.ApplyResult { return d.result.Clone() }
func (d *natRuleCtrErrAPIDP) ReadNATRuleCounter(uint32) (dataplane.CounterValue, error) {
	return dataplane.CounterValue{}, errors.New("nat rule counter bridge degraded")
}

func TestNATPoolStatsHandlerSurfacesRuntimeStatusReadError(t *testing.T) {
	s := &Server{store: newNATPoolStatsAPIStore(t), dp: &natStatusErrAPIDP{Manager: dataplane.New()}}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/security/nat/source/pools", nil)
	s.natPoolStatsHandler(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("natPoolStatsHandler status = %d, want %d on runtime status read failure. body=%s",
			rr.Code, http.StatusInternalServerError, rr.Body.String())
	}
}

func TestNATPoolStatsHandlerSurfacesPortCounterReadError(t *testing.T) {
	s := &Server{
		store: newNATPoolStatsAPIStore(t),
		dp: &natPortCtrErrAPIDP{
			Manager: dataplane.New(),
			result:  &dataplane.ApplyResult{PoolIDs: map[string]uint8{"p1": 7}},
		},
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/security/nat/source/pools", nil)
	s.natPoolStatsHandler(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("natPoolStatsHandler status = %d, want %d on port counter read failure. body=%s",
			rr.Code, http.StatusInternalServerError, rr.Body.String())
	}
}

func TestNATRuleStatsHandlerSurfacesRuleCounterReadError(t *testing.T) {
	s := &Server{
		store: newNATStatsAPIStore(t),
		dp: &natRuleCtrErrAPIDP{
			Manager: dataplane.New(),
			result: &dataplane.ApplyResult{
				NATCounterIDs: map[string]uint32{
					dataplane.NATCounterKey(dataplane.NATCounterTypeSource, "trust-to-untrust", "r1"): 31,
					dataplane.NATCounterKey(dataplane.NATCounterTypeSource, "trust-to-untrust", "r2"): 32,
				},
			},
		},
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/security/nat/source/rules", nil)
	s.natRuleStatsHandler(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("natRuleStatsHandler status = %d, want %d on rule counter read failure. body=%s",
			rr.Code, http.StatusInternalServerError, rr.Body.String())
	}
}

// TestCollectNATPoolMetricsSkipsSampleAndBumpsOnPortCounterError pins the
// Prometheus half of the contract: on a ReadNATPortCounter failure the
// collector must OMIT the xpf_nat_pool_used_ports sample (never a fake 0) AND
// bump the shared xpf_counter_read_errors_total, matching the zone/policy/
// filter collectors.
func TestCollectNATPoolMetricsSkipsSampleAndBumpsOnPortCounterError(t *testing.T) {
	srv := &Server{store: newNATPoolStatsAPIStore(t)}
	c := newCollector(srv)
	dp := &natPortCtrErrAPIDP{
		Manager: dataplane.New(),
		result:  &dataplane.ApplyResult{PoolIDs: map[string]uint8{"p1": 7}},
	}

	ch := make(chan prometheus.Metric, 64)
	c.collectNATPoolMetrics(ch, dp)
	close(ch)

	var usedEmitted int
	for m := range ch {
		if strings.Contains(m.Desc().String(), "xpf_nat_pool_used_ports") {
			usedEmitted++
		}
	}
	if usedEmitted != 0 {
		t.Errorf("collectNATPoolMetrics emitted %d xpf_nat_pool_used_ports samples on a read failure; want 0 (omit on error)", usedEmitted)
	}
	if c.counterReadErrors.Load() == 0 {
		t.Error("counterReadErrors not bumped on a NAT port counter read failure")
	}
}
