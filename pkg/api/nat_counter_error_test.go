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

// natStatusAndApplyErrAPIDP is a loaded DP with an apply result whose
// userspace Status() FAILS -- the shape collectNATPoolMetrics needs to reach
// its status-error branch (#8606).
type natStatusAndApplyErrAPIDP struct {
	*dataplane.Manager
	result *dataplane.ApplyResult
}

func (d *natStatusAndApplyErrAPIDP) IsLoaded() bool                          { return true }
func (d *natStatusAndApplyErrAPIDP) LastApplyResult() *dataplane.ApplyResult { return d.result.Clone() }
func (d *natStatusAndApplyErrAPIDP) Status() (dpuserspace.ProcessStatus, error) {
	return dpuserspace.ProcessStatus{}, errors.New("nat status bridge degraded")
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

// #8606: TestNATPoolStatsHandlerSurfacesPortCounterReadError was REMOVED here,
// deliberately rather than by attrition.
//
// Its subject was the handler's legacy fallback to `ReadNATPortCounter` when
// the helper reported no runtime entry. That fallback is gone: the map it read
// is seeded with `rand.Uint64()` and has had no writer since #1476 deleted the
// eBPF pipeline, so the fallback filled a blank with a random number and called
// it a measurement.
//
// The CONTRACT the deleted test guarded -- a failed read must surface as 500,
// never as a healthy zero-usage pool (#5046, #3345) -- is unchanged and is
// covered by TestNATPoolStatsHandlerSurfacesRuntimeStatusReadError above, which
// exercises the read that still exists. Deleting the test rather than
// retargeting it is the honest form: retargeted, it would have been a second
// copy of its own sibling.

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
// Prometheus half of the contract, re-keyed onto the surviving read (#8606).
//
// The collector's occupancy source is now the per-scrape helper status, shared
// across collectors under #5317. A nil status is what a FAILED or absent round
// trip yields, and it must OMIT the xpf_nat_pool_used_ports sample (never a
// fake 0) AND bump the shared xpf_counter_read_errors_total, matching the
// zone/policy/filter collectors. That is the same #5046/#3345 contract the
// ReadNATPortCounter version of this test guarded, on the read that exists now.
func TestCollectNATPoolMetricsSkipsSampleAndBumpsOnStatusReadError(t *testing.T) {
	srv := &Server{store: newNATPoolStatsAPIStore(t)}
	c := newCollector(srv)
	// Needs BOTH a failing Status() and an apply result: collectNATPoolMetrics
	// returns early when LastApplyResult is nil, so a fixture with only the
	// failing status never reaches the code under test and the assertion would
	// fail for the wrong reason.
	dp := &natStatusAndApplyErrAPIDP{
		Manager: dataplane.New(),
		result:  &dataplane.ApplyResult{PoolIDs: map[string]uint8{"p1": 7}},
	}

	ch := make(chan prometheus.Metric, 64)
	c.collectNATPoolMetrics(ch, dp, nil)
	close(ch)

	var usedEmitted int
	for m := range ch {
		if strings.Contains(m.Desc().String(), "xpf_nat_pool_used_ports") {
			usedEmitted++
		}
	}
	if usedEmitted != 0 {
		t.Errorf("collectNATPoolMetrics emitted %d xpf_nat_pool_used_ports samples on a status read failure; want 0 (omit on error)", usedEmitted)
	}
	if c.counterReadErrors.Load() == 0 {
		t.Error("counterReadErrors not bumped on a NAT pool status read failure")
	}
}
