package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/psaab/xpf/pkg/conntrack"
	"github.com/psaab/xpf/pkg/dataplane"
	xnft "github.com/psaab/xpf/pkg/nftables"
)

// zoneRealReadDP reuses the fully-wired descriptorCoverageDP (loaded, apply
// result, all OTHER counter reads succeed) but delegates the per-zone counter
// read to the REAL dataplane.Manager instead of the success-stub. That
// exercises the production #3643 HIDE read path: an empty sparse offset map ->
// ErrCounterNotPopulated for any zone id, including a stable-hash id >=
// MaxZones. On master (pre-#3643) the real Manager instead OOB'd the dense
// zone_counters array / returned "map not found", which the read surfaces
// turned into a 500 (REST) or a false xpf_counter_read_errors_total bump
// (Prometheus).
type zoneRealReadDP struct {
	*descriptorCoverageDP
}

func (d *zoneRealReadDP) ReadZoneCounters(zoneID uint16, dir int) (dataplane.CounterValue, error) {
	return d.Manager.ReadZoneCounters(zoneID, dir)
}

// TestZonesHandlerZoneCountersNotAvailable is the #3643 REST HIDE pin. A zone
// whose stable-hash id is >= MaxZones (40000/41000 here) must NOT 500 the
// /security/zones endpoint; it returns 200 with per_zone_counters_available
// false and the numeric per-zone counts unset (not a misleading 0).
//
// FAIL-ON-REVERT: restoring the dense-array read in ReadZoneCounters (or the
// old "err != nil -> readErr -> 500" handling that treats
// ErrCounterNotPopulated as a genuine failure) makes the endpoint 500 for the
// large-id zone, so the 200 assertion goes RED.
func TestZonesHandlerZoneCountersNotAvailable(t *testing.T) {
	s := &Server{
		store: newDescriptorCoverageStore(t),
		dp: &zoneRealReadDP{&descriptorCoverageDP{
			Manager: dataplane.New(),
			apply:   &dataplane.ApplyResult{ZoneIDs: map[string]uint16{"trust": 40000, "untrust": 41000}},
		}},
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/security/zones", nil)
	s.zonesHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("zonesHandler status = %d, want 200 (a stable-hash zone id >= MaxZones "+
			"must not 500 the endpoint). body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Success bool       `json:"success"`
		Data    []ZoneInfo `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal zones response: %v; body=%s", err, rr.Body.String())
	}
	if !resp.Success || len(resp.Data) == 0 {
		t.Fatalf("success=%v, %d zones; want success + >=1 zone; body=%s",
			resp.Success, len(resp.Data), rr.Body.String())
	}
	for _, z := range resp.Data {
		if z.PerZoneCountersAvailable {
			t.Errorf("zone %q per_zone_counters_available = true, want false "+
				"(per-zone counters are HIDE'd in the userspace era)", z.Name)
		}
		if z.IngressPackets != 0 || z.EgressPackets != 0 || z.IngressBytes != 0 || z.EgressBytes != 0 {
			t.Errorf("zone %q reports nonzero per-zone counts (%+v) while marked unavailable",
				z.Name, z)
		}
	}
}

// TestCollectDoesNotFalseAlertOnZoneReads is the #3643 Prometheus HIDE pin.
// A full Collect() over a loaded DP whose per-zone reads go through the real
// Manager (stable-hash ids >= MaxZones) must NOT bump
// xpf_counter_read_errors_total and must NOT emit any xpf_zone_* sample --
// the per-zone metric family was dropped. Global/interface/policy/filter reads
// succeed and the pre-gate host-inbound read is neutralized, so a nonzero
// error count could only come from the (now removed) per-zone collector.
//
// FAIL-ON-REVERT: restoring collectZoneCounters + the dense-array read makes
// the per-zone read fail for the large-id zones and bump
// xpf_counter_read_errors_total once per zone, so the == 0 assertion goes RED
// (and the xpf_zone_ family reappears).
func TestCollectDoesNotFalseAlertOnZoneReads(t *testing.T) {
	orig := readHostInboundDenyCounters
	readHostInboundDenyCounters = func() ([]xnft.HostInboundDenyCount, error) { return nil, nil }
	defer func() { readHostInboundDenyCounters = orig }()

	store := newDescriptorCoverageStore(t)
	srv := &Server{store: store, gc: conntrack.NewGC(nil, time.Minute), startTime: time.Now()}
	srv.dp = &zoneRealReadDP{&descriptorCoverageDP{
		Manager: dataplane.New(),
		apply: &dataplane.ApplyResult{
			ZoneIDs:   map[string]uint16{"trust": 40000, "untrust": 41000},
			FilterIDs: map[string]uint32{"inet:fin": 0, "inet6:fin6": 100},
		},
	}}
	c := newCollector(srv)

	ch := make(chan prometheus.Metric, 256)
	c.Collect(ch)
	close(ch)

	var sawZoneMetric bool
	for m := range ch {
		if strings.Contains(m.Desc().String(), "xpf_zone_") {
			sawZoneMetric = true
		}
	}
	if sawZoneMetric {
		t.Error("Collect() emitted an xpf_zone_* metric; the per-zone family must be dropped (#3643 HIDE)")
	}
	if got := c.counterReadErrors.Load(); got != 0 {
		t.Errorf("counterReadErrors = %d after Collect() with stable-hash zone ids >= MaxZones; "+
			"want 0 -- the structural per-zone OOB must no longer false-alert (#3643/#3345)", got)
	}
}
