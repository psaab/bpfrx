// #3681: REST /statistics/global must not diverge from the Prometheus collector
// on the kernel nftables host-inbound DROP counters — the PRIMARY host-inbound
// enforcement signal. The pre-#3681 handler (H04) 503-gated the whole endpoint
// behind dp.IsLoaded() BEFORE reading the kernel counters, so a config-only /
// degraded boot lost the host-inbound signal entirely; (H05) swallowed a netlink
// read error into a clean 0 (indistinguishable from "healthy, no denies"); and
// (L03) collapsed the per-zone/family split. Prometheus deliberately does the
// opposite for all three (metrics_counters.go collectHostInboundKernelDenies,
// read before its gate + skip-on-error + [zone,family] labels).
//
// These tests are the L07 fill: they exercise dp-unloaded and a mocked nft read
// error through the REST handler.
package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	xnft "github.com/psaab/xpf/pkg/nftables"
)

// errNftRead models a genuine netlink read failure (permission/state), distinct
// from the (nil, nil) "chain absent, no denies" case.
var errNftRead = errors.New("nftables netlink: permission denied")

func decodeGlobalStats(t *testing.T, rr *httptest.ResponseRecorder) GlobalStats {
	t.Helper()
	var resp struct {
		Success bool        `json:"success"`
		Data    GlobalStats `json:"data"`
		Error   string      `json:"error"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v body=%s", err, rr.Body.String())
	}
	if !resp.Success {
		t.Fatalf("response success=false err=%q body=%s", resp.Error, rr.Body.String())
	}
	return resp.Data
}

// TestGlobalStatsReportsKernelDeniesWhenDataplaneUnloaded is the H04 + L03
// fail-on-revert proof. The kernel nft host-inbound chain drops control-plane
// traffic independent of dataplane load, so with the dataplane UNLOADED the REST
// endpoint must still report the aggregate + per-zone/family breakdown (as a
// partial, DataplaneDegraded response) rather than a blanket 503.
//
// RED on revert: restoring the pre-#3681 `if s.dp == nil || !s.dp.IsLoaded() {
// 503 }` guard at the TOP returns 503 before the kernel read, so decode fails /
// no data — this test goes RED.
func TestGlobalStatsReportsKernelDeniesWhenDataplaneUnloaded(t *testing.T) {
	orig := readHostInboundDenyCounters
	defer func() { readHostInboundDenyCounters = orig }()
	readHostInboundDenyCounters = func() ([]xnft.HostInboundDenyCount, xnft.HostInboundTableState, error) {
		return []xnft.HostInboundDenyCount{
			{Zone: "wan", Family: "ip", Packets: 7, Bytes: 700},
			{Zone: "wan", Family: "ip6", Packets: 3, Bytes: 300},
		}, xnft.HostInboundTableCounted, nil
	}

	s := &Server{} // dp intentionally nil — degraded / config-only boot.
	rr := httptest.NewRecorder()
	s.globalStatsHandler(rr, httptest.NewRequest("GET", "/api/v1/statistics/global", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (degraded boot must still expose the "+
			"kernel host-inbound signal, not 503). body=%s", rr.Code, rr.Body.String())
	}
	data := decodeGlobalStats(t, rr)

	if !data.DataplaneDegraded {
		t.Error("DataplaneDegraded = false, want true on an unloaded dataplane")
	}
	if data.HostInboundKernelDeniesUnavailable {
		t.Error("HostInboundKernelDeniesUnavailable = true on a CLEAN nft read")
	}
	if data.HostInboundKernelDenies != 10 {
		t.Errorf("HostInboundKernelDenies = %d, want 10 (7+3)", data.HostInboundKernelDenies)
	}
	// L03: per-zone/family split preserved.
	got := map[string]uint64{}
	for _, d := range data.HostInboundKernelDenyDetail {
		got[d.Zone+"/"+d.Family] = d.Packets
	}
	if got["wan/ip"] != 7 || got["wan/ip6"] != 3 {
		t.Errorf("per-zone/family detail = %+v, want wan/ip=7 wan/ip6=3 (L03 split lost)", got)
	}
	// The dataplane-dependent counters are absent (0) on a degraded boot.
	if data.RxPackets != 0 {
		t.Errorf("RxPackets = %d, want 0 on unloaded dataplane", data.RxPackets)
	}
}

// TestGlobalStatsKernelDenyReadErrorMarksUnavailableUnloaded is the H05
// fail-on-revert proof for the degraded-boot path: a netlink read failure must
// surface as HostInboundKernelDeniesUnavailable=true, NOT a misleading 0.
//
// RED on revert: the pre-#3681 `if ...; err == nil` swallow left the field 0 with
// no marker, so a read failure was indistinguishable from "no denies" — the
// Unavailable assertion goes RED.
func TestGlobalStatsKernelDenyReadErrorMarksUnavailableUnloaded(t *testing.T) {
	orig := readHostInboundDenyCounters
	defer func() { readHostInboundDenyCounters = orig }()
	readHostInboundDenyCounters = func() ([]xnft.HostInboundDenyCount, xnft.HostInboundTableState, error) {
		return nil, xnft.HostInboundTableAbsent, errNftRead
	}

	s := &Server{} // dp nil — degraded boot AND nft read error.
	rr := httptest.NewRecorder()
	s.globalStatsHandler(rr, httptest.NewRequest("GET", "/api/v1/statistics/global", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200. body=%s", rr.Code, rr.Body.String())
	}
	data := decodeGlobalStats(t, rr)
	if !data.HostInboundKernelDeniesUnavailable {
		t.Error("HostInboundKernelDeniesUnavailable = false on a FAILED nft read " +
			"(a read error must not look like a clean 0 — #3345 contract)")
	}
	if data.HostInboundKernelDenies != 0 {
		t.Errorf("HostInboundKernelDenies = %d, want 0 when unavailable", data.HostInboundKernelDenies)
	}
	if len(data.HostInboundKernelDenyDetail) != 0 {
		t.Errorf("HostInboundKernelDenyDetail = %+v, want empty on read error", data.HostInboundKernelDenyDetail)
	}
}

// TestGlobalStatsKernelDenyReadErrorMarksUnavailableLoaded proves the same H05
// marker on the fully-loaded path: the userspace-dp global counters read fine
// (200), but the kernel nft read failed, so the aggregate is marked Unavailable
// rather than silently reported as 0.
func TestGlobalStatsKernelDenyReadErrorMarksUnavailableLoaded(t *testing.T) {
	orig := readHostInboundDenyCounters
	defer func() { readHostInboundDenyCounters = orig }()
	readHostInboundDenyCounters = func() ([]xnft.HostInboundDenyCount, xnft.HostInboundTableState, error) {
		return nil, xnft.HostInboundTableAbsent, errNftRead
	}

	s := &Server{dp: &idxValueAPIDP{Manager: dataplane.New()}}
	rr := httptest.NewRecorder()
	s.globalStatsHandler(rr, httptest.NewRequest("GET", "/api/v1/statistics/global", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (loaded dp, only the kernel read failed). body=%s",
			rr.Code, rr.Body.String())
	}
	data := decodeGlobalStats(t, rr)
	if data.DataplaneDegraded {
		t.Error("DataplaneDegraded = true on a LOADED dataplane")
	}
	if !data.HostInboundKernelDeniesUnavailable {
		t.Error("HostInboundKernelDeniesUnavailable = false on a FAILED nft read")
	}
	// The userspace counter still reads its own index-derived value (proves the
	// dataplane-dependent path still runs when only the kernel read failed).
	wantRx := uint64(dataplane.GlobalCtrRxPackets)*1000 + 7
	if data.RxPackets != wantRx {
		t.Errorf("RxPackets = %d, want %d (loaded userspace counters must still read)",
			data.RxPackets, wantRx)
	}
}

// TestGlobalStatsKernelDenyCleanReadNoMarker guards against a false-positive
// Unavailable marker: when the chain is absent the nft reader returns (nil, nil)
// — no enforcement means no denies, not an error — so the aggregate is a real 0
// and Unavailable stays false.
func TestGlobalStatsKernelDenyCleanReadNoMarker(t *testing.T) {
	orig := readHostInboundDenyCounters
	defer func() { readHostInboundDenyCounters = orig }()
	readHostInboundDenyCounters = func() ([]xnft.HostInboundDenyCount, xnft.HostInboundTableState, error) {
		return nil, xnft.HostInboundTableAbsent, nil
	}

	s := &Server{dp: &idxValueAPIDP{Manager: dataplane.New()}}
	rr := httptest.NewRecorder()
	s.globalStatsHandler(rr, httptest.NewRequest("GET", "/api/v1/statistics/global", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200. body=%s", rr.Code, rr.Body.String())
	}
	data := decodeGlobalStats(t, rr)
	if data.HostInboundKernelDeniesUnavailable {
		t.Error("HostInboundKernelDeniesUnavailable = true on a CLEAN empty read " +
			"(absent chain is a real 0, not a read error)")
	}
	if data.HostInboundKernelDenies != 0 || len(data.HostInboundKernelDenyDetail) != 0 {
		t.Errorf("aggregate=%d detail=%+v, want 0/empty on absent chain",
			data.HostInboundKernelDenies, data.HostInboundKernelDenyDetail)
	}
}
