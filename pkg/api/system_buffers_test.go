package api

import (
	"encoding/json"
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

type systemBuffersAPIUserspaceDP struct {
	*dataplane.Manager
	status         dpuserspace.ProcessStatus
	statusErr      error
	getMapStatsHit bool
}

func (f *systemBuffersAPIUserspaceDP) IsLoaded() bool {
	return true
}

func (f *systemBuffersAPIUserspaceDP) Status() (dpuserspace.ProcessStatus, error) {
	return f.status, f.statusErr
}

func (f *systemBuffersAPIUserspaceDP) GetMapStats() []dataplane.MapStats {
	f.getMapStatsHit = true
	return []dataplane.MapStats{
		{Name: "legacy_bpf_map", Type: "Hash", MaxEntries: 10, UsedCount: 9},
	}
}

type systemBuffersAPILegacyDP struct {
	*dataplane.Manager
	getMapStatsHit bool
}

func (f *systemBuffersAPILegacyDP) IsLoaded() bool {
	return true
}

func (f *systemBuffersAPILegacyDP) GetMapStats() []dataplane.MapStats {
	f.getMapStatsHit = true
	return []dataplane.MapStats{
		{Name: "session_map", Type: "Hash", MaxEntries: 100, UsedCount: 85},
	}
}

func TestSystemBuffersHandlerUsesUserspaceStatusRows(t *testing.T) {
	dp := &systemBuffersAPIUserspaceDP{
		Manager: dataplane.New(),
		status: dpuserspace.ProcessStatus{
			NeighborEntries: 7,
			PerBinding: []dpuserspace.BindingCountersSnapshot{
				{
					WorkerID:           0,
					QueueID:            1,
					Ifindex:            5,
					UmemTotalFrames:    1000,
					UmemInflightFrames: 800,
					TxRingCapacity:     100,
					OutstandingTX:      95,
					ActiveFlowCount:    11,
				},
			},
		},
	}
	s := &Server{dp: dp}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/system/buffers", nil)
	s.systemBuffersHandler(rr, req)

	if rr.Code != 200 {
		t.Fatalf("status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
	if dp.getMapStatsHit {
		t.Fatal("systemBuffersHandler fell back to BPF map stats for userspace dataplane")
	}

	var resp struct {
		Success bool         `json:"success"`
		Data    []BufferInfo `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if !resp.Success {
		t.Fatalf("success = false; body: %s", rr.Body.String())
	}
	if len(resp.Data) != 4 {
		t.Fatalf("len(resp.Data) = %d, want 4; data: %+v", len(resp.Data), resp.Data)
	}

	rows := make(map[string]BufferInfo, len(resp.Data))
	for _, row := range resp.Data {
		rows[row.Name] = row
		if row.Type == "Userspace" && row.Scope != "aggregate/1" {
			t.Fatalf("row %q scope = %q, want aggregate/1", row.Name, row.Scope)
		}
	}
	umem := rows["AF_XDP UMEM frames"]
	if umem.MaxEntries != 1000 || umem.UsedCount != 800 ||
		umem.UsagePercent != 80.0 || umem.Status != "WARNING" {
		t.Fatalf("UMEM row = %+v, want 1000/800 80%% WARNING", umem)
	}
	tx := rows["AF_XDP TX ring"]
	if tx.MaxEntries != 100 || tx.UsedCount != 95 ||
		tx.UsagePercent != 95.0 || tx.Status != "CRITICAL" {
		t.Fatalf("TX row = %+v, want 100/95 95%% CRITICAL", tx)
	}
	neighbor := rows["Neighbor cache entries"]
	if neighbor.Type != "UserspaceCounter" || neighbor.Scope != "dynamic" ||
		neighbor.Value != 7 || neighbor.UsagePercent != 0 {
		t.Fatalf("neighbor counter row = %+v, want dynamic counter value 7", neighbor)
	}
	flows := rows["Flow cache active flows"]
	if flows.Type != "UserspaceCounter" || flows.Scope != "active window" ||
		flows.Value != 11 || flows.UsagePercent != 0 {
		t.Fatalf("flow-cache counter row = %+v, want active-window counter value 11", flows)
	}
}

func TestSystemBuffersHandlerDoesNotFallbackToMapsOnUserspaceStatusError(t *testing.T) {
	dp := &systemBuffersAPIUserspaceDP{
		Manager:   dataplane.New(),
		statusErr: errors.New("helper offline"),
	}
	s := &Server{dp: dp}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/system/buffers", nil)
	s.systemBuffersHandler(rr, req)

	if rr.Code != 503 {
		t.Fatalf("status = %d, want 503; body: %s", rr.Code, rr.Body.String())
	}
	if dp.getMapStatsHit {
		t.Fatal("systemBuffersHandler used BPF map stats after userspace status error")
	}

	var resp Response
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp.Success {
		t.Fatalf("success = true, want false; body: %s", rr.Body.String())
	}
}

func TestSystemBuffersHandlerRejectsUserspaceStatusWithoutCapacityRows(t *testing.T) {
	dp := &systemBuffersAPIUserspaceDP{
		Manager: dataplane.New(),
		status:  dpuserspace.ProcessStatus{NeighborEntries: 3},
	}
	s := &Server{dp: dp}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/system/buffers", nil)
	s.systemBuffersHandler(rr, req)

	if rr.Code != 503 {
		t.Fatalf("status = %d, want 503; body: %s", rr.Code, rr.Body.String())
	}
	if dp.getMapStatsHit {
		t.Fatal("systemBuffersHandler used BPF map stats for missing userspace capacity fields")
	}
}

func TestSystemBuffersHandlerKeepsLegacyMapStatsFallback(t *testing.T) {
	dp := &systemBuffersAPILegacyDP{Manager: dataplane.New()}
	s := &Server{dp: dp}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/system/buffers", nil)
	s.systemBuffersHandler(rr, req)

	if rr.Code != 200 {
		t.Fatalf("status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
	if !dp.getMapStatsHit {
		t.Fatal("systemBuffersHandler did not use GetMapStats for legacy dataplane")
	}

	var resp struct {
		Success bool         `json:"success"`
		Data    []BufferInfo `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if len(resp.Data) != 1 {
		t.Fatalf("len(resp.Data) = %d, want 1; data: %+v", len(resp.Data), resp.Data)
	}
	row := resp.Data[0]
	if row.Name != "session_map" || row.Type != "Hash" ||
		row.MaxEntries != 100 || row.UsedCount != 85 ||
		row.UsagePercent != 85.0 || row.Status != "WARNING" {
		t.Fatalf("legacy map row = %+v, want session_map 85/100 WARNING", row)
	}
}
