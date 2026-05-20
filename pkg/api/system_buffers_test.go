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

func TestSystemBuffersHandlerUsesUserspaceStatusRows(t *testing.T) {
	dp := &systemBuffersAPIUserspaceDP{
		Manager: dataplane.New(),
		status: dpuserspace.ProcessStatus{
			PerBinding: []dpuserspace.BindingCountersSnapshot{
				{
					WorkerID:           0,
					QueueID:            1,
					Ifindex:            5,
					UmemTotalFrames:    1000,
					UmemInflightFrames: 800,
					TxRingCapacity:     100,
					OutstandingTX:      95,
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
	if len(resp.Data) != 2 {
		t.Fatalf("len(resp.Data) = %d, want 2; data: %+v", len(resp.Data), resp.Data)
	}

	rows := make(map[string]BufferInfo, len(resp.Data))
	for _, row := range resp.Data {
		rows[row.Name] = row
		if row.Type != "Userspace" {
			t.Fatalf("row %q type = %q, want Userspace", row.Name, row.Type)
		}
		if row.Scope != "aggregate/1" {
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
