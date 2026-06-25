package api

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

type natApplyResultAPIDP struct {
	*dataplane.Manager
	result *dataplane.ApplyResult
	calls  int
}

func (d *natApplyResultAPIDP) IsLoaded() bool {
	return true
}

func (d *natApplyResultAPIDP) LastApplyResult() *dataplane.ApplyResult {
	d.calls++
	return d.result.Clone()
}

func (d *natApplyResultAPIDP) ReadNATRuleCounter(counterID uint32) (dataplane.CounterValue, error) {
	return dataplane.CounterValue{Packets: uint64(counterID), Bytes: uint64(counterID) * 100}, nil
}

func newNATStatsAPIStore(t *testing.T) *configstore.Store {
	t.Helper()

	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if _, err := store.LoadSet(`set security nat source rule-set trust-to-untrust from zone trust
set security nat source rule-set trust-to-untrust to zone untrust
set security nat source rule-set trust-to-untrust rule r1 match source-address 10.0.0.0/8
set security nat source rule-set trust-to-untrust rule r1 then source-nat interface
set security nat source rule-set trust-to-untrust rule r2 match source-address 172.16.0.0/12
set security nat source rule-set trust-to-untrust rule r2 then source-nat interface`); err != nil {
		t.Fatalf("LoadSet() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	return store
}

// natRuntimeStatusAPIDP exposes a fixed userspace ProcessStatus plus a
// deliberately MISLEADING legacy port counter, so a test can prove which
// source the REST NAT pool stats handler reads from.
type natRuntimeStatusAPIDP struct {
	*dataplane.Manager
	status      dpuserspace.ProcessStatus
	legacyCount uint64
	result      *dataplane.ApplyResult
}

func (d *natRuntimeStatusAPIDP) IsLoaded() bool { return true }

func (d *natRuntimeStatusAPIDP) Status() (dpuserspace.ProcessStatus, error) {
	return d.status, nil
}

func (d *natRuntimeStatusAPIDP) ReadNATPortCounter(uint32) (uint64, error) {
	return d.legacyCount, nil
}

func (d *natRuntimeStatusAPIDP) LastApplyResult() *dataplane.ApplyResult {
	return d.result.Clone()
}

func newNATPoolStatsAPIStore(t *testing.T) *configstore.Store {
	t.Helper()

	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	// Pool config text declares ONE address and the default port window. The
	// runtime helper will report a DIFFERENT (authoritative) view.
	if _, err := store.LoadSet(`set security nat source pool p1 address 203.0.113.10/32
set security nat source pool p1 port range low 1024 high 2023
set security nat source rule-set rs from zone trust
set security nat source rule-set rs to zone untrust
set security nat source rule-set rs rule r1 match source-address 10.0.0.0/8
set security nat source rule-set rs rule r1 then source-nat pool p1`); err != nil {
		t.Fatalf("LoadSet() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	return store
}

// TestNATPoolStatsHandlerUsesRuntimeStatus is a FAIL-ON-REVERT guard for
// #2938: the REST NAT pool stats handler must report in-use / capacity /
// utilization from the userspace helper's live SourceNATPoolStatus, NOT from
// config text (len(pool.Addresses)) + the retired-eBPF port counter.
//
// The fixture is built so the two sources disagree on EVERY field:
//   - config: 1 address, port window 1024..2023  => 1000 total ports
//   - runtime: 3 addresses, port window 1024..1523 (500/addr) => 1500 total,
//     750 used.
//   - legacy ReadNATPortCounter returns 99 (a value the runtime never uses).
//
// If the handler is reverted to the config-derived path, total/used/util all
// change to the config+legacy numbers and the assertions fail.
func TestNATPoolStatsHandlerUsesRuntimeStatus(t *testing.T) {
	dp := &natRuntimeStatusAPIDP{
		Manager:     dataplane.New(),
		legacyCount: 99,
		result:      &dataplane.ApplyResult{PoolIDs: map[string]uint8{"p1": 7}},
		status: dpuserspace.ProcessStatus{
			SourceNATPools: []dpuserspace.SourceNATPoolStatus{
				{
					RuleName:     "r1",
					PoolName:     "p1",
					AddressCount: 3,
					PortLow:      1024,
					PortHigh:     1523,
					UsedPorts:    750,
				},
				// A second rule sharing the same pool reports the SAME
				// occupancy; the handler must dedup (never sum to 1500 used).
				{
					RuleName:     "r2",
					PoolName:     "p1",
					AddressCount: 3,
					PortLow:      1024,
					PortHigh:     1523,
					UsedPorts:    750,
				},
			},
		},
	}
	s := &Server{store: newNATPoolStatsAPIStore(t), dp: dp}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/security/nat/source/pools", nil)
	s.natPoolStatsHandler(rr, req)

	if rr.Code != 200 {
		t.Fatalf("status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}

	var resp struct {
		Success bool               `json:"success"`
		Data    []NATPoolStatsInfo `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if !resp.Success {
		t.Fatalf("success = false; body: %s", rr.Body.String())
	}

	var p1 *NATPoolStatsInfo
	for i := range resp.Data {
		if resp.Data[i].Name == "p1" {
			p1 = &resp.Data[i]
		}
	}
	if p1 == nil {
		t.Fatalf("pool p1 not in response: %+v", resp.Data)
	}

	// Runtime SSOT: 3 addresses * 500 ports = 1500 total; 750 used.
	const (
		wantTotal = 1500
		wantUsed  = 750
		wantAvail = 750
		wantUtil  = "50.0%"
	)
	if p1.TotalPorts != wantTotal {
		t.Errorf("TotalPorts = %d, want %d (runtime AddressCount*window, NOT config len()=1 => 1000)",
			p1.TotalPorts, wantTotal)
	}
	if p1.UsedPorts != wantUsed {
		t.Errorf("UsedPorts = %d, want %d (runtime UsedPorts, NOT legacy counter 99)",
			p1.UsedPorts, wantUsed)
	}
	if p1.AvailablePorts != wantAvail {
		t.Errorf("AvailablePorts = %d, want %d", p1.AvailablePorts, wantAvail)
	}
	if p1.Utilization != wantUtil {
		t.Errorf("Utilization = %q, want %q", p1.Utilization, wantUtil)
	}
}

func TestNATRuleStatsHandlerReadsApplyResultOnce(t *testing.T) {
	dp := &natApplyResultAPIDP{
		Manager: dataplane.New(),
		result: &dataplane.ApplyResult{
			NATCounterIDs: map[string]uint32{
				dataplane.NATCounterKey(dataplane.NATCounterTypeSource, "trust-to-untrust", "r1"): 31,
				dataplane.NATCounterKey(dataplane.NATCounterTypeSource, "trust-to-untrust", "r2"): 32,
			},
		},
	}
	s := &Server{store: newNATStatsAPIStore(t), dp: dp}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/security/nat/source/rules", nil)
	s.natRuleStatsHandler(rr, req)

	if rr.Code != 200 {
		t.Fatalf("status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
	if dp.calls != 1 {
		t.Fatalf("LastApplyResult() calls = %d, want 1", dp.calls)
	}

	var resp struct {
		Success bool               `json:"success"`
		Data    []NATRuleStatsInfo `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if !resp.Success {
		t.Fatalf("success = false; body: %s", rr.Body.String())
	}
	if len(resp.Data) != 2 {
		t.Fatalf("len(resp.Data) = %d, want 2", len(resp.Data))
	}
	hits := make(map[string]uint64, len(resp.Data))
	for _, rule := range resp.Data {
		hits[rule.RuleName] = rule.HitPackets
	}
	if hits["r1"] != 31 || hits["r2"] != 32 {
		t.Fatalf("hit packets = %+v, want r1=31 r2=32", hits)
	}
}
