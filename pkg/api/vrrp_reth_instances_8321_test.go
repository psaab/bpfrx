package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

// #8321 finding 15: the REST /vrrp handler collected only the generic
// per-interface `vrrp-group` instances (`vrrp.CollectInstances`) and never the
// RETH ones (`vrrp.CollectRethInstances`).
//
// On a chassis cluster the VIPs live on RETH instances, so the endpoint
// returned an EMPTY instance list on exactly the deployments that have VRRP —
// while the gRPC `GetVRRPStatus` had been appending them all along
// (`grpcapi/server_nat.go`). A parity gap between two surfaces, not a missing
// feature: the collector was right, one caller did not use it.
//
// The cells drive the real handler through `http.ServeHTTP`, not
// `CollectRethInstances` directly. That distinction is the whole point here —
// a cell that called the collector would pass against the defective handler,
// because the collector was never what was broken.

// newRethClusterStore commits a minimal chassis cluster whose RG 1 is carried
// by reth0, so CollectRethInstances has something to return.
func newRethClusterStore(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	lines := []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster authentication-key test-cluster-psk-8321",
		"set chassis cluster reth-count 2",
		"set chassis cluster no-private-rg-election",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set interfaces ge-0/0/1 gigether-options redundant-parent reth0",
		"set interfaces reth0 redundant-ether-options redundancy-group 1",
		"set interfaces reth0 unit 0 family inet address 10.0.61.1/24",
	}
	if _, err := store.LoadSet(strings.Join(lines, "\n")); err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	return store
}

func vrrpInstancesVia(t *testing.T, s *Server) []VRRPInstanceInfo {
	t.Helper()
	rec := httptest.NewRecorder()
	// The handler is the subject; the route is not. Calling it on a Server
	// built by NewServer binds the chain the fix added —
	// Config.VRRPLocalPrioritiesFn -> Server.vrrpLocalPrioritiesFn -> here.
	s.vrrpHandler(rec, httptest.NewRequest(http.MethodGet, "/vrrp", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/vrrp status = %d, want 200", rec.Code)
	}
	var env struct {
		Data VRRPStatusResponse `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode /vrrp body %q: %v", rec.Body.String(), err)
	}
	return env.Data.Instances
}

func TestRESTVRRPReportsRethInstances_8321(t *testing.T) {
	store := newRethClusterStore(t)
	s := NewServer(Config{
		Addr:                  "127.0.0.1:0",
		Store:                 store,
		VRRPLocalPrioritiesFn: func() map[int]int { return map[int]int{1: 200} },
	})

	instances := vrrpInstancesVia(t, s)
	if len(instances) == 0 {
		t.Fatal("#8321 finding 15: /vrrp returned NO instances on a chassis cluster whose " +
			"RG 1 is carried by reth0. The RETH instances are where the VIPs live, so this " +
			"endpoint reported an empty set on exactly the deployments that have VRRP.")
	}
	// The RETH instance's group id is 100+rgID by construction
	// (vrrp.CollectRethInstances), so this asserts it is the RETH one and not
	// some generic instance that happened to appear.
	var sawReth bool
	for _, inst := range instances {
		if inst.GroupID == 101 {
			sawReth = true
			if len(inst.VirtualAddresses) == 0 {
				t.Errorf("#8321: the RETH instance must carry reth0's address as its VIP; got none")
			}
			if inst.Priority != 200 {
				t.Errorf("#8321: the RETH instance must carry this node's RG priority; got %d, want 200",
					inst.Priority)
			}
		}
	}
	if !sawReth {
		t.Fatalf("#8321 finding 15: no instance with group id 101 (100+RG 1) in %+v — the "+
			"handler is still reporting only the generic per-interface vrrp-group set",
			instances)
	}
}

// TestRESTVRRPWithoutClusterIsUnchanged_8321 is the control that fails on the
// over-broad fix. `VRRPLocalPrioritiesFn` is optional — a non-clustered node
// wires no cluster — and a handler that synthesised RETH instances anyway, or
// panicked on the nil hook, would report instances that do not exist. The
// pre-#8321 behaviour is the CORRECT answer here and must be preserved.
func TestRESTVRRPWithoutClusterIsUnchanged_8321(t *testing.T) {
	store := newRethClusterStore(t)
	s := NewServer(Config{
		Addr:  "127.0.0.1:0",
		Store: store,
		// no VRRPLocalPrioritiesFn: this is a node with no cluster manager
	})

	for _, inst := range vrrpInstancesVia(t, s) {
		if inst.GroupID == 101 {
			t.Fatalf("#8321: with no cluster priority source the handler must report only the "+
				"generic vrrp-group instances; it reported a RETH instance %+v", inst)
		}
	}
}
