// FAIL-ON-REVERT: the REST /api/v1/security/nat/deterministic endpoint must
// resolve the deterministic source-NAT forward (subscriber -> translated
// IPv4 + port block) AND reverse (translated IPv4 + port -> subscriber)
// mapping from the LAST-APPLIED NAT generation (#5794). Reverting the handler
// wiring (so it no longer calls pkg/nat against the applied view) makes the
// forward/reverse assertions below go RED. Golden values match the Rust
// dataplane allocator vectors (userspace-dp/src/nat/tests_pool.rs).
package api

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/nat"
)

// appliedViewAPIDP is a loaded DP that returns a fixed applied NAT view for
// the deterministic-mapping lookup.
type appliedViewAPIDP struct {
	*dataplane.Manager
	view dpuserspace.AppliedNATView
}

func (d *appliedViewAPIDP) IsLoaded() bool                             { return true }
func (d *appliedViewAPIDP) AppliedNATView() dpuserspace.AppliedNATView { return d.view }

func deterministicV4APIView(gen uint64) dpuserspace.AppliedNATView {
	pool := &config.NATPool{
		Name:      "cgn-pool",
		Addresses: []string{"203.0.113.1", "203.0.113.2", "203.0.113.3", "203.0.113.4"},
		PortLow:   1024,
		PortHigh:  65535,
		Deterministic: &config.DeterministicNATConfig{
			BlockSize:   512,
			HostAddress: "100.64.0.0/22",
		},
	}
	cfg := &config.Config{}
	cfg.Security.NAT.SourcePools = map[string]*config.NATPool{"cgn-pool": pool}
	return dpuserspace.AppliedNATView{Config: cfg, AppliedGeneration: gen, Available: true}
}

func decodeNATDeterministic(t *testing.T, body []byte) NATDeterministicInfo {
	t.Helper()
	var resp struct {
		Success bool                 `json:"success"`
		Data    NATDeterministicInfo `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode: %v (body=%s)", err, body)
	}
	if !resp.Success {
		t.Fatalf("expected success envelope, got %s", body)
	}
	return resp.Data
}

func TestRESTDeterministicForwardReverse(t *testing.T) {
	s := &Server{dp: &appliedViewAPIDP{
		Manager: dataplane.New(),
		view:    deterministicV4APIView(13),
	}}

	// Forward.
	req := httptest.NewRequest("GET", "/api/v1/security/nat/deterministic?internal-host=100.64.0.5&pool=cgn-pool", nil)
	rec := httptest.NewRecorder()
	s.natDeterministicHandler(rec, req)
	fwd := decodeNATDeterministic(t, rec.Body.Bytes())
	if !fwd.Found || fwd.Direction != "forward" || fwd.ExternalIP != "203.0.113.1" ||
		fwd.PortLow != 3584 || fwd.PortHigh != 4095 || fwd.Mode != 1 || fwd.AppliedGeneration != 13 {
		t.Fatalf("forward mismatch: %+v", fwd)
	}

	// Reverse.
	req = httptest.NewRequest("GET", "/api/v1/security/nat/deterministic?nat-ip=203.0.113.1&nat-port=3900&pool=cgn-pool", nil)
	rec = httptest.NewRecorder()
	s.natDeterministicHandler(rec, req)
	rev := decodeNATDeterministic(t, rec.Body.Bytes())
	if !rev.Found || rev.Direction != "reverse" || rev.InternalHost != "100.64.0.5" ||
		rev.NATPort != 3900 || rev.PortLow != 3584 || rev.PortHigh != 4095 || rev.AppliedGeneration != 13 {
		t.Fatalf("reverse mismatch: %+v", rev)
	}
}

func TestRESTDeterministicErrors(t *testing.T) {
	s := &Server{dp: &appliedViewAPIDP{
		Manager: dataplane.New(),
		view:    deterministicV4APIView(1),
	}}
	cases := []struct {
		name string
		url  string
		want string
	}{
		{"unknown-pool", "/api/v1/security/nat/deterministic?internal-host=100.64.0.5&pool=nope", nat.ErrCodeUnknownPool},
		{"out-of-range", "/api/v1/security/nat/deterministic?internal-host=100.64.4.0&pool=cgn-pool", nat.ErrCodeOutOfRange},
		{"bad-port", "/api/v1/security/nat/deterministic?nat-ip=203.0.113.1&nat-port=70000&pool=cgn-pool", nat.ErrCodeMalformedInput},
		{"reverse-not-found", "/api/v1/security/nat/deterministic?nat-ip=192.0.2.1&nat-port=3584&pool=cgn-pool", nat.ErrCodeNotFound},
		{"no-direction", "/api/v1/security/nat/deterministic?pool=cgn-pool", nat.ErrCodeMalformedInput},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tc.url, nil)
			rec := httptest.NewRecorder()
			s.natDeterministicHandler(rec, req)
			info := decodeNATDeterministic(t, rec.Body.Bytes())
			if info.Found || info.ErrorCode != tc.want {
				t.Fatalf("expected code %q, got found=%v code=%q", tc.want, info.Found, info.ErrorCode)
			}
		})
	}
}

func TestRESTDeterministicNoAppliedView(t *testing.T) {
	s := &Server{dp: &appliedViewAPIDP{
		Manager: dataplane.New(),
		view:    dpuserspace.AppliedNATView{Available: false},
	}}
	req := httptest.NewRequest("GET", "/api/v1/security/nat/deterministic?internal-host=100.64.0.5", nil)
	rec := httptest.NewRecorder()
	s.natDeterministicHandler(rec, req)
	info := decodeNATDeterministic(t, rec.Body.Bytes())
	if info.Found || info.ErrorCode != nat.ErrCodeNoAppliedView {
		t.Fatalf("expected no-applied-view, got %+v", info)
	}
}
