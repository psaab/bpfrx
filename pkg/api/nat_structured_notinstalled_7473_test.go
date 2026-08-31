// #7473: the REST NAT objects must carry the builder's fail-closed verdict.
//
// The gRPC twin of this file covers the protobuf getters. Both exist because
// the issue's own discipline is PER FUNCTION, not per surface: four handlers
// here and four getters there means seven can be wrong while a surface-level
// cell passes on the eighth.
//
// Fixtures go through the TOLERANT peer-sync ingress, not LoadSet+Commit.
// #5877's strict gate rejects a rule referencing an empty pool and #7640's
// rejects an actionless destination rule, so a disarmed rule cannot reach an
// operator surface by way of a local commit — it arrives by HA peer-sync, boot
// or rollback, which is the path this uses. A Commit-built fixture could not
// reproduce the state under test at all.
package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func natRESTServer(t *testing.T, content string) *Server {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if _, err := store.SyncApply(content, nil); err != nil {
		t.Fatalf("SyncApply: %v", err)
	}
	return &Server{store: store}
}

func sourceCfg7473(addr string) string {
	pool := "pool p1 {\n"
	if addr != "" {
		pool += "address " + addr + ";\n"
	}
	pool += "port { range low 1024 high 2023; }\n}\n"
	return "security {\nnat {\nsource {\n" + pool +
		"rule-set rs {\nfrom zone trust;\nto zone untrust;\n" +
		"rule r1 {\nmatch { source-address 10.0.0.0/8; }\n" +
		"then { source-nat { pool p1; } }\n}\n}\n}\n}\n}\n"
}

func destCfg7473(action bool) string {
	then := ""
	if action {
		then = "then { destination-nat { pool dp1; } }\n"
	}
	return "security {\nnat {\ndestination {\npool dp1 { address 10.0.0.5; }\n" +
		"rule-set drs {\nfrom zone untrust;\n" +
		"rule dr1 {\nmatch { destination-address 203.0.113.10/32; }\n" +
		then + "}\n}\n}\n}\n}\n"
}

// notInstalledFlags decodes the handler's JSON and returns each element's
// not_installed flag. The field is `omitempty`, so a missing key decodes to
// false — which is exactly the pre-fix behaviour and therefore the thing the
// disarmed leg must catch.
func notInstalledFlags(t *testing.T, h http.HandlerFunc, path string) []bool {
	t.Helper()
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, path, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("%s: status %d, body %s", path, rec.Code, rec.Body.String())
	}
	var env struct {
		Data []struct {
			NotInstalled bool `json:"not_installed"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("%s: decode: %v (body %s)", path, err, rec.Body.String())
	}
	out := make([]bool, 0, len(env.Data))
	for _, d := range env.Data {
		out = append(out, d.NotInstalled)
	}
	return out
}

func TestRESTNATObjectsCarryTheNotInstalledVerdict7473(t *testing.T) {
	for _, tc := range []struct {
		name            string
		disarmed, armed string
		path            string
		handler         func(*Server) http.HandlerFunc
	}{
		{"natSourceHandler", sourceCfg7473(""), sourceCfg7473("203.0.113.10/32"), "/api/v1/security/nat/source",
			func(s *Server) http.HandlerFunc { return s.natSourceHandler }},
		{"natRuleStatsHandler", sourceCfg7473(""), sourceCfg7473("203.0.113.10/32"), "/api/v1/security/nat/rules",
			func(s *Server) http.HandlerFunc { return s.natRuleStatsHandler }},
		{"natPoolStatsHandler", sourceCfg7473(""), sourceCfg7473("203.0.113.10/32"), "/api/v1/security/nat/source/pools",
			func(s *Server) http.HandlerFunc { return s.natPoolStatsHandler }},
		{"natDestHandler", destCfg7473(false), destCfg7473(true), "/api/v1/security/nat/destination",
			func(s *Server) http.HandlerFunc { return s.natDestHandler }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			disarmed := notInstalledFlags(t, tc.handler(natRESTServer(t, tc.disarmed)), tc.path)
			if len(disarmed) == 0 {
				t.Fatalf("%s returned no objects for the disarmed fixture; the "+
					"assertion below would be vacuous", tc.name)
			}
			anyMarked := false
			for _, f := range disarmed {
				anyMarked = anyMarked || f
			}
			if !anyMarked {
				t.Errorf("%s returned an object the builder REFUSED with "+
					"not_installed absent or false. A JSON consumer has nowhere to "+
					"learn the object is not enforced — and where the object carries "+
					"a hit counter, its 0 reads as \"no traffic matched\" rather than "+
					"\"not armed\" (#7473)", tc.name)
			}

			// Control: an ARMED config must mark nothing. Without it this row
			// passes for a handler that sets the flag unconditionally.
			armed := notInstalledFlags(t, tc.handler(natRESTServer(t, tc.armed)), tc.path)
			if len(armed) == 0 {
				t.Fatalf("%s returned no objects for the armed fixture", tc.name)
			}
			for _, f := range armed {
				if f {
					t.Errorf("%s marked an ARMED object not_installed — the handler is "+
						"stamping the field rather than consulting the predicate, and "+
						"the disarmed leg above proves nothing", tc.name)
				}
			}
		})
	}
}
