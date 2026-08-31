package api

import (
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)

// algAPIStore commits a config carrying one disabled modeled ALG and one
// unmodeled proto, so a single render exercises both directions.
func algAPIStore(t *testing.T, body string) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(body); err != nil {
		t.Fatalf("LoadOverride() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	return store
}

func algText7423(t *testing.T, store *configstore.Store) string {
	t.Helper()
	s := &Server{store: store}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/show/text?topic=alg", nil)
	s.showTextHandler(rec, req)
	if rec.Code != 200 {
		t.Fatalf("showTextHandler status = %d, body %s", rec.Code, rec.Body.String())
	}
	return rec.Body.String()
}

// #7423 row 6, REST surface. The CLI carried the fabricated rows, but the
// `enabled` overstatement was on all three surfaces, and after the CLI fix
// alone they would have described the same four ALGs differently — the exact
// divergence flow_tcp_timeouts_6539.go's header calls always-a-bug.
//
// This drives the REST handler itself rather than the shared pkg/config
// helper, because a shared helper is not evidence that a caller reaches it.
func TestShowTextALGDoesNotClaimEnabled_7423(t *testing.T) {
	out := algText7423(t, algAPIStore(t, "security {\n    alg {\n        sip disable;\n    }\n}\n"))

	if strings.Contains(out, "enabled") {
		t.Errorf("REST show alg still reports an ALG as enabled:\n%s", out)
	}
	if !strings.Contains(out, "SIP:  "+config.ALGStatusDisabled) {
		t.Errorf("a disabled ALG must still read disabled:\n%s", out)
	}
	if !strings.Contains(out, "DNS:  "+config.ALGStatusSessionTagged) {
		t.Errorf("a non-disabled ALG should report session tagging:\n%s", out)
	}
	if !strings.Contains(out, "TFTP: "+config.ALGStatusRecordedOnly) {
		t.Errorf("TFTP has no dataplane consumer at all and must say so:\n%s", out)
	}
}

// The three surfaces must agree. This pins the REST rendering against the same
// shared constants the CLI and gRPC assertions use, so a future edit to one
// surface's wording cannot pass its own package's tests while diverging.
func TestShowTextALGRendersConfiguredUnmodeledProto_7423(t *testing.T) {
	out := algText7423(t, algAPIStore(t, "security {\n    alg {\n        h323 disable;\n    }\n}\n"))

	if !strings.Contains(out, "H323: "+config.ALGStatusNotImplemented) {
		t.Errorf("`security alg h323` is accepted at commit (#4232) and must not "+
			"vanish from this surface:\n%s", out)
	}
	if strings.Contains(out, "H323: "+config.ALGStatusSessionTagged) {
		t.Errorf("an unmodeled ALG must not claim the modeled behaviour:\n%s", out)
	}
}
