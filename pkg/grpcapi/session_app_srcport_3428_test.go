// #3428 caller-threading regression: the gRPC session-view RPCs must pass the
// REAL session source port into appid.ResolveSessionName, not a hardcoded 0.
//
// The appid unit tests pin the matcher (matchTuple honors source-port), but a
// production caller that stopped threading key.SrcPort (passing 0) would
// re-introduce the bug without failing any matcher-level test. This test drives
// the real GetSessions legacy enrichment path end-to-end with a
// source-port-constrained application and a session whose source port MATCHES
// the constraint, asserting the session is labeled with that app. If the caller
// passes srcPort=0, the source-port constraint (40000) no longer matches and the
// session resolves to "" instead — turning this RED. It thus pins the caller's
// source-port threading, complementing the matcher-level coverage.
package grpcapi

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// srcPortSessionDP yields a single v4 session and reports the dataplane as
// loaded. GetSessionV4 errors so the reverse-counter merge is skipped while the
// Application enrichment still runs.
type srcPortSessionDP struct {
	*dataplane.Manager
	session dataplane.SessionKey
}

func (d *srcPortSessionDP) IsLoaded() bool { return true }

func (d *srcPortSessionDP) IterateSessions(cb func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	cb(d.session, dataplane.SessionValue{})
	return nil
}

func (d *srcPortSessionDP) IterateSessionsV6(func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	return nil
}

func (d *srcPortSessionDP) GetSessionV4(dataplane.SessionKey) (dataplane.SessionValue, error) {
	return dataplane.SessionValue{}, errors.New("no reverse entry in test")
}

func newSrcPortStore(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	// AppID is left DISABLED (no `services application-identification`), so the
	// session (app_id 0) resolves through the tuple fallback, which is the
	// path that must honor source-port.
	override := `
applications {
    application backup-control {
        protocol tcp;
        source-port 40000;
        destination-port 8443;
    }
}
`
	if err := store.LoadOverride(override); err != nil {
		t.Fatalf("LoadOverride() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	return store
}

func TestGetSessionsThreadsSourcePortForAppResolution(t *testing.T) {
	store := newSrcPortStore(t)

	// Session source port MATCHES the app's source-port (40000); dst 8443.
	matching := &srcPortSessionDP{
		Manager: dataplane.New(),
		session: dataplane.SessionKey{
			SrcIP:    [4]byte{198, 51, 100, 10},
			DstIP:    [4]byte{172, 16, 80, 8},
			SrcPort:  hostToNetwork16(40000),
			DstPort:  hostToNetwork16(8443),
			Protocol: 6,
		},
	}
	s := &Server{store: store, dp: matching}

	resp, err := s.GetSessions(context.Background(), &pb.GetSessionsRequest{})
	if err != nil {
		t.Fatalf("GetSessions() error = %v", err)
	}
	if len(resp.GetSessions()) != 1 {
		t.Fatalf("GetSessions() returned %d sessions, want 1", len(resp.GetSessions()))
	}
	// The matching-source-port session MUST be labeled backup-control. If the
	// caller stops threading key.SrcPort (passes 0), the source-port constraint
	// no longer matches and this becomes "" — the fail-on-revert signal.
	if got := resp.GetSessions()[0].GetApplication(); got != "backup-control" {
		t.Fatalf("session app = %q, want backup-control (caller must thread the real source port)", got)
	}

	// A session to the SAME destination port with a NON-matching source port
	// must NOT be mislabeled as backup-control (the #3428 mislabel itself).
	mismatch := &srcPortSessionDP{
		Manager: dataplane.New(),
		session: dataplane.SessionKey{
			SrcIP:    [4]byte{198, 51, 100, 10},
			DstIP:    [4]byte{172, 16, 80, 8},
			SrcPort:  hostToNetwork16(9999),
			DstPort:  hostToNetwork16(8443),
			Protocol: 6,
		},
	}
	s2 := &Server{store: store, dp: mismatch}
	resp2, err := s2.GetSessions(context.Background(), &pb.GetSessionsRequest{})
	if err != nil {
		t.Fatalf("GetSessions() (mismatch) error = %v", err)
	}
	if len(resp2.GetSessions()) != 1 {
		t.Fatalf("GetSessions() (mismatch) returned %d sessions, want 1", len(resp2.GetSessions()))
	}
	if got := resp2.GetSessions()[0].GetApplication(); got == "backup-control" {
		t.Fatalf("non-matching source-port session mislabeled as %q (#3428)", got)
	}
}
