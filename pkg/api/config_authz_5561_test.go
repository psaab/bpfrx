package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/authz"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)

// config_authz_5561_test.go is the fail-on-revert gate for #5561: the REST
// mutation surface must refuse a caller it cannot authorize, and must keep
// serving one it can.
//
// Every case drives real HTTP over a real loopback listener through a server
// built by the PRODUCTION constructor (buildHTTPServer), so the ConnContext
// plumbing that carries the connection's identity into the request is on the
// tested path rather than reconstructed by the test. Only the peer-UID
// resolution itself is injected (Config.PeerLookupFn), so a case can choose which
// principal is calling instead of testing whichever account runs the suite; the
// kernel lookup behind it is covered against live sockets in pkg/authz, and
// TestProductionServerEnforcesRealPeerIdentity_5561 below closes the loop with
// no injection at all.

const (
	authzUIDReadOnly  = 4242
	authzUIDSuperuser = 4243
	authzUIDStranger  = 4244 // a real OS account that is not a `system login user`
)

// authzTestConfig is the active config every case is evaluated against: two
// provisioned login users with different classes, so a denial can be attributed
// to the CLASS rather than to the absence of a config.
const authzTestConfig = `
system {
    host-name authz-test;
    login {
        user opsuser {
            class read-only;
        }
        user adminuser {
            class super-user;
        }
    }
}
`

// authzPasswdFixture maps the UIDs above to account names. It replaces
// /etc/passwd for the duration of a case so the resolution path runs for real
// against identities the test controls.
const authzPasswdFixture = `root:x:0:0:root:/root:/bin/bash
opsuser:x:4242:4242::/home/opsuser:/bin/bash
adminuser:x:4243:4243::/home/adminuser:/bin/bash
stranger:x:4244:4244::/home/stranger:/bin/bash
`

// authzServer stands up a Server over a real listener and returns its base URL.
// peerUID/peerErr are what the injected resolver reports for every connection.
func authzServer(t *testing.T, cfg Config) (*Server, string) {
	t.Helper()
	s := NewServer(cfg)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	// buildHTTPServer is the production path: it installs listenerHandler
	// (cross-site guard -> authz guard -> mux) AND the ConnContext hook.
	srv := s.buildHTTPServer(ln.Addr().String())
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return s, "http://" + ln.Addr().String()
}

// authzStore returns a store whose ACTIVE config is `text`, committed through
// the real configure/load/commit path so the login model the gate reads is a
// genuinely compiled one.
func authzStore(t *testing.T, text string) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := store.LoadOverride(text); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	store.ExitConfigure()
	if store.ActiveConfig() == nil {
		t.Fatal("store has no active config after commit")
	}
	return store
}

// usePasswdFixture points the UID resolver at authzPasswdFixture.
func usePasswdFixture(t *testing.T) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "passwd")
	if err := os.WriteFile(path, []byte(authzPasswdFixture), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(authz.SetPasswdPathForTest(path))
}

// fixedPeerUID builds a resolver that attributes every connection to uid.
func fixedPeerUID(uid uint32) func(client, server net.Addr) authz.PeerIdentity {
	return func(net.Addr, net.Addr) authz.PeerIdentity {
		return authz.PeerIdentity{UID: uid, OK: true, Local: true}
	}
}

// unattributableLocalPeer builds a resolver reporting a caller that IS on this
// host but could not be attributed — a half-closed socket, a TIME_WAIT row, or
// an unreadable socket table. It must DENY, never reach the credential.
func unattributableLocalPeer() func(client, server net.Addr) authz.PeerIdentity {
	return func(net.Addr, net.Addr) authz.PeerIdentity {
		return authz.PeerIdentity{Local: true, Detail: "test: socket not established"}
	}
}

// remotePeer builds a resolver reporting a caller that is NOT on this host —
// the only case in which an api-auth credential may speak for it.
func remotePeer() func(client, server net.Addr) authz.PeerIdentity {
	return func(net.Addr, net.Addr) authz.PeerIdentity {
		return authz.PeerIdentity{Detail: "test: peer is not on this host"}
	}
}

// postRoute issues a mutating request against a route key ("POST /path"),
// returning the status and the decoded `error` field.
func postRoute(t *testing.T, base, route string, hdrs map[string]string) (int, string) {
	t.Helper()
	method, path, ok := strings.Cut(route, " ")
	if !ok {
		t.Fatalf("malformed route key %q", route)
	}
	req, err := http.NewRequest(method, base+path, strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdrs {
		req.Header.Set(k, v)
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("%s: %v", route, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var r Response
	_ = json.Unmarshal(body, &r)
	return resp.StatusCode, r.Error
}

// enterConfigure opens a configure session over the guarded route and returns
// the session token the subsequent mutation must carry.
func enterConfigure(t *testing.T, base string, hdrs ...map[string]string) string {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, base+"/api/v1/config/enter", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	for _, h := range hdrs {
		for k, v := range h {
			req.Header.Set(k, v)
		}
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("config/enter refused an authorized principal: %d %s", resp.StatusCode, raw)
	}
	var r struct {
		Data struct {
			SessionID string `json:"session_id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatalf("decode config/enter response %s: %v", raw, err)
	}
	if r.Data.SessionID == "" {
		t.Fatalf("config/enter returned no session id: %s", raw)
	}
	return r.Data.SessionID
}

// TestEveryMutatingRouteRefusesWithoutPrincipal_5561 is the primary gate: with
// no establishable peer identity and no api-auth credential, EVERY route in the
// mutation table is refused — not just config/set, load and commit.
//
// On master every one of these returns something other than 403: the request
// reaches its handler and, for the config family, mutates and commits.
func TestEveryMutatingRouteRefusesWithoutPrincipal_5561(t *testing.T) {
	usePasswdFixture(t)
	store := authzStore(t, authzTestConfig)
	_, base := authzServer(t, Config{
		Addr:         "127.0.0.1:8080",
		Store:        store,
		PeerLookupFn: unattributableLocalPeer(),
	})

	routes := sortedRouteKeys()
	if len(routes) == 0 {
		t.Fatal("mutation permission table is empty")
	}
	for _, route := range routes {
		t.Run(route, func(t *testing.T) {
			status, errMsg := postRoute(t, base, route, nil)
			if status != http.StatusForbidden {
				t.Fatalf("%s returned %d for a caller with NO server-derived identity — "+
					"an unauthenticated local process reached the handler (error=%q)",
					route, status, errMsg)
			}
			if !strings.Contains(errMsg, "could not establish who is calling") {
				t.Errorf("%s denial did not name the missing identity: %q", route, errMsg)
			}
		})
	}
}

// TestClassGatesMutationPerPermission_5561 proves the gate is per-permission
// rather than a blanket refusal: the SAME caller, on the SAME connection, is
// refused the configure- and maintenance-tier routes its `read-only` class does
// not hold, and admitted to the view-tier ones it does.
func TestClassGatesMutationPerPermission_5561(t *testing.T) {
	usePasswdFixture(t)
	store := authzStore(t, authzTestConfig)
	_, base := authzServer(t, Config{
		Addr:         "127.0.0.1:8080",
		Store:        store,
		PeerLookupFn: fixedPeerUID(authzUIDReadOnly),
	})

	for _, route := range sortedRouteKeys() {
		required := restMutationPermissions[route]
		wantAllowed := required == config.PermView // read-only holds PermView only
		t.Run(route, func(t *testing.T) {
			status, errMsg := postRoute(t, base, route, nil)
			if wantAllowed && status == http.StatusForbidden {
				t.Fatalf("%s (requires %s) refused a read-only principal that HOLDS that "+
					"permission: %q", route, authz.PermissionName(required), errMsg)
			}
			if !wantAllowed && status != http.StatusForbidden {
				t.Fatalf("%s (requires %s) admitted a read-only principal with %d — the "+
					"CLI RBAC boundary is still bypassable over REST",
					route, authz.PermissionName(required), status)
			}
			if !wantAllowed && !strings.Contains(errMsg, "lacks the") {
				t.Errorf("%s denial did not name the missing permission: %q", route, errMsg)
			}
		})
	}
}

// TestAuthorizedPrincipalStillMutatesConfig_5561 is the negative control: a
// principal whose login class holds `configure` reaches the handlers and the
// candidate configuration ACTUALLY changes. A gate that refuses everyone would
// pass every assertion above and fail here.
func TestAuthorizedPrincipalStillMutatesConfig_5561(t *testing.T) {
	usePasswdFixture(t)
	for _, tc := range []struct {
		name string
		uid  uint32
	}{
		{"super-user login class", authzUIDSuperuser},
		{"root", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := authzStore(t, authzTestConfig)
			_, base := authzServer(t, Config{
				Addr:         "127.0.0.1:8080",
				Store:        store,
				PeerLookupFn: fixedPeerUID(tc.uid),
			})

			session := enterConfigure(t, base)

			// Drive a real mutation through the guarded route.
			body := strings.NewReader(`{"input":"set system host-name authorized-write"}`)
			req, err := http.NewRequest(http.MethodPost, base+"/api/v1/config/set", body)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set(restConfigSessionHeader, session)
			resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("config/set refused an authorized principal: %d %s", resp.StatusCode, raw)
			}
			if candidate := store.ShowCandidate(); !strings.Contains(candidate, "authorized-write") {
				t.Fatalf("config/set returned 200 but the candidate does not carry the edit:\n%s", candidate)
			}
		})
	}
}

// TestReadOnlyEndpointsUnaffected_5561 pins the blast radius: with NO
// establishable principal at all, the read surface — REST GETs, /health and
// /metrics — behaves exactly as before. The gate must not have turned a
// monitoring endpoint into a 403.
func TestReadOnlyEndpointsUnaffected_5561(t *testing.T) {
	usePasswdFixture(t)
	store := authzStore(t, authzTestConfig)
	_, base := authzServer(t, Config{
		Addr:         "127.0.0.1:8080",
		Store:        store,
		PeerLookupFn: unattributableLocalPeer(),
	})

	for _, path := range []string{
		"/health",
		"/metrics",
		"/api/v1/config",
		"/api/v1/config/show",
		"/api/v1/config/status",
		"/api/v1/status",
		"/api/v1/interfaces",
		"/api/v1/security/zones",
	} {
		t.Run(path, func(t *testing.T) {
			resp, err := (&http.Client{Timeout: 10 * time.Second}).Get(base + path)
			if err != nil {
				t.Fatalf("GET %s: %v", path, err)
			}
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusForbidden {
				body, _ := io.ReadAll(resp.Body)
				t.Fatalf("GET %s returned 403 — the mutation gate is refusing read traffic: %s",
					path, body)
			}
		})
	}
}

// TestUnknownMutatingRouteFailsClosed_5561 covers the scope note: a
// state-changing request that no table entry governs is DENIED, so a future
// route registered without a permission is inert rather than unguarded.
func TestUnknownMutatingRouteFailsClosed_5561(t *testing.T) {
	usePasswdFixture(t)
	_, base := authzServer(t, Config{
		Addr:         "127.0.0.1:8080",
		Store:        authzStore(t, authzTestConfig),
		PeerLookupFn: fixedPeerUID(0), // even ROOT is refused an ungoverned route
	})

	for _, route := range []string{
		"POST /api/v1/config/some-future-verb",
		"DELETE /api/v1/config/set",
		"PUT /api/v1/system/action",
		// A non-canonical spelling of a guarded route must not slip past the
		// exact-match table into the mux's redirect.
		"POST /api/v1/config//set",
	} {
		t.Run(route, func(t *testing.T) {
			status, errMsg := postRoute(t, base, route, nil)
			if status != http.StatusForbidden {
				t.Fatalf("%s returned %d, want 403: an ungoverned mutating request must "+
					"fail closed (error=%q)", route, status, errMsg)
			}
		})
	}
}

// TestApiAuthCredentialIsAFullPowerPrincipal_5561 covers the second identity and
// its precedence. A valid api-auth credential authorizes a caller that is NOT on
// this host — the remote administrator #4047 requires it for — and it does not
// speak for ANY local caller, identified or not.
func TestApiAuthCredentialIsAFullPowerPrincipal_5561(t *testing.T) {
	usePasswdFixture(t)
	auth := &AuthConfig{Users: map[string]string{"webadmin": "s3cret"}}
	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte("webadmin:s3cret"))

	t.Run("credential authorizes a caller that is not on this host", func(t *testing.T) {
		_, base := authzServer(t, Config{
			Addr:         "127.0.0.1:8080",
			Store:        authzStore(t, authzTestConfig),
			Auth:         auth,
			PeerLookupFn: remotePeer(),
		})
		status, errMsg := postRoute(t, base, "POST /api/v1/config/enter",
			map[string]string{"Authorization": basic})
		if status == http.StatusForbidden {
			t.Fatalf("a valid api-auth credential was refused for an off-box caller: %q", errMsg)
		}
	})

	t.Run("without the credential the same remote caller is refused", func(t *testing.T) {
		_, base := authzServer(t, Config{
			Addr:         "127.0.0.1:8080",
			Store:        authzStore(t, authzTestConfig),
			Auth:         auth,
			PeerLookupFn: remotePeer(),
		})
		status, _ := postRoute(t, base, "POST /api/v1/config/enter", nil)
		// The api-auth middleware answers first with its own 401 challenge.
		if status == http.StatusOK {
			t.Fatal("an uncredentialed, unidentifiable caller reached the handler")
		}
	})

	t.Run("peer identity outranks the credential", func(t *testing.T) {
		_, base := authzServer(t, Config{
			Addr:         "127.0.0.1:8080",
			Store:        authzStore(t, authzTestConfig),
			Auth:         auth,
			PeerLookupFn: fixedPeerUID(authzUIDReadOnly),
		})
		status, errMsg := postRoute(t, base, "POST /api/v1/config/enter",
			map[string]string{"Authorization": basic})
		if status != http.StatusForbidden {
			t.Fatalf("a read-only login user holding the api-auth secret was admitted to "+
				"configure with %d — the shared secret re-privileged a restricted account", status)
		}
		if !strings.Contains(errMsg, "opsuser") {
			t.Errorf("denial did not attribute the read-only account: %q", errMsg)
		}
	})
}

// TestAttributedLocalCallerOutsideLoginModelIsDenied_5561 pins row (2) of the
// precedence table, and is the MAJOR-A guard.
//
// An earlier version denied an UNATTRIBUTABLE local caller but still let an
// api-auth credential speak for an ATTRIBUTED one that was not a configured
// `system login user`. That is exactly the population #5561 exists to constrain:
// it made the per-principal gate optional for anyone holding the shared
// password, and it contradicted docs/system-login.md, which already said such a
// caller is denied.
//
// The rule is now: a caller on this host is governed by the login model and
// nothing else. If a local account needs access, it gets a class — that is the
// one place access is supposed to be written down.
func TestAttributedLocalCallerOutsideLoginModelIsDenied_5561(t *testing.T) {
	usePasswdFixture(t)
	auth := &AuthConfig{Users: map[string]string{"webadmin": "s3cret"}}
	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte("webadmin:s3cret"))

	t.Run("attributed local account outside the login model is refused", func(t *testing.T) {
		_, base := authzServer(t, Config{
			Addr:  "127.0.0.1:8080",
			Store: authzStore(t, authzTestConfig),
			Auth:  auth,
			// A REAL OS account (uid 4244 = "stranger") that carries no
			// `system login user` stanza.
			PeerLookupFn: fixedPeerUID(authzUIDStranger),
		})
		for _, route := range []string{
			"POST /api/v1/config/enter",
			"POST /api/v1/config/set",
			"POST /api/v1/config/commit",
			"POST /api/v1/system/action",
		} {
			status, errMsg := postRoute(t, base, route, map[string]string{"Authorization": basic})
			if status != http.StatusForbidden {
				t.Errorf("%s admitted a local account OUTSIDE the login model with %d because "+
					"it presented the shared api-auth secret — the per-principal gate is "+
					"optional for anyone who knows the password", route, status)
			}
			if !strings.Contains(errMsg, "not a configured") {
				t.Errorf("%s denial did not name the reason: %q", route, errMsg)
			}
		}
	})

	// The discriminating control: an attributed local UID that IS in the login
	// model, with a class that holds `configure`, still works normally. A gate
	// that simply refused every local caller would pass the subtest above and
	// fail this one.
	t.Run("attributed local account INSIDE the login model still works", func(t *testing.T) {
		store := authzStore(t, authzTestConfig)
		_, base := authzServer(t, Config{
			Addr:         "127.0.0.1:8080",
			Store:        store,
			Auth:         auth,
			PeerLookupFn: fixedPeerUID(authzUIDSuperuser), // uid 4243 = adminuser, super-user
		})
		// The credential is presented here too, so this subtest and the one above
		// differ in EXACTLY one variable: whether the attributed uid is in the
		// login model.
		session := enterConfigure(t, base, map[string]string{"Authorization": basic})
		body := strings.NewReader(`{"input":"set system host-name inside-model"}`)
		req, err := http.NewRequest(http.MethodPost, base+"/api/v1/config/set", body)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", basic)
		req.Header.Set(restConfigSessionHeader, session)
		resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("a super-user login account was refused config/set: %d %s", resp.StatusCode, raw)
		}
		if candidate := store.ShowCandidate(); !strings.Contains(candidate, "inside-model") {
			t.Fatalf("config/set returned 200 but the candidate does not carry the edit:\n%s", candidate)
		}
	})
}

// TestUnattributableLocalCallerCannotBorrowCredential_5561 pins row (3) of the
// precedence table in Server.principal: a caller that IS on this host but could
// not be attributed must be DENIED, never handed the api-auth credential.
//
// The first version of this gate fell back to the credential whenever the peer
// lookup failed, and the caller controlled whether it failed — so a restricted
// account escalated to full power simply by making itself unidentifiable. A
// precedence rule that only holds when the lookup succeeds is not a precedence
// rule.
func TestUnattributableLocalCallerCannotBorrowCredential_5561(t *testing.T) {
	usePasswdFixture(t)
	auth := &AuthConfig{Users: map[string]string{"webadmin": "s3cret"}}
	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte("webadmin:s3cret"))

	t.Run("local but unattributable is refused despite a valid credential", func(t *testing.T) {
		_, base := authzServer(t, Config{
			Addr:         "127.0.0.1:8080",
			Store:        authzStore(t, authzTestConfig),
			Auth:         auth,
			PeerLookupFn: unattributableLocalPeer(),
		})
		for _, route := range []string{
			"POST /api/v1/config/enter",
			"POST /api/v1/config/set",
			"POST /api/v1/config/commit",
			"POST /api/v1/system/action",
		} {
			status, errMsg := postRoute(t, base, route, map[string]string{"Authorization": basic})
			if status != http.StatusForbidden {
				t.Errorf("%s admitted an UNIDENTIFIABLE local caller with %d because it "+
					"presented the shared api-auth secret — a restricted account only has to "+
					"make its own identity unreadable to reach full power", route, status)
			}
			if !strings.Contains(errMsg, "local but could not be identified") {
				t.Errorf("%s denial did not name the reason: %q", route, errMsg)
			}
		}
	})

	// The negative control for the rule above: a caller that is genuinely NOT
	// on this host is exactly who the credential exists to identify (#4047), so
	// it must still be admitted. A gate that refused every unattributed caller
	// would pass the subtest above and lock out every remote administrator.
	t.Run("a remote caller with the credential is still admitted", func(t *testing.T) {
		_, base := authzServer(t, Config{
			Addr:         "127.0.0.1:8080",
			Store:        authzStore(t, authzTestConfig),
			Auth:         auth,
			PeerLookupFn: remotePeer(),
		})
		status, errMsg := postRoute(t, base, "POST /api/v1/config/enter",
			map[string]string{"Authorization": basic})
		if status == http.StatusForbidden {
			t.Fatalf("a remote administrator holding a valid api-auth credential was refused: %q",
				errMsg)
		}
	})
}

// TestHalfCloseCannotBorrowCredential_5561 is the MAJOR-2 regression guard on
// the REAL path: production server construction, real ConnContext, real kernel
// socket-table lookup, real /etc/passwd, real credential — and a real
// `shutdown(SHUT_WR)` on a hand-written HTTP request.
//
// Reproduced before the fix: the same `read-only` account with the same valid
// credential got 403 when polite and 200/400 (i.e. past the gate, inside the
// handler) when it half-closed first. The lazy lookup let the caller choose the
// moment of resolution, and a failed resolution fell through to the full-power
// credential. Both halves are fixed — the identity is resolved at accept, and a
// local caller that cannot be attributed is denied rather than downgraded to
// "anonymous with a password".
func TestHalfCloseCannotBorrowCredential_5561(t *testing.T) {
	uid := os.Getuid()
	if uid == 0 {
		t.Skip("running as root: UID 0 is authorized unconditionally, so the class " +
			"this case restricts cannot be observed")
	}
	name, ok := authz.UsernameForUID(uint32(uid))
	if !ok {
		t.Skipf("uid %d has no /etc/passwd entry on this machine", uid)
	}

	cfgText := fmt.Sprintf("system {\n    host-name authz-halfclose;\n    login {\n        user %s {\n            class read-only;\n        }\n    }\n}\n", name)
	auth := &AuthConfig{Users: map[string]string{"webadmin": "s3cret"}}
	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte("webadmin:s3cret"))

	// No PeerLookupFn: the kernel answers for real.
	_, base := authzServer(t, Config{
		Addr:  "127.0.0.1:8080",
		Store: authzStore(t, cfgText),
		Auth:  auth,
	})
	addr := strings.TrimPrefix(base, "http://")

	// rawPost writes a complete request by hand so the caller can half-close
	// between the request and the response — something net/http's client will
	// not do for us.
	rawPost := func(path string, halfClose bool) string {
		c, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer c.Close()
		req := "POST " + path + " HTTP/1.1\r\nHost: " + addr +
			"\r\nAuthorization: " + basic +
			"\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}"
		if _, err := c.Write([]byte(req)); err != nil {
			t.Fatalf("write: %v", err)
		}
		if halfClose {
			// Leave ESTABLISHED while still reading the response — the move
			// that used to defeat the lookup.
			if err := c.(*net.TCPConn).CloseWrite(); err != nil {
				t.Fatalf("CloseWrite: %v", err)
			}
			time.Sleep(150 * time.Millisecond)
		}
		buf := make([]byte, 128)
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, _ := c.Read(buf)
		return string(buf[:n])
	}

	for _, path := range []string{
		"/api/v1/config/enter",
		"/api/v1/config/set",
		"/api/v1/config/commit",
		"/api/v1/system/action",
	} {
		t.Run(path, func(t *testing.T) {
			// Precondition: a polite request from this read-only account is
			// refused, so a pass below is the half-close and nothing else.
			if polite := rawPost(path, false); !strings.HasPrefix(polite, "HTTP/1.1 403") {
				t.Fatalf("precondition: a POLITE read-only caller was not refused: %q", polite)
			}
			hostile := rawPost(path, true)
			if !strings.HasPrefix(hostile, "HTTP/1.1 403") {
				t.Fatalf("a read-only account reached %s by calling shutdown(SHUT_WR) before "+
					"the request was authorized, borrowing the api-auth credential: %q",
					path, hostile)
			}
		})
	}
}

// TestPeerIdentityIsResolvedAtAccept_5561 pins WHEN the identity is taken.
//
// The lookup must happen once per CONNECTION, at accept — not per mutating
// request. Resolving it later hands the caller the choice of when it runs, and
// therefore the choice of making it fail (see
// TestHalfCloseCannotBorrowCredential_5561). Two observable consequences of
// resolving at accept: it runs exactly once no matter how many requests the
// connection carries, and it runs even on a connection that only ever issues a
// safe request.
func TestPeerIdentityIsResolvedAtAccept_5561(t *testing.T) {
	usePasswdFixture(t)

	var mu sync.Mutex
	calls := 0
	counting := func(net.Addr, net.Addr) authz.PeerIdentity {
		mu.Lock()
		calls++
		mu.Unlock()
		return authz.PeerIdentity{UID: authzUIDSuperuser, OK: true, Local: true}
	}
	count := func() int {
		mu.Lock()
		defer mu.Unlock()
		return calls
	}

	_, base := authzServer(t, Config{
		Addr:         "127.0.0.1:8080",
		Store:        authzStore(t, authzTestConfig),
		PeerLookupFn: counting,
	})

	// One connection, kept alive across two requests.
	client := &http.Client{Timeout: 10 * time.Second}
	for i := 0; i < 2; i++ {
		req, err := http.NewRequest(http.MethodPost, base+"/api/v1/config/status", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Method = http.MethodGet
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	if got := count(); got != 1 {
		t.Fatalf("peer identity resolved %d times for ONE connection carrying two SAFE "+
			"requests, want exactly 1 at accept — a per-request lookup lets the caller "+
			"choose the moment it runs, and choose to make it fail", got)
	}

	// A second connection resolves again — the cache is per connection, not
	// per server, so a later caller is not attributed to an earlier one.
	client.CloseIdleConnections()
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Get(base + "/api/v1/config/status")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if got := count(); got != 2 {
		t.Fatalf("a second connection resolved the peer %d times in total, want 2 — the "+
			"identity must be per connection, never shared between callers", got)
	}
}

// TestPeerLookupDoesNotBlockTheAcceptLoop_5561 is the MAJOR-D guard.
//
// ConnContext runs SERIALLY in http.Server's accept loop. A peer whose socket is
// not found costs a walk of the socket table, so resolving inline meant
// connection churn serialized those walks behind Accept and filled the listen
// backlog — locking out remote administrators before api-auth was even
// evaluated.
//
// The probe is deterministic rather than timing-based: the injected resolver
// blocks until the test releases it. If ConnContext resolves inline, the accept
// loop is stuck inside the FIRST connection's lookup and the second connection
// is never accepted, so the resolver is entered exactly once. Off the accept
// path, both connections are accepted and both lookups are in flight.
func TestPeerLookupDoesNotBlockTheAcceptLoop_5561(t *testing.T) {
	usePasswdFixture(t)

	release := make(chan struct{})
	entered := make(chan struct{}, 8)
	blocking := func(net.Addr, net.Addr) authz.PeerIdentity {
		entered <- struct{}{}
		<-release
		return authz.PeerIdentity{UID: authzUIDSuperuser, OK: true, Local: true}
	}
	defer close(release)

	_, base := authzServer(t, Config{
		Addr:         "127.0.0.1:8080",
		Store:        authzStore(t, authzTestConfig),
		PeerLookupFn: blocking,
	})
	addr := strings.TrimPrefix(base, "http://")

	// Two independent connections, neither of which needs to complete a request.
	for i := 0; i < 2; i++ {
		c, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		defer c.Close()
		// Write a byte so the server's serve goroutine is definitely engaged.
		_, _ = c.Write([]byte("G"))
	}

	deadline := time.After(10 * time.Second)
	for got := 0; got < 2; got++ {
		select {
		case <-entered:
		case <-deadline:
			t.Fatalf("only %d of 2 peer lookups started while the first was still "+
				"running — ConnContext is resolving inline, so the accept loop is "+
				"serialized behind every socket-table walk and connection churn can "+
				"fill the listen backlog", got)
		}
	}
}

// TestInjectedResolverIsNormalized_5561 covers the boundary normalization: an
// injected resolver is not bound by LookupPeer's invariants and can report the
// nonsensical (OK=true, Local=false). An attributed peer is local by
// construction — its UID came out of THIS host's socket table — so the
// combination must be normalized before it reaches the precedence rule, which
// has no row for "attributed but off-box".
//
// Unnormalized, such an identity would take the OK branch anyway, so the visible
// consequence is subtle: it is the invariant, not the outcome, that is pinned
// here. The observable assertion is that a restricted class still governs and
// the credential is never consulted.
func TestInjectedResolverIsNormalized_5561(t *testing.T) {
	usePasswdFixture(t)
	auth := &AuthConfig{Users: map[string]string{"webadmin": "s3cret"}}
	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte("webadmin:s3cret"))

	s := NewServer(Config{
		Addr:  "127.0.0.1:8080",
		Store: authzStore(t, authzTestConfig),
		Auth:  auth,
		PeerLookupFn: func(net.Addr, net.Addr) authz.PeerIdentity {
			return authz.PeerIdentity{UID: authzUIDReadOnly, OK: true, Local: false}
		},
	})
	got := s.lookupPeer(&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1},
		&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080})
	if !got.Local {
		t.Fatal("an ATTRIBUTED peer identity was left marked non-local — the precedence " +
			"rule has no row for that combination, and treating it as off-box would let a " +
			"credential speak for a caller we identified")
	}

	// End to end, the read-only class still governs and the credential does not
	// rescue it.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := s.buildHTTPServer(ln.Addr().String())
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	status, errMsg := postRoute(t, "http://"+ln.Addr().String(), "POST /api/v1/config/enter",
		map[string]string{"Authorization": basic})
	if status != http.StatusForbidden {
		t.Fatalf("a read-only principal marked non-local was admitted with %d", status)
	}
	if !strings.Contains(errMsg, "opsuser") {
		t.Errorf("denial did not attribute the read-only account: %q", errMsg)
	}
}

// TestProductionServerEnforcesRealPeerIdentity_5561 runs the whole path with NO
// injection: the production server construction, the real ConnContext hook, the
// real kernel socket-table lookup, the real /etc/passwd, and the real class
// evaluation — with the suite's own connection as the caller. It is the
// end-to-end proof that the identity the gate acts on is the one the kernel
// reports for the process making the request.
func TestProductionServerEnforcesRealPeerIdentity_5561(t *testing.T) {
	uid := os.Getuid()
	if uid == 0 {
		t.Skip("running as root: UID 0 is authorized unconditionally, so the class " +
			"evaluation this case pins cannot be observed")
	}
	name, ok := authz.UsernameForUID(uint32(uid))
	if !ok {
		t.Skipf("uid %d has no /etc/passwd entry on this machine", uid)
	}

	for _, tc := range []struct {
		class      string
		wantDenied bool
	}{
		{"read-only", true},
		{"super-user", false},
	} {
		t.Run(tc.class, func(t *testing.T) {
			cfgText := fmt.Sprintf("system {\n    host-name authz-real;\n    login {\n        user %s {\n            class %s;\n        }\n    }\n}\n",
				name, tc.class)
			// No PeerLookupFn: authz.LookupPeer queries the kernel for real.
			_, base := authzServer(t, Config{
				Addr:  "127.0.0.1:8080",
				Store: authzStore(t, cfgText),
			})
			status, errMsg := postRoute(t, base, "POST /api/v1/config/enter", nil)
			if tc.wantDenied && status != http.StatusForbidden {
				t.Fatalf("uid %d (%s, class %s) was admitted to configure with %d",
					uid, name, tc.class, status)
			}
			if !tc.wantDenied && status == http.StatusForbidden {
				t.Fatalf("uid %d (%s, class %s) was refused configure: %q",
					uid, name, tc.class, errMsg)
			}
			if tc.wantDenied && !strings.Contains(errMsg, strconv.Itoa(uid)) {
				t.Errorf("denial did not report the kernel-derived uid: %q", errMsg)
			}
		})
	}
}

// TestEveryMutatingRouteHasAPermission_5561 is the anti-drift guard. It reads
// the route registrations out of server.go and requires the permission table to
// cover them EXACTLY in both directions: a new state-changing route with no
// entry fails here rather than silently becoming an inert 403 in production,
// and an entry whose route was renamed or removed fails here rather than
// silently guarding nothing.
func TestEveryMutatingRouteHasAPermission_5561(t *testing.T) {
	registered := registeredRoutes(t, "server.go")
	if len(registered) < 40 {
		t.Fatalf("only parsed %d routes out of server.go — the scanner has stopped "+
			"matching the registration form and is no longer guarding anything", len(registered))
	}

	for _, route := range registered {
		method, _, _ := strings.Cut(route, " ")
		if isSafeHTTPMethod(method) {
			if _, listed := restMutationPermissions[route]; listed {
				t.Errorf("%s is a SAFE method but appears in the mutation permission "+
					"table; the guard never consults it there", route)
			}
			continue
		}
		if _, ok := restMutationPermissions[route]; !ok {
			t.Errorf("%s is a state-changing route with no entry in "+
				"restMutationPermissions: it fails closed at runtime, but that is a "+
				"silently dead endpoint. Add its required permission.", route)
		}
	}

	reg := make(map[string]bool, len(registered))
	for _, r := range registered {
		reg[r] = true
	}
	for route := range restMutationPermissions {
		if !reg[route] {
			t.Errorf("restMutationPermissions has an entry for %q, which is not a "+
				"registered route — it guards nothing and hides a renamed endpoint", route)
		}
	}
}

// TestEveryListenerCarriesPeerIdentity_5561 guards the plumbing rather than the
// policy. The gate can only see a caller if the listener that accepted the
// connection installed the ConnContext hook, and http.Server is constructed in
// more than one place: at startup AND on the #5866 day-2 make-before-break
// rebind (listener.go), which a `system services web-management` bind change
// takes. A rebuild that omitted the hook would leave the reconciled listener
// unable to identify anyone — every mutation on it refused, silently, only
// after an operator changed an unrelated setting.
func TestEveryListenerCarriesPeerIdentity_5561(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parse pkg/api: %v", err)
	}
	found := 0
	for _, pkg := range pkgs {
		for name, f := range pkg.Files {
			ast.Inspect(f, func(n ast.Node) bool {
				lit, ok := n.(*ast.CompositeLit)
				if !ok {
					return true
				}
				sel, ok := lit.Type.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "Server" {
					return true
				}
				if x, ok := sel.X.(*ast.Ident); !ok || x.Name != "http" {
					return true
				}
				found++
				for _, elt := range lit.Elts {
					kv, ok := elt.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					if key, ok := kv.Key.(*ast.Ident); ok && key.Name == "ConnContext" {
						return true
					}
				}
				t.Errorf("%s: an http.Server is constructed without ConnContext — "+
					"connections it accepts carry no peer identity, so every mutating "+
					"request on that listener is refused (#5561)", fset.Position(lit.Pos()))
				return true
			})
			_ = name
		}
	}
	if found < 2 {
		t.Fatalf("found only %d http.Server literals in pkg/api; the scanner has stopped "+
			"matching and is no longer guarding the rebind path", found)
	}
}

// sortedRouteKeys returns the mutation table's route keys in a stable order so
// subtest names and failures are deterministic.
func sortedRouteKeys() []string {
	keys := make([]string, 0, len(restMutationPermissions))
	for k := range restMutationPermissions {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// registeredRoutes extracts the "METHOD /path" patterns passed to mux.Handle /
// mux.HandleFunc in the named source file.
func registeredRoutes(t *testing.T, file string) []string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		recv, ok := sel.X.(*ast.Ident)
		if !ok || recv.Name != "mux" {
			return true
		}
		if sel.Sel.Name != "HandleFunc" && sel.Sel.Name != "Handle" {
			return true
		}
		lit, ok := call.Args[0].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			t.Errorf("route registration at %s has a non-literal pattern; the coverage "+
				"guard cannot see it", fset.Position(call.Pos()))
			return true
		}
		pattern, err := strconv.Unquote(lit.Value)
		if err != nil {
			t.Errorf("unquote %s: %v", lit.Value, err)
			return true
		}
		out = append(out, pattern)
		return true
	})
	sort.Strings(out)
	return out
}
