package api

import (
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// authz_bodywindow_5561_test.go guards the window the mutation gate holds open
// while the CALLER supplies its body (#5561 round 10) — its FRESHNESS at the
// intersection the existing matrix omits, and the one route class that must
// never enter it at all. authz_bodybudget_5561_test.go owns what that window
// may COST.

// ==========================================================================
// Freshness at the local-caller / credential-change intersection.
// ==========================================================================

// TestLocalCallerCredentialIsRevalidatedAfterTheBody_5561 drives the cell the
// freshness matrix leaves empty.
//
// authz_freshness_5561_test.go covers local class demotion on one row and
// REMOTE credential revocation on another. The gate's second pass re-reads the
// config snapshot for every row, so the first is caught; the credential,
// however, was re-validated only inside principalFrom's off-box branch — the
// one row an attributed LOCAL caller never takes. So a configured administrator
// calling from this host could present credential A, withhold its body, let
// another session rotate A to B, and still have the mutation run: pass 2
// refreshed the class and nothing else.
//
// Both spellings of the change are driven, because they fail for the same
// reason and are the two an operator actually commits:
//
//	rotated    `set ... api-auth user webadmin authentication-key <new>`
//	           — the presented secret stops being valid.
//	newly-required
//	           `set ... api-auth ...` on a listener that had NONE — a request
//	           admitted through the nil-snapshot pass-through would otherwise
//	           stay credentialless for the rest of its life.
//
// Each row runs TWICE. The control must be ADMITTED: a second pass that denied
// everything would satisfy the assertion below just as well.
func TestLocalCallerCredentialIsRevalidatedAfterTheBody_5561(t *testing.T) {
	const (
		credUser = "webadmin"
		credPass = "s3cret"
	)
	basic := map[string]string{
		"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte(credUser+":"+credPass)),
	}
	for _, tc := range []struct {
		name string
		// startAuth is the listener's policy when the request is admitted.
		startAuth *AuthConfig
		hdrs      map[string]string
		// change is what another session commits while the body is outstanding.
		change *AuthConfig
		why    string
	}{
		{
			name:      "credential-rotated-under-a-local-administrator",
			startAuth: &AuthConfig{Users: map[string]string{credUser: credPass}},
			hdrs:      basic,
			change:    &AuthConfig{Users: map[string]string{credUser: "rotated-secret"}},
			why: "the api-auth credential the request presented was rotated while that " +
				"request sat withholding its body, and the caller is a LOCAL attributed " +
				"administrator — the row whose principal is derived from the peer UID, so " +
				"the credential re-check inside the off-box branch never runs for it",
		},
		{
			name:      "api-auth-newly-required-under-a-local-administrator",
			startAuth: nil,
			hdrs:      nil,
			change:    &AuthConfig{Users: map[string]string{credUser: credPass}},
			why: "api-auth was ADDED while an uncredentialed request sat withholding its " +
				"body. It was admitted through dynamicAuthMiddleware's nil-snapshot " +
				"pass-through, so a tightening the operator committed did not reach the " +
				"request it was committed to stop",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, change := range []bool{false, true} {
				name := "control-no-change"
				if change {
					name = "changed-while-body-withheld"
				}
				t.Run(name, func(t *testing.T) {
					usePasswdFixture(t)
					store := authzStore(t, authzTestConfig)
					s, base := authzServer(t, Config{
						Addr:  "127.0.0.1:8080",
						Store: store,
						Auth:  tc.startAuth,
						// LOCAL and ATTRIBUTED: the principal comes from the peer
						// UID, so principalFrom takes its first branch and returns
						// before any credential is consulted.
						PeerLookupFn: fixedPeerUID(authzUIDSuperuser),
					})

					req := openWithheldBody(t, base, "POST /api/v1/config/enter", tc.hdrs)

					// Authorized, and now parked reading a body the caller has not
					// sent. This is the window, and the caller holds it open.
					waitForMutationBodyWaiter(t)
					if change {
						s.ReplaceAuth(tc.change)
					}

					status, msg := req.finish(t)

					if !change {
						if status == http.StatusForbidden || status == http.StatusUnauthorized {
							t.Fatalf("the CONTROL was refused (%d, %q) — a caller whose "+
								"credential was never touched must be admitted, so the "+
								"refusal below would prove nothing", status, msg)
						}
						return
					}
					if status != http.StatusForbidden {
						t.Fatalf("got %d (error=%q), want 403: %s. The mutation ran on an "+
							"authentication decision made before the caller supplied its "+
							"body", status, msg, tc.why)
					}
				})
			}
		})
	}
}

// ==========================================================================
// Shared raw-HTTP helpers: a caller-chosen Content-Length is the lever the
// buffered-body cost is a function of, so the cases below have to speak it.
// ==========================================================================

// openDeclaredBody sends a mutating request's headers declaring a body of
// `declared` bytes, writes `sent` of them, and withholds the rest. It is
// openWithheldBody with the declaration under the case's control.
//
// Raw sockets rather than http.Client for the same reason openWithheldBody
// gives: net/http buffers the request headers and flushes them only once the
// body produces bytes, so a withheld body withholds the headers too and the
// server never starts the request.
func openDeclaredBody(t *testing.T, base, route string, declared int, sent string, hdrs map[string]string) net.Conn {
	t.Helper()
	method, path, ok := strings.Cut(route, " ")
	if !ok {
		t.Fatalf("malformed route key %q", route)
	}
	addr := strings.TrimPrefix(base, "http://")
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	var b strings.Builder
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\n", method, path)
	fmt.Fprintf(&b, "Host: %s\r\n", addr)
	b.WriteString("Content-Type: application/json\r\n")
	fmt.Fprintf(&b, "Content-Length: %d\r\n", declared)
	for k, v := range hdrs {
		fmt.Fprintf(&b, "%s: %s\r\n", k, v)
	}
	b.WriteString("Connection: close\r\n\r\n")
	b.WriteString(sent)
	if err := conn.SetDeadline(time.Now().Add(60 * time.Second)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	if _, err := io.WriteString(conn, b.String()); err != nil {
		t.Fatalf("write request headers: %v", err)
	}
	return conn
}

// readStatus reads the response status code off a raw connection, or reports
// false if none arrives within `within` (which is itself the assertion in a
// case about a server that must answer before the body it is waiting for).
func readStatus(t *testing.T, conn net.Conn, within time.Duration) (int, bool) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(within)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	line := make([]byte, 0, 64)
	buf := make([]byte, 1)
	for len(line) < 64 {
		n, err := conn.Read(buf)
		if n == 0 || err != nil {
			return 0, false
		}
		if buf[0] == '\n' {
			break
		}
		line = append(line, buf[0])
	}
	var proto string
	var code int
	if _, err := fmt.Sscanf(strings.TrimSpace(string(line)), "%s %d", &proto, &code); err != nil {
		return 0, false
	}
	return code, true
}

// TestNoBodyRouteIsNotBufferedByTheGate_5561 pins the restored immediate answer
// on the routes whose handlers never touch the request body.
//
// `POST /api/v1/security/sessions/clear` is parameterless by contract (#3421
// H6): it answers on any query string or non-zero ContentLength WITHOUT reading
// a byte. `POST /api/v1/security/counters/clear` ignores the request entirely.
// Once the gate began draining every authorized mutating request, both answers
// moved behind a read the CALLER controls — so a caller could declare 16 MiB,
// send all but the last byte, and make the daemon hold a buffer until
// apiReadTimeout (30s), once per connection, for a request no handler was going
// to read.
//
// The assertion is the outcome the caller sees on a body it never finishes: the
// answer must arrive WITHOUT it, and no request may be parked reading one. The
// status itself is deliberately not asserted — it depends on whether the
// fixture wires a dataplane, and the property under test is that the handler
// was reached at all before the caller chose to finish.
//
// The CONTROL is the discriminator: `POST /api/v1/config/enter` DOES take a
// body, so it must still park. Without it, a probe that reported "answered"
// for every route would look like a pass.
func TestNoBodyRouteIsNotBufferedByTheGate_5561(t *testing.T) {
	usePasswdFixture(t)
	_, base := authzServer(t, Config{
		Addr:         "127.0.0.1:8080",
		Store:        authzStore(t, authzTestConfig),
		PeerLookupFn: fixedPeerUID(authzUIDSuperuser),
	})

	for _, route := range []string{
		"POST /api/v1/security/sessions/clear",
		"POST /api/v1/security/counters/clear",
	} {
		t.Run(route, func(t *testing.T) {
			// A 16 MiB declaration with ONE byte sent and the rest withheld.
			conn := openDeclaredBody(t, base, route, 16<<20, "{", nil)

			if _, got := readStatus(t, conn, 10*time.Second); !got {
				t.Fatalf("%s never answered a request whose body no handler reads. The gate "+
					"is draining a 16 MiB declaration on its behalf, so the caller — not the "+
					"server — decides how long the daemon holds that buffer, once per "+
					"connection, until the 30s read timeout", route)
			}
			if n := MutationBodyWaitersForTest(); n != 0 {
				t.Fatalf("%d requests are parked reading a body inside the gate after a "+
					"no-body route answered; want 0", n)
			}
		})
	}

	t.Run("control: a body-taking route still parks", func(t *testing.T) {
		conn := openDeclaredBody(t, base, "POST /api/v1/config/enter", 16<<20, "{", nil)
		if status, got := readStatus(t, conn, 2*time.Second); got {
			t.Fatalf("POST /api/v1/config/enter answered %d before its body arrived. It "+
				"DOES decode one, so the gate must hold the second adjudication until the "+
				"caller supplies it — and the probe above cannot distinguish anything if "+
				"every route answers early", status)
		}
	})
}
