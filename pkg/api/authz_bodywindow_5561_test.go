package api

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dhcp"
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

					// The waiter edge below is a process-global count, so no
					// request from another case may still be parked in the drain.
					waitForGateQuiescent(t)

					// A route whose HANDLER blocks on the caller (configSetHandler
					// decodes before anything else), so the window driven here is
					// the real one rather than an artefact of the gate buffering on
					// some handler's behalf — a route in the mutationBodyNone class
					// answers without entering it at all.
					// #6977: baseline before the request exists.
					parked := MutationBodyWaitersForTest()
					req := openWithheldBody(t, base, "POST /api/v1/config/set", tc.hdrs)

					// Authorized, and now parked reading a body the caller has not
					// sent. This is the window, and the caller holds it open.
					waitForNewMutationBodyWaiter(t, parked)
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
	if err := conn.SetDeadline(time.Now().Add(60 * time.Second)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	if _, err := io.WriteString(conn, b.String()); err != nil {
		t.Fatalf("write request headers: %v", err)
	}
	// The body goes separately, and a short write on it is NOT fatal: a request
	// the gate refuses has its response written and its connection closed while
	// the caller is still sending, which is exactly the outcome some cases are
	// here to observe. The status is still readable from what the server sent
	// before it hung up. A failed HEADER write above is always a bug, so that
	// one stays fatal.
	if sent != "" {
		_, _ = io.WriteString(conn, sent)
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

// TestNoBodyRouteIsNotBufferedByTheGate_5561 pins the restored immediate
// answer on EVERY route in the no-body class.
//
// Those handlers answer from the request line and its headers — the two clear
// verbs are parameterless by contract (#3421 H6) and the five config lifecycle
// and commit verbs are addressed by the X-Config-Session header — so once the
// gate began draining every authorized mutating request, their answers moved
// behind a read the CALLER controls. A caller could declare 16 MiB, send all
// but the last byte, and make the daemon hold a buffer until apiReadTimeout
// (30s), once per connection, for a request no handler was going to read.
//
// The class is read from restMutationBodyLimits rather than listed here, so a
// route added to it is covered without anybody remembering to extend this case.
// Its MEMBERSHIP is a separate question, answered against the handlers
// themselves by TestNoBodyClassMatchesTheHandlersThatDecode_5561.
//
// The assertion is the outcome the caller sees on a body it never finishes: the
// answer must arrive WITHOUT it, and no request may be parked reading one. The
// status itself is deliberately not asserted — it depends on whether the
// fixture wires a dataplane, and the property under test is that the handler was
// reached at all before the caller chose to finish.
//
// The CONTROL is the discriminator, and it has to be a route whose HANDLER
// blocks on the caller — not merely one the gate buffers, which would be a
// tautology about the classification the case is trying to discriminate.
// configSetHandler decodes the body before it looks at anything else, so
// POST /api/v1/config/set parks because of what it does, not because of how it
// is classified.
func TestNoBodyRouteIsNotBufferedByTheGate_5561(t *testing.T) {
	usePasswdFixture(t)
	_, base := authzServer(t, Config{
		Addr:         "127.0.0.1:8080",
		Store:        authzStore(t, authzTestConfig),
		PeerLookupFn: fixedPeerUID(authzUIDSuperuser),
	})

	noBody := make([]string, 0, len(restMutationBodyLimits))
	for route, limit := range restMutationBodyLimits {
		if limit == mutationBodyNone {
			noBody = append(noBody, route)
		}
	}
	sort.Strings(noBody)
	if len(noBody) == 0 {
		t.Fatal("no route is classified mutationBodyNone, so this case asserts nothing")
	}

	for _, route := range noBody {
		t.Run(route, func(t *testing.T) {
			// #6977: this is an ABSENCE assertion on a PROCESS-GLOBAL counter,
			// and it is the property this case exists to state — the other
			// class-A sites use the counter as a precondition. The direction of
			// its contamination is therefore the opposite one: a request some
			// other case left parked does not make this pass early, it makes it
			// RED, naming a route that parked nothing. Compare against a
			// baseline read before this request exists, so what is asserted is
			// "this route added no park", which is what the sentence means.
			parked := MutationBodyWaitersForTest()
			conn := openDeclaredBody(t, base, route, 16<<20, "{", nil)

			if _, got := readStatus(t, conn, 10*time.Second); !got {
				t.Fatalf("%s never answered a request whose body no handler reads. The gate "+
					"is draining a 16 MiB declaration on its behalf, so the caller — not the "+
					"server — decides how long the daemon holds that buffer, once per "+
					"connection, until the 30s read timeout", route)
			}
			if n := MutationBodyWaitersForTest(); n != parked {
				t.Fatalf("%d requests are parked reading a body inside the gate after a "+
					"no-body route answered, up from %d before it opened; want no change. "+
					"A no-body route must not enter the gate's drain at all", n, parked)
			}
		})
	}

	t.Run("control: a route whose handler decodes still parks", func(t *testing.T) {
		conn := openDeclaredBody(t, base, "POST /api/v1/config/set", 16<<20, "{", nil)
		if status, got := readStatus(t, conn, 2*time.Second); got {
			t.Fatalf("POST /api/v1/config/set answered %d before its body arrived. Its handler "+
				"decodes one before it does anything else, so the gate must hold the second "+
				"adjudication until the caller supplies it — and the probe above cannot "+
				"distinguish anything if every route answers early", status)
		}
		// This control ENDS with a request deliberately parked on a body it will
		// never finish, and the counter it is holding is process-global. Hang up
		// and wait for the gate to let go before returning (#6645 r22, finding
		// 2): openDeclaredBody's own cleanup closes the connection but nothing
		// joins the handler, so without this the waiter outlives the case and
		// the next one's waitForMutationBodyWaiter can take it for its own.
		//
		// The close is load-bearing; its ERROR is not. A failure to close a
		// client-side test socket says nothing about production, so it is
		// deliberately unasserted — the binding assertion is the quiescence
		// wait that follows.
		_ = conn.Close()
		waitForGateQuiescent(t)
	})
}

// TestNoBodyClassMatchesTheHandlersThatDecode_5561 pins the MEMBERSHIP of the
// no-body class against the handlers themselves.
//
// mutationBodyNone means "this route's handler never reads the request body",
// and everything the class buys follows from that being true: the gate skips
// the drain, so the route keeps its immediate answer, never enters the window
// the caller controls, and never charges the aggregate budget for a body
// nobody is going to look at. A route that belongs in the class and is not in
// it pays all three costs for nothing; one that does NOT belong and is in it
// loses the second adjudication's ordering.
//
// The probe cannot ask "did this request park", because the GATE parks it — a
// route buffered by the gate parks whether or not its handler would have read
// anything, which makes that observation a tautology about the classification
// rather than a test of it. So it asks the handler a question only a handler
// that decodes can answer: it sends a complete, tiny, syntactically INVALID
// JSON body. A handler that decodes answers 400 "invalid JSON body"; a handler
// that never looks answers whatever it answers from headers alone. That
// partition must be exactly the classification.
func TestNoBodyClassMatchesTheHandlersThatDecode_5561(t *testing.T) {
	usePasswdFixture(t)
	// The DHCP manager is wired deliberately. clearDHCPIdentifiersHandler
	// answers "No DHCP clients running" and returns BEFORE its decode when
	// s.dhcp is nil, so an unwired fixture reports that route as one that never
	// reads a body — and acting on that would move a route whose handler DOES
	// block on the caller out of the ordering the second adjudication provides.
	// A probe of handler behaviour has to reach the handler's real path.
	dhcpMgr, err := dhcp.New(t.TempDir(), func() {}, func() {})
	if err != nil {
		t.Fatalf("dhcp.New: %v", err)
	}
	_, base := authzServer(t, Config{
		Addr:  "127.0.0.1:8080",
		Store: authzStore(t, authzTestConfig),
		DHCP:  dhcpMgr,
		// super-user: every guarded route is authorized, so the answer observed
		// is the HANDLER's and not the gate's.
		PeerLookupFn: fixedPeerUID(authzUIDSuperuser),
	})

	// The message both decode sites write on malformed input — pkg/api/api.go's
	// shared decodeJSONBody and pkg/api/dhcp.go's equivalent.
	const decodeErr = "invalid JSON body"

	routes := make([]string, 0, len(restMutationBodyLimits))
	for route := range restMutationBodyLimits {
		routes = append(routes, route)
	}
	sort.Strings(routes)

	for _, route := range routes {
		t.Run(route, func(t *testing.T) {
			conn := openDeclaredBody(t, base, route, 1, "!", nil)
			status, msg := readWholeResponse(t, conn, 10*time.Second)
			decoded := status == http.StatusBadRequest && msg == decodeErr
			inClass := restMutationBodyLimits[route] == mutationBodyNone

			switch {
			case decoded && inClass:
				t.Fatalf("%s is classified mutationBodyNone, but its handler DECODED the body "+
					"(%d %q). The gate skips the drain for this class, so the second "+
					"adjudication no longer sits in front of the block the caller controls — "+
					"the ordering the whole two-pass gate exists for is gone on this route",
					route, status, msg)
			case !decoded && !inClass:
				t.Fatalf("%s answered %d %q WITHOUT decoding the body, yet it is classified as "+
					"a body-taking route (limit %d). The gate drains a body its handler never "+
					"reads: an immediate answer becomes a read the caller can stall for the "+
					"whole apiReadTimeout, and it charges the aggregate body budget for the "+
					"stall. It belongs in mutationBodyNone",
					route, status, msg, restMutationBodyLimits[route])
			}
		})
	}
}

// readWholeResponse reads a complete HTTP response off a raw connection and
// returns its status and the Response.Error field.
func readWholeResponse(t *testing.T, conn net.Conn, within time.Duration) (int, string) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(within)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodPost})
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var r Response
	_ = json.Unmarshal(raw, &r)
	return resp.StatusCode, r.Error
}
