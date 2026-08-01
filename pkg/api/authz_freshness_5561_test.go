package api

import (
	"context"
	"encoding/base64"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/authz"
	"github.com/psaab/xpf/pkg/configstore"
)

// authz_freshness_5561_test.go is the fail-on-revert gate for the three
// FRESHNESS properties of the #5561 mutation gate — the ones a fixture that
// holds its inputs immutable for the whole request cannot see:
//
//  1. The config snapshot the decision is evaluated against is read AFTER the
//     gate's blocking peer wait, not before it.
//  2. An api-auth credential principal cannot outlive the snapshot that minted
//     it: a revocation landing while the request is blocked must deny it.
//  3. An accept-time lookup slot is RETURNED when the lookup finishes, so the
//     admission pool is a ceiling on concurrency rather than a lifetime budget.
//
// Every case here drives real HTTP through the production constructor
// (buildHTTPServer) so the ConnContext plumbing is on the tested path, and every
// case carries a CONTROL that must NOT deny — a freshness test whose only
// assertion is "403" passes just as well when the endpoint is broken.

// authzRecommit replaces a store's ACTIVE config through the real
// configure/load/commit path, which is what a `commit` from another session
// does while a request is in flight.
func authzRecommit(t *testing.T, store *configstore.Store, text string) {
	t.Helper()
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
}

// waitForPeerWaiter blocks until a request is parked in the mutation gate's peer
// wait — the happens-before edge that says "the gate has started and has read
// nothing yet".
func waitForPeerWaiter(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if PeerIdentityWaitersForTest() > 0 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("no request ever parked in the gate's peer wait, so the case never reached the " +
		"window it tests")
}

// authzConfigAdminDemoted is authzTestConfig with adminuser demoted from
// super-user to read-only — the class no longer holds `configure`.
const authzConfigAdminDemoted = `
system {
    host-name authz-test;
    login {
        user opsuser {
            class read-only;
        }
        user adminuser {
            class read-only;
        }
    }
}
`

// authzConfigAdminDeleted is authzTestConfig with adminuser removed from the
// login model entirely — no class governs it, so Authorize denies whatever
// snapshot it is handed.
const authzConfigAdminDeleted = `
system {
    host-name authz-test;
    login {
        user opsuser {
            class read-only;
        }
    }
}
`

// TestConfigSnapshotIsReadAfterThePeerWait_5561 is the round-9 finding-1 guard.
//
// mutationAuthzGuard read the active config and THEN called principal(), whose
// first action is pendingPeer.wait — the only unbounded block in the gate, up to
// peerLookupTimeout (5 seconds). The authorization decision was therefore
// evaluated against a snapshot captured up to five seconds before it was made,
// and a commit landing inside that window did not reach the decision at all: a
// principal demoted or deleted while its own request was blocked kept the
// authority the superseded config gave it.
//
// The window is caller-influenced, which is what makes it more than a race. The
// lookup a request waits on is a socket-table read; a caller that opens
// connections while the table is contended lengthens its own wait, and every
// millisecond it adds is a millisecond of revoked authority it keeps.
//
// Each case runs TWICE against the same fixture: once with no commit (the
// CONTROL, which must be admitted) and once with the revoking commit landing
// while the lookup is blocked (which must be denied). Without the control a
// reverted ordering could be "caught" by any unrelated 403.
func TestConfigSnapshotIsReadAfterThePeerWait_5561(t *testing.T) {
	for _, tc := range []struct {
		name    string
		revoked string
		why     string
	}{
		{
			name:    "demoted",
			revoked: authzConfigAdminDemoted,
			why: "adminuser was demoted from super-user to read-only while its own request " +
				"was blocked in the peer lookup",
		},
		{
			name:    "deleted",
			revoked: authzConfigAdminDeleted,
			why: "adminuser was deleted from `system login user` while its own request was " +
				"blocked in the peer lookup",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, commitDuringWait := range []bool{false, true} {
				name := "control-no-commit"
				if commitDuringWait {
					name = "commit-during-wait"
				}
				t.Run(name, func(t *testing.T) {
					usePasswdFixture(t)
					store := authzStore(t, authzTestConfig)

					entered := make(chan struct{}, 1)
					release := make(chan struct{})
					_, base := authzServer(t, Config{
						Addr:  "127.0.0.1:8080",
						Store: store,
						PeerLookupFn: func(net.Addr, net.Addr) authz.PeerIdentity {
							select {
							case entered <- struct{}{}:
							default:
							}
							<-release
							return authz.PeerIdentity{UID: authzUIDSuperuser, OK: true, Local: true}
						},
					})

					type result struct {
						status int
						msg    string
					}
					done := make(chan result, 1)
					go func() {
						status, msg := postRoute(t, base, "POST /api/v1/config/enter", nil)
						done <- result{status, msg}
					}()

					// Wait for the accept-time lookup to start...
					select {
					case <-entered:
					case <-time.After(10 * time.Second):
						t.Fatal("the peer lookup never started; the case never reached the window it tests")
					}
					// ...and then for the REQUEST to be parked on it. This second
					// edge is the one that makes the case deterministic, and the
					// first draft of this test did not have it: connContext runs at
					// ACCEPT, so `entered` fires before the request bytes are even
					// read, and a commit landing there is a commit landing BEFORE the
					// gate runs — which both the fixed and the broken ordering answer
					// identically. A parked waiter means the gate has entered
					// authorizeInputs and has not yet returned from the wait, so a
					// snapshot read before the wait has ALREADY happened and one read
					// after it has NOT.
					waitForPeerWaiter(t)
					if commitDuringWait {
						authzRecommit(t, store, tc.revoked)
					}
					close(release)

					var got result
					select {
					case got = <-done:
					case <-time.After(20 * time.Second):
						t.Fatal("the request never completed")
					}

					if !commitDuringWait {
						if got.status == http.StatusForbidden {
							t.Fatalf("the CONTROL was denied (%d, %q) — a super-user with no "+
								"intervening commit must be admitted, so the denial below would "+
								"prove nothing", got.status, got.msg)
						}
						return
					}
					if got.status != http.StatusForbidden {
						t.Fatalf("got %d, want 403: %s, and the request was still authorized. "+
							"The active config was read BEFORE the blocking peer wait, so the "+
							"decision was evaluated against the snapshot the commit superseded "+
							"(error=%q)", got.status, tc.why, got.msg)
					}
				})
			}
		})
	}
}

// TestRevokedCredentialCannotFinishAnInFlightRequest_5561 is the round-9
// finding-2 guard.
//
// principal() minted an authz.CredentialPrincipal from the auth snapshot live at
// the moment the credential row was entered, and that principal is a VALUE:
// ReplaceAuth swaps the atomic pointer and cannot reach anything already
// constructed. A credential revoked or rotated mid-request therefore did not
// invalidate the principal already speaking for that request — and Authorize
// short-circuits on Superuser, so the principal is full power.
//
// The gap is not a nanosecond. peerIsLocalNow sits between the mint and the
// decision and BLOCKS: it takes hostAddrScan's single-flight, so a request can
// wait out another goroutine's whole interface enumeration inside that window.
// The test makes that block explicit through Config.PeerLocalityFn, which is the
// production seam for exactly this step.
//
// Both credential SHAPES are covered, because credentialPrincipalUser has two
// arms — a Basic header and an X-API-Key token — and a re-validation added to
// one only would leave the other on the old behaviour.
func TestRevokedCredentialCannotFinishAnInFlightRequest_5561(t *testing.T) {
	const (
		user   = "webadmin"
		secret = "s3cret"
		apiKey = "k3y-aaaaaaaaaaaaaaaaaaaa"
	)
	for _, tc := range []struct {
		name string
		hdrs map[string]string
	}{
		{
			name: "basic",
			hdrs: map[string]string{
				"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+secret)),
			},
		},
		{
			name: "api-key",
			hdrs: map[string]string{"X-API-Key": apiKey},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, revokeDuringWait := range []bool{false, true} {
				name := "control-no-revocation"
				if revokeDuringWait {
					name = "revoked-during-adjudication"
				}
				t.Run(name, func(t *testing.T) {
					usePasswdFixture(t)

					entered := make(chan struct{}, 1)
					release := make(chan struct{})
					s, base := authzServer(t, Config{
						Addr:  "127.0.0.1:8080",
						Store: authzStore(t, authzTestConfig),
						Auth: &AuthConfig{
							Users:   map[string]string{user: secret},
							APIKeys: map[string]bool{apiKey: true},
						},
						PeerLookupFn: remotePeer(),
						// The production step this stands in for is
						// authz.PeerCouldBeLocalNow, which single-flights an
						// interface enumeration and so genuinely blocks.
						PeerLocalityFn: func(net.Addr, net.Addr) bool {
							select {
							case entered <- struct{}{}:
							default:
							}
							<-release
							return false
						},
					})

					type result struct {
						status int
						msg    string
					}
					done := make(chan result, 1)
					go func() {
						status, msg := postRoute(t, base, "POST /api/v1/config/enter", tc.hdrs)
						done <- result{status, msg}
					}()

					// The request has authenticated against the LIVE snapshot and is
					// now parked in the locality re-derivation, holding a principal
					// minted from that snapshot.
					select {
					case <-entered:
					case <-time.After(10 * time.Second):
						t.Fatal("the locality re-derivation never started; the case never reached " +
							"the window it tests")
					}
					if revokeDuringWait {
						// Exactly what a `delete system services web-management
						// ... api-auth` commit does: ReplaceAuth with a policy that
						// no longer honours the presented credential.
						s.ReplaceAuth(&AuthConfig{Users: map[string]string{"someone-else": "different"}})
					}
					close(release)

					var got result
					select {
					case got = <-done:
					case <-time.After(20 * time.Second):
						t.Fatal("the request never completed")
					}

					if !revokeDuringWait {
						if got.status == http.StatusForbidden || got.status == http.StatusUnauthorized {
							t.Fatalf("the CONTROL was refused (%d, %q) — an off-box caller holding a "+
								"VALID credential must be admitted, so the refusal below would prove "+
								"nothing", got.status, got.msg)
						}
						return
					}
					if got.status == http.StatusOK {
						t.Fatalf("a request whose api-auth credential was REVOKED while it was "+
							"blocked in the locality re-derivation was still authorized (%d). The "+
							"credential principal was minted from the superseded snapshot and "+
							"ReplaceAuth cannot reach it, so revoking a leaked secret does not stop "+
							"a request already in flight", got.status)
					}
				})
			}
		})
	}
}

// slotConn is the minimum net.Conn Server.connContext reads: the two addresses.
type slotConn struct {
	net.Conn
	client, server net.Addr
}

func (c slotConn) RemoteAddr() net.Addr { return c.client }
func (c slotConn) LocalAddr() net.Addr  { return c.server }

// waitSlots polls the admission pool until it holds want tokens.
func waitSlots(t *testing.T, want int, what string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if PeerLookupSlotsInUseForTest() == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("%s: the pool holds %d tokens, want %d", what, PeerLookupSlotsInUseForTest(), want)
}

// TestPeerLookupSlotsAreReturned_5561 is the round-9 finding-5 guard: it
// exercises the RELEASE side of the accept-time admission pool.
//
// TestWedgedLookupsDoNotAccumulate_5561 fills the pool with a bare channel send
// and drains it in a defer, so it never acquires a token through connContext and
// the `defer func() { <-peerLookupSlots }()` at the acquire site is unexercised
// by it. Delete that defer and it stays green — while the daemon converts a
// CONCURRENCY ceiling into a LIFETIME budget: the 1024th connection ever
// accepted exhausts the pool permanently, and every connection after it resolves
// to the capacity denial. That is a total management-plane lockout reached by
// ordinary use, with no attacker and no wedge.
//
// Three accounting facts are pinned, which together are the pool's whole
// contract:
//
//	acquire   a running lookup HOLDS a token
//	release   a finished lookup RETURNS it, and the token is genuinely reusable
//	refusal   a connection REFUSED admission neither takes nor returns one
//
// The third is the other edge. A release moved or duplicated into the refusal
// arm would keep this test's first two assertions green while letting the pool
// drain below zero occupancy — i.e. admitting past the cap it exists to enforce.
func TestPeerLookupSlotsAreReturned_5561(t *testing.T) {
	usePasswdFixture(t)

	// Take every token but one, so a single lookup can be observed against a
	// pool whose occupancy is otherwise pinned.
	held := 0
	defer func() {
		for i := 0; i < held; i++ {
			<-peerLookupSlots
		}
	}()
	for held < maxConcurrentPeerLookups-1 {
		select {
		case peerLookupSlots <- struct{}{}:
			held++
		default:
			t.Fatalf("could not fill the lookup pool; %d of %d taken before it refused",
				held, maxConcurrentPeerLookups-1)
		}
	}
	if n := PeerLookupSlotsInUseForTest(); n != maxConcurrentPeerLookups-1 {
		t.Fatalf("pool holds %d tokens before the case starts, want %d", n, maxConcurrentPeerLookups-1)
	}

	entered := make(chan struct{}, 4)
	release := make(chan struct{})
	s := NewServer(Config{
		Addr:  "127.0.0.1:8080",
		Store: authzStore(t, authzTestConfig),
		PeerLookupFn: func(net.Addr, net.Addr) authz.PeerIdentity {
			entered <- struct{}{}
			<-release
			return authz.PeerIdentity{UID: authzUIDSuperuser, OK: true, Local: true}
		},
	})
	conn := slotConn{
		client: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40001},
		server: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080},
	}

	// ACQUIRE: the running lookup holds the last token.
	ctx := s.connContext(context.Background(), conn)
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the lookup never started, so the acquire path was not exercised")
	}
	if n := PeerLookupSlotsInUseForTest(); n != maxConcurrentPeerLookups {
		t.Fatalf("a RUNNING lookup left the pool at %d, want the full %d — the acquire path "+
			"did not take a token", n, maxConcurrentPeerLookups)
	}

	// REFUSAL: with the pool full, a second connection must be refused WITHOUT
	// disturbing the accounting in either direction.
	refused := s.connContext(context.Background(), conn)
	rp, ok := peerIdentityFrom(refused)
	if !ok {
		t.Fatal("connContext did not attach a pending identity to the refused connection")
	}
	<-rp.done
	if rp.id.OK || !rp.id.Local {
		t.Fatalf("a connection refused admission resolved to %+v, want an unattributable LOCAL "+
			"identity (which denies)", rp.id)
	}
	if n := PeerLookupSlotsInUseForTest(); n != maxConcurrentPeerLookups {
		t.Fatalf("a REFUSED connection moved the pool to %d, want it untouched at %d — the "+
			"refusal arm must neither take a token nor return one it never took",
			n, maxConcurrentPeerLookups)
	}

	// RELEASE: finishing the lookup returns the token.
	close(release)
	p, ok := peerIdentityFrom(ctx)
	if !ok {
		t.Fatal("connContext did not attach a pending identity")
	}
	<-p.done
	if !p.id.OK {
		t.Fatalf("the admitted lookup resolved to %+v, want the injected attribution", p.id)
	}
	waitSlots(t, maxConcurrentPeerLookups-1,
		"a FINISHED lookup did not return its token, so the pool is a lifetime budget rather "+
			"than a concurrency ceiling: the 1024th connection ever accepted locks the "+
			"management plane out permanently")

	// And the returned token is genuinely REUSABLE — the operator-visible half.
	// A connection arriving now must reach the resolver, not the capacity denial.
	// `release` is already closed, so this lookup runs straight through.
	next := s.connContext(context.Background(), conn)
	np, ok := peerIdentityFrom(next)
	if !ok {
		t.Fatal("connContext did not attach a pending identity to the follow-on connection")
	}
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the follow-on connection never reached the resolver: it was refused admission " +
			"even though the previous lookup had finished")
	}
	<-np.done
	if !np.id.OK {
		t.Fatalf("a connection arriving after a completed lookup resolved to %+v, want the "+
			"injected attribution — the token the finished lookup returned was not reusable", np.id)
	}
	waitSlots(t, maxConcurrentPeerLookups-1, "the follow-on lookup did not return its token")
}
