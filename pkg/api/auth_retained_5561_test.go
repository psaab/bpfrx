package api

import "testing"

// auth_retained_5561_test.go pins AuthForRetainedListener's semantics (#5561
// round 12). The daemon-side tests prove the reconciler CALLS it at the right
// moments; these prove the function itself computes the set that makes those
// call sites correct — in particular the nil-is-universal rule, without which
// the round-9 hoist (publish the credential before a new off-box socket serves)
// would silently publish an empty deny-all set instead.

func TestAuthForRetainedListenerNilLiveIsUniversal_5561(t *testing.T) {
	next := &AuthConfig{Users: map[string]string{"admin": "pw"}, APIKeys: map[string]bool{"k": true}}
	got := AuthForRetainedListener(nil, next)
	if got == nil {
		t.Fatal("a nil live snapshot yielded nil — that would leave a listener with NO auth")
	}
	if got.Users["admin"] != "pw" || !got.APIKeys["k"] {
		t.Fatalf("got %+v, want the full set. A nil live snapshot is dynamicAuthMiddleware's "+
			"pass-through: that listener already accepts everyone, so `next` is unambiguously "+
			"a tightening and must be published whole (the #5561 round-9 case)", got)
	}
}

func TestAuthForRetainedListenerDropsRevoked_5561(t *testing.T) {
	live := &AuthConfig{Users: map[string]string{"admin": "pw", "gone": "x"}, APIKeys: map[string]bool{"k": true, "old": true}}
	next := &AuthConfig{Users: map[string]string{"admin": "pw"}, APIKeys: map[string]bool{"k": true}}
	got := AuthForRetainedListener(live, next)
	if _, ok := got.Users["gone"]; ok {
		t.Fatalf("got %+v: a credential the committed config no longer carries survived — a "+
			"revocation must land on the retained listener immediately (#5561 round 7)", got)
	}
	if got.APIKeys["old"] {
		t.Fatalf("got %+v: a revoked api-key survived", got)
	}
	if got.Users["admin"] != "pw" || !got.APIKeys["k"] {
		t.Fatalf("got %+v: a credential that was already accepted here AND is still committed "+
			"was dropped — that is over-restriction with no property behind it", got)
	}
}

func TestAuthForRetainedListenerWithholdsGrants_5561(t *testing.T) {
	live := &AuthConfig{Users: map[string]string{"admin": "pw"}}
	next := &AuthConfig{
		Users:   map[string]string{"admin": "pw", "autobot": "new"},
		APIKeys: map[string]bool{"fresh": true},
	}
	got := AuthForRetainedListener(live, next)
	if _, ok := got.Users["autobot"]; ok {
		t.Fatalf("got %+v: a principal this listener never accepted was granted. The credential "+
			"set was committed together with the endpoint it is meant for; a listener retained "+
			"by a failed rebind is not that endpoint", got)
	}
	if got.APIKeys["fresh"] {
		t.Fatalf("got %+v: an api-key this listener never accepted was granted", got)
	}
}

// A same-username secret ROTATION is a revocation plus a grant, and the match is
// on the PAIR: the old secret goes, the new one does not arrive. Asserting the
// pair rule explicitly is what keeps a future "match on username" relaxation
// from silently publishing a new secret on an address the operator was moving
// away from.
func TestAuthForRetainedListenerRotationIsNotAGrant_5561(t *testing.T) {
	live := &AuthConfig{Users: map[string]string{"admin": "old"}}
	next := &AuthConfig{Users: map[string]string{"admin": "new"}}
	got := AuthForRetainedListener(live, next)
	if got == nil {
		t.Fatal("got nil — a nil snapshot disables authentication entirely, the opposite of the " +
			"fail-closed outcome a disjoint rotation calls for")
	}
	if pw, ok := got.Users["admin"]; ok {
		t.Fatalf("got admin=%q: the rotation was published to the retained listener. Revoking "+
			"the old secret tightens; granting the new one does not, and the new one was "+
			"committed for the endpoint that failed to bind", pw)
	}
	if CredentialCount(got) != 0 {
		t.Fatalf("got %+v, want an EMPTY (non-nil) set — every non-exempt request is then "+
			"rejected, which is the intended fail-closed state", got)
	}
}

// The result must not alias either operand: the live snapshot is read from a
// running server and `next` is the caller's config, so sharing a map would let a
// later edit rewrite what a listener enforces.
func TestAuthForRetainedListenerDoesNotAlias_5561(t *testing.T) {
	live := &AuthConfig{Users: map[string]string{"admin": "pw"}}
	next := &AuthConfig{Users: map[string]string{"admin": "pw"}}
	got := AuthForRetainedListener(live, next)
	next.Users["sneak"] = "in"
	live.Users["also"] = "in"
	if _, ok := got.Users["sneak"]; ok {
		t.Fatalf("got %+v: the result aliases next.Users, so editing the config after the "+
			"publish changes what the listener accepts", got)
	}
	if _, ok := got.Users["also"]; ok {
		t.Fatalf("got %+v: the result aliases live.Users", got)
	}
}

// A nil `next` is the remove-all-api-auth direction, which reconcileTo handles
// separately behind its loopback gate; the helper must not manufacture a
// credential set for it.
func TestAuthForRetainedListenerNilNext_5561(t *testing.T) {
	if got := AuthForRetainedListener(&AuthConfig{Users: map[string]string{"a": "b"}}, nil); got != nil {
		t.Fatalf("got %+v, want nil", got)
	}
}
