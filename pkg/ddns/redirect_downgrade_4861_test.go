package ddns

import (
	"net/http"
	"net/url"
	"testing"
)

// mkReq is a small helper building a *http.Request for a scheme+host.
func mkReq(t *testing.T, rawurl string) *http.Request {
	t.Helper()
	u, err := url.Parse(rawurl)
	if err != nil {
		t.Fatalf("parse %q: %v", rawurl, err)
	}
	return &http.Request{URL: u}
}

// TestRefuseSchemeDowngrade pins #4861: the shared HTTP DDNS client must refuse
// an HTTPS->HTTP redirect downgrade so a 30x Location cannot walk a credentialed
// update onto a plaintext connection. Same-scheme redirects and an HTTP->HTTPS
// upgrade are still followed, and the 10-redirect cap is preserved.
//
// RED on revert: dropping CheckRedirect (or its downgrade branch) makes the
// https->http subtest return nil, so the client would follow the downgrade and
// transmit credentials in cleartext.
func TestRefuseSchemeDowngrade(t *testing.T) {
	cases := []struct {
		name    string
		prev    string // previous hop
		next    string // redirect target
		wantErr bool
	}{
		{"https->http downgrade refused", "https://prov.example/upd", "http://prov.example/upd", true},
		{"https->http other host refused", "https://prov.example/upd", "http://evil.example/upd", true},
		{"https->https allowed", "https://prov.example/upd", "https://prov.example/v2", false},
		{"http->https upgrade allowed", "http://prov.example/upd", "https://prov.example/upd", false},
		{"http->http allowed", "http://prov.example/upd", "http://prov.example/v2", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			via := []*http.Request{mkReq(t, tc.prev)}
			err := guardRedirect(mkReq(t, tc.next), via)
			if tc.wantErr && err == nil {
				t.Fatalf("expected the redirect to be refused, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected the redirect to be allowed, got: %v", err)
			}
		})
	}

	// The 10-redirect cap is preserved even when every hop is same-scheme.
	via := make([]*http.Request, 10)
	for i := range via {
		via[i] = mkReq(t, "https://prov.example/upd")
	}
	if err := guardRedirect(mkReq(t, "https://prov.example/upd"), via); err == nil {
		t.Fatalf("expected the 10-redirect cap to fire, got nil")
	}
}

// TestHTTPClientWiresCheckRedirect asserts every shared HTTP DDNS client carries
// the downgrade-refusing CheckRedirect (the wiring, RED on revert).
func TestHTTPClientWiresCheckRedirect(t *testing.T) {
	cl := newHTTPClient()
	if cl.CheckRedirect == nil {
		t.Fatal("newHTTPClient() has no CheckRedirect; HTTPS->HTTP downgrade is not blocked")
	}
	via := []*http.Request{mkReq(t, "https://prov.example/upd")}
	if err := cl.CheckRedirect(mkReq(t, "http://prov.example/upd"), via); err == nil {
		t.Fatal("client CheckRedirect followed an HTTPS->HTTP downgrade; want refused")
	}
}
