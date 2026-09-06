package api

import (
	"io"
	"net/http"
	"regexp"
	"sort"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #9134: HEAD WAS A COMPLETE AUTHORIZATION BYPASS ON EVERY GUARDED READ ROUTE.
//
// isSafeHTTPMethod admits HEAD, readAuthz keyed its lookup on
// `r.Method + " " + path`, and restReadPermissions holds 40 `"GET "` keys and
// ZERO `"HEAD "` keys. An unknown key is the deliberate fail-OPEN arm — so that
// /health and /metrics keep serving — so every HEAD landed there and went
// straight to the mux, which routes HEAD to the GET pattern DIRECTLY with no
// redirect. No authorization decision ran at all.
//
// A HEAD response carries no body, which is why this reads as harmless and is
// not: Content-Length is the body's EXACT size, and the status code separates
// "exists and you may not see it" from "exists". Both are read access to
// information the same caller was refused on GET, by the same server, in the
// same second.

func req9134(t *testing.T, method, base, path string) (int, string) {
	t.Helper()
	r, err := http.NewRequest(method, base+path, nil)
	if err != nil {
		t.Fatalf("NewRequest %s %s: %v", method, path, err)
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(r)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// TestHeadIsAuthorizedLikeGet9134 is the defect itself, asserted as an
// AGREEMENT between the two methods rather than as a status code for HEAD
// alone — "HEAD is 403" would also be satisfied by a server that refused
// everything.
func TestHeadIsAuthorizedLikeGet9134(t *testing.T) {
	usePasswdFixture(t)
	store := authzStore(t, authzTestConfig)
	_, base := authzServer(t, Config{
		Addr:         "127.0.0.1:8080",
		Store:        store,
		PeerLookupFn: unattributableLocalPeer(),
	})

	for _, path := range []string{
		"/api/v1/config",
		"/api/v1/config/show",
		"/api/v1/show-text",
		"/api/v1/interfaces",
		"/api/v1/security/zones",
		"/api/v1/security/policies",
		"/api/v1/routes",
	} {
		t.Run(path, func(t *testing.T) {
			getCode, body := req9134(t, http.MethodGet, base, path)
			// POSITIVE CONTROL: the GET must actually be refused, or the HEAD
			// assertion below is comparing two permitted requests and proves
			// nothing.
			if getCode != http.StatusForbidden {
				t.Fatalf("control failed: GET %s returned %d, want 403 — this caller is "+
					"supposed to be refused: %s", path, getCode, body)
			}
			headCode, _ := req9134(t, http.MethodHead, base, path)
			if headCode != getCode {
				t.Errorf("HEAD %s returned %d while GET returned %d — the same caller is "+
					"refused on GET and served on HEAD, so the handler ran with NO "+
					"authorization decision (#9134)", path, headCode, getCode)
			}
		})
	}
}

// TestEveryGuardedReadRouteResolvesForEverySafeMethod9134 is the completeness
// gate, and it is keyed on the MECHANISM rather than on HEAD.
//
// Adding 40 `"HEAD "` keys to the table would have fixed the reported symptom
// and left the shape that produced it: a table needing two entries per route
// forever, and a hole reopening for the next safe method the mux learns to
// alias. Resolving the alias in readPermissionFor is what this asserts, across
// every safe method, for every route the mux registers.
func TestEveryGuardedReadRouteResolvesForEverySafeMethod9134(t *testing.T) {
	src := readServerSourceForTest(t)
	re := regexp.MustCompile(`mux\.HandleFunc\("GET (/api/v1/[^"]*)"`)
	matches := re.FindAllStringSubmatch(src, -1)
	if len(matches) == 0 {
		t.Fatal("the route scan matched NOTHING — the regex or the registration shape " +
			"changed, and a completeness gate that matches nothing passes vacuously")
	}
	var missing []string
	for _, m := range matches {
		path := m[1]
		for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace} {
			if !isSafeHTTPMethod(method) {
				t.Fatalf("fixture: %s is not classified safe, so this row is not testing "+
					"what it claims", method)
			}
			if _, ok := readPermissionFor(method, path); !ok {
				missing = append(missing, method+" "+path)
			}
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("%d (safe method, guarded route) pair(s) resolve to NO permission and so "+
			"serve unauthorized: %v", len(missing), missing)
	}
}

// TestUnguardedSafeRoutesStillServe9134 is the bound. readAuthz serves an
// unguarded safe route rather than refusing it so /health and /metrics keep
// working, and a fix that closed the world here would break them at the first
// request — the in-tree incus harnesses read /metrics.
func TestUnguardedSafeRoutesStillServe9134(t *testing.T) {
	for _, path := range []string{"/health", "/metrics"} {
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			if _, known := readPermissionFor(method, path); known {
				t.Errorf("%s %s now resolves to a permission; it must stay unguarded or the "+
					"health check and the metrics scrape break", method, path)
			}
		}
	}
}

// TestMutatingRoutesAreNotAliased9134 pins the other side: a safe method must
// not pick up a MUTATION route's permission, which would be the same aliasing
// bug pointed the other way.
func TestMutatingRoutesAreNotAliased9134(t *testing.T) {
	for route := range restMutationPermissions {
		i := len(route)
		for j, c := range route {
			if c == ' ' {
				i = j
				break
			}
		}
		path := route[i+1:]
		if _, known := readPermissionFor(http.MethodHead, path); known {
			// Only a problem if the path is NOT also a legitimate read route.
			if _, alsoRead := restReadPermissions[http.MethodGet+" "+path]; !alsoRead {
				t.Errorf("HEAD %s resolves to a read permission but %q is a MUTATION route "+
					"with no GET entry", path, route)
			}
		}
	}
	_ = config.PermView
}
