package ddns

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// The round-10 review found doRequest hardening ONE of its two adjacent error
// returns. client.Do's error was scrubbed; readCappedBody's, four lines below,
// was rendered with %w. The structural gate could not see it — readCappedBody
// was not a urlErrorProducer, so no site was built for `rerr` — so the package
// was green over a verbatim render inside the very function the scrubber
// exists to protect.
//
// These are the behavioural half. The structural half (readCappedBody as a
// producer, scrubInnerError as a renderer) lives in
// url_render_class_6545_test.go and is what stops the shape returning.

// bodyErrRoundTripper answers with a real response whose BODY read fails, which
// is the only way to reach readCappedBody's error return. The caller supplies
// the *http.Client throughout this package, so a caller that owns RoundTrip
// owns resp.Body too — the same adversary model rounds 7 and 8 were built for.
type bodyErrRoundTripper struct{ readErr error }

func (rt bodyErrRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(errReader{rt.readErr}),
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

type errReader struct{ err error }

func (r errReader) Read([]byte) (int, error) { return 0, r.err }

// TestBodyReadErrorIsClassifiedNotEchoed pins the credential half: a body-read
// error that echoes the request URL must not reach the returned error, because
// the daemon logs that string verbatim.
func TestBodyReadErrorIsClassifiedNotEchoed(t *testing.T) {
	const secret = "SUPERSECRET"
	hostile := errors.New("upstream read of http://prov.example/update?token=" + secret + " failed")
	client := &http.Client{Transport: bodyErrRoundTripper{readErr: hostile}}

	_, _, err := CheckIP(context.Background(), client, "http://prov.example/ip", true, nil)
	if err == nil {
		t.Fatal("a failing body read reported success")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("body-read error echoed the credential: %v", err)
	}
	if strings.Contains(err.Error(), "prov.example/update") {
		t.Fatalf("body-read error echoed a provider-supplied URL: %v", err)
	}
}

// TestBodyReadErrorIsStableAcrossConnections pins the availability half, which
// is the part with no adversary at all. A mid-body RST yields a *net.OpError
// whose text embeds the EPHEMERAL LOCAL PORT, so it differs on every
// connection. The daemon keys a process-lifetime sync.Map on this string to log
// "once per (provider, error)"; a varying string mints a new key and a new WARN
// every reconcile tick, forever, and the map is never pruned.
//
// Distinct transport-level texts must therefore collapse to the SAME rendered
// error, which is what classification buys and what %w did not.
func TestBodyReadErrorIsStableAcrossConnections(t *testing.T) {
	renders := make(map[string]struct{})
	for _, port := range []string{"50876", "50886", "50894"} {
		rt := bodyErrRoundTripper{readErr: &net_OpErrorStub{
			text: "read tcp 127.0.0.1:" + port + "->127.0.0.1:41397: read: connection reset by peer",
		}}
		_, _, err := CheckIP(context.Background(), &http.Client{Transport: rt},
			"http://prov.example/ip", true, nil)
		if err == nil {
			t.Fatal("a failing body read reported success")
		}
		renders[err.Error()] = struct{}{}
	}
	if len(renders) != 1 {
		keys := make([]string, 0, len(renders))
		for k := range renders {
			keys = append(keys, k)
		}
		t.Fatalf("three connection-varying read errors produced %d distinct rendered "+
			"strings, want 1; the daemon keys a never-pruned sync.Map on this text, so "+
			"each distinct string is a permanent entry and a fresh WARN every tick:\n%s",
			len(renders), strings.Join(keys, "\n"))
	}
}

// net_OpErrorStub stands in for a *net.OpError without depending on the kernel
// producing a real RST. Only its text varies, which is the property under test.
type net_OpErrorStub struct{ text string }

func (e *net_OpErrorStub) Error() string { return e.text }

// TestCyclicURLErrorDoesNotOverflowTheStack pins the mutual recursion between
// scrubURLError and scrubInnerError. maxUnwrapDepth's comment claimed to bound
// "every chain walk in this file"; it bounded findRedirectRefusal and the
// Location-prefix loop but NOT this pair, so a caller-supplied *url.Error whose
// Err points at itself overflowed the stack.
//
// That is a `fatal error`, not a panic: recover() does not catch it and the
// whole xpfd process dies. Unreachable from production — net/http never builds
// a cyclic *url.Error — but the guard is cheap and the claim should be true.
func TestCyclicURLErrorDoesNotOverflowTheStack(t *testing.T) {
	const secret = "SUPERSECRET"
	ue := &url.Error{Op: "Get", URL: "http://prov.example/?p=" + secret}
	ue.Err = ue

	got := scrubURLError(ue)

	if strings.Contains(got, secret) {
		t.Fatalf("cyclic *url.Error leaked the credential: %s", got)
	}
	if !strings.Contains(got, string(transportWithheld)) {
		t.Fatalf("cyclic *url.Error did not terminate at the depth bound; got: %s", got)
	}
}

// TestDeeplyNestedURLErrorDoesNotOverflowTheStack is the non-cyclic sibling:
// a finite but very deep nest reaches the same recursion by a different route,
// so a fix that special-cased self-reference would pass the test above and
// still die here.
func TestDeeplyNestedURLErrorDoesNotOverflowTheStack(t *testing.T) {
	const secret = "SUPERSECRET"
	var err error = errors.New("leaf")
	for i := 0; i < 100_000; i++ {
		err = &url.Error{Op: "Get", URL: "http://prov.example/?p=" + secret, Err: err}
	}

	got := scrubURLError(err)

	if strings.Contains(got, secret) {
		t.Fatalf("deeply nested *url.Error leaked the credential: %s", got)
	}
	if !strings.Contains(got, string(transportWithheld)) {
		t.Fatalf("deeply nested *url.Error did not terminate at the depth bound; got: %s", got)
	}
}
