package rpm

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// probe9049 runs the http-get arm against a live test server.
func probe9049(t *testing.T, target string) (time.Duration, error) {
	t.Helper()
	m := &Manager{}
	return m.probeHTTP(context.Background(),
		&config.RPMTest{Target: target}, probeSockOpts{})
}

// #9049: the io.Copy draining the response body discarded its error, so a body
// read that hit http.Client.Timeout returned err == nil and the caller scored
// the probe a SUCCESS. A timed-out response was indistinguishable, in the
// probe's own verdict, from a fast complete one.
func TestTruncatedBodyIsAFailureNotASuccess9049(t *testing.T) {
	// A server that promises 1024 bytes and delivers 5, then closes. io.Copy
	// gets an unexpected EOF.
	//
	// The PRODUCTION trigger is the 10s http.Client.Timeout firing mid-body,
	// but a fixture that waits for it costs ten seconds per run and, written
	// with a blocking handler, DEADLOCKS: httptest's Close waits for the
	// handler, and a defer that releases the handler is registered earlier so
	// it runs later. A truncated body exercises the identical code path -- the
	// io.Copy error that used to be discarded -- deterministically and in
	// milliseconds.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "1024")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("short"))
	}))
	defer srv.Close()

	// REFERENCE ARM: a healthy server must still succeed. Without it, a fix
	// that failed every probe would satisfy the assertion below.
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer good.Close()
	if _, err := probe9049(t, good.URL); err != nil {
		t.Fatalf("a healthy http-get must succeed: %v", err)
	}

	_, err := probe9049(t, srv.URL)
	if err == nil {
		t.Error("a probe whose body read FAILED was scored a SUCCESS. The drain " +
			"error is the only signal that the response never completed, and the " +
			"probe reports the path healthy exactly when it is not")
	} else if !strings.Contains(err.Error(), "body read failed") {
		t.Logf("note: failed with %v (any error is acceptable; the message names the cause)", err)
	}
}

// #9049: RTT is time to RESPONSE, not time to drain. A fast server with a slow
// body reported its transfer time as its round-trip time, and that figure is
// folded into MinRTT/MaxRTT/AvgRTT and the jitter an operator reads.
func TestRTTMeasuresTheHeaderNotTheBody9049(t *testing.T) {
	const bodyDelay = 400 * time.Millisecond
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		time.Sleep(bodyDelay)
		_, _ = w.Write([]byte("late"))
	}))
	defer srv.Close()

	rtt, err := probe9049(t, srv.URL)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if rtt >= bodyDelay {
		t.Errorf("RTT = %v, which includes the %v body delay. The headers were "+
			"available immediately; billing transfer time to round-trip time is "+
			"what turned 704us of responsiveness into 2.0s in the measured case",
			rtt, bodyDelay)
	}
}

// NARROWNESS: a large but HEALTHY body must still succeed. The LimitReader
// stops it dominating the probe window; reaching the limit is not a failure,
// because the server answered — which is what the probe asked. Scoring a big
// body as a failed probe would mark a healthy path down for a property the
// probe does not measure.
func TestLargeBodyStillSucceeds9049(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		chunk := make([]byte, 64<<10)
		for i := 0; i < 40; i++ { // 2.5 MiB, past the 1 MiB drain limit
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	if _, err := probe9049(t, srv.URL); err != nil {
		t.Errorf("a large but healthy response was scored a failure: %v", err)
	}
}

// An HTTP error status still reports the status, not the drain — the two are
// different verdicts and the status is the more specific one.
func TestStatusErrorTakesPrecedence9049(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	_, err := probe9049(t, srv.URL)
	if err == nil || !strings.Contains(err.Error(), "503") {
		t.Errorf("a 503 must be reported as HTTP 503, got %v", err)
	}
}

var _ = net.JoinHostPort
