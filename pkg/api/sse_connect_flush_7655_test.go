package api

import (
	"bufio"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/logging"
)

// sse_connect_flush_7655_test.go — #7655.
//
// `net/http` sends no response headers until the first Write or Flush.
// `setSSEHeaders` only set header VALUES, so a client connecting to a QUIET SSE
// feed blocked waiting for headers that were never sent — a browser
// `EventSource` on an idle firewall hung rather than establishing the stream.
//
// Not cosmetic: until the first event arrives, which on a quiet box could be
// hours, an SSE consumer cannot distinguish "connected and quiet" from "not
// connected", and every reconnect/backoff decision rests on that distinction.
//
// THE EVIDENCE THIS WAS REAL is the #7632 slow-reader harness, which had to
// publish its establishing event from a goroutine because the GET could not
// return until one landed. A test harness that must generate traffic to observe
// a connection is describing this defect.
//
// So the assertion here is the one that harness could not make: THE HEADERS
// ARRIVE BEFORE ANY EVENT IS PUBLISHED. It runs against a real
// httptest.Server — an httptest.ResponseRecorder cannot express the defect at
// all, because it records header values without modelling when they reach the
// wire, and would pass either way.

func TestSSEHeadersArriveBeforeAnyEvent7655(t *testing.T) {
	buf := logging.NewEventBuffer(100)
	s := &Server{eventBuf: buf}

	ts := httptest.NewServer(http.HandlerFunc(s.eventStreamHandler))
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", ts.URL, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	// NOTHING is published. The response must still arrive.
	type result struct {
		resp *http.Response
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		resp, err := http.DefaultClient.Do(req)
		ch <- result{resp, err}
	}()

	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("the GET failed: %v", r.err)
		}
		defer r.resp.Body.Close()
		if ct := r.resp.Header.Get("Content-Type"); ct != "text/event-stream" {
			t.Errorf("Content-Type = %q, want text/event-stream", ct)
		}
		if cc := r.resp.Header.Get("Cache-Control"); cc != "no-cache" {
			t.Errorf("Cache-Control = %q, want no-cache", cc)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the response headers never arrived on a feed with NO events. net/http " +
			"sends nothing until the first Write or Flush, so a client cannot tell " +
			"'connected and quiet' from 'not connected' — which on a quiet box could " +
			"last hours (#7655)")
	}
}

// The same for the log stream handler, which had the identical shape. A fix at
// one call site would leave the other hanging, which is why the flush lives in
// setSSEHeaders rather than beside each call.
func TestLogStreamHeadersArriveBeforeAnyEvent7655(t *testing.T) {
	buf := logging.NewEventBuffer(100)
	s := &Server{eventBuf: buf}

	ts := httptest.NewServer(http.HandlerFunc(s.logStreamHandler))
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", ts.URL, nil)

	ch := make(chan *http.Response, 1)
	errCh := make(chan error, 1)
	go func() {
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			errCh <- err
			return
		}
		ch <- resp
	}()

	select {
	case resp := <-ch:
		defer resp.Body.Close()
		if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
			t.Errorf("Content-Type = %q, want text/event-stream", ct)
		}
	case err := <-errCh:
		t.Fatalf("the GET failed: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("the log-stream response headers never arrived on a quiet feed (#7655)")
	}
}

// AND THE STREAM STILL WORKS. Flushing at connect must not disturb event
// delivery — without this cell, a "fix" that flushed and then broke the body
// would satisfy both cells above.
func TestSSEStillDeliversEventsAfterTheConnectFlush7655(t *testing.T) {
	buf := logging.NewEventBuffer(100)
	s := &Server{eventBuf: buf}

	ts := httptest.NewServer(http.HandlerFunc(s.eventStreamHandler))
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", ts.URL, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	// Publish only AFTER the headers are in hand, which is the ordering the
	// defect made impossible.
	go func() {
		time.Sleep(50 * time.Millisecond)
		buf.Add(logging.EventRecord{Time: time.Now(), Type: "SESSION_OPEN", SrcAddr: "10.0.0.7:7655", Reason: "zzmarker7655"})
	}()

	sc := bufio.NewScanner(resp.Body)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if !sc.Scan() {
			break
		}
		if strings.Contains(sc.Text(), "zzmarker7655") {
			return // delivered
		}
	}
	t.Error("the event never arrived: flushing the headers at connect must not disturb " +
		"delivery (#7655)")
}
