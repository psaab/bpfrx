package api

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/psaab/bpfrx/pkg/logging"
)

func TestSetSSEHeaders(t *testing.T) {
	w := httptest.NewRecorder()
	setSSEHeaders(w)

	if ct := w.Header().Get("Content-Type"); ct != "text/event-stream" {
		t.Errorf("Content-Type = %q, want text/event-stream", ct)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "no-cache" {
		t.Errorf("Cache-Control = %q, want no-cache", cc)
	}
	if cn := w.Header().Get("Connection"); cn != "keep-alive" {
		t.Errorf("Connection = %q, want keep-alive", cn)
	}
}

func TestWriteSSEEvent(t *testing.T) {
	w := httptest.NewRecorder()
	writeSSEEvent(w, "42", "test_event", `{"key":"value"}`)

	body := w.Body.String()
	if !strings.Contains(body, "id: 42\n") {
		t.Errorf("missing id line in %q", body)
	}
	if !strings.Contains(body, "event: test_event\n") {
		t.Errorf("missing event line in %q", body)
	}
	if !strings.Contains(body, "data: {\"key\":\"value\"}\n") {
		t.Errorf("missing data line in %q", body)
	}
	if !strings.HasSuffix(body, "\n\n") {
		t.Errorf("SSE event should end with double newline")
	}
}

func TestWriteSSEEventNoEventType(t *testing.T) {
	w := httptest.NewRecorder()
	writeSSEEvent(w, "1", "", "hello")

	body := w.Body.String()
	if strings.Contains(body, "event:") {
		t.Errorf("should not have event line when empty, got %q", body)
	}
	if !strings.Contains(body, "id: 1\n") {
		t.Errorf("missing id line")
	}
	if !strings.Contains(body, "data: hello\n") {
		t.Errorf("missing data line")
	}
}

func TestEventStreamHandler(t *testing.T) {
	buf := logging.NewEventBuffer(100)
	s := &Server{eventBuf: buf}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	req := httptest.NewRequest("GET", "/api/v1/events/stream", nil)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	// Run handler in background
	done := make(chan struct{})
	go func() {
		s.eventStreamHandler(w, req)
		close(done)
	}()

	// Wait for subscription to be set up
	time.Sleep(50 * time.Millisecond)

	// Add events
	buf.Add(logging.EventRecord{
		Time:     time.Now(),
		Type:     "SESSION_OPEN",
		SrcAddr:  "10.0.1.5:12345",
		DstAddr:  "10.0.2.100:80",
		Protocol: "TCP",
		Action:   "permit",
		PolicyID: 1,
		InZone:   1,
		OutZone:  2,
	})

	time.Sleep(50 * time.Millisecond)

	// Cancel and wait for handler to exit
	cancel()
	<-done

	body := w.Body.String()
	if !strings.Contains(body, "event: SESSION_OPEN") {
		t.Errorf("expected SESSION_OPEN event in response, got %q", body)
	}
	if !strings.Contains(body, "10.0.1.5:12345") {
		t.Errorf("expected source addr in event data, got %q", body)
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/event-stream" {
		t.Errorf("Content-Type = %q, want text/event-stream", ct)
	}
}

func TestEventStreamCategoryFilter(t *testing.T) {
	buf := logging.NewEventBuffer(100)
	s := &Server{eventBuf: buf}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	req := httptest.NewRequest("GET", "/api/v1/events/stream?category=policy", nil)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		s.eventStreamHandler(w, req)
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)

	// Add session event (should be filtered out)
	buf.Add(logging.EventRecord{
		Time: time.Now(), Type: "SESSION_OPEN", Action: "permit",
	})
	// Add policy deny event (should pass)
	buf.Add(logging.EventRecord{
		Time: time.Now(), Type: "POLICY_DENY", Action: "deny",
		SrcAddr: "1.2.3.4:100", DstAddr: "5.6.7.8:80", Protocol: "TCP",
	})

	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done

	body := w.Body.String()
	if strings.Contains(body, "SESSION_OPEN") {
		t.Errorf("SESSION_OPEN should be filtered out, got %q", body)
	}
	if !strings.Contains(body, "POLICY_DENY") {
		t.Errorf("POLICY_DENY should pass filter, got %q", body)
	}
}

func TestLogStreamHandler(t *testing.T) {
	buf := logging.NewEventBuffer(100)
	s := &Server{eventBuf: buf}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	req := httptest.NewRequest("GET", "/api/v1/logs/stream", nil)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		s.logStreamHandler(w, req)
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)

	buf.Add(logging.EventRecord{
		Time: time.Now(), Type: "POLICY_DENY", Action: "deny",
		SrcAddr: "10.0.1.5:999", DstAddr: "10.0.2.1:22", Protocol: "TCP",
		PolicyID: 5, InZone: 1, OutZone: 2,
	})

	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done

	body := w.Body.String()
	if !strings.Contains(body, "event: log") {
		t.Errorf("expected 'event: log' in response, got %q", body)
	}
	if !strings.Contains(body, "RT_FLOW") {
		t.Errorf("expected RT_FLOW message in response, got %q", body)
	}

	// Parse the SSE data line
	scanner := bufio.NewScanner(strings.NewReader(body))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "data: ") {
			var entry LogStreamEntry
			if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &entry); err != nil {
				t.Fatalf("unmarshal log entry: %v", err)
			}
			if entry.Severity != "warning" {
				t.Errorf("severity = %q, want warning", entry.Severity)
			}
			if !strings.Contains(entry.Message, "POLICY_DENY") {
				t.Errorf("message missing POLICY_DENY: %q", entry.Message)
			}
			break
		}
	}
}

func TestLogStreamSeverityFilter(t *testing.T) {
	buf := logging.NewEventBuffer(100)
	s := &Server{eventBuf: buf}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Only error severity
	req := httptest.NewRequest("GET", "/api/v1/logs/stream?severity=error", nil)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		s.logStreamHandler(w, req)
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)

	// Info event (should be filtered)
	buf.Add(logging.EventRecord{
		Time: time.Now(), Type: "SESSION_OPEN", Action: "permit",
	})
	// Error event (should pass)
	buf.Add(logging.EventRecord{
		Time: time.Now(), Type: "SCREEN_DROP", Action: "deny",
		SrcAddr: "1.2.3.4:1", DstAddr: "5.6.7.8:2", Protocol: "TCP",
		ScreenCheck: "syn-flood",
	})

	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done

	body := w.Body.String()
	if strings.Contains(body, "SESSION_OPEN") {
		t.Errorf("SESSION_OPEN (info) should be filtered with severity=error, got %q", body)
	}
	if !strings.Contains(body, "SCREEN_DROP") {
		t.Errorf("SCREEN_DROP (error) should pass severity=error filter, got %q", body)
	}
}

func TestEventStreamNoBuffer(t *testing.T) {
	s := &Server{eventBuf: nil}
	req := httptest.NewRequest("GET", "/api/v1/events/stream", nil)
	w := httptest.NewRecorder()
	s.eventStreamHandler(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d", w.Code, http.StatusServiceUnavailable)
	}
}

func TestParseCategories(t *testing.T) {
	tests := []struct {
		input string
		want  uint8
	}{
		{"", 0},
		{"session", logging.CategorySession},
		{"policy", logging.CategoryPolicy},
		{"screen", logging.CategoryScreen},
		{"firewall", logging.CategoryFirewall},
		{"session,policy", logging.CategorySession | logging.CategoryPolicy},
		{" session , screen ", logging.CategorySession | logging.CategoryScreen},
	}

	for _, tt := range tests {
		got := parseCategories(tt.input)
		if got != tt.want {
			t.Errorf("parseCategories(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

func TestMatchCategory(t *testing.T) {
	tests := []struct {
		eventType string
		mask      uint8
		want      bool
	}{
		{"SESSION_OPEN", logging.CategorySession, true},
		{"SESSION_CLOSE", logging.CategorySession, true},
		{"SESSION_OPEN", logging.CategoryPolicy, false},
		{"POLICY_DENY", logging.CategoryPolicy, true},
		{"SCREEN_DROP", logging.CategoryScreen, true},
		{"FILTER_LOG", logging.CategoryFirewall, true},
		{"UNKNOWN_TYPE", logging.CategorySession, true}, // unknown passes
	}

	for _, tt := range tests {
		got := matchCategory(tt.eventType, tt.mask)
		if got != tt.want {
			t.Errorf("matchCategory(%q, %d) = %v, want %v", tt.eventType, tt.mask, got, tt.want)
		}
	}
}

func TestEventBufferSubscription(t *testing.T) {
	buf := logging.NewEventBuffer(10)
	sub := buf.Subscribe(16)
	defer sub.Close()

	rec := logging.EventRecord{
		Time: time.Now(), Type: "SESSION_OPEN", Action: "permit",
	}
	buf.Add(rec)

	select {
	case got := <-sub.C:
		if got.Type != "SESSION_OPEN" {
			t.Errorf("type = %q, want SESSION_OPEN", got.Type)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for subscription event")
	}

	// Unsubscribe and verify no more events
	sub.Close()
	buf.Add(rec)
	select {
	case <-sub.C:
		// drain any buffered
	case <-time.After(50 * time.Millisecond):
	}
}
