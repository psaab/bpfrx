package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/logging"
)

// setSSEHeaders configures the response for Server-Sent Events streaming.
func setSSEHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
}

// --- #7632: bounding a SLOW SSE READER -------------------------------------
//
// An SSE stream writes straight to the ResponseWriter and flushes, and
// http.Server runs with WriteTimeout deliberately 0 process-wide so these
// long-lived streams are not severed. So a subscriber that stays CONNECTED and
// stops reading fills the socket buffers and parks this handler goroutine in
// Write indefinitely, holding a subscriber slot with it — the same mechanism
// #6809 bounded on the BGP route stream.
//
// A per-handler CONTEXT deadline does not help: it bounds a handler's work, not
// a write already blocked in the kernel. Only a socket write deadline ends
// that. See the corrected note in server.go's timeout block.
//
// WHY A PER-WRITE DEADLINE AND *NOT* AN ELAPSED BUDGET. An SSE stream is
// SUPPOSED to sit idle with no data for long stretches — that is the normal
// operating state of an event feed on a quiet firewall, not a symptom. An
// elapsed budget would sever exactly the healthy case. A per-write deadline
// bounds a write that has BEGUN and says nothing about the gap between events,
// so idling is untouched and only a peer that has stopped draining is cut.
// This is the axis on which SSE genuinely differs from the RIB dump, where a
// total budget was a sensible backstop.
//
// THE ERROR RETURN IS PRECAUTIONARY, NOT BOUND — labelled as such because I
// first claimed the opposite and measured it.
//
// The claim was that adding the deadline without propagating the error would be
// WORSE than the pin: the write failing on every later event while the loop
// kept draining the subscription and discarding. Measured, it is not. With the
// deadline armed and the error deliberately discarded, the handler still
// returns in 254.6ms against a 250ms deadline — indistinguishable from 254.9ms
// with the check — because net/http cancels the request context as soon as a
// write to the connection fails, so the loop exits through its ctx.Done() arm
// regardless.
//
// So the deadline is what fixes the pin, and the error return currently changes
// nothing observable. It is kept for one reason that survives the measurement:
// that exit depends on net/http cancelling the context on a write error, which
// is behaviour rather than contract. A wrapping ResponseWriter, or a different
// server, that does not do it would leave this loop draining the subscription
// into a dead connection. Checking the error makes the exit local and explicit
// instead of inherited.
//
// Stated this way deliberately: a guard described as load-bearing when it is
// defence in depth is the kind of claim that survives into someone else's
// reasoning. The mutation matrix agrees — removing the error check leaves the
// suite green, and that is recorded rather than papered over.

// sseWriteDeadline bounds a SINGLE downstream SSE write. A subscriber that
// cannot accept one small event within this window is not reading. Generous by
// design: an SSE event is a few hundred bytes and fits in any socket buffer
// instantly unless the peer has stopped draining. A package var so a test can
// compress it without a real slow reader.
//
// Deliberately NOT shared with bgpStreamWriteDeadline (routing.go): the two
// endpoints have different traffic shapes and a shared knob would couple a
// change to one into the other.
var sseWriteDeadline = 30 * time.Second

// sseStream is one SSE response: a deadline-arming writer over the
// ResponseWriter plus its flusher. It single-sources the deadline, the flush
// and the error return for both stream handlers, so neither can drift into
// discarding a write failure again.
type sseStream struct {
	w io.Writer
	f http.Flusher
}

// newSSEStream wraps w so every SSE write arms a fresh write deadline first.
// It reuses deadlineArmingWriter (routing.go, #6809): arming at the WRITE
// rather than at a call site makes the coverage structural, which is what
// #6809's own first attempt got wrong.
func newSSEStream(w http.ResponseWriter, d time.Duration) *sseStream {
	st := &sseStream{w: &deadlineArmingWriter{
		w:  w,
		rc: http.NewResponseController(w),
		d:  d,
	}}
	if f, ok := w.(http.Flusher); ok {
		st.f = f
	}
	return st
}

// writeEvent writes a single SSE event and RETURNS the first write error.
// A non-nil return is terminal for the stream: the peer is not reading, and
// continuing would drain the subscription into a connection that cannot take
// it.
func (s *sseStream) writeEvent(id, event, data string) error {
	if _, err := fmt.Fprintf(s.w, "id: %s\n", id); err != nil {
		return err
	}
	if event != "" {
		if _, err := fmt.Fprintf(s.w, "event: %s\n", event); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(s.w, "data: %s\n\n", data); err != nil {
		return err
	}
	if s.f != nil {
		s.f.Flush()
	}
	return nil
}

// writeSSEEvent writes a single SSE event to the response.
//
// #7632: retained as the unbounded form for callers that are NOT a long-lived
// stream — it has no write deadline and discards errors, which is only safe
// where the response ends immediately afterwards. A streaming handler must use
// sseStream.
func writeSSEEvent(w http.ResponseWriter, id string, event string, data string) {
	fmt.Fprintf(w, "id: %s\n", id)
	if event != "" {
		fmt.Fprintf(w, "event: %s\n", event)
	}
	fmt.Fprintf(w, "data: %s\n\n", data)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}

// eventStreamHandler streams firewall events via SSE.
// Supports ?category= filter (comma-separated: session,policy,screen,firewall).
func (s *Server) eventStreamHandler(w http.ResponseWriter, r *http.Request) {
	if s.eventBuf == nil {
		writeError(w, http.StatusServiceUnavailable, "event buffer not available")
		return
	}

	// Parse category filter. Reject a typo before switching to SSE so a
	// misspelled query does not silently stream everything (#3383).
	categoryFilter, err := parseCategories(r.URL.Query().Get("category"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Bound concurrent SSE subscribers before switching to event-stream
	// (#4484 L-2): a nil return means the cap is reached — respond 503 while
	// we can still send a normal error (after setSSEHeaders we no longer can).
	sub := s.eventBuf.TrySubscribe(128)
	if sub == nil {
		writeError(w, http.StatusServiceUnavailable, "too many concurrent event subscribers")
		return
	}
	defer sub.Close()

	setSSEHeaders(w)

	// #7632: bound a subscriber that stays connected and stops reading.
	stream := newSSEStream(w, sseWriteDeadline)
	var seq uint64
	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case rec := <-sub.C:
			if categoryFilter != 0 && !matchCategory(rec.Type, categoryFilter) {
				continue
			}
			seq++
			data, err := json.Marshal(eventEntryFromRecord(rec))
			if err != nil {
				continue
			}
			// #7632: a write failure is TERMINAL. Continuing would drain the
			// subscription into a connection that cannot take it, holding a
			// subscriber slot while silently discarding the feed.
			if err := stream.writeEvent(fmt.Sprintf("%d", seq), rec.Type, string(data)); err != nil {
				return
			}
		}
	}
}

// logStreamHandler streams firewall events formatted as log messages via SSE.
// Supports ?severity= and ?category= filters.
func (s *Server) logStreamHandler(w http.ResponseWriter, r *http.Request) {
	if s.eventBuf == nil {
		writeError(w, http.StatusServiceUnavailable, "event buffer not available")
		return
	}

	// Reject a typo'd severity/category before switching to SSE (#3383):
	// a misspelled filter must not silently widen the live feed to all
	// events. Distinguish absent ("" -> 0, no filter) from unrecognized.
	severityFilter, err := logging.ParseSeverityStrict(r.URL.Query().Get("severity"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	categoryFilter, err := parseCategories(r.URL.Query().Get("category"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Bound concurrent SSE subscribers before switching to event-stream
	// (#4484 L-2); see eventStreamHandler for the rationale.
	sub := s.eventBuf.TrySubscribe(128)
	if sub == nil {
		writeError(w, http.StatusServiceUnavailable, "too many concurrent event subscribers")
		return
	}
	defer sub.Close()

	setSSEHeaders(w)

	// #7632: same bound as the event stream.
	stream := newSSEStream(w, sseWriteDeadline)
	var seq uint64
	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case rec := <-sub.C:
			severity := eventRecordSeverity(rec)
			if severityFilter != 0 && severity > severityFilter {
				continue
			}
			if categoryFilter != 0 && !matchCategory(rec.Type, categoryFilter) {
				continue
			}
			seq++
			logEntry := LogStreamEntry{
				Time:     rec.Time.Format(time.RFC3339),
				Severity: severityName(severity),
				Message:  formatLogMessage(rec),
			}
			data, err := json.Marshal(logEntry)
			if err != nil {
				continue
			}
			// #7632: terminal on a write failure — see eventStreamHandler.
			if err := stream.writeEvent(fmt.Sprintf("%d", seq), "log", string(data)); err != nil {
				return
			}
		}
	}
}

// LogStreamEntry is a log message sent via SSE.
type LogStreamEntry struct {
	Time     string `json:"time"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

// eventEntryFromRecord maps a logging.EventRecord to the REST/SSE EventEntry.
// It is the single SSOT for both the GET /security/events response and the SSE
// event stream, so the two surfaces never drift (#3337). The timestamp uses
// RFC3339Nano so high-rate RT_FLOW events keep sub-second ordering for
// cross-system correlation (the CLI keeps human-friendly seconds).
func eventEntryFromRecord(rec logging.EventRecord) EventEntry {
	return EventEntry{
		Time:            rec.Time.Format(time.RFC3339Nano),
		Type:            rec.Type,
		SrcAddr:         rec.SrcAddr,
		DstAddr:         rec.DstAddr,
		Protocol:        rec.Protocol,
		Action:          rec.Action,
		PolicyID:        rec.PolicyID,
		InZone:          rec.InZone,
		OutZone:         rec.OutZone,
		InZoneName:      rec.InZoneName,
		OutZoneName:     rec.OutZoneName,
		ScreenCheck:     rec.ScreenCheck,
		SessionPkts:     rec.SessionPkts,
		SessionBytes:    rec.SessionBytes,
		RevSessionPkts:  rec.RevSessionPkts,
		RevSessionBytes: rec.RevSessionBytes,
		PolicyName:      rec.PolicyName,
		AppName:         rec.AppName,
		IngressIface:    rec.IngressIface,
		CloseReason:     rec.CloseReason,
		Reason:          rec.Reason,
		NATSrcAddr:      rec.NATSrcAddr,
		NATDstAddr:      rec.NATDstAddr,
		SessionID:       rec.SessionID,
		ElapsedTime:     rec.ElapsedTime,
		Created:         rec.Created,
		CreatedNanos:    rec.CreatedNanos,
		EgressIfindex:   rec.EgressIfindex,
		IngressIfindex:  rec.IngressIfindex,
		TOS:             rec.TOS,
		TCPControlBits:  rec.TCPControlBits,
	}
}

// parseCategories parses a comma-separated category string into a bitmask.
// It is fail-closed (#3383): an unrecognized OR empty token returns an error
// rather than silently collapsing to 0 ("no filter"), which would widen the
// live SSE feed to everything on a typo or a malformed list (a leading,
// trailing, or doubled comma). A fully-ABSENT category param ("") still means
// match-all and yields a 0 mask with no error; only the named "all" token is
// the explicit no-filter request within a present list.
func parseCategories(s string) (uint8, error) {
	if s == "" {
		return 0, nil
	}
	var mask uint8
	for _, c := range strings.Split(s, ",") {
		tok := strings.TrimSpace(c)
		if tok == "" {
			return 0, fmt.Errorf("empty category token in %q (no leading/trailing/double comma)", s)
		}
		bit, err := logging.ParseCategoryStrict(tok)
		if err != nil {
			return 0, err
		}
		mask |= bit
	}
	return mask, nil
}

// matchCategory checks if an event type matches a category bitmask.
func matchCategory(eventType string, mask uint8) bool {
	var bit uint8
	switch eventType {
	case "SESSION_OPEN", "SESSION_CLOSE":
		bit = logging.CategorySession
	case "POLICY_DENY":
		bit = logging.CategoryPolicy
	case "SCREEN_DROP":
		bit = logging.CategoryScreen
	case "FILTER_LOG":
		bit = logging.CategoryFirewall
	default:
		// Fail-closed (#3383): a future/unknown event type does not belong
		// to any requested category, so a narrow category mask must not
		// deliver it. (A zero mask = "no filter" is handled by the caller,
		// which only calls matchCategory when mask != 0.)
		return false
	}
	return mask&bit != 0
}

// eventRecordSeverity maps an event record to a syslog severity, classifying
// by BOTH type and action (#3383). This mirrors logging.eventSeverity: a
// SCREEN_DROP with action=permit is the #2234 scan-table-pressure alarm — the
// packet still forwards, so it is informational (SyslogNotice), not an error.
// Only a screen event that actually dropped (deny/reject) is SyslogError.
// Classifying every SCREEN_DROP as error emitted false error-severity alerts
// and let permitted packets pass a severity=error filter.
func eventRecordSeverity(rec logging.EventRecord) int {
	switch rec.Type {
	case "SCREEN_DROP":
		if strings.EqualFold(rec.Action, "permit") {
			return logging.SyslogNotice
		}
		return logging.SyslogError
	case "POLICY_DENY":
		return logging.SyslogWarning
	default:
		return logging.SyslogInfo
	}
}

func severityName(s int) string {
	switch s {
	case logging.SyslogError:
		return "error"
	case logging.SyslogWarning:
		return "warning"
	case logging.SyslogNotice:
		return "notice"
	default:
		return "info"
	}
}

func formatLogMessage(rec logging.EventRecord) string {
	if rec.Type == "SCREEN_DROP" {
		return fmt.Sprintf("RT_FLOW %s screen=%s src=%s dst=%s proto=%s action=%s zone=%d",
			rec.Type, rec.ScreenCheck, rec.SrcAddr, rec.DstAddr, rec.Protocol, rec.Action, rec.InZone)
	}
	if rec.Type == "SESSION_CLOSE" {
		return fmt.Sprintf("RT_FLOW %s src=%s dst=%s proto=%s action=%s policy=%d zone=%d->%d pkts=%d bytes=%d",
			rec.Type, rec.SrcAddr, rec.DstAddr, rec.Protocol, rec.Action,
			rec.PolicyID, rec.InZone, rec.OutZone, rec.SessionPkts, rec.SessionBytes)
	}
	if rec.Type == "FILTER_LOG" {
		source := rec.Reason
		if source == "" {
			source = "unknown"
		}
		return fmt.Sprintf("RT_FLOW %s src=%s dst=%s proto=%s action=%s zone=%d->%d source=%s filter=%d term=%d",
			rec.Type, rec.SrcAddr, rec.DstAddr, rec.Protocol, rec.Action,
			rec.InZone, rec.OutZone, source, rec.RuleID, rec.TermID)
	}
	return fmt.Sprintf("RT_FLOW %s src=%s dst=%s proto=%s action=%s policy=%d zone=%d->%d",
		rec.Type, rec.SrcAddr, rec.DstAddr, rec.Protocol, rec.Action,
		rec.PolicyID, rec.InZone, rec.OutZone)
}
