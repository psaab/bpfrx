package api

import (
	"encoding/json"
	"fmt"
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

// writeSSEEvent writes a single SSE event to the response.
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

	setSSEHeaders(w)

	sub := s.eventBuf.Subscribe(128)
	defer sub.Close()

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
			writeSSEEvent(w, fmt.Sprintf("%d", seq), rec.Type, string(data))
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

	setSSEHeaders(w)

	sub := s.eventBuf.Subscribe(128)
	defer sub.Close()

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
			writeSSEEvent(w, fmt.Sprintf("%d", seq), "log", string(data))
		}
	}
}

// LogStreamEntry is a log message sent via SSE.
type LogStreamEntry struct {
	Time     string `json:"time"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

func eventEntryFromRecord(rec logging.EventRecord) EventEntry {
	return EventEntry{
		Time:         rec.Time.Format(time.RFC3339),
		Type:         rec.Type,
		SrcAddr:      rec.SrcAddr,
		DstAddr:      rec.DstAddr,
		Protocol:     rec.Protocol,
		Action:       rec.Action,
		PolicyID:     rec.PolicyID,
		InZone:       rec.InZone,
		OutZone:      rec.OutZone,
		ScreenCheck:  rec.ScreenCheck,
		SessionPkts:  rec.SessionPkts,
		SessionBytes: rec.SessionBytes,
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
