package api

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/logging"
)

// forensicCloseRecord is a SESSION_CLOSE event carrying every RT_FLOW forensic
// field the buffer can hold, with a sub-second timestamp.
func forensicCloseRecord() logging.EventRecord {
	return logging.EventRecord{
		Time:            time.Date(2026, 6, 29, 12, 0, 0, 123456789, time.UTC),
		Type:            "SESSION_CLOSE",
		SrcAddr:         "10.0.1.5:51000",
		DstAddr:         "10.0.2.9:443",
		Protocol:        "TCP",
		Action:          "permit",
		PolicyID:        7,
		InZone:          3,
		OutZone:         4,
		InZoneName:      "trust",
		OutZoneName:     "untrust",
		ScreenCheck:     "",
		SessionPkts:     12,
		SessionBytes:    3400,
		RevSessionPkts:  10,
		RevSessionBytes: 9000,
		PolicyName:      "allow-web",
		AppName:         "junos-https",
		IngressIface:    "ge-0-0-0.0",
		CloseReason:     "TCP FIN",
		Reason:          "policy",
		NATSrcAddr:      "172.16.1.1:12345",
		NATDstAddr:      "10.0.2.9:443",
		SessionID:       0xDEADBEEF,
		ElapsedTime:     42,
		Created:         1750000000,
		CreatedNanos:    500000000,
		EgressIfindex:   17,
		IngressIfindex:  9,
		TOS:             0xB8,
		TCPControlBits:  0x1B,
	}
}

// TestRESTEventForensicFieldsSurfaced pins #3337 on the REST surface: the GET
// /security/events response must carry every RT_FLOW forensic field the
// EventRecord holds, and the timestamp must keep sub-second (RFC3339Nano)
// resolution.
//
// FAIL-ON-REVERT: reverting EventEntry / eventEntryFromRecord to the reduced
// type/src/dst/proto/action/policy_id/zones/screen_check/session_pkts/bytes
// view drops PolicyName, AppName, CloseReason, the reverse counters, NAT
// tuples, session ID, elapsed/created, ifindexes, TOS, and TCP flags — every
// assertion below for those fields fails. Reverting RFC3339Nano -> RFC3339
// truncates the timestamp and fails the nanosecond-fraction assertion.
func TestRESTEventForensicFieldsSurfaced(t *testing.T) {
	eb := logging.NewEventBuffer(16)
	eb.Add(forensicCloseRecord())
	s := &Server{eventBuf: eb}

	rr := httptest.NewRecorder()
	s.eventsHandler(rr, httptest.NewRequest("GET", "/api/v1/security/events", nil))
	if rr.Code != 200 {
		t.Fatalf("events status = %d; want 200; body=%s", rr.Code, rr.Body.String())
	}
	evs := decodeEvents(t, rr.Body.Bytes())
	if len(evs) != 1 {
		t.Fatalf("got %d events; want 1", len(evs))
	}
	got := evs[0]

	// Sub-second timestamp must survive (RFC3339Nano, not RFC3339).
	if !strings.Contains(got.Time, ".123456789") {
		t.Errorf("Time = %q; want RFC3339Nano with sub-second fraction .123456789", got.Time)
	}

	checks := []struct {
		name string
		got  any
		want any
	}{
		{"InZoneName", got.InZoneName, "trust"},
		{"OutZoneName", got.OutZoneName, "untrust"},
		{"PolicyName", got.PolicyName, "allow-web"},
		{"AppName", got.AppName, "junos-https"},
		{"IngressIface", got.IngressIface, "ge-0-0-0.0"},
		{"CloseReason", got.CloseReason, "TCP FIN"},
		{"Reason", got.Reason, "policy"},
		{"RevSessionPkts", got.RevSessionPkts, uint64(10)},
		{"RevSessionBytes", got.RevSessionBytes, uint64(9000)},
		{"NATSrcAddr", got.NATSrcAddr, "172.16.1.1:12345"},
		{"NATDstAddr", got.NATDstAddr, "10.0.2.9:443"},
		{"SessionID", got.SessionID, uint64(0xDEADBEEF)},
		{"ElapsedTime", got.ElapsedTime, uint32(42)},
		{"Created", got.Created, uint32(1750000000)},
		{"CreatedNanos", got.CreatedNanos, uint32(500000000)},
		{"EgressIfindex", got.EgressIfindex, uint32(17)},
		{"IngressIfindex", got.IngressIfindex, uint32(9)},
		{"TOS", got.TOS, uint8(0xB8)},
		{"TCPControlBits", got.TCPControlBits, uint8(0x1B)},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("EventEntry.%s = %v; want %v", c.name, c.got, c.want)
		}
	}
}

// TestSSEEventForensicFieldsSurfaced pins the SSE surface to the same SSOT
// mapper: eventEntryFromRecord must carry the forensic fields and RFC3339Nano
// timestamp, so the live event stream matches the GET response.
func TestSSEEventForensicFieldsSurfaced(t *testing.T) {
	got := eventEntryFromRecord(forensicCloseRecord())
	if !strings.Contains(got.Time, ".123456789") {
		t.Errorf("Time = %q; want RFC3339Nano with sub-second fraction", got.Time)
	}
	if got.PolicyName != "allow-web" || got.AppName != "junos-https" ||
		got.CloseReason != "TCP FIN" || got.NATSrcAddr != "172.16.1.1:12345" ||
		got.SessionID != 0xDEADBEEF || got.RevSessionBytes != 9000 ||
		got.TOS != 0xB8 || got.TCPControlBits != 0x1B || got.IngressIface != "ge-0-0-0.0" {
		t.Errorf("eventEntryFromRecord dropped a forensic field: %+v", got)
	}
}
