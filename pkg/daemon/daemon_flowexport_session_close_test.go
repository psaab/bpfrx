package daemon

import (
	"encoding/binary"
	"testing"
	"unsafe"

	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/logging"
)

// buildSessionCloseRawEventV4 builds the canonical 136-byte dataplane.Event
// RT_FLOW payload for a SESSION_CLOSE, byte-for-byte mirroring the Rust
// EventFrame::encode_session_close_rt_flow encoder
// (userspace-dp/src/event_stream/codec.rs). This is the #2460 cross-language
// wire-parity anchor: the offsets/endianness here MUST match the Rust
// encoder, and the resulting bytes MUST decode to a Type=="SESSION_CLOSE"
// EventRecord via logging.DecodeRawEventRecord / EventReader.ProcessRawEvent.
//
// Volume counters (offsets 56/64/112/120) and the created stamp (offset 108)
// are intentionally 0 — the userspace dataplane does not yet maintain
// per-session byte/packet accounting (tracked in #2501).
func buildSessionCloseRawEventV4(
	proto uint8,
	srcIP, dstIP [4]byte,
	srcPort, dstPort uint16,
	natSrcIP [4]byte,
	natSrcPort uint16,
	ingressZone, egressZone uint16,
) []byte {
	buf := make([]byte, int(unsafe.Sizeof(dataplane.Event{})))
	// [8:12] src ip, [24:28] dst ip (16-byte slots, v4 left-aligned).
	copy(buf[8:12], srcIP[:])
	copy(buf[24:28], dstIP[:])
	// [40:42] src port, [42:44] dst port — BIG-endian.
	binary.BigEndian.PutUint16(buf[40:42], srcPort)
	binary.BigEndian.PutUint16(buf[42:44], dstPort)
	// [48:50] ingress zone, [50:52] egress zone — little-endian.
	binary.LittleEndian.PutUint16(buf[48:50], ingressZone)
	binary.LittleEndian.PutUint16(buf[50:52], egressZone)
	// [52] event type = SESSION_CLOSE (2); [53] protocol; [55] addr family.
	buf[52] = dataplane.EventTypeSessionClose
	buf[53] = proto
	buf[55] = dataplane.AFInet
	// [72:76] nat src ip, [104:106] nat src port (BIG-endian).
	copy(buf[72:76], natSrcIP[:])
	binary.BigEndian.PutUint16(buf[104:106], natSrcPort)
	return buf
}

// TestSessionCloseRawEventDrivesFlowExport is the #2460 end-to-end (P1)
// assertion: a userspace SESSION_CLOSE RT_FLOW event delivered on the raw
// dataplane-event channel (exactly the path SetOnRawDataplaneEvent ->
// eventReader.ProcessRawEvent uses for the EventFrameTypeSessionClose frame)
// produces exactly one Type=="SESSION_CLOSE" EventRecord that reaches BOTH
// the NetFlow v9 and IPFIX flow-export callbacks, carrying the correct
// 5-tuple. Volume counters are 0 (P2/#2501).
//
// Fail-on-revert: without the helper emitting the type-14 SESSION_CLOSE
// frame, no SESSION_CLOSE EventRecord is ever produced in userspace mode, so
// the flowExportCallback / ipfixExportCallback early-return on
// rec.Type != "SESSION_CLOSE" and never fire — exactly the #2460 defect.
func TestSessionCloseRawEventDrivesFlowExport(t *testing.T) {
	d := newFlowTestDaemon()
	t.Cleanup(d.stopFlowExporter)
	t.Cleanup(d.stopIPFIXExporter)

	// rate=1 so ShouldExport always admits the close (deterministic).
	if !d.reconcileFlowExporters(ipfixSamplingConfig("127.0.0.1", 1)) {
		t.Fatal("flow + ipfix exporters must start")
	}
	if b := d.flowBundle.Load(); b == nil || b.exp == nil {
		t.Fatal("v9 exporter must be live")
	}
	if b := d.ipfixBundlePtr.Load(); b == nil || b.exp == nil {
		t.Fatal("ipfix exporter must be live")
	}

	// Spy callback gating identically to the real flow-export callbacks.
	// Registered AFTER the two real callbacks so all three see the record.
	var sessionCloses []logging.EventRecord
	d.eventReader.AddCallback(func(rec logging.EventRecord, _ []byte) {
		if rec.Type != "SESSION_CLOSE" {
			return
		}
		sessionCloses = append(sessionCloses, rec)
	})

	payload := buildSessionCloseRawEventV4(
		6, // TCP
		[4]byte{10, 0, 1, 102}, [4]byte{172, 16, 80, 200},
		12345, 443,
		[4]byte{172, 16, 80, 8}, 40000,
		2, 3, // trust -> untrust
	)

	if !d.eventReader.ProcessRawEvent(payload) {
		t.Fatal("ProcessRawEvent rejected a valid SESSION_CLOSE payload")
	}

	if len(sessionCloses) != 1 {
		t.Fatalf("expected exactly one SESSION_CLOSE record, got %d", len(sessionCloses))
	}
	rec := sessionCloses[0]
	if rec.Type != "SESSION_CLOSE" {
		t.Fatalf("Type = %q, want SESSION_CLOSE", rec.Type)
	}
	if rec.SrcAddr != "10.0.1.102:12345" {
		t.Fatalf("SrcAddr = %q, want 10.0.1.102:12345", rec.SrcAddr)
	}
	if rec.DstAddr != "172.16.80.200:443" {
		t.Fatalf("DstAddr = %q, want 172.16.80.200:443", rec.DstAddr)
	}
	if rec.Protocol != "TCP" {
		t.Fatalf("Protocol = %q, want TCP", rec.Protocol)
	}
	if rec.NATSrcAddr != "172.16.80.8:40000" {
		t.Fatalf("NATSrcAddr = %q, want 172.16.80.8:40000", rec.NATSrcAddr)
	}
	if rec.InZone != 2 || rec.OutZone != 3 {
		t.Fatalf("zones = (%d,%d), want (2,3)", rec.InZone, rec.OutZone)
	}
	// #2501: volume counters are 0 until per-session accounting lands. This
	// is asserted explicitly (NOT non-zero) — the P1 fix wires the record
	// through; the P2 follow-up populates the volume.
	if rec.SessionPkts != 0 || rec.SessionBytes != 0 {
		t.Fatalf("counters = (%d,%d), want (0,0) pending #2501",
			rec.SessionPkts, rec.SessionBytes)
	}
	if rec.RevSessionPkts != 0 || rec.RevSessionBytes != 0 {
		t.Fatalf("rev counters = (%d,%d), want (0,0) pending #2501",
			rec.RevSessionPkts, rec.RevSessionBytes)
	}
}

// TestNonSessionCloseRawEventDoesNotDriveFlowExport is the negative half of
// the fail-on-revert proof: a NON-close RT_FLOW event (policy deny) on the
// same raw channel must NOT reach the session-close export gate. If a future
// change broadened the gate (or mislabeled the close), this catches it.
func TestNonSessionCloseRawEventDoesNotDriveFlowExport(t *testing.T) {
	d := newFlowTestDaemon()
	t.Cleanup(d.stopFlowExporter)
	t.Cleanup(d.stopIPFIXExporter)
	if !d.reconcileFlowExporters(ipfixSamplingConfig("127.0.0.1", 1)) {
		t.Fatal("exporters must start")
	}

	var sessionCloses int
	d.eventReader.AddCallback(func(rec logging.EventRecord, _ []byte) {
		if rec.Type == "SESSION_CLOSE" {
			sessionCloses++
		}
	})

	// A POLICY_DENY raw event (event-type byte 3, not 2).
	payload := buildSessionCloseRawEventV4(
		6,
		[4]byte{10, 0, 1, 102}, [4]byte{172, 16, 80, 200},
		12345, 443,
		[4]byte{}, 0,
		2, 3,
	)
	payload[52] = dataplane.EventTypePolicyDeny

	if !d.eventReader.ProcessRawEvent(payload) {
		t.Fatal("ProcessRawEvent rejected a valid POLICY_DENY payload")
	}
	if sessionCloses != 0 {
		t.Fatalf("a POLICY_DENY must not produce a SESSION_CLOSE record, got %d", sessionCloses)
	}
}

// TestEventFrameTypeSessionCloseConstant pins the Go frame-type constant so a
// drift from the Rust MSG_SESSION_CLOSE_RT_FLOW (14) is caught at unit level.
func TestEventFrameTypeSessionCloseConstant(t *testing.T) {
	if dpuserspace.EventFrameTypeSessionClose != 14 {
		t.Fatalf("EventFrameTypeSessionClose = %d, want 14 (must match Rust MSG_SESSION_CLOSE_RT_FLOW)",
			dpuserspace.EventFrameTypeSessionClose)
	}
}
