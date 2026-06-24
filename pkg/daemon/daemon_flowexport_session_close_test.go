package daemon

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
	"unsafe"

	"github.com/psaab/xpf/pkg/config"
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

// flowIPFIXConfigPorts builds a sampling config with the v9 and IPFIX
// collectors bound to caller-chosen ports (so a test can bind a real UDP
// listener for each and observe the transmitted datagram). rate=1 so
// ShouldExport always admits the close.
func flowIPFIXConfigPorts(addr string, v9Port, ipfixPort int) *config.Config {
	cfg := flowSamplingConfig(addr, 1)
	fam := cfg.ForwardingOptions.Sampling.Instances["s"].FamilyInet
	fam.FlowServers[0].Port = v9Port
	fam.FlowServers[0].Version = config.FlowServerVersion9
	fam.FlowServers = append(fam.FlowServers, &config.FlowServer{
		Address: addr, Port: ipfixPort, Version: config.FlowServerVersionIPFIX,
	})
	cfg.Services.FlowMonitoring.VersionIPFIX = &config.NetFlowIPFIXConfig{
		Templates: map[string]*config.NetFlowIPFIXTemplate{"t": {Name: "t"}},
	}
	return cfg
}

// listenUDP binds a UDP socket on 127.0.0.1:0 and returns it plus its port.
func listenUDP(t *testing.T) (*net.UDPConn, int) {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	return pc, pc.LocalAddr().(*net.UDPAddr).Port
}

// waitFlows polls an exporter's Stats() until it reports at least one
// EXPORTED FLOW RECORD (not a template — Stats.flows increments only in
// sendRecords, never in sendTemplates), or the 3s deadline elapses. The
// v9/IPFIX exporters flush queued records on a 100ms ticker started by
// reconcile, so a SESSION_CLOSE admitted by ShouldExport becomes an
// exported flow well within the deadline. A non-zero flow count is
// close-specific: it proves the SESSION_CLOSE-derived FlowRecord reached
// the real exporter and was transmitted, distinct from the unconditional
// startup template datagram.
func waitFlows(t *testing.T, stats func() (uint64, uint64)) uint64 {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if flows, _ := stats(); flows >= 1 {
			return flows
		}
		time.Sleep(10 * time.Millisecond)
	}
	flows, _ := stats()
	return flows
}

// TestSessionCloseRawEventDrivesFlowExport is the #2460 end-to-end (P1)
// assertion: a userspace SESSION_CLOSE RT_FLOW event delivered on the raw
// dataplane-event channel (exactly the path SetOnRawDataplaneEvent ->
// eventReader.ProcessRawEvent uses for the EventFrameTypeSessionClose frame)
// produces exactly one Type=="SESSION_CLOSE" EventRecord that reaches BOTH
// the NetFlow v9 and IPFIX flow-export callbacks, carrying the correct
// 5-tuple. It proves "both callbacks" two ways:
//
//  1. The two REAL exporters (flowExportCallback / ipfixExportCallback,
//     registered by reconcile) are bound to real UDP collectors and each
//     transmits a datagram for the admitted close — proving the record
//     truly reaches both production export paths, not just a spy.
//  2. Two distinct fanout callbacks gating identically on
//     rec.Type=="SESSION_CLOSE" (standing in for the NetFlow and IPFIX
//     consumers) BOTH fire exactly once with the correct tuple — the
//     deterministic content assertion the datagram-receipt cannot give.
//
// Volume counters are 0 (P2/#2501), asserted explicitly.
//
// Fail-on-revert: without the helper emitting the type-14 SESSION_CLOSE
// frame, no SESSION_CLOSE EventRecord is ever produced in userspace mode, so
// the flowExportCallback / ipfixExportCallback early-return on
// rec.Type != "SESSION_CLOSE" and never fire — exactly the #2460 defect.
// Dropping EITHER fanout callback registration drops its fire count to 0.
func TestSessionCloseRawEventDrivesFlowExport(t *testing.T) {
	v9Coll, v9Port := listenUDP(t)
	t.Cleanup(func() { v9Coll.Close() })
	ipfixColl, ipfixPort := listenUDP(t)
	t.Cleanup(func() { ipfixColl.Close() })

	d := newFlowTestDaemon()
	t.Cleanup(d.stopFlowExporter)
	t.Cleanup(d.stopIPFIXExporter)

	if !d.reconcileFlowExporters(flowIPFIXConfigPorts("127.0.0.1", v9Port, ipfixPort)) {
		t.Fatal("flow + ipfix exporters must start")
	}
	if b := d.flowBundle.Load(); b == nil || b.exp == nil {
		t.Fatal("v9 exporter must be live")
	}
	if b := d.ipfixBundlePtr.Load(); b == nil || b.exp == nil {
		t.Fatal("ipfix exporter must be live")
	}
	// The two real export callbacks are registered exactly once.
	if n := d.eventReader.CallbackCount(); n != 2 {
		t.Fatalf("expected 2 real export callbacks (v9 + ipfix), got %d", n)
	}

	// Two distinct fanout callbacks standing in for the NetFlow and IPFIX
	// SESSION_CLOSE consumers — registered AFTER the two real callbacks so
	// all four see the record. Dropping either makes its count 0
	// (fail-on-revert for the "both callbacks" claim).
	var netflowFires, ipfixFires int
	var seen logging.EventRecord
	d.eventReader.AddCallback(func(rec logging.EventRecord, _ []byte) {
		if rec.Type != "SESSION_CLOSE" {
			return
		}
		netflowFires++
		seen = rec
	})
	d.eventReader.AddCallback(func(rec logging.EventRecord, _ []byte) {
		if rec.Type != "SESSION_CLOSE" {
			return
		}
		ipfixFires++
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

	// Both SESSION_CLOSE-gated consumers fire exactly once.
	if netflowFires != 1 {
		t.Fatalf("NetFlow SESSION_CLOSE callback fired %d times, want 1", netflowFires)
	}
	if ipfixFires != 1 {
		t.Fatalf("IPFIX SESSION_CLOSE callback fired %d times, want 1", ipfixFires)
	}

	// Both REAL exporters export a flow record for the close — proving the
	// SESSION_CLOSE-derived FlowRecord reaches both production export paths
	// (Stats.flows counts data records, not templates).
	if got := waitFlows(t, d.flowExporter.Stats); got < 1 {
		t.Fatalf("NetFlow v9 exporter exported %d flows after the SESSION_CLOSE, want >= 1", got)
	}
	if got := waitFlows(t, d.ipfixExporter.Stats); got < 1 {
		t.Fatalf("IPFIX exporter exported %d flows after the SESSION_CLOSE, want >= 1", got)
	}

	// Record content (the deterministic boundary assertion).
	rec := seen
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
