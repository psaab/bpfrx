// Package logging implements eBPF ring buffer event reading.
package logging

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/psviderski/bpfrx/pkg/dataplane"
)

// EventReader reads events from the eBPF ring buffer.
type EventReader struct {
	eventsMap *ebpf.Map
}

// NewEventReader creates a new event reader for the given events map.
func NewEventReader(eventsMap *ebpf.Map) *EventReader {
	return &EventReader{eventsMap: eventsMap}
}

// Run starts reading events. It blocks until ctx is cancelled.
func (er *EventReader) Run(ctx context.Context) {
	if er.eventsMap == nil {
		slog.Warn("events map is nil, event reader not starting")
		return
	}

	rd, err := ringbuf.NewReader(er.eventsMap)
	if err != nil {
		slog.Error("failed to create ring buffer reader", "err", err)
		return
	}
	defer rd.Close()

	slog.Info("event reader started")

	// Close the reader when context is done
	go func() {
		<-ctx.Done()
		rd.Close()
	}()

	for {
		record, err := rd.Read()
		if err != nil {
			select {
			case <-ctx.Done():
				slog.Info("event reader stopped")
				return
			default:
				slog.Error("ring buffer read error", "err", err)
				return
			}
		}

		if len(record.RawSample) < int(unsafe.Sizeof(dataplane.Event{})) {
			continue
		}

		er.logEvent(record.RawSample)
	}
}

func (er *EventReader) logEvent(data []byte) {
	// Event struct layout (with 16-byte IPs):
	// [0:8]   timestamp (u64)
	// [8:24]  src_ip (16 bytes)
	// [24:40] dst_ip (16 bytes)
	// [40:42] src_port (u16 BE)
	// [42:44] dst_port (u16 BE)
	// [44:48] policy_id (u32)
	// [48:50] ingress_zone (u16)
	// [50:52] egress_zone (u16)
	// [52]    event_type (u8)
	// [53]    protocol (u8)
	// [54]    action (u8)
	// [55]    addr_family (u8)
	// [56:64] session_packets (u64)
	// [64:72] session_bytes (u64)
	var evt dataplane.Event
	evt.Timestamp = binary.LittleEndian.Uint64(data[0:8])
	copy(evt.SrcIP[:], data[8:24])
	copy(evt.DstIP[:], data[24:40])
	evt.SrcPort = binary.BigEndian.Uint16(data[40:42])
	evt.DstPort = binary.BigEndian.Uint16(data[42:44])
	evt.PolicyID = binary.LittleEndian.Uint32(data[44:48])
	evt.IngressZone = binary.LittleEndian.Uint16(data[48:50])
	evt.EgressZone = binary.LittleEndian.Uint16(data[50:52])
	evt.EventType = data[52]
	evt.Protocol = data[53]
	evt.Action = data[54]
	evt.AddrFamily = data[55]

	var srcStr, dstStr string
	if evt.AddrFamily == dataplane.AFInet6 {
		srcIP := net.IP(evt.SrcIP[:])
		dstIP := net.IP(evt.DstIP[:])
		srcStr = fmt.Sprintf("[%s]:%d", srcIP, evt.SrcPort)
		dstStr = fmt.Sprintf("[%s]:%d", dstIP, evt.DstPort)
	} else {
		srcIP := net.IP(evt.SrcIP[:4])
		dstIP := net.IP(evt.DstIP[:4])
		srcStr = fmt.Sprintf("%s:%d", srcIP, evt.SrcPort)
		dstStr = fmt.Sprintf("%s:%d", dstIP, evt.DstPort)
	}

	eventName := eventTypeName(evt.EventType)
	actionName := actionName(evt.Action)
	protoName := protoName(evt.Protocol)

	if evt.EventType == dataplane.EventTypeSessionClose {
		sessionPkts := binary.LittleEndian.Uint64(data[56:64])
		sessionBytes := binary.LittleEndian.Uint64(data[64:72])
		slog.Info("firewall event",
			"type", eventName,
			"src", srcStr,
			"dst", dstStr,
			"proto", protoName,
			"action", actionName,
			"policy_id", evt.PolicyID,
			"ingress_zone", evt.IngressZone,
			"egress_zone", evt.EgressZone,
			"session_packets", sessionPkts,
			"session_bytes", sessionBytes)
	} else if evt.EventType == dataplane.EventTypeScreenDrop {
		screenName := screenFlagName(evt.PolicyID)
		slog.Info("firewall event",
			"type", eventName,
			"screen_check", screenName,
			"src", srcStr,
			"dst", dstStr,
			"proto", protoName,
			"action", actionName,
			"ingress_zone", evt.IngressZone)
	} else {
		slog.Info("firewall event",
			"type", eventName,
			"src", srcStr,
			"dst", dstStr,
			"proto", protoName,
			"action", actionName,
			"policy_id", evt.PolicyID,
			"ingress_zone", evt.IngressZone,
			"egress_zone", evt.EgressZone)
	}
}

func eventTypeName(t uint8) string {
	switch t {
	case dataplane.EventTypeSessionOpen:
		return "SESSION_OPEN"
	case dataplane.EventTypeSessionClose:
		return "SESSION_CLOSE"
	case dataplane.EventTypePolicyDeny:
		return "POLICY_DENY"
	case dataplane.EventTypeScreenDrop:
		return "SCREEN_DROP"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", t)
	}
}

func actionName(a uint8) string {
	switch a {
	case dataplane.ActionPermit:
		return "permit"
	case dataplane.ActionDeny:
		return "deny"
	case dataplane.ActionReject:
		return "reject"
	default:
		return fmt.Sprintf("unknown(%d)", a)
	}
}

func protoName(p uint8) string {
	switch p {
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 1:
		return "ICMP"
	case dataplane.ProtoICMPv6:
		return "ICMPv6"
	default:
		return fmt.Sprintf("%d", p)
	}
}

func screenFlagName(flag uint32) string {
	if name, ok := dataplane.ScreenFlagNames[flag]; ok {
		return name
	}
	return fmt.Sprintf("screen(0x%x)", flag)
}
