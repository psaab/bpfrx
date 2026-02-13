// Package logging implements eBPF ring buffer event reading.
package logging

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/psaab/bpfrx/pkg/dataplane"
)

// EventCallback is called for each processed event record.
type EventCallback func(rec EventRecord, raw []byte)

// EventReader reads events from the eBPF ring buffer.
type EventReader struct {
	eventsMap     *ebpf.Map
	buffer        *EventBuffer
	syslogMu      sync.RWMutex
	syslogClients []*SyslogClient
	callbackMu    sync.RWMutex
	callbacks     []EventCallback
}

// NewEventReader creates a new event reader for the given events map.
func NewEventReader(eventsMap *ebpf.Map, buffer *EventBuffer) *EventReader {
	return &EventReader{
		eventsMap: eventsMap,
		buffer:    buffer,
	}
}

// AddCallback registers a callback that will be invoked for every event.
// The raw byte slice is the original ring buffer sample data.
func (er *EventReader) AddCallback(cb EventCallback) {
	er.callbackMu.Lock()
	er.callbacks = append(er.callbacks, cb)
	er.callbackMu.Unlock()
}

// ClearCallbacks removes all registered callbacks.
func (er *EventReader) ClearCallbacks() {
	er.callbackMu.Lock()
	er.callbacks = nil
	er.callbackMu.Unlock()
}

// SetSyslogClients replaces the set of syslog clients (goroutine-safe).
func (er *EventReader) SetSyslogClients(clients []*SyslogClient) {
	er.syslogMu.Lock()
	er.syslogClients = clients
	er.syslogMu.Unlock()
}

// ReplaceSyslogClients atomically swaps syslog clients and closes old ones.
func (er *EventReader) ReplaceSyslogClients(clients []*SyslogClient) {
	er.syslogMu.Lock()
	old := er.syslogClients
	er.syslogClients = clients
	er.syslogMu.Unlock()
	for _, c := range old {
		c.Close()
	}
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
	actionStr := actionName(evt.Action)
	protoStr := protoName(evt.Protocol)

	// Build EventRecord
	rec := EventRecord{
		Time:     time.Now(),
		Type:     eventName,
		SrcAddr:  srcStr,
		DstAddr:  dstStr,
		Protocol: protoStr,
		Action:   actionStr,
		PolicyID: evt.PolicyID,
		InZone:   evt.IngressZone,
		OutZone:  evt.EgressZone,
	}

	if evt.EventType == dataplane.EventTypeSessionClose {
		rec.SessionPkts = binary.LittleEndian.Uint64(data[56:64])
		rec.SessionBytes = binary.LittleEndian.Uint64(data[64:72])
	}
	if evt.EventType == dataplane.EventTypeScreenDrop {
		rec.ScreenCheck = screenFlagName(evt.PolicyID)
	}

	// Store in buffer
	if er.buffer != nil {
		er.buffer.Add(rec)
	}

	// Invoke registered callbacks
	er.callbackMu.RLock()
	cbs := er.callbacks
	er.callbackMu.RUnlock()
	for _, cb := range cbs {
		cb(rec, data)
	}

	// Log to slog (existing behavior)
	if evt.EventType == dataplane.EventTypeSessionClose {
		slog.Info("firewall event",
			"type", eventName,
			"src", srcStr,
			"dst", dstStr,
			"proto", protoStr,
			"action", actionStr,
			"policy_id", evt.PolicyID,
			"ingress_zone", evt.IngressZone,
			"egress_zone", evt.EgressZone,
			"session_packets", rec.SessionPkts,
			"session_bytes", rec.SessionBytes)
	} else if evt.EventType == dataplane.EventTypeScreenDrop {
		slog.Info("firewall event",
			"type", eventName,
			"screen_check", rec.ScreenCheck,
			"src", srcStr,
			"dst", dstStr,
			"proto", protoStr,
			"action", actionStr,
			"ingress_zone", evt.IngressZone)
	} else {
		slog.Info("firewall event",
			"type", eventName,
			"src", srcStr,
			"dst", dstStr,
			"proto", protoStr,
			"action", actionStr,
			"policy_id", evt.PolicyID,
			"ingress_zone", evt.IngressZone,
			"egress_zone", evt.EgressZone)
	}

	// Forward to syslog clients
	er.syslogMu.RLock()
	clients := er.syslogClients
	er.syslogMu.RUnlock()

	if len(clients) > 0 {
		severity := eventSeverity(evt.EventType)
		msg := formatSyslogMsg(rec)
		for _, c := range clients {
			if c.ShouldSend(severity) {
				if err := c.Send(severity, msg); err != nil {
					slog.Debug("syslog send failed", "err", err)
				}
			}
		}
	}
}

// eventSeverity maps event types to syslog severity levels.
func eventSeverity(eventType uint8) int {
	switch eventType {
	case dataplane.EventTypeScreenDrop:
		return SyslogError
	case dataplane.EventTypePolicyDeny:
		return SyslogWarning
	case dataplane.EventTypeFilterLog:
		return SyslogInfo
	default:
		return SyslogInfo
	}
}

// formatSyslogMsg formats an EventRecord as a syslog message body.
func formatSyslogMsg(rec EventRecord) string {
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
		return fmt.Sprintf("RT_FLOW %s src=%s dst=%s proto=%s action=%s zone=%d",
			rec.Type, rec.SrcAddr, rec.DstAddr, rec.Protocol, rec.Action, rec.InZone)
	}
	return fmt.Sprintf("RT_FLOW %s src=%s dst=%s proto=%s action=%s policy=%d zone=%d->%d",
		rec.Type, rec.SrcAddr, rec.DstAddr, rec.Protocol, rec.Action,
		rec.PolicyID, rec.InZone, rec.OutZone)
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
	case dataplane.EventTypeFilterLog:
		return "FILTER_LOG"
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
