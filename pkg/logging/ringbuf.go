// Package logging implements dataplane event reading.
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

	"github.com/psaab/bpfrx/pkg/dataplane"
)

// EventCallback is called for each processed event record.
type EventCallback func(rec EventRecord, raw []byte)

// EventReader reads events from a dataplane EventSource.
type EventReader struct {
	source        dataplane.EventSource
	buffer        *EventBuffer
	syslogMu      sync.RWMutex
	syslogClients []*SyslogClient
	localMu       sync.RWMutex
	localWriters  []*LocalLogWriter
	callbackMu    sync.RWMutex
	callbacks     []EventCallback
	zoneNamesMu   sync.RWMutex
	zoneNames     map[uint16]string // zone ID -> zone name
}

// NewEventReader creates a new event reader for the given event source.
func NewEventReader(source dataplane.EventSource, buffer *EventBuffer) *EventReader {
	return &EventReader{
		source: source,
		buffer: buffer,
	}
}

// SetZoneNames updates the zone ID to name mapping (goroutine-safe).
func (er *EventReader) SetZoneNames(names map[uint16]string) {
	er.zoneNamesMu.Lock()
	er.zoneNames = names
	er.zoneNamesMu.Unlock()
}

func (er *EventReader) resolveZoneName(id uint16) string {
	er.zoneNamesMu.RLock()
	name := er.zoneNames[id]
	er.zoneNamesMu.RUnlock()
	if name != "" {
		return name
	}
	return fmt.Sprintf("%d", id)
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

// SetLocalWriters replaces the set of local log writers (goroutine-safe).
func (er *EventReader) SetLocalWriters(writers []*LocalLogWriter) {
	er.localMu.Lock()
	er.localWriters = writers
	er.localMu.Unlock()
}

// ReplaceLocalWriters atomically swaps local writers and closes old ones.
func (er *EventReader) ReplaceLocalWriters(writers []*LocalLogWriter) {
	er.localMu.Lock()
	old := er.localWriters
	er.localWriters = writers
	er.localMu.Unlock()
	for _, w := range old {
		w.Close()
	}
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

// ForwardLogMsg sends a pre-formatted message to all configured syslog clients
// and local log writers. Used by the aggregation reporter.
func (er *EventReader) ForwardLogMsg(severity int, msg string) {
	er.syslogMu.RLock()
	clients := er.syslogClients
	er.syslogMu.RUnlock()
	for _, c := range clients {
		if c.ShouldSend(severity) {
			_ = c.Send(severity, msg)
		}
	}

	er.localMu.RLock()
	writers := er.localWriters
	er.localMu.RUnlock()
	for _, lw := range writers {
		_ = lw.Send(severity, msg)
	}
}

// Run starts reading events. It blocks until ctx is cancelled.
func (er *EventReader) Run(ctx context.Context) {
	if er.source == nil {
		slog.Warn("event source is nil, event reader not starting")
		return
	}

	slog.Info("event reader started")

	// Close the source when context is done
	go func() {
		<-ctx.Done()
		er.source.Close()
	}()

	for {
		data, err := er.source.ReadEvent()
		if err != nil {
			select {
			case <-ctx.Done():
				slog.Info("event reader stopped")
				return
			default:
				slog.Error("event source read error", "err", err)
				return
			}
		}

		if len(data) < int(unsafe.Sizeof(dataplane.Event{})) {
			continue
		}

		er.logEvent(data)
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

	// Parse NAT fields (offsets 72..112) if data is long enough
	if len(data) >= 112 {
		copy(evt.NATSrcIP[:], data[72:88])
		copy(evt.NATDstIP[:], data[88:104])
		evt.NATSrcPort = binary.BigEndian.Uint16(data[104:106])
		evt.NATDstPort = binary.BigEndian.Uint16(data[106:108])
		evt.Created = binary.LittleEndian.Uint32(data[108:112])
	}

	var srcStr, dstStr, natSrcStr, natDstStr string
	if evt.AddrFamily == dataplane.AFInet6 {
		srcIP := net.IP(evt.SrcIP[:])
		dstIP := net.IP(evt.DstIP[:])
		srcStr = fmt.Sprintf("[%s]:%d", srcIP, evt.SrcPort)
		dstStr = fmt.Sprintf("[%s]:%d", dstIP, evt.DstPort)
		natSrcIP := net.IP(evt.NATSrcIP[:])
		natDstIP := net.IP(evt.NATDstIP[:])
		natSrcStr = fmt.Sprintf("[%s]:%d", natSrcIP, evt.NATSrcPort)
		natDstStr = fmt.Sprintf("[%s]:%d", natDstIP, evt.NATDstPort)
	} else {
		srcIP := net.IP(evt.SrcIP[:4])
		dstIP := net.IP(evt.DstIP[:4])
		srcStr = fmt.Sprintf("%s:%d", srcIP, evt.SrcPort)
		dstStr = fmt.Sprintf("%s:%d", dstIP, evt.DstPort)
		natSrcIP := net.IP(evt.NATSrcIP[:4])
		natDstIP := net.IP(evt.NATDstIP[:4])
		natSrcStr = fmt.Sprintf("%s:%d", natSrcIP, evt.NATSrcPort)
		natDstStr = fmt.Sprintf("%s:%d", natDstIP, evt.NATDstPort)
	}

	eventName := eventTypeName(evt.EventType)
	actionStr := actionName(evt.Action)
	protoStr := protoName(evt.Protocol)

	// Build EventRecord
	rec := EventRecord{
		Time:        time.Now(),
		Type:        eventName,
		SrcAddr:     srcStr,
		DstAddr:     dstStr,
		Protocol:    protoStr,
		Action:      actionStr,
		PolicyID:    evt.PolicyID,
		InZone:      evt.IngressZone,
		OutZone:     evt.EgressZone,
		NATSrcAddr:  natSrcStr,
		NATDstAddr:  natDstStr,
		InZoneName:  er.resolveZoneName(evt.IngressZone),
		OutZoneName: er.resolveZoneName(evt.EgressZone),
	}

	if evt.EventType == dataplane.EventTypeSessionClose {
		rec.SessionPkts = binary.LittleEndian.Uint64(data[56:64])
		rec.SessionBytes = binary.LittleEndian.Uint64(data[64:72])
		// Compute elapsed time from session creation
		if evt.Created > 0 {
			nowSec := uint32(evt.Timestamp / 1000000000)
			if nowSec > evt.Created {
				rec.ElapsedTime = nowSec - evt.Created
			}
		}
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
		catBit := eventCategory(evt.EventType)
		// Cache formatted messages lazily per format type
		var stdMsg, structMsg string
		for _, c := range clients {
			if !c.ShouldSendEvent(severity, catBit) {
				continue
			}
			var msg string
			if c.Format == "structured" {
				if structMsg == "" {
					structMsg = formatStructuredMsg(rec, evt.Protocol)
				}
				msg = structMsg
			} else {
				if stdMsg == "" {
					stdMsg = formatSyslogMsg(rec)
				}
				msg = stdMsg
			}
			if err := c.Send(severity, msg); err != nil {
				slog.Debug("syslog send failed", "err", err)
			}
		}
	}

	// Forward to local log writers (event mode)
	er.localMu.RLock()
	localWriters := er.localWriters
	er.localMu.RUnlock()

	if len(localWriters) > 0 {
		severity := eventSeverity(evt.EventType)
		catBit := eventCategory(evt.EventType)
		var stdMsg string
		for _, lw := range localWriters {
			if !lw.ShouldSendEvent(severity, catBit) {
				continue
			}
			if stdMsg == "" {
				stdMsg = formatSyslogMsg(rec)
			}
			if err := lw.Send(severity, stdMsg); err != nil {
				slog.Debug("local log write failed", "err", err)
			}
		}
	}
}

// eventCategory maps event types to category bitmask values.
func eventCategory(eventType uint8) uint8 {
	switch eventType {
	case dataplane.EventTypeSessionOpen, dataplane.EventTypeSessionClose:
		return CategorySession
	case dataplane.EventTypePolicyDeny:
		return CategoryPolicy
	case dataplane.EventTypeScreenDrop:
		return CategoryScreen
	case dataplane.EventTypeFilterLog:
		return CategoryFirewall
	default:
		return CategoryAll // unknown events pass all category filters
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

// formatStructuredMsg formats an EventRecord as a Junos-compatible structured
// syslog message with RT_FLOW_SESSION_CREATE/CLOSE/DENY event tags.
func formatStructuredMsg(rec EventRecord, protoNum uint8) string {
	// Split addr:port pairs
	srcIP, srcPort := splitAddrPort(rec.SrcAddr)
	dstIP, dstPort := splitAddrPort(rec.DstAddr)
	natSrcIP, natSrcPort := splitAddrPort(rec.NATSrcAddr)
	natDstIP, natDstPort := splitAddrPort(rec.NATDstAddr)

	switch rec.Type {
	case "SESSION_OPEN":
		return fmt.Sprintf("RT_FLOW_SESSION_CREATE "+
			"source-address=\"%s\" source-port=\"%s\" "+
			"destination-address=\"%s\" destination-port=\"%s\" "+
			"nat-source-address=\"%s\" nat-source-port=\"%s\" "+
			"nat-destination-address=\"%s\" nat-destination-port=\"%s\" "+
			"protocol-id=\"%d\" policy-name=\"%d\" "+
			"source-zone-name=\"%s\" destination-zone-name=\"%s\"",
			srcIP, srcPort, dstIP, dstPort,
			natSrcIP, natSrcPort, natDstIP, natDstPort,
			protoNum, rec.PolicyID,
			rec.InZoneName, rec.OutZoneName)

	case "SESSION_CLOSE":
		return fmt.Sprintf("RT_FLOW_SESSION_CLOSE "+
			"source-address=\"%s\" source-port=\"%s\" "+
			"destination-address=\"%s\" destination-port=\"%s\" "+
			"nat-source-address=\"%s\" nat-source-port=\"%s\" "+
			"nat-destination-address=\"%s\" nat-destination-port=\"%s\" "+
			"protocol-id=\"%d\" policy-name=\"%d\" "+
			"source-zone-name=\"%s\" destination-zone-name=\"%s\" "+
			"packets-from-client=\"%d\" bytes-from-client=\"%d\" "+
			"elapsed-time=\"%d\"",
			srcIP, srcPort, dstIP, dstPort,
			natSrcIP, natSrcPort, natDstIP, natDstPort,
			protoNum, rec.PolicyID,
			rec.InZoneName, rec.OutZoneName,
			rec.SessionPkts, rec.SessionBytes,
			rec.ElapsedTime)

	case "POLICY_DENY":
		return fmt.Sprintf("RT_FLOW_SESSION_DENY "+
			"source-address=\"%s\" source-port=\"%s\" "+
			"destination-address=\"%s\" destination-port=\"%s\" "+
			"protocol-id=\"%d\" policy-name=\"%d\" "+
			"source-zone-name=\"%s\" destination-zone-name=\"%s\"",
			srcIP, srcPort, dstIP, dstPort,
			protoNum, rec.PolicyID,
			rec.InZoneName, rec.OutZoneName)

	default:
		return formatSyslogMsg(rec)
	}
}

// splitAddrPort splits "10.0.1.5:443" or "[::1]:443" into IP and port strings.
func splitAddrPort(addr string) (string, string) {
	if addr == "" {
		return "0.0.0.0", "0"
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, "0"
	}
	return host, port
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
