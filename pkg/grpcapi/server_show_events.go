package grpcapi

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/config"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"github.com/psaab/xpf/pkg/logging"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *Server) GetEvents(_ context.Context, req *pb.GetEventsRequest) (*pb.GetEventsResponse, error) {
	if s.eventBuf == nil {
		return &pb.GetEventsResponse{}, nil
	}

	// Zone IDs are uint16 internally; the request value is uint32. A value
	// above 65535 used to be narrowed by an unchecked uint16() cast, which
	// silently WRAPS (65536 -> 0 = no filter, 65537 -> zone 1) and returns
	// the wrong events or hides the intended ones. Reject out-of-range input
	// up front, matching the sessions path (buildSessionFilter) and the REST
	// events guard (queryUint16Strict) which both fail-closed (#3334).
	if req.Zone > 65535 {
		return nil, status.Errorf(codes.InvalidArgument, "invalid zone id %d", req.Zone)
	}

	limit := int(req.Limit)
	if limit <= 0 {
		limit = 50
	}
	if limit > 10000 {
		limit = 10000
	}

	filter := logging.EventFilter{
		Zone:     uint16(req.Zone),
		Action:   req.Action,
		Protocol: req.Protocol,
	}

	var events []logging.EventRecord
	if filter.IsEmpty() {
		events = s.eventBuf.Latest(limit)
	} else {
		events = s.eventBuf.LatestFiltered(limit, filter)
	}

	// Build reverse zone ID → name map
	evZoneNames := make(map[uint16]string)
	if cr := s.applyResult(); cr != nil {
		for name, id := range cr.ZoneIDs {
			evZoneNames[id] = name
		}
	}

	resp := &pb.GetEventsResponse{}
	for _, ev := range events {
		resp.Events = append(resp.Events, &pb.EventEntry{
			Time:            ev.Time.Format(time.RFC3339),
			Type:            ev.Type,
			SrcAddr:         ev.SrcAddr,
			DstAddr:         ev.DstAddr,
			Protocol:        ev.Protocol,
			Action:          ev.Action,
			PolicyId:        ev.PolicyID,
			IngressZone:     uint32(ev.InZone),
			EgressZone:      uint32(ev.OutZone),
			IngressZoneName: evZoneNames[ev.InZone],
			EgressZoneName:  evZoneNames[ev.OutZone],
			ScreenCheck:     ev.ScreenCheck,
			SessionPackets:  ev.SessionPkts,
			SessionBytes:    ev.SessionBytes,
			PolicyName:      ev.PolicyName,
			RevSessionPkts:  ev.RevSessionPkts,
			RevSessionBytes: ev.RevSessionBytes,
			AppName:         ev.AppName,
			IngressIface:    ev.IngressIface,
			CloseReason:     ev.CloseReason,
		})
	}
	return resp, nil
}

// --- #1700: residual ShowText branches ---

func (s *Server) showEventOptions(cfg *config.Config, buf *strings.Builder) {
	if cfg == nil || len(cfg.EventOptions) == 0 {
		buf.WriteString("No event-options configured\n")
	} else {
		for _, ep := range cfg.EventOptions {
			fmt.Fprintf(buf, "Policy: %s\n", ep.Name)
			if len(ep.Events) > 0 {
				fmt.Fprintf(buf, "  Events: %s\n", strings.Join(ep.Events, ", "))
			}
			for _, w := range ep.WithinClauses {
				fmt.Fprintf(buf, "  Within: %d seconds", w.Seconds)
				if w.TriggerOn > 0 {
					fmt.Fprintf(buf, ", trigger on %d", w.TriggerOn)
				}
				if w.TriggerUntil > 0 {
					fmt.Fprintf(buf, ", trigger until %d", w.TriggerUntil)
				}
				buf.WriteString("\n")
			}
			if len(ep.AttributesMatch) > 0 {
				buf.WriteString("  Attributes match:\n")
				for _, am := range ep.AttributesMatch {
					fmt.Fprintf(buf, "    %s\n", am)
				}
			}
			if len(ep.ThenCommands) > 0 {
				buf.WriteString("  Then commands:\n")
				for _, cmd := range ep.ThenCommands {
					fmt.Fprintf(buf, "    %s\n", cmd)
				}
			}
			buf.WriteString("\n")
		}
	}
}
