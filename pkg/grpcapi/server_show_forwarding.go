package grpcapi

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/fwdstatus"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc/metadata"
)

func (s *Server) buildLocalForwarding() string {
	var snap fwdstatus.SamplerSnapshot
	if s.fwdSampler != nil {
		snap = s.fwdSampler.Snapshot()
	}
	fs, err := fwdstatus.Build(
		s.forwardingStatusDataplane(),
		fwdstatus.OSProcReader{},
		s.startTime,
		snap,
	)
	if err != nil {
		return fmt.Sprintf("FWDD status:\n  (build failed: %s)\n", err)
	}
	return fwdstatus.Format(fs)
}

type forwardingStatusServerDataPlane struct {
	server *Server
}

func (a forwardingStatusServerDataPlane) IsLoaded() bool {
	return a.server != nil && a.server.dp != nil && a.server.dp.IsLoaded()
}

func (a forwardingStatusServerDataPlane) GetMapStats() []fwdstatus.MapStats {
	if a.server == nil || a.server.dp == nil {
		return nil
	}
	stats := a.server.dp.GetMapStats()
	out := make([]fwdstatus.MapStats, 0, len(stats))
	for _, ms := range stats {
		out = append(out, fwdstatus.MapStats{
			Type:       ms.Type,
			MaxEntries: ms.MaxEntries,
			UsedCount:  ms.UsedCount,
		})
	}
	return out
}

type forwardingStatusServerUserspaceDataPlane struct {
	forwardingStatusServerDataPlane
}

func (a forwardingStatusServerUserspaceDataPlane) Status() (dpuserspace.ProcessStatus, error) {
	return a.server.userspaceDataplaneStatus()
}

func (s *Server) forwardingStatusDataplane() fwdstatus.DataPlaneAccessor {
	if s == nil {
		return nil
	}
	// #2114/#6743 r2-B7: the publication check must ask the CELL, not the
	// field. `s.dp == nil` is permanently false under the daemon's live
	// indirection, so a daemon whose startup arm failed and cleared the
	// cell fell PAST this guard and returned the non-userspace `base`
	// wrapper. fwdstatus.Build then took its BPF-map arm, where
	// GetMapStats() returns nil and the max-occupancy loop over an empty
	// slice leaves maxPct at 0 — and sets BufferKnown=true. The render is
	// "Buffer utilization   0 percent" where the nil-dp control correctly
	// says "unknown (see #878)".
	//
	// This is worse than the sibling r6-F3 renders: a misleading string is
	// read by a human, but BufferKnown=true tells every downstream consumer
	// the zero is TRUSTWORTHY. Returning nil here restores
	// BufferKnown=false, not merely the string.
	//
	// ONE resolution feeds both decisions, as in showBuffers (r7): a
	// setDataplane(nil) landing between a publication check and a separate
	// dpProbe() re-creates the confusion the check exists to prevent.
	backend := dataplane.Unwrap(s.dp)
	if backend == nil {
		return nil
	}
	base := forwardingStatusServerDataPlane{server: s}
	if _, ok := backend.(userspaceStatusProvider); ok {
		return forwardingStatusServerUserspaceDataPlane{forwardingStatusServerDataPlane: base}
	}
	return base
}

func (s *Server) dialAndShowForwarding(ctx context.Context) (string, error) {
	conn, err := s.dialPeer()
	if err != nil {
		return "", err
	}
	defer conn.Close()
	client := pb.NewBpfrxServiceClient(conn)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ctx = metadata.AppendToOutgoingContext(ctx, "xpf-no-peer", "1")
	resp, err := client.ShowText(ctx, &pb.ShowTextRequest{Topic: "chassis-forwarding"})
	if err != nil {
		return "", err
	}
	return resp.Output, nil
}

// --- #1700: residual ShowText branches ---

func (s *Server) showForwardingOptions(cfg *config.Config, buf *strings.Builder) {
	if cfg == nil {
		buf.WriteString("No active configuration\n")
	} else {
		fo := &cfg.ForwardingOptions
		hasContent := false
		if fo.FamilyInet6Mode != "" {
			fmt.Fprintf(buf, "Family inet6 mode: %s\n", fo.FamilyInet6Mode)
			hasContent = true
		}
		if fo.Sampling != nil && len(fo.Sampling.Instances) > 0 {
			buf.WriteString("Sampling:\n")
			for name, inst := range fo.Sampling.Instances {
				fmt.Fprintf(buf, "  Instance: %s\n", name)
				if inst.InputRate > 0 {
					fmt.Fprintf(buf, "    Input rate: 1/%d\n", inst.InputRate)
				}
				for _, fam := range []*config.SamplingFamily{inst.FamilyInet, inst.FamilyInet6} {
					if fam == nil {
						continue
					}
					for _, fs := range fam.FlowServers {
						fmt.Fprintf(buf, "    Flow server: %s:%d\n", fs.Address, fs.Port)
						if fs.Version9Template != "" {
							fmt.Fprintf(buf, "      Version 9 template: %s\n", fs.Version9Template)
						}
						// Per-collector source-address override (#3745).
						if fs.SourceAddress != "" {
							fmt.Fprintf(buf, "      Source address: %s\n", fs.SourceAddress)
						}
					}
					if fam.SourceAddress != "" {
						fmt.Fprintf(buf, "    Source address: %s\n", fam.SourceAddress)
					}
					if fam.InlineJflow {
						buf.WriteString("    Inline jflow: enabled\n")
					}
					if fam.InlineJflowSourceAddress != "" {
						fmt.Fprintf(buf, "    Inline jflow source: %s\n", fam.InlineJflowSourceAddress)
					}
				}
			}
			hasContent = true
		}
		if fo.DHCPRelay != nil {
			buf.WriteString("DHCP relay: (see 'show dhcp-relay' for details)\n")
			hasContent = true
		}
		if fo.PortMirroring != nil && len(fo.PortMirroring.Instances) > 0 {
			buf.WriteString("Port mirroring: (see 'show forwarding-options port-mirroring' for details)\n")
			hasContent = true
		}
		if !hasContent {
			buf.WriteString("No forwarding-options configured\n")
		}
	}
}

func (s *Server) showForwardingOptionsPortMirroring(cfg *config.Config, buf *strings.Builder) {
	if cfg == nil {
		buf.WriteString("No active configuration\n")
	} else {
		pm := cfg.ForwardingOptions.PortMirroring
		if pm == nil || len(pm.Instances) == 0 {
			buf.WriteString("No port-mirroring instances configured\n")
		} else {
			for name, inst := range pm.Instances {
				fmt.Fprintf(buf, "Instance: %s\n", name)
				if inst.InputRate > 0 {
					fmt.Fprintf(buf, "  Input rate: 1/%d\n", inst.InputRate)
				} else {
					buf.WriteString("  Input rate: all packets\n")
				}
				if len(inst.Input) > 0 {
					fmt.Fprintf(buf, "  Input interfaces: %s\n", strings.Join(inst.Input, ", "))
				}
				if inst.Output != "" {
					fmt.Fprintf(buf, "  Output interface: %s\n", inst.Output)
				}
				// #6534: mirror of the cli.showPortMirroring annotation. These
				// two renderers are byte-identical copies with no shared
				// formatter, so BOTH must carry it — annotating one leaves the
				// other lying, which is why the agreement test asserts both.
				if reason := config.PortMirroringInstanceExcludedReason(inst); reason != "" {
					fmt.Fprintf(buf, "  NOT INSTALLED: %s\n", reason)
				}
				buf.WriteString("\n")
			}
		}
	}
}
