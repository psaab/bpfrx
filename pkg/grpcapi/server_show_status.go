package grpcapi

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"github.com/vishvananda/netlink"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *Server) GetStatus(_ context.Context, _ *pb.GetStatusRequest) (*pb.GetStatusResponse, error) {
	resp := &pb.GetStatusResponse{
		Uptime:          time.Since(s.startTime).Truncate(time.Second).String(),
		DataplaneLoaded: s.dp != nil && s.dp.IsLoaded(),
		ConfigLoaded:    s.store.ActiveConfig() != nil,
	}
	if cfg := s.store.ActiveConfig(); cfg != nil {
		resp.ZoneCount = int32(len(cfg.Security.Zones))
	}
	if s.gc != nil {
		stats := s.gc.Stats()
		resp.SessionCount = int32(stats.TotalEntries)
	}
	if s.cluster != nil {
		rg0 := s.cluster.GroupState(0)
		if rg0 != nil {
			if rg0.State == cluster.StatePrimary {
				resp.ClusterRole = "primary"
			} else {
				resp.ClusterRole = "secondary"
			}
		}
		resp.ClusterNodeId = int32(s.cluster.NodeID())
	}
	return resp, nil
}

func (s *Server) GetGlobalStats(_ context.Context, _ *pb.GetGlobalStatsRequest) (*pb.GetGlobalStatsResponse, error) {
	if s.dp == nil || !s.dp.IsLoaded() {
		return nil, status.Error(codes.Unavailable, "dataplane not loaded")
	}
	readCounter := func(idx uint32) uint64 {
		v, _ := s.dp.ReadGlobalCounter(idx)
		return v
	}

	// Collect per-screen-type drop counters
	screenDetails := make(map[string]uint64)
	screenCounters := []struct {
		idx  uint32
		name string
	}{
		{dataplane.GlobalCtrScreenSynFlood, "syn-flood"},
		{dataplane.GlobalCtrScreenICMPFlood, "icmp-flood"},
		{dataplane.GlobalCtrScreenUDPFlood, "udp-flood"},
		{dataplane.GlobalCtrScreenPortScan, "port-scan"},
		{dataplane.GlobalCtrScreenIPSweep, "ip-sweep"},
		{dataplane.GlobalCtrScreenLandAttack, "land-attack"},
		{dataplane.GlobalCtrScreenPingOfDeath, "ping-of-death"},
		{dataplane.GlobalCtrScreenTearDrop, "tear-drop"},
		{dataplane.GlobalCtrScreenTCPSynFin, "tcp-syn-fin"},
		{dataplane.GlobalCtrScreenTCPNoFlag, "tcp-no-flag"},
		{dataplane.GlobalCtrScreenTCPFinNoAck, "tcp-fin-no-ack"},
		{dataplane.GlobalCtrScreenWinNuke, "winnuke"},
		{dataplane.GlobalCtrScreenIPSrcRoute, "ip-source-route"},
		{dataplane.GlobalCtrScreenSynFrag, "syn-fragment"},
		{dataplane.GlobalCtrSyncookieSent, "syncookie-sent"},
		{dataplane.GlobalCtrSyncookieValid, "syncookie-valid"},
		{dataplane.GlobalCtrSyncookieInvalid, "syncookie-invalid"},
		{dataplane.GlobalCtrSyncookieBypass, "syncookie-bypass"},
	}
	for _, sc := range screenCounters {
		v := readCounter(sc.idx)
		if v > 0 {
			screenDetails[sc.name] = v
		}
	}

	return &pb.GetGlobalStatsResponse{
		RxPackets:          readCounter(dataplane.GlobalCtrRxPackets),
		TxPackets:          readCounter(dataplane.GlobalCtrTxPackets),
		Drops:              readCounter(dataplane.GlobalCtrDrops),
		SessionsCreated:    readCounter(dataplane.GlobalCtrSessionsNew),
		SessionsClosed:     readCounter(dataplane.GlobalCtrSessionsClosed),
		ScreenDrops:        readCounter(dataplane.GlobalCtrScreenDrops),
		PolicyDenies:       readCounter(dataplane.GlobalCtrPolicyDeny),
		NatAllocFailures:   readCounter(dataplane.GlobalCtrNATAllocFail),
		HostInboundDenies:  readCounter(dataplane.GlobalCtrHostInboundDeny),
		TcEgressPackets:    readCounter(dataplane.GlobalCtrTCEgressPackets),
		Nat64Translations:  readCounter(dataplane.GlobalCtrNAT64Xlate),
		HostInboundAllowed: readCounter(dataplane.GlobalCtrHostInbound),
		ScreenDropDetails:  screenDetails,
	}, nil
}

func (s *Server) GetSystemInfo(_ context.Context, req *pb.GetSystemInfoRequest) (*pb.GetSystemInfoResponse, error) {
	var buf strings.Builder

	switch req.Type {
	case "uptime":
		data, err := os.ReadFile("/proc/uptime")
		if err != nil {
			return nil, status.Errorf(codes.Internal, "reading uptime: %v", err)
		}
		fields := strings.Fields(string(data))
		if len(fields) < 1 {
			return nil, status.Error(codes.Internal, "unexpected /proc/uptime format")
		}
		var upSec float64
		fmt.Sscanf(fields[0], "%f", &upSec)

		days := int(upSec) / 86400
		hours := (int(upSec) % 86400) / 3600
		mins := (int(upSec) % 3600) / 60
		secs := int(upSec) % 60

		now := time.Now()
		fmt.Fprintf(&buf, "Current time: %s\n", now.Format("2006-01-02 15:04:05 MST"))
		fmt.Fprintf(&buf, "System booted: %s\n", now.Add(-time.Duration(upSec)*time.Second).Format("2006-01-02 15:04:05 MST"))
		fmt.Fprintf(&buf, "Daemon uptime: %s\n", time.Since(s.startTime).Truncate(time.Second))
		if days > 0 {
			fmt.Fprintf(&buf, "System uptime: %d days, %d hours, %d minutes, %d seconds\n", days, hours, mins, secs)
		} else {
			fmt.Fprintf(&buf, "System uptime: %d hours, %d minutes, %d seconds\n", hours, mins, secs)
		}

	case "memory":
		data, err := os.ReadFile("/proc/meminfo")
		if err != nil {
			return nil, status.Errorf(codes.Internal, "reading meminfo: %v", err)
		}
		info := make(map[string]uint64)
		for _, line := range strings.Split(string(data), "\n") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				key := strings.TrimSuffix(parts[0], ":")
				val, _ := strconv.ParseUint(parts[1], 10, 64)
				info[key] = val
			}
		}
		total := info["MemTotal"]
		free := info["MemFree"]
		buffers := info["Buffers"]
		cached := info["Cached"]
		available := info["MemAvailable"]
		used := total - free - buffers - cached

		fmt.Fprintf(&buf, "%-20s %10s\n", "Type", "kB")
		fmt.Fprintf(&buf, "%-20s %10d\n", "Total memory", total)
		fmt.Fprintf(&buf, "%-20s %10d\n", "Used memory", used)
		fmt.Fprintf(&buf, "%-20s %10d\n", "Free memory", free)
		fmt.Fprintf(&buf, "%-20s %10d\n", "Buffers", buffers)
		fmt.Fprintf(&buf, "%-20s %10d\n", "Cached", cached)
		fmt.Fprintf(&buf, "%-20s %10d\n", "Available", available)
		if total > 0 {
			fmt.Fprintf(&buf, "Utilization: %.1f%%\n", float64(used)/float64(total)*100)
		}

	case "processes":
		cmd := exec.Command("ps", "aux", "--sort=-rss")
		out, err := cmd.Output()
		if err != nil {
			return nil, status.Errorf(codes.Internal, "running ps: %v", err)
		}
		buf.Write(out)

	case "storage":
		cmd := exec.Command("df", "-h")
		out, err := cmd.Output()
		if err != nil {
			return nil, status.Errorf(codes.Internal, "running df: %v", err)
		}
		buf.Write(out)

	case "arp":
		neighbors, err := netlink.NeighList(0, netlink.FAMILY_V4)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "listing ARP entries: %v", err)
		}
		writeNeighSummary(&buf, neighbors, neighStateStr)
		fmt.Fprintf(&buf, "%-18s %-20s %-12s %-10s\n", "MAC Address", "Address", "Interface", "State")
		for _, n := range neighbors {
			if n.IP == nil || n.HardwareAddr == nil {
				continue
			}
			ifName := ""
			if link, err := netlink.LinkByIndex(n.LinkIndex); err == nil {
				ifName = link.Attrs().Name
			}
			fmt.Fprintf(&buf, "%-18s %-20s %-12s %-10s\n",
				n.HardwareAddr, n.IP, ifName, neighStateStr(n.State))
		}

	case "ipv6-neighbors":
		neighbors, err := netlink.NeighList(0, netlink.FAMILY_V6)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "listing IPv6 neighbors: %v", err)
		}
		writeNeighSummary(&buf, neighbors, neighStateStr)
		fmt.Fprintf(&buf, "%-18s %-40s %-12s %-10s\n", "MAC Address", "IPv6 Address", "Interface", "State")
		for _, n := range neighbors {
			if n.IP == nil || n.HardwareAddr == nil {
				continue
			}
			ifName := ""
			if link, err := netlink.LinkByIndex(n.LinkIndex); err == nil {
				ifName = link.Attrs().Name
			}
			fmt.Fprintf(&buf, "%-18s %-40s %-12s %-10s\n",
				n.HardwareAddr, n.IP, ifName, neighStateStr(n.State))
		}

	case "boot-messages":
		cmd := exec.Command("journalctl", "--boot", "-n", "100", "--no-pager")
		out, err := cmd.Output()
		if err != nil {
			return nil, status.Errorf(codes.Internal, "running journalctl: %v", err)
		}
		buf.Write(out)

	case "connections":
		cmd := exec.Command("ss", "-tnp")
		out, err := cmd.Output()
		if err != nil {
			return nil, status.Errorf(codes.Internal, "running ss: %v", err)
		}
		buf.Write(out)

	case "users":
		cfg := s.store.ActiveConfig()
		if cfg == nil || cfg.System.Login == nil || len(cfg.System.Login.Users) == 0 {
			fmt.Fprintln(&buf, "No login users configured")
		} else {
			fmt.Fprintf(&buf, "%-20s %-8s %-20s %s\n", "Username", "UID", "Class", "SSH Keys")
			for _, u := range cfg.System.Login.Users {
				uid := "-"
				if u.UID > 0 {
					uid = strconv.Itoa(u.UID)
				}
				class := u.Class
				if class == "" {
					class = "-"
				}
				fmt.Fprintf(&buf, "%-20s %-8s %-20s %d\n", u.Name, uid, class, len(u.SSHKeys))
			}
		}

	default:
		return nil, status.Errorf(codes.InvalidArgument, "unknown system info type: %s", req.Type)
	}

	return &pb.GetSystemInfoResponse{Output: buf.String()}, nil
}
