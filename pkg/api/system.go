package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

func (s *Server) systemInfoHandler(w http.ResponseWriter, r *http.Request) {
	typ := r.URL.Query().Get("type")
	var b strings.Builder

	switch typ {
	case "uptime":
		data, err := os.ReadFile("/proc/uptime")
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		fields := strings.Fields(string(data))
		if len(fields) < 1 {
			writeError(w, http.StatusInternalServerError, "unexpected /proc/uptime format")
			return
		}
		var upSec float64
		fmt.Sscanf(fields[0], "%f", &upSec)

		days := int(upSec) / 86400
		hours := (int(upSec) % 86400) / 3600
		mins := (int(upSec) % 3600) / 60
		secs := int(upSec) % 60

		now := time.Now()
		fmt.Fprintf(&b, "Current time: %s\n", now.Format("2006-01-02 15:04:05 MST"))
		fmt.Fprintf(&b, "System booted: %s\n", now.Add(-time.Duration(upSec)*time.Second).Format("2006-01-02 15:04:05 MST"))
		fmt.Fprintf(&b, "Daemon uptime: %s\n", time.Since(s.startTime).Truncate(time.Second))
		if days > 0 {
			fmt.Fprintf(&b, "System uptime: %d days, %d hours, %d minutes, %d seconds\n", days, hours, mins, secs)
		} else {
			fmt.Fprintf(&b, "System uptime: %d hours, %d minutes, %d seconds\n", hours, mins, secs)
		}

	case "memory":
		data, err := os.ReadFile("/proc/meminfo")
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
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

		fmt.Fprintf(&b, "%-20s %10s\n", "Type", "kB")
		fmt.Fprintf(&b, "%-20s %10d\n", "Total memory", total)
		fmt.Fprintf(&b, "%-20s %10d\n", "Used memory", used)
		fmt.Fprintf(&b, "%-20s %10d\n", "Free memory", free)
		fmt.Fprintf(&b, "%-20s %10d\n", "Buffers", buffers)
		fmt.Fprintf(&b, "%-20s %10d\n", "Cached", cached)
		fmt.Fprintf(&b, "%-20s %10d\n", "Available", available)
		if total > 0 {
			fmt.Fprintf(&b, "Utilization: %.1f%%\n", float64(used)/float64(total)*100)
		}

	default:
		writeError(w, http.StatusBadRequest, "type parameter required (uptime, memory)")
		return
	}

	writeOK(w, TextResponse{Output: b.String()})
}

func (s *Server) pingHandler(w http.ResponseWriter, r *http.Request) {
	var req PingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.Target == "" {
		writeError(w, http.StatusBadRequest, "target required")
		return
	}

	count := req.Count
	if count <= 0 {
		count = 5
	}
	if count > 100 {
		count = 100
	}

	args := []string{"-c", fmt.Sprintf("%d", count)}
	if req.Source != "" {
		args = append(args, "-I", req.Source)
	}
	if req.Size > 0 {
		args = append(args, "-s", fmt.Sprintf("%d", req.Size))
	}
	args = append(args, req.Target)

	var cmd []string
	if req.RoutingInstance != "" {
		vrfDev := req.RoutingInstance
		if !strings.HasPrefix(vrfDev, "vrf-") {
			vrfDev = "vrf-" + vrfDev
		}
		cmd = append(cmd, "ip", "vrf", "exec", vrfDev)
	}
	cmd = append(cmd, "ping")
	cmd = append(cmd, args...)

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, cmd[0], cmd[1:]...).CombinedOutput()
	output := string(out)
	if err != nil {
		output += "\n" + err.Error()
	}
	writeOK(w, TextResponse{Output: output})
}

func (s *Server) tracerouteHandler(w http.ResponseWriter, r *http.Request) {
	var req TracerouteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.Target == "" {
		writeError(w, http.StatusBadRequest, "target required")
		return
	}

	args := []string{}
	if req.Source != "" {
		args = append(args, "-s", req.Source)
	}
	args = append(args, req.Target)

	var cmd []string
	if req.RoutingInstance != "" {
		vrfDev := req.RoutingInstance
		if !strings.HasPrefix(vrfDev, "vrf-") {
			vrfDev = "vrf-" + vrfDev
		}
		cmd = append(cmd, "ip", "vrf", "exec", vrfDev)
	}
	cmd = append(cmd, "traceroute")
	cmd = append(cmd, args...)

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, cmd[0], cmd[1:]...).CombinedOutput()
	output := string(out)
	if err != nil {
		output += "\n" + err.Error()
	}
	writeOK(w, TextResponse{Output: output})
}

func (s *Server) systemBuffersHandler(w http.ResponseWriter, _ *http.Request) {
	if s.dp == nil || !s.dp.IsLoaded() {
		writeOK(w, []BufferInfo{})
		return
	}

	if provider, ok := s.dp.(interface {
		Status() (dpuserspace.ProcessStatus, error)
	}); ok {
		status, err := provider.Status()
		if err != nil {
			msg := fmt.Sprintf("userspace buffer status unavailable: %v", err)
			writeError(w, http.StatusServiceUnavailable, msg)
			return
		}
		rows := dpuserspace.StructuredSystemBufferRows(status, false)
		if len(rows.Utilization) == 0 {
			msg := "userspace buffer status missing bounded capacity fields"
			writeError(w, http.StatusServiceUnavailable, msg)
			return
		}
		buffers := make([]BufferInfo, 0, len(rows.Utilization)+len(rows.Counters))
		for _, row := range rows.Utilization {
			buffers = append(buffers, BufferInfo{
				Name:         row.Name,
				Type:         "Userspace",
				Scope:        row.Scope,
				MaxEntries:   row.Capacity,
				UsedCount:    row.Used,
				UsagePercent: row.UsagePercent,
				Status:       row.Status,
			})
		}
		for _, row := range rows.Counters {
			buffers = append(buffers, BufferInfo{
				Name:   row.Name,
				Type:   "UserspaceCounter",
				Scope:  row.Scope,
				Value:  row.Value,
				Status: "OK",
			})
		}
		writeOK(w, buffers)
		return
	}

	stats := s.dp.GetMapStats()
	buffers := make([]BufferInfo, 0, len(stats))
	for _, st := range stats {
		usage := 0.0
		status := "OK"
		if st.MaxEntries > 0 && st.Type != "Array" && st.Type != "PerCPUArray" {
			usage = float64(st.UsedCount) / float64(st.MaxEntries) * 100
			if usage >= 90 {
				status = "CRITICAL"
			} else if usage >= 80 {
				status = "WARNING"
			}
		}
		buffers = append(buffers, BufferInfo{
			Name:         st.Name,
			Type:         st.Type,
			MaxEntries:   uint64(st.MaxEntries),
			UsedCount:    uint64(st.UsedCount),
			UsagePercent: usage,
			Status:       status,
		})
	}
	writeOK(w, buffers)
}

func (s *Server) systemActionHandler(w http.ResponseWriter, r *http.Request) {
	var req SystemActionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	switch req.Action {
	case "reboot":
		go func() {
			time.Sleep(1 * time.Second)
			exec.Command("systemctl", "reboot").Run()
		}()
		writeOK(w, map[string]string{"message": "System going down for reboot NOW!"})

	case "halt":
		go func() {
			time.Sleep(1 * time.Second)
			exec.Command("systemctl", "halt").Run()
		}()
		writeOK(w, map[string]string{"message": "System halting NOW!"})

	default:
		writeError(w, http.StatusBadRequest, fmt.Sprintf("unknown action: %s (use 'reboot' or 'halt')", req.Action))
	}
}
