// Phase 2 of #1043: extract the `chassis` ShowText case body into a
// dedicated method. Same methodology as Phase 1 (#1148): semantic
// relocation, no behavior change. The case body is moved verbatim
// apart from `&buf` references becoming `buf` (passed-in
// `*strings.Builder`). Output is unchanged.

package grpcapi

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// showChassis renders `cli show chassis` — CPU, memory, load, uptime,
// kernel info from /proc/cpuinfo, /proc/meminfo, sysinfo, uname.
func (s *Server) showChassis(buf *strings.Builder) {
	// CPU info
	cpuData, _ := os.ReadFile("/proc/cpuinfo")
	cpuModel := ""
	cpuCount := 0
	for _, line := range strings.Split(string(cpuData), "\n") {
		if strings.HasPrefix(line, "model name") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				cpuModel = strings.TrimSpace(parts[1])
			}
			cpuCount++
		}
	}
	if cpuModel != "" {
		fmt.Fprintf(buf, "CPU: %s (%d cores)\n", cpuModel, cpuCount)
	}
	// Memory
	memData, _ := os.ReadFile("/proc/meminfo")
	for _, line := range strings.Split(string(memData), "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				if kb, err := strconv.ParseUint(parts[1], 10, 64); err == nil {
					fmt.Fprintf(buf, "Memory: %.1f GB total\n", float64(kb)/(1024*1024))
				}
			}
			break
		}
	}
	// Memory — include free/available
	memFree := uint64(0)
	memAvail := uint64(0)
	for _, line := range strings.Split(string(memData), "\n") {
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		if strings.HasPrefix(line, "MemFree:") {
			if kb, err := strconv.ParseUint(parts[1], 10, 64); err == nil {
				memFree = kb
			}
		}
		if strings.HasPrefix(line, "MemAvailable:") {
			if kb, err := strconv.ParseUint(parts[1], 10, 64); err == nil {
				memAvail = kb
			}
		}
	}
	if memAvail > 0 {
		fmt.Fprintf(buf, "Memory available: %.1f GB\n", float64(memAvail)/(1024*1024))
	} else if memFree > 0 {
		fmt.Fprintf(buf, "Memory free: %.1f GB\n", float64(memFree)/(1024*1024))
	}
	// Load average
	var sysinfo unix.Sysinfo_t
	if err := unix.Sysinfo(&sysinfo); err == nil {
		loads := [3]float64{
			float64(sysinfo.Loads[0]) / 65536.0,
			float64(sysinfo.Loads[1]) / 65536.0,
			float64(sysinfo.Loads[2]) / 65536.0,
		}
		fmt.Fprintf(buf, "Load average: %.2f, %.2f, %.2f\n", loads[0], loads[1], loads[2])
		days := sysinfo.Uptime / 86400
		hours := (sysinfo.Uptime % 86400) / 3600
		mins := (sysinfo.Uptime % 3600) / 60
		fmt.Fprintf(buf, "System uptime: %d days, %d:%02d\n", days, hours, mins)
	}
	// Kernel
	var uts unix.Utsname
	if err := unix.Uname(&uts); err == nil {
		release := strings.TrimRight(string(uts.Release[:]), "\x00")
		machine := strings.TrimRight(string(uts.Machine[:]), "\x00")
		fmt.Fprintf(buf, "Kernel: %s (%s)\n", release, machine)
	}
}
