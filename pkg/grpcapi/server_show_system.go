// Phase 7 of #1043: extract the system-info ShowText case bodies into
// dedicated methods. Same methodology as Phases 1-6 (#1148, #1150,
// #1151, #1153, #1154, #1155): semantic relocation, no behavior
// change. Each case body is moved verbatim apart from `&buf`
// references becoming `buf` (passed-in `*strings.Builder`).
//
// `showCommitHistory` returns `error` (the original case had an early
// `return nil, status.Errorf` path) — same pattern as Phase 6's
// interfaces methods. The dispatcher rewraps via
// `if err := …; err != nil { return nil, err }`.
//
// Cases that used `break` on a no-config guard (system-services, ntp,
// system-syslog) are converted to early `return` so the rest of the
// method body is dead-code-skipped, semantically identical to the
// original `break`-out-of-switch behavior because the original
// statements after the `break` were inside the same case body and
// therefore unreachable too.

package grpcapi

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// showVersion renders daemon version, hostname, kernel, and uptime.
func (s *Server) showVersion(buf *strings.Builder) {
	ver := s.version
	if ver == "" {
		ver = "dev"
	}
	fmt.Fprintf(buf, "xpf eBPF firewall %s\n", ver)
	var uts unix.Utsname
	if err := unix.Uname(&uts); err == nil {
		sysname := strings.TrimRight(string(uts.Sysname[:]), "\x00")
		release := strings.TrimRight(string(uts.Release[:]), "\x00")
		machine := strings.TrimRight(string(uts.Machine[:]), "\x00")
		nodename := strings.TrimRight(string(uts.Nodename[:]), "\x00")
		fmt.Fprintf(buf, "Hostname: %s\n", nodename)
		fmt.Fprintf(buf, "Kernel: %s %s (%s)\n", sysname, release, machine)
	}
	fmt.Fprintf(buf, "Daemon uptime: %s\n", time.Since(s.startTime).Truncate(time.Second))
}

// showStorage renders /, /var, /tmp filesystem usage.
func (s *Server) showStorage(buf *strings.Builder) {
	var stat unix.Statfs_t
	mounts := []struct{ path, name string }{
		{"/", "Root (/)"},
		{"/var", "/var"},
		{"/tmp", "/tmp"},
	}
	fmt.Fprintf(buf, "%-20s %12s %12s %12s %6s\n", "Filesystem", "Size", "Used", "Avail", "Use%")
	for _, m := range mounts {
		if err := unix.Statfs(m.path, &stat); err != nil {
			continue
		}
		total := stat.Blocks * uint64(stat.Bsize)
		free := stat.Bavail * uint64(stat.Bsize)
		used := total - (stat.Bfree * uint64(stat.Bsize))
		pct := float64(0)
		if total > 0 {
			pct = float64(used) / float64(total) * 100
		}
		fmt.Fprintf(buf, "%-20s %11.1fG %11.1fG %11.1fG %5.0f%%\n",
			m.name,
			float64(total)/float64(1<<30),
			float64(used)/float64(1<<30),
			float64(free)/float64(1<<30),
			pct)
	}
}

// showCommitHistory renders the most recent 50 commit-history entries.
// Returns error when the underlying configstore lookup fails so the
// dispatcher can re-raise as a gRPC status error.
func (s *Server) showCommitHistory(buf *strings.Builder) error {
	entries, err := s.store.ListCommitHistory(50)
	if err != nil {
		return status.Errorf(codes.Internal, "commit history: %v", err)
	}
	if len(entries) == 0 {
		buf.WriteString("No commit history available\n")
		return nil
	}
	for i, e := range entries {
		detail := ""
		if e.Detail != "" {
			detail = "  " + e.Detail
		}
		fmt.Fprintf(buf, "  %d  %s  %s%s\n", i, e.Timestamp.Format("2006-01-02 15:04:05"), e.Action, detail)
	}
	return nil
}

// showAlarms renders config-validation warnings as alarms.
func (s *Server) showAlarms(buf *strings.Builder) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		buf.WriteString("No active configuration loaded\n")
		return
	}
	warnings := config.ValidateConfig(cfg)
	if len(warnings) == 0 {
		buf.WriteString("No alarms currently active\n")
		return
	}
	fmt.Fprintf(buf, "%d active alarm(s):\n", len(warnings))
	for _, w := range warnings {
		fmt.Fprintf(buf, "  WARNING: %s\n", w)
	}
}

// showChassisEnvironment renders thermal-zone temperatures and the
// system uptime + load average.
func (s *Server) showChassisEnvironment(buf *strings.Builder) {
	thermalZones, _ := filepath.Glob("/sys/class/thermal/thermal_zone*/temp")
	if len(thermalZones) > 0 {
		fmt.Fprintln(buf, "Temperature:")
		for _, tz := range thermalZones {
			data, err := os.ReadFile(tz)
			if err != nil {
				continue
			}
			millideg, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
			if err != nil {
				continue
			}
			typeFile := filepath.Join(filepath.Dir(tz), "type")
			name := filepath.Base(filepath.Dir(tz))
			if typeData, err := os.ReadFile(typeFile); err == nil {
				name = strings.TrimSpace(string(typeData))
			}
			fmt.Fprintf(buf, "  %-30s %d.%d C\n", name, millideg/1000, (millideg%1000)/100)
		}
		fmt.Fprintln(buf)
	}
	var sysinfo unix.Sysinfo_t
	if err := unix.Sysinfo(&sysinfo); err == nil {
		days := sysinfo.Uptime / 86400
		hours := (sysinfo.Uptime % 86400) / 3600
		mins := (sysinfo.Uptime % 3600) / 60
		fmt.Fprintf(buf, "System uptime: %d days, %d:%02d\n", days, hours, mins)
		fmt.Fprintf(buf, "Load average: %.2f %.2f %.2f\n",
			float64(sysinfo.Loads[0])/65536.0,
			float64(sysinfo.Loads[1])/65536.0,
			float64(sysinfo.Loads[2])/65536.0)
	}
}

// showSystemServices renders gRPC/HTTP/SSH/WebManagement/DNS/NTP and
// derived service-state summaries (security log, syslog, NetFlow,
// IPFIX, AppID, RPM).
func (s *Server) showSystemServices(buf *strings.Builder) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		fmt.Fprintln(buf, "No active configuration")
		return
	}
	fmt.Fprintln(buf, "System services:")
	fmt.Fprintln(buf, "  gRPC:           127.0.0.1:50051 (always on)")
	fmt.Fprintln(buf, "  HTTP REST:      127.0.0.1:8080 (always on)")
	if cfg.System.Services != nil {
		if cfg.System.Services.SSH != nil {
			rootLogin := cfg.System.Services.SSH.RootLogin
			if rootLogin == "" {
				rootLogin = "deny"
			}
			fmt.Fprintf(buf, "  SSH:            enabled (root-login: %s)\n", rootLogin)
		}
		if cfg.System.Services.WebManagement != nil {
			wm := cfg.System.Services.WebManagement
			if wm.HTTP {
				iface := "all"
				if wm.HTTPInterface != "" {
					iface = wm.HTTPInterface
				}
				fmt.Fprintf(buf, "  Web HTTP:       enabled (interface: %s)\n", iface)
			}
			if wm.HTTPS {
				iface := "all"
				if wm.HTTPSInterface != "" {
					iface = wm.HTTPSInterface
				}
				cert := ""
				if wm.SystemGeneratedCert {
					cert = ", system-generated-certificate"
				}
				fmt.Fprintf(buf, "  Web HTTPS:      enabled (interface: %s%s)\n", iface, cert)
			}
		}
		if cfg.System.Services.DNSEnabled {
			fmt.Fprintln(buf, "  DNS:            enabled")
		}
	}
	if len(cfg.System.NameServers) > 0 {
		fmt.Fprintf(buf, "  DNS servers:    %s\n", strings.Join(cfg.System.NameServers, ", "))
	}
	if len(cfg.System.NTPServers) > 0 {
		fmt.Fprintf(buf, "  NTP servers:    %s\n", strings.Join(cfg.System.NTPServers, ", "))
		if cfg.System.NTPThreshold > 0 && cfg.System.NTPThresholdAction != "" {
			fmt.Fprintf(buf, "  NTP threshold:  %d seconds (%s)\n", cfg.System.NTPThreshold, cfg.System.NTPThresholdAction)
		}
	}
	if cfg.Security.Log.Mode != "" {
		fmt.Fprintf(buf, "  Security log:   mode %s\n", cfg.Security.Log.Mode)
	}
	if len(cfg.Security.Log.Streams) > 0 {
		fmt.Fprintf(buf, "  Syslog:         %d stream(s)\n", len(cfg.Security.Log.Streams))
	}
	if cfg.Services.FlowMonitoring != nil && cfg.Services.FlowMonitoring.Version9 != nil {
		fmt.Fprintf(buf, "  NetFlow v9:     %d template(s)\n", len(cfg.Services.FlowMonitoring.Version9.Templates))
	}
	if cfg.Services.FlowMonitoring != nil && cfg.Services.FlowMonitoring.VersionIPFIX != nil {
		fmt.Fprintf(buf, "  IPFIX:          %d template(s)\n", len(cfg.Services.FlowMonitoring.VersionIPFIX.Templates))
	}
	if cfg.Services.ApplicationIdentification {
		fmt.Fprintln(buf, "  AppID:          enabled")
	}
	if cfg.Services.RPM != nil && len(cfg.Services.RPM.Probes) > 0 {
		total := 0
		for _, probe := range cfg.Services.RPM.Probes {
			total += len(probe.Tests)
		}
		fmt.Fprintf(buf, "  RPM probes:     %d probe(s), %d test(s)\n", len(cfg.Services.RPM.Probes), total)
	}
}

// showNTP renders configured NTP servers and chronyc/ntpq tracking.
func (s *Server) showNTP(buf *strings.Builder) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		fmt.Fprintln(buf, "No active configuration")
		return
	}
	if len(cfg.System.NTPServers) == 0 {
		fmt.Fprintln(buf, "No NTP servers configured")
		return
	}
	fmt.Fprintln(buf, "NTP servers:")
	for _, server := range cfg.System.NTPServers {
		fmt.Fprintf(buf, "  %s\n", server)
	}
	if cfg.System.NTPThreshold > 0 && cfg.System.NTPThresholdAction != "" {
		fmt.Fprintf(buf, "  Threshold: %d seconds (%s)\n", cfg.System.NTPThreshold, cfg.System.NTPThresholdAction)
	}
	if out, err := exec.Command("chronyc", "tracking").CombinedOutput(); err == nil {
		writeChronyTracking(buf, string(out))
		if src, err := exec.Command("chronyc", "-n", "sources").CombinedOutput(); err == nil {
			fmt.Fprintf(buf, "\nNTP sources:\n%s", string(src))
		}
	} else if out, err := exec.Command("ntpq", "-pn").CombinedOutput(); err == nil {
		fmt.Fprintf(buf, "\nNTP peers:\n%s\n", string(out))
	} else if out, err := exec.Command("timedatectl", "show", "--property=NTPSynchronized", "--value").CombinedOutput(); err == nil {
		fmt.Fprintf(buf, "\nNTP synchronized: %s\n", strings.TrimSpace(string(out)))
	}
}

// showSystemSyslog renders configured syslog hosts/files/users.
func (s *Server) showSystemSyslog(buf *strings.Builder) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		fmt.Fprintln(buf, "No active configuration")
		return
	}
	if cfg.System.Syslog == nil {
		fmt.Fprintln(buf, "No system syslog configuration")
		return
	}
	sys := cfg.System.Syslog
	if len(sys.Hosts) > 0 {
		fmt.Fprintln(buf, "Syslog hosts:")
		for _, h := range sys.Hosts {
			fmt.Fprintf(buf, "  %-20s", h.Address)
			if h.AllowDuplicates {
				fmt.Fprint(buf, " allow-duplicates")
			}
			fmt.Fprintln(buf)
			for _, f := range h.Facilities {
				fmt.Fprintf(buf, "    %-20s %s\n", f.Facility, f.Severity)
			}
		}
	}
	if len(sys.Files) > 0 {
		fmt.Fprintln(buf, "Syslog files:")
		for _, f := range sys.Files {
			fmt.Fprintf(buf, "  %-20s %s %s\n", f.Name, f.Facility, f.Severity)
		}
	}
	if len(sys.Users) > 0 {
		fmt.Fprintln(buf, "Syslog users:")
		for _, u := range sys.Users {
			fmt.Fprintf(buf, "  %-20s %s %s\n", u.User, u.Facility, u.Severity)
		}
	}
}
