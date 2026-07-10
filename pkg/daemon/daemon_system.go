// Package daemon implements the xpf daemon lifecycle.
package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/fsatomic"
	"github.com/psaab/xpf/pkg/logging"
	"github.com/vishvananda/netlink"
)

// applySyslogConfig constructs syslog clients or local log writers from the
// config and applies them to the event reader. When mode is "event", events
// are written to a local file; when "stream" (default), events are forwarded
// to remote syslog servers. Also updates zone name resolution for structured logging.
func (d *Daemon) applySyslogConfig(er *logging.EventReader, cfg *config.Config) {
	if er == nil {
		return
	}
	// Update zone name map for structured syslog formatting
	zoneNames := make(map[uint16]string)
	zoneIDs := buildZoneIDs(cfg)
	for name, id := range zoneIDs {
		zoneNames[id] = name
	}
	er.SetZoneNames(zoneNames)

	// Wire policy names and app names for structured logging
	if d.dp != nil {
		if cr := d.applyResult(); cr != nil {
			er.SetPolicyNames(cr.PolicyNames)
			if cr.AppNames != nil {
				er.SetAppNames(cr.AppNames)
			}
		}
	}

	// Wire interface names (ifindex -> name) from config
	ifNames := make(map[uint32]string)
	for name, iface := range cfg.Interfaces.Interfaces {
		ifName := name
		if iface != nil && iface.Name != "" {
			ifName = iface.Name
		}
		if link, err := netlink.LinkByName(ifName); err == nil {
			ifNames[uint32(link.Attrs().Index)] = ifName
		}
	}
	er.SetIfNames(ifNames)

	// Event mode: write to local file instead of remote syslog
	if cfg.Security.Log.Mode == "event" {
		er.ReplaceSyslogClients(nil) // close + clear any remote clients (#3579)
		lw, err := logging.NewLocalLogWriter(logging.LocalLogConfig{})
		if err != nil {
			slog.Warn("failed to create local log writer", "err", err)
		} else {
			if cfg.Security.Log.Format != "" {
				lw.Format = cfg.Security.Log.Format
			}
			er.ReplaceLocalWriters([]*logging.LocalLogWriter{lw})
			slog.Info("security log event mode: writing to /var/log/xpf/security.log",
				"format", cfg.Security.Log.Format)
		}
		d.applyAggregator(er, cfg)
		return
	}

	// Stream mode (default): clear local writers, set up remote syslog
	er.ReplaceLocalWriters(nil)

	if len(cfg.Security.Log.Streams) == 0 {
		// Tear down any clients a prior config installed: a day-2 commit that
		// removes ALL streams must not leave lingering clients forwarding to a
		// deleted destination. This matches the event-mode (line ~65) and
		// applySystemSyslog teardown paths, which already clear clients. It
		// matters most after #3351: a down-at-apply TCP/TLS stream is now an
		// installed RECONNECTING client, so without this it would resume
		// sending audit logs to a removed receiver once that receiver recovers.
		// ReplaceSyslogClients (not the non-closing SetSyslogClients) also
		// Closes the superseded clients' connections so a CONNECTED stream's
		// fd is not leaked when all streams are removed (#3579).
		er.ReplaceSyslogClients(nil)
		d.applyAggregator(er, cfg)
		return
	}
	// Resolve global source-interface to IP (fallback for streams without source-address).
	// Prefer PrimaryAddress from config if set on the source interface unit.
	var globalSourceAddr string
	if cfg.Security.Log.SourceInterface != "" {
		globalSourceAddr = resolveSourceAddr(cfg, cfg.Security.Log.SourceInterface)
	}

	var clients []*logging.SyslogClient
	for name, stream := range cfg.Security.Log.Streams {
		srcAddr := stream.SourceAddress
		if srcAddr == "" {
			srcAddr = globalSourceAddr
		}
		protocol := stream.Transport.Protocol
		if protocol == "" {
			protocol = "udp"
		}
		// #3350: the final *tls.Config is nil — a TLS stream trusts the system
		// CA roots (pkg/logging/syslog.go dialTLS). A named `transport
		// tls-profile` is NOT honored here (there is no TLS profile definition
		// stanza to resolve into a cert/CA/SNI config); it is rejected at commit
		// by validateSecurityLogStreamTLSProfileAST so it can never silently
		// degrade the secure-syslog posture. If profile resolution is ever
		// implemented, build the *tls.Config from stream.Transport.TLSProfile
		// here and lift that compiler reject.
		client, err := logging.NewSyslogClientTransport(stream.Host, stream.Port, srcAddr, protocol, nil)
		if err != nil {
			if client == nil {
				// UDP / unrecoverable construction error: skip the stream.
				slog.Warn("failed to create syslog client",
					"stream", name, "host", stream.Host, "protocol", protocol, "err", err)
				continue
			}
			// #3351: a TCP/TLS receiver unreachable at apply returns a usable
			// but unconnected client. Install it in this reconnecting state so
			// audit logging resumes when the receiver comes back, instead of
			// silently dropping the stream for the life of this config.
			slog.Warn("syslog stream receiver unreachable at apply; installed in reconnecting state",
				"stream", name, "host", stream.Host, "protocol", protocol, "err", err)
		}
		if stream.Severity != "" {
			client.MinSeverity = logging.ParseSeverity(stream.Severity)
		}
		if stream.Facility != "" {
			client.Facility = logging.ParseFacility(stream.Facility)
		}
		if stream.Category != "" {
			client.Categories = logging.ParseCategory(stream.Category)
		}
		// Per-stream format overrides global log format
		format := stream.Format
		if format == "" {
			format = cfg.Security.Log.Format
		}
		if format != "" {
			client.Format = format
		}
		slog.Info("syslog stream configured",
			"stream", name, "host", stream.Host, "port", stream.Port,
			"protocol", protocol, "severity", stream.Severity,
			"facility", stream.Facility, "format", format,
			"category", stream.Category)
		clients = append(clients, client)
	}
	// #3579: install the freshly-built client set AND close the superseded
	// set in one atomic swap. applySyslogConfig rebuilds every SyslogClient
	// from config on each apply (the loop above always constructs new
	// objects via NewSyslogClientTransport), so the prior set is ALWAYS fully
	// superseded by-object and every old client's connection must be closed —
	// otherwise a re-apply that changed or dropped a CONNECTED TCP/TLS stream
	// would leak the old socket (fd). ReplaceSyslogClients (the closing
	// variant the CLI apply path already uses, pkg/cli/apply.go) closes the
	// old set AFTER releasing syslogMu, and SyslogClient.Close only takes the
	// client's own mutex (no slog under it), so the close cannot re-enter the
	// slog->syslog handler path under a held lock (#2285). The prior
	// len(clients) > 0 guard is intentionally gone: when streams are
	// configured but none could be built (all UDP construction failures), the
	// old clients must still be torn down rather than left forwarding to a
	// stale destination.
	er.ReplaceSyslogClients(clients)
	d.applyAggregator(er, cfg)
}

// resolveSourceAddr returns the source IP for syslog from the given interface.
// It prefers PrimaryAddress from config (stripped to bare IP); falls back to
// the first IPv4 address on the kernel interface.
func resolveSourceAddr(cfg *config.Config, srcIface string) string {
	// Parse "iface.unit" — e.g. "reth1.100" → base="reth1", unit=100
	base, unitStr, hasUnit := strings.Cut(srcIface, ".")
	unitNum := 0
	if hasUnit {
		if n, err := strconv.Atoi(unitStr); err == nil {
			unitNum = n
		}
	}
	if ifc, ok := cfg.Interfaces.Interfaces[base]; ok && ifc != nil {
		if unit, ok := ifc.Units[unitNum]; ok && unit.PrimaryAddress != "" {
			// PrimaryAddress is CIDR — strip the prefix length
			if ip, _, err := net.ParseCIDR(unit.PrimaryAddress); err == nil {
				return ip.String()
			}
		}
	}
	// Fallback: first IPv4 from kernel
	if iface, err := net.InterfaceByName(srcIface); err == nil {
		if addrs, err := iface.Addrs(); err == nil {
			for _, a := range addrs {
				if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
					return ipn.IP.String()
				}
			}
		}
	}
	return ""
}

// aggregationCallback is the single, stable session-aggregation handler
// registered on the EventReader exactly ONCE (aggCBOnce). It reads the live
// SessionAggregator lock-free from the atomic pointer, so a config commit can
// swap the aggregator — or clear it to nil on disable — without ever
// registering a second callback. This is the #4964 fix mirroring the #3932
// flow-trace / #2075 flow-export indirection: the previous applyAggregator
// called er.AddCallback on every report-enabled reconcile, so a long-lived
// daemon leaked one callback (and one never-flushed aggregator) per commit and
// dispatched every event to all of them. A nil pointer (reporting disabled)
// makes this a no-op.
func (d *Daemon) aggregationCallback(rec logging.EventRecord, raw []byte) {
	agg := d.aggregatorPtr.Load()
	if agg == nil {
		return
	}
	agg.HandleEvent(rec, raw)
}

// applyAggregator starts or stops the session aggregation reporter. The stable
// indirection callback (aggregationCallback) is registered on er exactly once
// — the first time reporting is enabled — and every later call only SWAPS the
// active aggregator, cancelling the Run goroutine of the one it replaced. So N
// report-enabled commits leave exactly one registered callback and one live
// aggregator (#4964). Disabling reporting stores a nil aggregator; the stable
// callback stays but becomes a no-op.
func (d *Daemon) applyAggregator(er *logging.EventReader, cfg *config.Config) {
	d.aggReconMu.Lock()
	defer d.aggReconMu.Unlock()

	// Stop the currently-running aggregator generation (if any). Swap the
	// published pointer to nil FIRST so no in-flight event can enter the
	// retired aggregator via the stable callback, THEN cancel its flush
	// goroutine. Retiring in the other order would let HandleEvent keep
	// feeding a cancelled aggregator whose Run no longer flushes (the #4964
	// leak).
	if d.aggCancel != nil {
		d.aggregatorPtr.Store(nil)
		d.aggCancel()
		d.aggCancel = nil
	}

	if !cfg.Security.Log.Report {
		return
	}

	agg := logging.NewSessionAggregator(0, 0) // defaults: 5min, top-10

	// Wire aggregator log output to the first available syslog client or local writer
	agg.SetLogFunc(func(severity int, msg string) {
		er.ForwardLogMsg(severity, msg)
	})

	ctx, cancel := context.WithCancel(context.Background())

	// Publish the new aggregator BEFORE arming the callback (and before Run
	// starts) so the stable callback, once registered, never observes a nil
	// during startup. Add accumulates immediately; Run only flushes.
	d.aggregatorPtr.Store(agg)
	d.aggCancel = cancel

	// Register the single stable callback exactly once, the first time
	// reporting is enabled. A boot with reporting disabled registers nothing;
	// the first enable arms it. er is the same EventReader across every commit
	// (daemon_run.go assigns the boot reader to d.eventReader, daemon_apply.go
	// passes d.eventReader), so one registration covers all generations.
	d.aggCBOnce.Do(func() {
		er.AddCallback(d.aggregationCallback)
	})

	go agg.Run(ctx)
	slog.Info("session aggregation reporting enabled (5 min interval)")
}

// applyHostname sets the system hostname from system { host-name } config.
func (d *Daemon) applyHostname(cfg *config.Config) {
	if cfg.System.HostName == "" {
		return
	}

	current, _ := os.Hostname()
	if current == cfg.System.HostName {
		return
	}

	if err := syscall.Sethostname([]byte(cfg.System.HostName)); err != nil {
		slog.Warn("failed to set hostname", "err", err)
		return
	}

	// Persist to /etc/hostname (DurableState: node identity must survive
	// a power cut so the box keeps its configured name across reboot).
	if err := fsatomic.WriteFileDurable("/etc/hostname", []byte(cfg.System.HostName+"\n"), 0644); err != nil {
		slog.Warn("failed to write /etc/hostname", "err", err)
	}
	slog.Info("hostname set", "hostname", cfg.System.HostName)
}

// isProcessDisabled checks if a Junos process name is in the disabled list.
func isProcessDisabled(cfg *config.Config, name string) bool {
	for _, p := range cfg.System.DisabledProcesses {
		if p == name {
			return true
		}
	}
	return false
}

// DNS reconciliation moved to daemon_dns.go (#1715): xpf owns
// /etc/resolv.conf as a managed plain file via a single applySem-locked
// reconcileDNS. The former applySystemDNS (resolved drop-in + restart),
// restartResolved, and applyDNSService (disable resolved) were removed —
// their write-then-disable apply order was the dangling-symlink race.
// RenderResolvedDropin remains in pkg/daemon/system for any future
// resolved-owner mode but is no longer wired into the apply path.

const (
	chronySourcesPath   = "/etc/chrony/sources.d/xpf.sources"
	chronyThresholdPath = "/etc/chrony/conf.d/xpf-threshold.conf"
)

func renderChronySources(servers []string) string {
	var b strings.Builder
	for _, server := range servers {
		// #4902 render belt: a leniently-loaded / peer-synced value that is not
		// a bare IP or a safe DNS hostname (e.g. an embedded space carrying a
		// second chrony directive token, or a malformed value) is skipped so it
		// cannot inject an extra source-line token or fail the chrony reload. The
		// strict commit gate (config.ValidateNTPServer) rejects it at commit.
		if err := config.ValidateNTPServer(server, nil); err != nil {
			slog.Warn("skipping invalid NTP server", "server", server, "err", err)
			continue
		}
		// Use "pool" for hostnames and "server" for literal IPs.
		directive := "pool"
		if net.ParseIP(server) != nil {
			directive = "server"
		}
		fmt.Fprintf(&b, "%s %s iburst\n", directive, server)
	}
	return b.String()
}

func renderChronyThreshold(threshold int, action string) string {
	if threshold <= 0 || action == "" {
		return ""
	}

	// Only "accept" and "reject" are valid actions. Log and ignore anything else.
	if action != "accept" && action != "reject" {
		slog.Warn("unsupported NTP threshold action, ignoring", "action", action)
		return ""
	}

	// Junos NTP threshold is configured in seconds; chrony directives use
	// seconds as well. "accept" logs offsets beyond the threshold while
	// allowing correction, and "reject" additionally refuses large changes
	// after the initial update.
	var b strings.Builder
	fmt.Fprintf(&b, "logchange %d\n", threshold)
	if action == "reject" {
		fmt.Fprintf(&b, "maxchange %d 1 -1\n", threshold)
	}
	return b.String()
}

func reconcileManagedFile(path, content string) (bool, error) {
	current, err := os.ReadFile(path)
	if err == nil && string(current) == content {
		return false, nil
	}
	if err != nil && !os.IsNotExist(err) {
		return false, fmt.Errorf("read %s: %w", path, err)
	}

	if content == "" {
		removeErr := os.Remove(path)
		if removeErr != nil && !os.IsNotExist(removeErr) {
			return false, fmt.Errorf("remove %s: %w", path, removeErr)
		}
		return removeErr == nil, nil
	}

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return false, fmt.Errorf("create dir for %s: %w", path, err)
	}
	// AtomicGeneratedConfig: regenerated from active config every apply; a
	// torn file is unacceptable but a power-cut loss self-heals next apply.
	if err := fsatomic.WriteFileAtomic(path, []byte(content), 0644); err != nil {
		return false, fmt.Errorf("write %s: %w", path, err)
	}
	return true, nil
}

func reloadChronyRuntime(sourcesChanged, thresholdChanged bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if sourcesChanged {
		chronyCmd := exec.CommandContext(ctx, "chronyc", "reload", "sources")
		chronyCmd.WaitDelay = 5 * time.Second // post-SIGKILL pipe-drain cap (#1794)
		if out, err := chronyCmd.CombinedOutput(); err != nil {
			slog.Warn("failed to reload chrony sources", "err", err, "output", string(out))
		}
	}

	if !thresholdChanged {
		return
	}

	commands := [][]string{
		{"systemctl", "reload", "chrony"},
		{"systemctl", "reload", "chronyd"},
		{"systemctl", "restart", "chrony"},
		{"systemctl", "restart", "chronyd"},
	}
	for _, cmd := range commands {
		reloadCmd := exec.CommandContext(ctx, cmd[0], cmd[1:]...)
		reloadCmd.WaitDelay = 5 * time.Second
		if out, err := reloadCmd.CombinedOutput(); err == nil {
			return
		} else {
			slog.Debug("chrony config reload attempt failed", "cmd", strings.Join(cmd, " "), "err", err, "output", string(out))
		}
	}
	slog.Warn("failed to reload chrony threshold config; change will apply on next chronyd restart")
}

// applySystemNTP configures chrony from system { ntp } config.
// Writes per-server source lines to /etc/chrony/sources.d/xpf.sources and
// optional threshold directives to /etc/chrony/conf.d/xpf-threshold.conf.
func (d *Daemon) applySystemNTP(cfg *config.Config) {
	if isProcessDisabled(cfg, "ntp") {
		sourcesChanged, err := reconcileManagedFile(chronySourcesPath, "")
		if err != nil {
			slog.Warn("failed to remove chrony sources", "err", err)
		}
		thresholdChanged, err := reconcileManagedFile(chronyThresholdPath, "")
		if err != nil {
			slog.Warn("failed to remove chrony threshold config", "err", err)
		}
		if sourcesChanged || thresholdChanged {
			reloadChronyRuntime(sourcesChanged, thresholdChanged)
			slog.Info("NTP disabled; chrony managed configuration removed")
		}
		return
	}

	sourcesChanged, err := reconcileManagedFile(chronySourcesPath, renderChronySources(cfg.System.NTPServers))
	if err != nil {
		slog.Warn("failed to reconcile chrony sources", "err", err)
		return
	}
	thresholdChanged, err := reconcileManagedFile(chronyThresholdPath, renderChronyThreshold(cfg.System.NTPThreshold, cfg.System.NTPThresholdAction))
	if err != nil {
		slog.Warn("failed to reconcile chrony threshold config", "err", err)
		return
	}
	if !sourcesChanged && !thresholdChanged {
		return
	}

	reloadChronyRuntime(sourcesChanged, thresholdChanged)
	slog.Info("NTP config applied via chrony",
		"servers", cfg.System.NTPServers,
		"threshold", cfg.System.NTPThreshold,
		"action", cfg.System.NTPThresholdAction)
}

// applyKernelTuning sets kernel sysctl parameters from config.
// Handles system { no-redirects } and system { internet-options }.
func (d *Daemon) applyKernelTuning(cfg *config.Config) {
	// Disable ICMP redirects (send + accept) on all interfaces
	// system { no-redirects; }
	if cfg.System.NoRedirects {
		sysctls := []string{
			"/proc/sys/net/ipv4/conf/all/send_redirects",
			"/proc/sys/net/ipv4/conf/all/accept_redirects",
			"/proc/sys/net/ipv6/conf/all/accept_redirects",
		}
		for _, path := range sysctls {
			current, _ := os.ReadFile(path)
			if strings.TrimSpace(string(current)) != "0" {
				if err := os.WriteFile(path, []byte("0\n"), 0644); err != nil {
					slog.Warn("failed to set sysctl", "path", path, "err", err)
				}
			}
		}
	}

	// system { internet-options { no-ipv6-reject-zero-hop-limit; } }
	// Normally Linux drops IPv6 packets with hop-limit=0 and sends ICMPv6
	// time exceeded. This sysctl raises the ratelimit to effectively
	// accept them without generating errors (Junos compatibility).
	if cfg.System.InternetOptions != nil && cfg.System.InternetOptions.NoIPv6RejectZeroHopLimit {
		path := "/proc/sys/net/ipv6/icmp/ratelimit"
		current, _ := os.ReadFile(path)
		if strings.TrimSpace(string(current)) != "0" {
			if err := os.WriteFile(path, []byte("0\n"), 0644); err != nil {
				slog.Warn("failed to set sysctl", "path", path, "err", err)
			}
		}
	}

	// Enable IP forwarding (required for firewall operation)
	for _, path := range []string{
		"/proc/sys/net/ipv4/ip_forward",
		"/proc/sys/net/ipv6/conf/all/forwarding",
	} {
		current, _ := os.ReadFile(path)
		if strings.TrimSpace(string(current)) != "1" {
			if err := os.WriteFile(path, []byte("1\n"), 0644); err != nil {
				slog.Warn("failed to enable forwarding", "path", path, "err", err)
			}
		}
	}
}

// applySSHKnownHosts writes /etc/ssh/ssh_known_hosts from
// security { ssh-known-hosts { host ... } } config.
func (d *Daemon) applySSHKnownHosts(cfg *config.Config) {
	const path = "/etc/ssh/ssh_known_hosts"
	if len(cfg.Security.SSHKnownHosts) == 0 {
		return
	}

	var buf strings.Builder
	buf.WriteString("# Managed by xpfd — do not edit\n")
	// Sort hosts for deterministic output
	var hosts []string
	for h := range cfg.Security.SSHKnownHosts {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	for _, host := range hosts {
		for _, key := range cfg.Security.SSHKnownHosts[host] {
			// Map Junos key type names to OpenSSH types
			sshType := key.Type
			switch sshType {
			case "ssh-rsa-key":
				sshType = "ssh-rsa"
			case "ecdsa-sha2-nistp256-key":
				sshType = "ecdsa-sha2-nistp256"
			case "ssh-ed25519-key":
				sshType = "ssh-ed25519"
			case "ecdsa-sha2-nistp384-key":
				sshType = "ecdsa-sha2-nistp384"
			case "ecdsa-sha2-nistp521-key":
				sshType = "ecdsa-sha2-nistp521"
			}
			fmt.Fprintf(&buf, "%s %s %s\n", host, sshType, key.Key)
		}
	}

	content := buf.String()
	current, _ := os.ReadFile(path)
	if string(current) == content {
		return
	}

	// AtomicGeneratedConfig (D2b): regenerated from declarative config and
	// governs only outbound host-key verification — a torn/lost file
	// re-renders next apply; no power-loss durability needed.
	if err := fsatomic.WriteFileAtomic(path, []byte(content), 0644); err != nil {
		slog.Warn("failed to write ssh known hosts", "err", err)
		return
	}
	slog.Info("SSH known hosts written", "hosts", len(cfg.Security.SSHKnownHosts))
}

// zoneinfoRoot is the directory tree a `system time-zone` value may reference.
// The /etc/localtime symlink target MUST resolve to a path within this root.
const zoneinfoRoot = "/usr/share/zoneinfo"

// zoneinfoTarget builds the /etc/localtime symlink target for the given
// time-zone value and reports whether it stays within zoneinfoRoot. It is the
// #5011 render belt: even if a traversal value ("../../etc/shadow") slips past
// the commit-time config.ValidateTimeZone gate on the tolerant load /
// peer-sync path (#1960), the daemon refuses to point /etc/localtime outside
// the zoneinfo tree. filepath.Join cleans the joined path (collapsing any ".."
// segments), so the containment test runs on the resolved target rather than
// the raw string; for a legitimate zone (America/Los_Angeles, UTC, Etc/GMT+5)
// the result is byte-identical to the old "/usr/share/zoneinfo/" + tz concat,
// so the symlink idempotence compare is unaffected.
func zoneinfoTarget(tz string) (string, bool) {
	// An empty or absolute value is never a legitimate zone. filepath.Join
	// would otherwise re-root an absolute value into the tree ("/etc/passwd"
	// -> "/usr/share/zoneinfo/etc/passwd"), silently reinterpreting it; refuse
	// it outright so the belt's rejection set matches ValidateTimeZone.
	if tz == "" || filepath.IsAbs(tz) {
		return "", false
	}
	target := filepath.Join(zoneinfoRoot, tz)
	rel, err := filepath.Rel(zoneinfoRoot, target)
	if err != nil {
		return "", false
	}
	// rel == "." means tz resolved to the root itself ("."), which is a
	// directory, not a zone file; a ".." or "../" prefix means it escaped.
	if rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", false
	}
	return target, true
}

// applyTimezone sets the system timezone from system { time-zone } config.
func (d *Daemon) applyTimezone(cfg *config.Config) {
	if cfg.System.TimeZone == "" {
		return
	}

	// #1916 Step 2b r4 case-split. The /etc/localtime symlink and the
	// /etc/timezone file are two pieces of the same setting; a prior crash
	// between the symlink write and the file write could leave them
	// inconsistent. The old code returned early whenever the symlink alone
	// matched, so a stale /etc/timezone would never be repaired (AGY r2 #3).
	// The naive fix (require BOTH to match before skipping, else fall
	// through) re-ran os.Remove("/etc/localtime")+Symlink even when the
	// symlink was already correct — a crash after the Remove would break a
	// correct symlink (Codex r3). So split the cases explicitly: only touch
	// the symlink when it is wrong; always (re)write /etc/timezone when its
	// content differs, including when the symlink was already correct.
	current, _ := os.Readlink("/etc/localtime")
	// #5011 render belt: resolve the symlink target and refuse to create
	// /etc/localtime if it escapes the zoneinfo root. The commit-time
	// ValidateTimeZone gate rejects a `..`/absolute value, but #1960
	// downgrades that to a warning on the tolerant load / peer-sync path, so
	// this fail-closed check is the real boundary against a traversal target.
	target, ok := zoneinfoTarget(cfg.System.TimeZone)
	if !ok {
		slog.Warn("refusing time-zone: symlink target escapes zoneinfo root",
			"timezone", cfg.System.TimeZone)
		return
	}

	tzContent := cfg.System.TimeZone + "\n"
	tzCurrent, _ := os.ReadFile("/etc/timezone")
	tzMatches := string(tzCurrent) == tzContent

	// Case 1: both pieces already correct → nothing to do.
	if current == target && tzMatches {
		return
	}

	// Verify the zoneinfo file exists before mutating anything.
	if _, err := os.Stat(target); err != nil {
		slog.Warn("invalid timezone", "timezone", cfg.System.TimeZone, "err", err)
		return
	}

	// Case 2: only re-run the symlink mutation when localtime is wrong; do
	// NOT remove an already-correct symlink (that opens a crash window).
	if current != target {
		os.Remove("/etc/localtime")
		if err := os.Symlink(target, "/etc/localtime"); err != nil {
			slog.Warn("failed to set timezone", "err", err)
			return
		}
	}

	// Case 3: always write /etc/timezone (AtomicGeneratedConfig) whenever
	// its content differs — including the symlink-already-correct branch,
	// which is how a "timezone-only stale" state gets repaired without
	// touching the good symlink.
	if !tzMatches {
		if err := fsatomic.WriteFileAtomic("/etc/timezone", []byte(tzContent), 0644); err != nil {
			slog.Warn("failed to write /etc/timezone", "err", err)
			return
		}
	}
	slog.Info("timezone set", "timezone", cfg.System.TimeZone)
}

// applySystemSyslog configures system-level syslog forwarding from
// system { syslog { host ... } } config. This forwards daemon log
// messages (Go slog) to remote syslog servers.
func (d *Daemon) applySystemSyslog(cfg *config.Config) {
	if d.slogHandler == nil {
		return
	}

	if cfg.System.Syslog == nil || len(cfg.System.Syslog.Hosts) == 0 {
		d.slogHandler.SetClients(nil)
		return
	}

	var clients []*logging.SyslogClient
	for _, host := range cfg.System.Syslog.Hosts {
		// #4303 S-1: honor `host <h> port <n>` and `source-address <ip>`.
		// Both were previously misparsed into bogus facility entries and
		// never reached the client; the port stayed pinned at 514 and the
		// source bind was ignored.
		port := 514
		if host.Port > 0 {
			port = host.Port
		}
		c, err := logging.NewSyslogClientWithSource(host.Address, port, host.SourceAddress)
		if err != nil {
			slog.Warn("failed to create system syslog client",
				"host", host.Address, "err", err)
			continue
		}

		// Apply facility from first facility entry, default to daemon
		c.Facility = logging.FacilityDaemon
		if len(host.Facilities) > 0 {
			c.Facility = logging.ParseFacility(host.Facilities[0].Facility)
			// Apply severity filter from the most restrictive facility entry
			for _, f := range host.Facilities {
				if sev := logging.ParseSeverity(f.Severity); sev > 0 {
					if c.MinSeverity == 0 || sev < c.MinSeverity {
						c.MinSeverity = sev
					}
				}
			}
		}

		clients = append(clients, c)
		slog.Info("system syslog forwarding configured",
			"host", host.Address, "facility", c.Facility)
	}

	d.slogHandler.SetClients(clients)
}

// applySyslogFiles writes rsyslog drop-in configs for system { syslog { file ... } }
// destinations. Each file entry generates a rule that directs matching
// facility/severity messages to /var/log/<name>.
func (d *Daemon) applySyslogFiles(cfg *config.Config) {
	confDir := "/etc/rsyslog.d"
	prefix := "10-xpf-"

	// Collect desired configs
	desired := make(map[string]string) // filename -> content
	if cfg.System.Syslog != nil {
		for _, f := range cfg.System.Syslog.Files {
			if f.Name == "" {
				continue
			}
			// #4902 render belt: the name is formatted into /var/log/<name> and
			// the drop-in filename 10-xpf-<name>.conf. Skip a leniently-loaded /
			// peer-synced name with a path separator / `..` / whitespace /
			// control char so it cannot escape /var/log or inject an rsyslog
			// directive. The strict commit gate (config.ValidateSyslogFileName)
			// rejects it at commit.
			if err := config.ValidateSyslogFileName(f.Name, nil); err != nil {
				slog.Warn("skipping invalid syslog file destination", "name", f.Name, "err", err)
				continue
			}
			// Map Junos facility/severity to rsyslog selector
			facility := f.Facility
			if facility == "" || facility == "any" {
				facility = "*"
			}
			// Junos "change-log" maps to local6; rsyslog doesn't know the name
			if facility == "change-log" {
				facility = "local6"
			}
			severity := f.Severity
			if severity == "" || severity == "any" {
				severity = "*"
			}
			// Junos severity names map directly to rsyslog (info, warning, error, etc.)
			selector := fmt.Sprintf("%s.%s", facility, severity)
			logPath := fmt.Sprintf("/var/log/%s", f.Name)

			content := fmt.Sprintf("# Managed by xpf — do not edit\n%s\t%s\n", selector, logPath)
			confFile := prefix + f.Name + ".conf"
			desired[confFile] = content
		}
		// Syslog user destinations: forward to logged-in users via rsyslog omusrmsg
		for _, u := range cfg.System.Syslog.Users {
			if u.User == "" {
				continue
			}
			// #4902 render belt: the user token is formatted into the drop-in
			// filename and the rsyslog `:omusrmsg:<user>` directive. Skip a
			// leniently-loaded / peer-synced value that is not '*' or a safe
			// account name. The strict commit gate (config.ValidateSyslogUser)
			// rejects it at commit.
			if err := config.ValidateSyslogUser(u.User, nil); err != nil {
				slog.Warn("skipping invalid syslog user destination", "user", u.User, "err", err)
				continue
			}
			facility := u.Facility
			if facility == "" || facility == "any" {
				facility = "*"
			}
			if facility == "change-log" {
				facility = "local6"
			}
			severity := u.Severity
			if severity == "" || severity == "any" {
				severity = "*"
			}
			selector := fmt.Sprintf("%s.%s", facility, severity)
			target := u.User // "*" means all logged-in users
			content := fmt.Sprintf("# Managed by xpf — do not edit\n%s\t:omusrmsg:%s\n", selector, target)
			confFile := prefix + "user-" + target + ".conf"
			desired[confFile] = content
		}
	}

	// Reconcile the on-disk managed drop-ins against `desired`. A removal OR a
	// (re)write flips `changed`, which gates the single restart below.
	changed := reconcileSyslogDropins(confDir, prefix, desired)

	if changed {
		if out, err := runCommandTimeout("systemctl", "restart", "rsyslog"); err != nil {
			slog.Error("failed to restart rsyslog",
				"err", err, "output", strings.TrimSpace(string(out)))
		} else {
			slog.Info("rsyslog file configs applied", "files", len(desired))
		}
	}
}

// reconcileSyslogDropins removes stale xpf-managed rsyslog drop-ins (any file
// under confDir whose name starts with prefix that is not present in desired)
// and writes the desired drop-ins. It returns true when the on-disk managed
// set actually changed — a file was removed OR a file was (re)written — which
// the caller uses to gate the single `systemctl restart rsyslog`.
//
// #5111: a successful removal MUST count as a change, even when `desired` is
// empty. Removing the final managed destination leaves nothing to write, so
// the write loop cannot set `changed`; before this fix `changed` stayed false
// and the restart was skipped, leaving rsyslog with the deleted rule still
// loaded (logs kept flowing to a removed destination — an audit/confidentiality
// leak). A no-op remove of an already-absent file (os.IsNotExist) does NOT count
// so a steady-state reconcile does not spuriously restart rsyslog every apply.
// os.Remove errors are surfaced (slog.Warn) rather than discarded, and still
// mark a change so the restart re-reads config instead of silently stranding a
// stale rule with no restart.
func reconcileSyslogDropins(confDir, prefix string, desired map[string]string) bool {
	changed := false

	// Remove stale xpf-managed files.
	entries, _ := os.ReadDir(confDir)
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), prefix) {
			continue
		}
		if _, keep := desired[e.Name()]; keep {
			continue
		}
		path := filepath.Join(confDir, e.Name())
		if err := os.Remove(path); err != nil {
			if os.IsNotExist(err) {
				// Already gone — nothing was actually removed, so no restart
				// is owed for this entry.
				continue
			}
			// A partial/failed removal is still a config change we want
			// rsyslog to re-read; surface the error instead of discarding it.
			slog.Warn("failed to remove stale rsyslog config",
				"file", e.Name(), "err", err)
		}
		changed = true
	}

	// Write desired configs.
	for name, content := range desired {
		path := filepath.Join(confDir, name)
		current, _ := os.ReadFile(path)
		if string(current) != content {
			// AtomicGeneratedConfig: regenerated each apply.
			if err := fsatomic.WriteFileAtomic(path, []byte(content), 0644); err != nil {
				slog.Warn("failed to write rsyslog config", "file", name, "err", err)
				continue
			}
			changed = true
		}
	}

	return changed
}

// applySystemLogin creates OS user accounts and SSH authorized_keys from
// system { login { user ... } } configuration.
func (d *Daemon) applySystemLogin(cfg *config.Config) {
	if cfg.System.Login == nil || len(cfg.System.Login.Users) == 0 {
		return
	}

	for _, user := range cfg.System.Login.Users {
		if user.Name == "" || user.Name == "root" {
			continue // never create/modify root via config
		}

		// #5005 defense in depth: never format an unvalidated username into a
		// root-privileged id/useradd/chown invocation. The strict commit-check
		// rejects a crafted name (schema keyValidator, ValidateLoginUsername),
		// but the tolerant load / peer-sync path downgrades that to a warning
		// (#1960), so a leading-dash or otherwise unsafe name can still reach
		// here. Skip it entirely — the same doctrine the sudoers writer already
		// applies (reconcileSudoers/writeSudoersGrant, #4895). Combined with the
		// `--` end-of-options separators below, this fails closed against option
		// injection into the account/SSH-key writer.
		if err := config.ValidateLoginUsername(user.Name, nil); err != nil {
			slog.Warn("refusing to provision invalid login user name",
				"user", user.Name, "err", err)
			continue
		}

		// Check if user already exists. A non-zero exit means "user
		// doesn't exist"; a timeout also lands here, in which case the
		// useradd below fails with "already exists" and is logged. The `--`
		// stops id treating a name as an option (#5005).
		_, err := runCommandTimeout("id", "--", user.Name)
		if err != nil {
			// User doesn't exist — create it
			args := []string{"-m", "-s", "/bin/bash"}
			if user.UID > 0 {
				args = append(args, "-u", fmt.Sprintf("%d", user.UID))
			}
			// `--` before the operand so a name is never parsed as a useradd
			// option (#5005 option-injection defense).
			args = append(args, "--", user.Name)
			if out, err := runCommandTimeout("useradd", args...); err != nil {
				slog.Warn("failed to create user",
					"user", user.Name, "err", err, "output", string(out))
				continue
			}
			slog.Info("created system user", "user", user.Name, "uid", user.UID)
			// Record provenance keyed by the account's actual UID so a
			// later directive removal can lock THIS exact account (D2),
			// while an out-of-band userdel+recreate with a different UID
			// is left untouched (#1944 §5.4).
			if uid, ok := lookupUID(user.Name); ok {
				if err := markProvisioned(user.Name, uid); err != nil {
					slog.Warn("failed to write provisioned-user marker",
						"user", user.Name, "err", err)
				}
			}
		}

		// Apply / lock the login password (#1944). Mirrors applyRootAuth's
		// `chpasswd -e` idiom; idempotent via a direct /etc/shadow read;
		// D2-locks the account when the directive is removed but ONLY for
		// the exact xpf-provisioned account (UID-keyed marker).
		d.reconcileUserPassword(user)

		// Super-user sudo grants are reconciled separately by
		// reconcileSudoers so that a class DOWNGRADE or full user removal
		// REVOKES the stale NOPASSWD grant. reconcileSudoers must run even
		// when this per-user loop is skipped (Login nil / no users), which
		// is exactly the "user removed from config" case (#3889).

		// Set SSH authorized keys. An EMPTY configured key list takes the else
		// branch below and REVOKES any xpf-managed authorized_keys (#5106).
		if len(user.SSHKeys) > 0 {
			homeDir := fmt.Sprintf("/home/%s", user.Name)
			sshDir := homeDir + "/.ssh"

			// Resolve the owner FIRST (cgo-free /etc/passwd parse). The user
			// was created above, so it resolves. If it does not, abort the
			// whole keys block (retried next apply) rather than installing
			// anything root-owned that sshd would refuse (#1916 D7).
			uid, gid, ok := lookupUIDGID(user.Name)
			if !ok {
				slog.Warn("could not resolve uid/gid for authorized_keys owner; skipping to avoid a root-owned-keys lockout window",
					"user", user.Name)
				continue
			}

			// MkdirAllDurable (not plain MkdirAll): authorized_keys is a
			// DurableState file written into this dir; WriteFileDurable
			// persists the file's entry in .ssh, not .ssh's own entry in
			// its parent, so a power cut could otherwise drop the
			// just-created .ssh directory (Codex r1, fsatomic README).
			if err := fsatomic.MkdirAllDurable(sshDir, 0700); err != nil {
				slog.Warn("failed to create .ssh dir", "user", user.Name, "dir", sshDir, "err", err)
				continue
			}
			// Chown the .ssh DIR to the user UNCONDITIONALLY (idempotent),
			// not only when the key content changes. MkdirAllDurable creates
			// it root-owned; if this chown ran only inside the content-changed
			// branch, a crash between the durable key write and the chown
			// would leave a durable root-owned .ssh that, since the key
			// content then matches on reboot, the whole block (and the chown)
			// would skip forever — never repairing the dir owner (Codex r2
			// HIGH). Running it every apply closes that window.
			// `--` stops chown parsing "-name:-name" as options (#5005).
			if out, err := runCommandTimeout("chown", "-R", "--", user.Name+":"+user.Name, sshDir); err != nil {
				slog.Warn("failed to chown ssh dir",
					"user", user.Name, "dir", sshDir,
					"err", err, "output", strings.TrimSpace(string(out)))
			}

			keysContent := strings.Join(user.SSHKeys, "\n") + "\n"
			keysFile := sshDir + "/authorized_keys"
			current, _ := os.ReadFile(keysFile)
			if string(current) != keysContent {
				// DurableState authorized_keys: SSH access must survive a
				// power cut. WriteFileDurable replaces the inode with a
				// root-owned temp; WithOwner chowns the temp fd BEFORE the
				// rename so the file is correctly-owned at install time —
				// closing the crash window that would otherwise leave
				// root-owned 0600 keys sshd refuses (EACCES → lockout).
				if err := fsatomic.WriteFileDurable(keysFile, []byte(keysContent), 0600, fsatomic.WithOwner(uid, gid)); err != nil {
					slog.Warn("failed to write authorized_keys",
						"user", user.Name, "err", err)
					continue
				}
				slog.Info("SSH keys updated", "user", user.Name, "keys", len(user.SSHKeys))
			}
		} else {
			// Empty key list on a RETAINED user: reconcile the xpf-managed
			// authorized_keys to ABSENT so removing the last key from config
			// actually revokes key-based login. Without this the stale key file
			// a prior apply wrote keeps granting access — reconcileAbsentLogin-
			// Users only covers a fully REMOVED user, not a retained user whose
			// key list was emptied (#5106). Gate on the UID-keyed provenance
			// marker (as deprovisionLoginUser does) so we only ever remove an
			// authorized_keys file xpf itself wrote — never a pre-existing /
			// out-of-band user's operator-installed keys. The whole file is
			// xpf-owned when the marker matches (applySystemLogin writes it
			// wholesale), so removing it is safe.
			if uid, ok := lookupUID(user.Name); ok && xpfProvisioned(user.Name, uid) {
				keysFile := managedAuthorizedKeysPath(user.Name)
				switch err := os.Remove(keysFile); {
				case err == nil:
					slog.Info("revoked SSH keys (last key removed from config)",
						"user", user.Name)
				case !os.IsNotExist(err):
					slog.Warn("failed to remove authorized_keys after key list emptied",
						"user", user.Name, "file", keysFile, "err", err)
				}
			}
		}
	}
}

// sudoersDir is the directory that holds xpf-managed NOPASSWD sudo grants
// for super-user login accounts. Overridable in tests so the reconcile can
// run against a throwaway directory instead of the real /etc/sudoers.d.
var sudoersDir = "/etc/sudoers.d"

// sudoersPrefix namespaces every xpf-managed sudoers drop-in. Only files
// with this prefix are ever written, kept, or removed by reconcileSudoers —
// operator-authored files in the same directory are left untouched.
const sudoersPrefix = "xpf-"

// validateSudoersFile checks a generated sudoers drop-in with `visudo -cf`
// so a malformed grant can never lock out sudo (a single broken drop-in
// makes sudo refuse to run at all). It is a package var so tests can stub
// it. The default is best-effort: it only validates when the process is
// root (the daemon is; unit tests are not) and when visudo is installed —
// otherwise it returns nil and the atomic durable write is relied on as
// the write safety (the file content is a fixed, config-validated template).
var validateSudoersFile = defaultValidateSudoersFile

func defaultValidateSudoersFile(path string) error {
	// visudo enforces root-ownership + 0440 on drop-ins, so the check is
	// only meaningful when we actually run as root. Skip otherwise to keep
	// non-root unit tests deterministic and hermetic.
	if os.Geteuid() != 0 {
		return nil
	}
	if _, err := exec.LookPath("visudo"); err != nil {
		return nil // best-effort: visudo not present
	}
	if out, err := runCommandTimeout("visudo", "-cf", path); err != nil {
		return fmt.Errorf("visudo -cf %s: %w: %s", path, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// reconcileSudoers makes /etc/sudoers.d match the CURRENT config's
// super-user set on every apply. It (a) writes a NOPASSWD grant
// xpf-<user> for each current super-user login account and (b) REVOKES
// any xpf-<user> drop-in whose user is no longer a super-user (class
// DOWNGRADE) or no longer present in the config (user REMOVAL). Without
// this sweep a demoted or deleted admin kept passwordless root sudo
// forever (#3889) — the original write-only path had no revocation branch.
//
// It mirrors the networkd/rsyslog stale-file reconcilers: build the desired
// set, sweep the managed namespace, remove what is not desired. Only
// sudoersPrefix files are touched. It MUST be called on every apply,
// independent of applySystemLogin's early return, so the "all users
// removed" case still revokes stale grants.
func (d *Daemon) reconcileSudoers(cfg *config.Config) {
	// Desired: an xpf-<user> drop-in for each current super-user account.
	desired := make(map[string]struct{})
	if cfg.System.Login != nil {
		for _, user := range cfg.System.Login.Users {
			if user.Name == "" || user.Name == "root" {
				continue // never grant/modify root via config
			}
			if user.Class != "super-user" {
				continue
			}
			// #4895 defense in depth: never format an unvalidated username into
			// an /etc/sudoers.d grant. Strict commit-check rejects a crafted
			// name (schema keyValidator), but the tolerant load / peer-sync path
			// downgrades that to a warning (#1960), so a bad name can still reach
			// here. Skip it entirely: neither desire nor write it, so any stale
			// grant is also revoked by the sweep below.
			if err := config.ValidateLoginUsername(user.Name, nil); err != nil {
				slog.Warn("refusing sudoers grant for invalid login user name",
					"user", user.Name, "err", err)
				continue
			}
			desired[sudoersPrefix+user.Name] = struct{}{}
			if err := writeSudoersGrant(user.Name); err != nil {
				slog.Warn("failed to write sudoers file",
					"user", user.Name, "err", err)
			}
		}
	}

	// Revoke: remove any xpf-managed drop-in that is no longer desired.
	entries, _ := os.ReadDir(sudoersDir)
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasPrefix(name, sudoersPrefix) {
			continue // leave non-xpf sudoers.d files (and subdirs) alone
		}
		if _, keep := desired[name]; keep {
			continue
		}
		path := filepath.Join(sudoersDir, name)
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			slog.Warn("failed to revoke stale sudoers grant",
				"file", name, "err", err)
		} else if err == nil {
			slog.Info("revoked stale super-user sudo grant", "file", name)
		}
	}
}

// writeSudoersGrant writes (idempotently) the NOPASSWD grant for one
// super-user. The write is durable because a torn or lost sudoers file is
// a management-access (sudo) hazard that must survive a power cut. The
// generated file is validated with visudo; if validation fails the file is
// removed rather than left as a lockout landmine (a broken drop-in breaks
// ALL sudo invocations).
//
// #4895: the username is formatted verbatim into both the drop-in filename
// and the grant line, and the config lexer decodes `\n` in a quoted string
// into a literal newline. A name with a newline/whitespace/sudoers
// metacharacter would inject additional directives that pass visudo's syntax
// check. Re-validate defensively here — never format an unvalidated name into
// sudoers, even if a caller bypassed reconcileSudoers' skip or the strict
// commit-check gate was downgraded on a tolerant load (#1960).
func writeSudoersGrant(user string) error {
	if err := config.ValidateLoginUsername(user, nil); err != nil {
		return fmt.Errorf("refusing sudoers grant for invalid login user name %q: %w", user, err)
	}
	path := filepath.Join(sudoersDir, sudoersPrefix+user)
	line := fmt.Sprintf("%s ALL=(ALL) NOPASSWD: ALL\n", user)
	if current, _ := os.ReadFile(path); string(current) == line {
		return nil // idempotent: already correct
	}
	// DurableState: a torn or lost sudoers file is a management-access
	// (sudo) hazard, so it must survive a power cut.
	if err := fsatomic.WriteFileDurable(path, []byte(line), 0440); err != nil {
		return err
	}
	if err := validateSudoersFile(path); err != nil {
		// Fail closed toward availability of sudo itself: never leave an
		// invalid drop-in that would break every sudo invocation.
		os.Remove(path)
		return fmt.Errorf("generated sudoers grant rejected: %w", err)
	}
	return nil
}

// reconcileUserPassword applies, leaves, or locks a login user's OS
// password per the declarative #1944 lifecycle. It runs inside
// applySystemLogin (under the apply lock, so there is no marker/shadow
// race) and never touches root (excluded by the applySystemLogin loop).
//
//   - encrypted-password set → write it via `chpasswd -e` unless the
//     on-disk shadow hash already equals it (idempotent); a successful
//     apply (re)records the UID-keyed provenance marker.
//   - encrypted-password absent → LOCK the account (Path D2) so removing
//     the directive disables password login instead of orphaning a live
//     credential — but only for the exact xpf-provisioned account (marker
//     UID matches the current UID) and never on a shadow read error.
func (d *Daemon) reconcileUserPassword(user *config.LoginUser) {
	desired := user.EncryptedPassword.Reveal()
	curUID, uidOK := lookupUID(user.Name)
	cur, ok := currentShadowHash(user.Name)

	switch passwordAction(cur, ok, desired) {
	case pwApply:
		// Defense-in-depth: re-validate the hash at the apply boundary
		// before it reaches /etc/shadow. The strict operator commit gate
		// (config.SchemaValidate → ValidateCryptHash) already rejects
		// plaintext/DES/empty-checksum/':' values, BUT the lenient
		// Load/SyncApply ingress (pkg/configstore/store.go
		// compileTreeLenient, #1319 PR 2) only DOWNGRADES that violation
		// to a warning so an older-binary persisted config or a synced
		// peer value cannot brick boot. Without this guard, such a value
		// would still be written to /etc/shadow verbatim — a plaintext
		// password or a chpasswd-stdin-corrupting ':' (Codex #1944 r1
		// High #2). Re-checking here makes "plaintext never reaches
		// /etc/shadow" hold on EVERY path, while still not bricking boot
		// (we skip+warn, leaving the existing shadow field untouched).
		if err := config.ValidateCryptHash(desired, nil); err != nil {
			slog.Warn("refusing to apply invalid login encrypted-password to /etc/shadow",
				"user", user.Name, "err", err)
			break
		}
		stdin := strings.NewReader(user.Name + ":" + desired + "\n")
		if out, err := runCommandStdinTimeout(stdin, "chpasswd", "-e"); err != nil {
			slog.Warn("failed to set user password",
				"user", user.Name, "err", err, "output", strings.TrimSpace(string(out)))
		} else {
			// xpf now manages this exact account's password — mark it so a
			// later directive removal locks it (covers a pre-existing or
			// marker-wiped account, #1944 §5.4).
			if uidOK {
				if err := markProvisioned(user.Name, curUID); err != nil {
					slog.Warn("failed to write provisioned-user marker",
						"user", user.Name, "err", err)
				}
			}
			slog.Info("user encrypted-password applied", "user", user.Name)
		}
	case pwLock:
		// Only lock the exact account xpf provisioned (UID-keyed marker).
		if !uidOK || !xpfProvisioned(user.Name, curUID) {
			break
		}
		stdin := strings.NewReader(user.Name + ":!\n")
		if out, err := runCommandStdinTimeout(stdin, "chpasswd", "-e"); err != nil {
			slog.Warn("failed to lock user password",
				"user", user.Name, "err", err, "output", strings.TrimSpace(string(out)))
		} else {
			slog.Info("user password locked (no encrypted-password in config)",
				"user", user.Name)
		}
	}
}

// sshdConfPath is the xpf-managed sshd drop-in. Overridable in tests so the
// remove/revert side effects can be exercised against a temp dir.
var sshdConfPath = "/etc/ssh/sshd_config.d/xpf.conf"

// FS + reload seam (#2062). applySSHConfig owns three real-world side effects
// — write the drop-in, remove the drop-in, reload sshd — and the
// config-removal and reload-failure recovery paths can only be tested if those
// effects are injectable. These package-level vars default to the production
// implementations and are overridden by a recorder in daemon_ssh_test.go.
// Mirrors the listenFn/ensureLinkLocalFn seam in pkg/ra.
var (
	sshdReadFile   = os.ReadFile
	sshdWriteFile  = fsatomic.WriteFileAtomic
	sshdRemoveFile = os.Remove
	sshdMkdirAll   = os.MkdirAll
	sshdReloadCmd  = func() ([]byte, error) {
		return runCommandTimeout("systemctl", "reload", "sshd")
	}
	// sshdValidateCmd runs `sshd -t`, which parses the full merged sshd
	// configuration (/etc/ssh/sshd_config plus the sshd_config.d drop-ins,
	// including the xpf drop-in) and fails on a bad Ciphers/MACs/
	// KexAlgorithms spelling or any other syntax error. applySSHConfig gates
	// the reload on this passing so a cipher/MAC typo never reaches a SIGHUP
	// that could drop sshd's listener (#4311 review). Overridden in
	// daemon_ssh_test.go.
	sshdValidateCmd = func() ([]byte, error) {
		return runCommandTimeout("/usr/sbin/sshd", "-t")
	}
)

// applySSHConfig configures sshd from system { services { ssh { ... } } }.
// Uses a drop-in config file to avoid modifying the main sshd_config.
//
// Drop-in lifecycle (#2062): the drop-in is created/updated when there are
// xpf-managed ssh settings, and REMOVED when there are none — including when
// the whole ssh stanza is deleted (cfg.System.Services / .SSH == nil) — so
// clearing the config reverts sshd to the base-image defaults instead of
// leaving stale PermitRootLogin/KexAlgorithms enforced — an existing drop-in
// that cannot be read (permission/IO error) is still treated as present so it
// gets removed. If the reload fails after a write, the drop-in is reverted to
// its prior content (or removed if there was none, the prior was unreadable,
// or the restore write itself fails) so a bad config never persists to break
// the next sshd restart.
func (d *Daemon) applySSHConfig(cfg *config.Config) {
	var ssh *config.SSHServiceConfig
	if cfg.System.Services != nil {
		ssh = cfg.System.Services.SSH
	}

	// buildSSHDConfig is nil-safe and returns "" when there is nothing to
	// manage, so an absent ssh stanza and an ssh stanza with no recognised
	// leaves collapse to the same "no managed settings" case.
	content := buildSSHDConfig(ssh)

	// Read the prior content once: needed both to skip no-op writes and to
	// restore the file if a reload fails after we change it.
	//
	// Distinguish "absent" from "exists but unreadable": a permission/IO error
	// reading an existing drop-in is NOT the same as no drop-in. Treating an
	// unreadable-but-present file as absent would skip removal and leave a
	// stale drop-in enforcing PermitRootLogin/KexAlgorithms after the config
	// was cleared. hadDropIn = the file exists (read OK, or failed with
	// something other than not-exist); priorReadable = we actually have its
	// content (only then can we restore it on a reload failure).
	prior, priorErr := sshdReadFile(sshdConfPath)
	priorReadable := priorErr == nil
	hadDropIn := priorReadable || !os.IsNotExist(priorErr)

	if content == "" {
		// No xpf-managed ssh settings. Remove any existing drop-in and reload
		// so sshd reverts to base-image defaults. No-op when absent.
		if !hadDropIn {
			return
		}
		if err := sshdRemoveFile(sshdConfPath); err != nil && !os.IsNotExist(err) {
			slog.Warn("failed to remove sshd config drop-in", "err", err)
			return
		}
		if out, err := sshdReloadCmd(); err != nil {
			slog.Error("failed to reload sshd after removing drop-in",
				"err", err, "output", strings.TrimSpace(string(out)))
			return
		}
		slog.Info("SSH config drop-in removed (reverted to defaults)")
		return
	}

	if priorReadable && string(prior) == content {
		return // no change
	}

	// Best-effort create the drop-in directory before writing. If this fails
	// the write below will also fail, but the mkdir error is the real cause
	// (e.g. a read-only /etc) so surface it rather than only the opaque write
	// error.
	if err := sshdMkdirAll("/etc/ssh/sshd_config.d", 0755); err != nil {
		slog.Warn("failed to create sshd config drop-in directory", "err", err)
	}
	// AtomicGeneratedConfig (D2): regenerated each apply and reloaded
	// immediately. A power-cut loss reverts PermitRootLogin to the base
	// image default (prohibit-password) until the next boot apply — that
	// FAILS SAFE (more restrictive, never more permissive), so no fsync.
	if err := sshdWriteFile(sshdConfPath, []byte(content), 0644); err != nil {
		slog.Warn("failed to write sshd config", "err", err)
		return
	}

	// revertDropIn restores the drop-in to its prior state after a validation
	// or reload failure: restore the previously-read content, else remove the
	// file. Only restore the prior content when we actually read it
	// (priorReadable); an unreadable-but-present prior is unknown, so fail safe
	// by removing the drop-in instead of restoring garbage. No drop-in is safer
	// than the known-bad content we just wrote (which would break the next sshd
	// restart).
	revertDropIn := func(reason string) {
		if priorReadable {
			if rerr := sshdWriteFile(sshdConfPath, prior, 0644); rerr != nil {
				slog.Warn("failed to restore prior sshd config; removing drop-in",
					"reason", reason, "err", rerr)
				if rmErr := sshdRemoveFile(sshdConfPath); rmErr != nil && !os.IsNotExist(rmErr) {
					slog.Warn("failed to remove bad sshd config after failed restore", "err", rmErr)
				}
			}
		} else {
			if rerr := sshdRemoveFile(sshdConfPath); rerr != nil && !os.IsNotExist(rerr) {
				slog.Warn("failed to remove bad sshd config", "reason", reason, "err", rerr)
			}
		}
	}

	// Validate the merged sshd config BEFORE reloading (#4311 review). A bad
	// Ciphers/MACs/KexAlgorithms line reaching a reload (SIGHUP) can make sshd
	// re-exec into an invalid config and drop its listener → SSH lockout on the
	// appliance. `sshd -t` catches the typo first. On failure revert the
	// drop-in and SKIP the reload entirely: the running sshd is never disturbed
	// and the next restart reads the good prior config. This makes the
	// cipher-typo-lockout protection self-contained rather than relying on the
	// base-image ExecReload=sshd -t.
	if out, err := sshdValidateCmd(); err != nil {
		slog.Error("sshd config validation failed; SSH drop-in not applied",
			"err", err, "output", strings.TrimSpace(string(out)))
		revertDropIn("validation-failed")
		return
	}

	// Reload sshd to pick up changes. Validation passed, so this should
	// succeed; the reload-failure revert stays as a backstop (e.g. a runtime
	// reload error unrelated to config syntax).
	if out, err := sshdReloadCmd(); err != nil {
		slog.Error("failed to reload sshd",
			"err", err, "output", strings.TrimSpace(string(out)))
		revertDropIn("reload-failed")
		// Best-effort reload of the restored content so the running sshd is
		// not left referencing a drop-in we just rewrote/removed underneath
		// it. The original reload already failed; a second failure here is
		// only logged.
		if out2, err2 := sshdReloadCmd(); err2 != nil {
			slog.Warn("failed to reload sshd after reverting drop-in",
				"err", err2, "output", strings.TrimSpace(string(out2)))
		}
		return
	}
	slog.Info("SSH config applied",
		"root_login", ssh.RootLogin,
		"key_exchange", strings.Join(ssh.KeyExchange, ","))
}

// buildSSHDConfig renders the xpf-managed sshd drop-in body from the SSH
// service config, or "" when there is nothing to manage. Each setting is an
// independent line: root-login → PermitRootLogin, key-exchange → KexAlgorithms
// (H5, #2008). sshd validates algorithm spellings at reload, so xpf does not
// enum-check the key-exchange list.
// filterSSHAlgorithms drops any token that is not a safe OpenSSH algorithm
// name (config.ValidateSSHAlgorithm), the render-side belt for #4902. Only the
// injection/breakage shape (comma/space/control char) is filtered; sshd still
// owns the actual algorithm-spelling check at reload. A dropped token is logged
// so an operator can see why a leniently-loaded value did not take effect.
func filterSSHAlgorithms(in []string) []string {
	out := in[:0:0]
	for _, tok := range in {
		if err := config.ValidateSSHAlgorithm(tok, nil); err != nil {
			slog.Warn("skipping invalid SSH algorithm token", "token", tok, "err", err)
			continue
		}
		out = append(out, tok)
	}
	return out
}

func buildSSHDConfig(ssh *config.SSHServiceConfig) string {
	if ssh == nil {
		return ""
	}
	var lines []string
	if ssh.RootLogin != "" {
		var permitRoot string
		switch ssh.RootLogin {
		case "allow":
			permitRoot = "yes"
		case "deny":
			permitRoot = "no"
		case "deny-password":
			permitRoot = "prohibit-password"
		}
		if permitRoot != "" {
			lines = append(lines, "PermitRootLogin "+permitRoot)
		}
	}
	// #4902 render belt: filter each algorithm list to safe OpenSSH tokens
	// before comma-joining into the sshd line. A leniently-loaded / peer-synced
	// token carrying a comma/space/control char (which would smuggle a second
	// sshd directive token onto the line, or fail the reload) is dropped; the
	// strict commit gate (config.ValidateSSHAlgorithm) rejects it at commit.
	if kex := filterSSHAlgorithms(ssh.KeyExchange); len(kex) > 0 {
		lines = append(lines, "KexAlgorithms "+strings.Join(kex, ","))
	}
	// #4305 S-4: sshd hardening knobs. sshd validates the algorithm
	// spellings and numeric ranges at reload; xpf gates the injection/breakage
	// shape (#4902) and lets sshd own the spelling check.
	if ciphers := filterSSHAlgorithms(ssh.Ciphers); len(ciphers) > 0 {
		lines = append(lines, "Ciphers "+strings.Join(ciphers, ","))
	}
	if macs := filterSSHAlgorithms(ssh.MACs); len(macs) > 0 {
		lines = append(lines, "MACs "+strings.Join(macs, ","))
	}
	if ssh.ConnectionLimit > 0 {
		// Junos `connection-limit` bounds concurrent sessions; sshd's
		// nearest knob is MaxStartups (concurrent unauthenticated
		// connections). Not an exact equivalent, but the standard mapping.
		lines = append(lines, fmt.Sprintf("MaxStartups %d", ssh.ConnectionLimit))
	}
	if ssh.ClientAliveIntervalSet {
		lines = append(lines, fmt.Sprintf("ClientAliveInterval %d", ssh.ClientAliveInterval))
	}
	if ssh.ClientAliveCountMaxSet {
		lines = append(lines, fmt.Sprintf("ClientAliveCountMax %d", ssh.ClientAliveCountMax))
	}
	if len(lines) == 0 {
		return ""
	}
	return "# Managed by xpf — do not edit\n" + strings.Join(lines, "\n") + "\n"
}

// applyRootAuth applies root-authentication config: encrypted-password and SSH keys.
func (d *Daemon) applyRootAuth(cfg *config.Config) {
	ra := cfg.System.RootAuthentication
	if ra == nil {
		return
	}

	// Set root password from encrypted-password (crypt(3) hash)
	if ra.EncryptedPassword != "" {
		// Defense-in-depth at the apply boundary, mirroring
		// reconcileUserPassword (#1944 E1 shares ValidateCryptHash between
		// root-auth and per-user auth). The strict operator-commit gate
		// rejects plaintext/DES/empty-checksum/':' values, but the lenient
		// Load/SyncApply ingress (pkg/configstore/store.go) only downgrades
		// that to a warning, so a persisted/synced bad value would otherwise
		// reach `chpasswd -e` verbatim — writing plaintext as root's password
		// or corrupting the chpasswd stdin line via ':'. Re-check here and
		// skip+warn so "plaintext never reaches /etc/shadow" holds for root
		// on every path too, without bricking boot. SSH keys below are
		// still applied regardless.
		if err := config.ValidateCryptHash(ra.EncryptedPassword.Reveal(), nil); err != nil {
			slog.Warn("refusing to apply invalid root encrypted-password to /etc/shadow", "err", err)
		} else {
			// Use chpasswd -e to set pre-hashed password
			stdin := strings.NewReader("root:" + ra.EncryptedPassword.Reveal() + "\n")
			if out, err := runCommandStdinTimeout(stdin, "chpasswd", "-e"); err != nil {
				slog.Warn("failed to set root password", "err", err, "output", string(out))
			} else {
				slog.Info("root encrypted-password applied")
			}
		}
	}

	// Write SSH authorized_keys for root
	if len(ra.SSHKeys) > 0 {
		sshDir := "/root/.ssh"
		// MkdirAllDurable: root authorized_keys is DurableState written into
		// this dir, so the dir's own entry must survive a power cut too
		// (Codex r1).
		if err := fsatomic.MkdirAllDurable(sshDir, 0700); err != nil {
			slog.Warn("failed to create /root/.ssh dir", "err", err)
			return
		}
		keysContent := strings.Join(ra.SSHKeys, "\n") + "\n"
		keysFile := sshDir + "/authorized_keys"
		current, _ := os.ReadFile(keysFile)
		if string(current) != keysContent {
			// DurableState: root SSH access must survive a power cut.
			// WithOwner(0,0) is harmless/explicit (root keys are already
			// uid 0) and keeps the install correctly-owned at rename.
			if err := fsatomic.WriteFileDurable(keysFile, []byte(keysContent), 0600, fsatomic.WithOwner(0, 0)); err != nil {
				slog.Warn("failed to write root authorized_keys", "err", err)
			} else {
				slog.Info("root SSH keys applied", "keys", len(ra.SSHKeys))
			}
		}
	}
}
