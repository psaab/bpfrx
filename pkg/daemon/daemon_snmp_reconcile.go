package daemon

import (
	"context"
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"log/slog"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/vishvananda/netlink"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/snmp"
)

// snmpBindTimeout bounds how long startSNMPLocked waits for the listener
// goroutine to confirm it bound UDP/161 before treating the start as failed.
// The real bind (ResolveUDPAddr + ListenUDP) is a synchronous syscall that
// reports in microseconds, so this ceiling only fires if a serve seam wedges;
// it exists solely to keep the apply path — which holds snmpReconMu — from
// blocking forever on a misbehaving listener.
const snmpBindTimeout = 5 * time.Second

// snmpEnabled reports whether the committed config asks for a running SNMP
// agent. It is the SINGLE source of truth shared by the boot start block
// (daemon_run.go) and the day-2 reconcile (reconcileSNMP) so the two can never
// diverge on what "SNMP is on" means: an SNMP stanza with at least one
// community or v3 user, and the snmpd process not administratively disabled.
func snmpEnabled(cfg *config.Config) bool {
	if cfg == nil || cfg.System.SNMP == nil {
		return false
	}
	s := cfg.System.SNMP
	if len(s.Communities) == 0 && len(s.V3Users) == 0 {
		return false
	}
	return !isProcessDisabled(cfg, "snmpd")
}

// snmpConfigHash is a deterministic fingerprint of the live SNMP stanza used as
// the reconcile idempotence gate: an unchanged stanza hashes equal, so a commit
// that does not touch SNMP is a true no-op (no listener bounce, no in-place
// swap). It hashes the RAW secret-bearing fields (community strings, v3
// passwords) directly rather than the redacting MarshalJSON surface, so a
// community rename or a password rotation is detected as a change. Maps are
// walked in sorted-key order so the hash is stable across map iteration order.
func snmpConfigHash(cfg *config.Config) uint64 {
	h := fnv.New64a()
	if cfg == nil || cfg.System.SNMP == nil {
		return h.Sum64()
	}
	s := cfg.System.SNMP
	write := func(str string) {
		var l [8]byte
		binary.LittleEndian.PutUint64(l[:], uint64(len(str)))
		_, _ = h.Write(l[:])
		_, _ = h.Write([]byte(str))
	}
	write(s.Location)
	write(s.Contact)
	write(s.Description)

	commNames := make([]string, 0, len(s.Communities))
	for name := range s.Communities {
		commNames = append(commNames, name)
	}
	sort.Strings(commNames)
	write("communities")
	for _, name := range commNames {
		c := s.Communities[name]
		write(name)
		if c != nil {
			write(c.Authorization)
			// #5105: the community `clients` source-IP allowlist and its
			// per-entry `restrict` (deny) bit are live authorization inputs
			// enforced by SNMPCommunity.AllowsSource. A day-2 edit that changes
			// ONLY the allowlist (same name + authorization) must NOT hash
			// equal, or reconcile takes the idempotent no-op path and the
			// running agent keeps the stale (possibly allow-all) source policy
			// while the commit reports success. Hash the allowlist in DOCUMENT
			// order (not sorted): AllowsSource resolves ties among equal-length
			// prefixes by first-match (strict `>` on prefix bits), so element
			// order is authorization-significant and must participate in the
			// fingerprint. Identical config text yields identical order, so an
			// unchanged stanza still hashes equal (no spurious reconcile).
			write("clients")
			for _, cl := range c.Clients {
				write(cl.Prefix)
				if cl.Restrict {
					write("restrict")
				} else {
					write("allow")
				}
			}
		}
	}

	tgNames := make([]string, 0, len(s.TrapGroups))
	for name := range s.TrapGroups {
		tgNames = append(tgNames, name)
	}
	sort.Strings(tgNames)
	write("trap-groups")
	for _, name := range tgNames {
		tg := s.TrapGroups[name]
		write(name)
		if tg != nil {
			write(tg.Version)
			targets := append([]string(nil), tg.Targets...)
			sort.Strings(targets)
			for _, t := range targets {
				write(t)
			}
		}
	}

	userNames := make([]string, 0, len(s.V3Users))
	for name := range s.V3Users {
		userNames = append(userNames, name)
	}
	sort.Strings(userNames)
	write("v3-users")
	for _, name := range userNames {
		u := s.V3Users[name]
		write(name)
		if u != nil {
			write(u.AuthProtocol)
			write(string(u.AuthPassword))
			write(u.PrivProtocol)
			write(string(u.PrivPassword))
		}
	}
	return h.Sum64()
}

// buildSNMPIfData returns the live interface table for the SNMP ifTable /
// ifXTable, read from netlink at call time. It is the SetIfDataFn callback
// wired onto every agent the daemon starts (both the boot start and a day-2
// reconcile start), so the agent always reports the current kernel interface
// state regardless of when it was started (#3967 extracted this from the boot
// block so the two start paths share one implementation).
func buildSNMPIfData() []snmp.IfData {
	links, err := netlink.LinkList()
	if err != nil {
		return nil
	}
	var result []snmp.IfData
	for _, link := range links {
		attrs := link.Attrs()
		if attrs.Name == "lo" {
			continue
		}
		ifType := 6 // ethernetCsmacd
		switch link.Type() {
		case "vrf":
			ifType = 53 // propVirtual
		case "gre", "ip6tnl", "xfrm":
			ifType = 131 // tunnel
		case "veth":
			ifType = 53
		}
		admin := 2 // down
		if attrs.Flags&net.FlagUp != 0 {
			admin = 1
		}
		oper := 2 // down
		if attrs.OperState == netlink.OperUp || attrs.OperState == netlink.OperUnknown {
			oper = 1
		}
		speed := uint32(0)
		if attrs.TxQLen > 0 {
			speed = 1000000000 // default 1Gbps
		}
		var stats *netlink.LinkStatistics
		if attrs.Statistics != nil {
			stats = attrs.Statistics
		}
		entry := snmp.IfData{
			IfIndex:     attrs.Index,
			IfDescr:     attrs.Name,
			IfType:      ifType,
			IfMtu:       attrs.MTU,
			IfSpeed:     speed,
			AdminStatus: admin,
			OperStatus:  oper,
			IfName:      attrs.Name,
			IfHighSpeed: speed / 1_000_000, // bps -> Mbps
		}
		if stats != nil {
			entry.InOctets = uint32(stats.RxBytes)
			entry.OutOctets = uint32(stats.TxBytes)
			entry.HCInOctets = stats.RxBytes
			entry.HCInUcastPkts = stats.RxPackets
			entry.HCOutOctets = stats.TxBytes
			entry.HCOutUcastPkts = stats.TxPackets
			entry.InMulticastPkts = uint32(stats.Multicast)
		}
		result = append(result, entry)
	}
	return result
}

// reconcileSNMP reconciles the running SNMP subsystem against the committed
// config on every apply (#3967). Before this, the agent + trap-group monitor
// were started ONCE at boot; a day-2 commit that enabled SNMP, added a
// community/trap target, or disabled SNMP sat inert in the config until a
// daemon restart. reconcileSNMP closes that gap by matching the live subsystem
// to the config on each commit:
//
//   - disabled -> enabled: create and start the agent listener (and the
//     link-state trap monitor if trap groups are configured).
//   - enabled  -> disabled: stop the listener and the monitor.
//   - enabled  -> enabled (config changed): swap the live authorization /
//     community / trap-target set in place via UpdateConfig (no listener
//     bounce — the UDP socket and in-flight polls are preserved), and start
//     the link-state monitor if trap groups appeared and it is not yet running.
//   - enabled  -> enabled (unchanged): no-op (idempotence gate on snmpConfigHash).
//
// It returns true when it changed the running subsystem. It runs BEFORE the
// dataplane apply in applyConfigLocked, mirroring the pre-#3967 UpdateConfig
// placement, so a committed change reaches the agent even on an apply that
// aborts early on a dataplane protocol-gate error.
//
// The START path requires d.snmpBootReady (set after the boot block) and
// d.daemonCtx. During the boot apply, snmpBootReady is still false so this
// no-ops the start and the boot block owns the first start (which respects
// config-only / bootstrap suppression). The UpdateConfig and disable paths do
// not depend on snmpBootReady, so an agent that IS running is always reconciled.
func (d *Daemon) reconcileSNMP(cfg *config.Config) bool {
	d.snmpReconMu.Lock()
	defer d.snmpReconMu.Unlock()

	desired := snmpEnabled(cfg)

	// Disable path: stop a running agent; no-op when already stopped.
	if !desired {
		if d.snmpAgent == nil {
			return false
		}
		d.teardownSNMPLocked()
		d.snmpHash, d.snmpHashSet = 0, false
		slog.Info("SNMP agent stopped (configuration disabled)")
		return true
	}

	h := snmpConfigHash(cfg)

	// Enable path, no agent running: start it. Gated on the boot handoff so
	// the boot apply does not race the boot block into a double-start, and on
	// daemonCtx so we have a lifetime to bind the goroutines to.
	if d.snmpAgent == nil {
		if !d.snmpBootReady || d.daemonCtx == nil {
			return false
		}
		// Record the desired hash ONLY on a confirmed-listening agent. If the
		// bind failed (e.g. transient UDP/161 conflict), startSNMPLocked has
		// already torn the half-started agent down and returned the error;
		// leaving snmpHash/snmpHashSet unchanged keeps d.snmpAgent nil, so the
		// NEXT identical apply re-enters this branch and RETRIES the bind
		// (self-heals a transient failure) instead of silently no-oping (#5110).
		if err := d.startSNMPLocked(cfg); err != nil {
			slog.Warn("SNMP agent start failed; leaving desired hash unrecorded so the next apply retries the bind",
				"err", err)
			return false
		}
		d.snmpHash, d.snmpHashSet = h, true
		return true
	}

	// Agent already running: idempotent no-op when the stanza is unchanged.
	if d.snmpHashSet && h == d.snmpHash {
		return false
	}

	// Live in-place reconcile: swap authorization / community / trap targets
	// without dropping the UDP listener.
	d.snmpAgent.UpdateConfig(cfg.System.SNMP)

	// Bring up the link-state trap monitor if trap groups appeared after the
	// agent started (the boot start only launches the monitor when trap groups
	// exist at boot). Requires daemonCtx (present whenever the agent is
	// running via the normal paths).
	if len(cfg.System.SNMP.TrapGroups) > 0 && !d.snmpMonitorRunning && d.snmpCtx != nil {
		d.startSNMPMonitorLocked()
	}

	d.snmpHash, d.snmpHashSet = h, true
	slog.Info("SNMP agent configuration reconciled")
	return true
}

// startSNMPLocked creates the SNMP agent for cfg and starts its UDP/161
// listener (and the link-state trap monitor when trap groups are configured)
// on a fresh lifetime context derived from d.daemonCtx. The caller MUST hold
// snmpReconMu and MUST have verified snmpEnabled(cfg). Shared by the boot start
// block and reconcileSNMP so both go through one implementation (#3967).
//
// It waits (bounded by snmpBindTimeout) for the listener goroutine to confirm
// it actually bound the socket before returning, and returns a non-nil error if
// the bind FAILED (or timed out). On that error path it has already rolled the
// half-started agent back via teardownSNMPLocked — no goroutine or socket is
// left behind and d.snmpAgent is nil again — so the caller must NOT publish the
// running-config hash and a later identical apply can retry a clean start. This
// closes #5110: the pre-fix serve closure discarded Agent.Start's bind error,
// so a transient UDP/161 failure left SNMP absent while the desired hash still
// recorded "applied", no-oping every subsequent identical commit.
func (d *Daemon) startSNMPLocked(cfg *config.Config) error {
	ctx, cancel := context.WithCancel(d.daemonCtx)
	agent := snmp.NewAgentWithBootsPath(cfg.System.SNMP, d.snmpBootsPath)
	agent.SetIfDataFn(buildSNMPIfData)

	// The serve seam binds UDP/161 and then serves for the lifetime of ctx. It
	// reports the bind outcome on `ready` EXACTLY ONCE — nil once the listener
	// is bound (before entering the blocking serve loop), or the bind error if
	// it failed — so startSNMPLocked can gate hash publication on a real bind.
	// The default splits Agent.Bind (synchronous bind) from Agent.Serve (the
	// blocking loop); tests inject a seam that scripts the bind outcome without
	// touching a privileged socket.
	serve := d.snmpServe
	if serve == nil {
		serve = func(ctx context.Context, a *snmp.Agent, ready chan<- error) {
			if err := a.Bind(ctx); err != nil {
				ready <- err
				return
			}
			ready <- nil
			a.Serve()
		}
	}

	wg := &sync.WaitGroup{}
	d.snmpAgent = agent
	d.snmpCtx = ctx
	d.snmpCancel = cancel
	d.snmpWg = wg
	d.snmpMonitorRunning = false

	// Buffered so the listener goroutine never blocks on the send even if we
	// stopped waiting (timeout path) before it reported.
	ready := make(chan error, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		serve(ctx, agent, ready)
	}()

	var bindErr error
	select {
	case bindErr = <-ready:
	case <-time.After(snmpBindTimeout):
		bindErr = fmt.Errorf("snmp: listener did not confirm bind within %s", snmpBindTimeout)
	}
	if bindErr != nil {
		// Roll the partially-started agent back so the failure path leaks no
		// goroutine/socket and the next identical apply retries a clean start.
		d.teardownSNMPLocked()
		return bindErr
	}

	if len(cfg.System.SNMP.TrapGroups) > 0 {
		d.startSNMPMonitorLocked()
	}
	slog.Info("SNMP agent started",
		"communities", len(cfg.System.SNMP.Communities),
		"v3_users", len(cfg.System.SNMP.V3Users),
		"trap_groups", len(cfg.System.SNMP.TrapGroups))
	return nil
}

// startSNMPMonitorLocked launches the netlink link-state trap monitor on the
// agent's lifetime context. The caller MUST hold snmpReconMu, MUST have a
// running agent (d.snmpAgent != nil, d.snmpCtx != nil), and MUST check
// d.snmpMonitorRunning first so the monitor is never started twice.
func (d *Daemon) startSNMPMonitorLocked() {
	d.snmpMonitorRunning = true
	d.snmpWg.Add(1)
	go func() {
		defer d.snmpWg.Done()
		d.monitorLinkState(d.snmpCtx)
	}()
}

// teardownSNMPLocked cancels the agent's lifetime context, joins the listener
// and monitor goroutines, closes the UDP socket, and clears the per-agent
// handles. The caller MUST hold snmpReconMu. Joining before nilling d.snmpAgent
// establishes a happens-before edge so the monitor goroutine's reads of
// d.snmpAgent (emitLinkStateTrap) never race the clear. Nil-safe / idempotent.
func (d *Daemon) teardownSNMPLocked() {
	if d.snmpCancel != nil {
		d.snmpCancel()
	}
	if d.snmpWg != nil {
		d.snmpWg.Wait()
	}
	if d.snmpAgent != nil {
		d.snmpAgent.Stop()
	}
	d.snmpAgent = nil
	d.snmpCtx = nil
	d.snmpCancel = nil
	d.snmpWg = nil
	d.snmpMonitorRunning = false
}

// teardownSNMP stops the SNMP subsystem during daemon shutdown. The agent
// goroutines bind to d.daemonCtx (never cancelled in production), so an
// explicit teardown is needed to release UDP/161 and join the goroutines on
// stop. Nil-safe / idempotent.
func (d *Daemon) teardownSNMP() {
	d.snmpReconMu.Lock()
	defer d.snmpReconMu.Unlock()
	d.teardownSNMPLocked()
	d.snmpHash, d.snmpHashSet = 0, false
}
