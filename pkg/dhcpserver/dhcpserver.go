// Package dhcpserver manages Kea DHCP server configuration and lifecycle.
package dhcpserver

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// systemctlTimeout bounds every systemctl shell-out. Apply/Clear run on
// the config-apply path under applyConfigLocked's applySem
// (daemon_apply.go d.dhcpServer.Apply), so a hung systemctl (dbus
// stall, wedged Kea stop job) would otherwise block every commit
// indefinitely. Mirrors the 15s FRR reload precedent
// (pkg/frr/manager.go reloadTimeout). #1794/#1800.
const systemctlTimeout = 15 * time.Second

// runSystemctl runs `systemctl <args...>` under systemctlTimeout. On
// failure the returned error includes the captured output, so callers
// that previously logged a bare exit status now surface the systemd
// diagnostic too.
func runSystemctl(args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), systemctlTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "systemctl", args...)
	// WaitDelay caps the post-SIGKILL pipe-drain window.
	cmd.WaitDelay = 5 * time.Second
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s: %w: %s",
			strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// unitIsActive reports whether a systemd unit is active (or on its way
// up) by querying `systemctl is-active`. A non-zero exit means "not
// active" — the state string is on stdout either way, so exit status
// is not treated as a query failure. If systemctl cannot run at all
// the output is empty and the unit is reported inactive (there is
// nothing useful to stop in that case anyway).
func unitIsActive(unit string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), systemctlTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "systemctl", "is-active", unit)
	cmd.WaitDelay = 5 * time.Second
	out, _ := cmd.Output()
	switch strings.TrimSpace(string(out)) {
	case "active", "activating", "reloading", "deactivating":
		// "deactivating" counts as active-for-stop (Codex review on PR
		// #1835): a previous daemon or external restart job can be
		// mid-stop with a queued start behind it — skipping the stop
		// here would let that queued start resurrect Kea after this
		// commit removed its config. An extra stop on a unit that was
		// going down anyway is harmless.
		return true
	}
	return false
}

const (
	kea4Config = "/etc/kea/kea-dhcp4.conf"
	kea6Config = "/etc/kea/kea-dhcp6.conf"
	kea4Svc    = "kea-dhcp4-server"
	kea6Svc    = "kea-dhcp6-server"
)

// Manager manages Kea DHCP server processes.
//
// The manager is authoritative over the kea-dhcp{4,6}-server units
// (#1778): it reconciles against the ACTUAL systemd unit state
// (`systemctl is-active`) rather than process-local booleans, so a
// stale Kea left running by a previous xpfd instance is stopped when
// the current config has no matching dhcp-server stanza.
type Manager struct {
	mu        sync.Mutex
	confPath4 string
	confPath6 string

	// Seams for tests (see test_seams.go). Production instances get
	// the package-level implementations from New().
	runSystemctl func(args ...string) error
	unitActive   func(unit string) bool
	warn         func(msg string, args ...any)

	// Generation-ordered supersession (#1835 F2 redesign after the
	// Codex confirm on PR #1835 head dcd98cf8e). EVERY applier — sync
	// Apply, sync ApplyClusterCommit, and ApplyAsync — allocates a
	// monotonic generation at CALL ENTRY from applyGen. The shared
	// apply body skips any request whose gen is <= lastAppliedGen
	// (a newer desired state already won), so a queued async request
	// can never be applied over a later synchronous commit and vice
	// versa: allocation order == arrival order, and the final state
	// is always the newest caller's.
	applyGen atomic.Uint64
	// lastAppliedGen is the generation of the newest desired state
	// whose apply body ran (guarded by mu). Set even when the apply
	// errored: the newest state was ATTEMPTED, and replaying an older
	// state over a failed newer one would regress desired state.
	lastAppliedGen uint64
	// staleApplySkips counts apply bodies skipped as superseded
	// (observable by tests; useful telemetry if exported later).
	staleApplySkips atomic.Uint64

	// ApplyAsync mailbox (#1835 F2): a mutex-guarded 1-slot pending
	// pointer plus a cap-1 wake channel, consumed by a single lazily
	// started worker goroutine, so VRRP transition callbacks never
	// block behind a 15s systemctl. (The first design used a cap-1
	// data channel with a send-after-drain retry loop; Codex showed
	// that loop is ABA-racy — an old producer could drain a newer
	// producer's request and land its older one. The pending slot is
	// overwritten only by a higher gen, so it is monotonic.)
	asyncOnce    sync.Once
	asyncMu      sync.Mutex
	pendingAsync *asyncApplyReq
	asyncNotify  chan struct{}
	// asyncWorkerStarts counts worker goroutine launches; tests assert
	// the sync.Once keeps it at 1 across ApplyAsync bursts.
	asyncWorkerStarts atomic.Int32
}

// asyncApplyReq is one desired DHCP-server state for the ApplyAsync
// worker. gen orders it against every other applier (sync and async);
// reason is logging context only (which VRRP transition asked).
type asyncApplyReq struct {
	gen    uint64
	cfg    *config.DHCPServerConfig
	reason string
}

// New creates a new DHCP server manager.
func New() *Manager {
	return &Manager{
		confPath4:    kea4Config,
		confPath6:    kea6Config,
		runSystemctl: runSystemctl,
		unitActive:   unitIsActive,
		warn:         slog.Warn,
	}
}

// Apply reconciles the Kea DHCP servers with the xpf DHCP server
// config. For each address family that is configured it regenerates
// the Kea config and restarts the unit; for each family that is NOT
// configured (including cfg == nil) it stops the unit if systemd
// reports it active — regardless of whether this process started it —
// and removes the generated config file.
//
// Fail-closed (#1778): a restart failure (or a failure to stop an
// active unit that is no longer in config) is returned to the caller
// so a config commit surfaces the failure instead of reporting
// success while no DHCP service is running. A nil return can also
// mean the request was superseded by a newer applier (gen ordering);
// being superseded is not a failure — the newer desired state won.
func (m *Manager) Apply(cfg *config.DHCPServerConfig) error {
	return m.apply(m.applyGen.Add(1), cfg, true)
}

// ApplyClusterCommit reconciles for a cluster-mode config commit
// (#1835 F3). Configured families ALWAYS get a freshly generated
// config file — so a dhcp-server config change is not lost until the
// next VRRP transition — but the unit is restarted only when systemd
// reports it active: an active unit means this node is currently
// serving (VRRP MASTER for the relevant RGs), so the change must
// reach the running Kea now. Inactive units stay stopped with the
// fresh config on disk; the next VRRP MASTER transition's Apply
// starts them. Unconfigured families are cleared exactly as in Apply.
// Fail-closed like Apply: generate/restart/stop failures are returned
// so the commit surfaces them.
func (m *Manager) ApplyClusterCommit(cfg *config.DHCPServerConfig) error {
	return m.apply(m.applyGen.Add(1), cfg, false)
}

// apply is the shared reconcile body for every applier (sync Apply,
// sync ApplyClusterCommit, async worker). gen is the caller's
// generation, allocated at call entry; a request older than the
// newest applied desired state is skipped (superseded — Codex hole 2
// on PR #1835: without this, a queued async request could be applied
// OVER a later synchronous commit's fresh config). restartInactive
// selects whether a configured family's unit is restarted
// unconditionally (standalone / VRRP-MASTER semantics) or only when
// already active (cluster commit semantics, see ApplyClusterCommit).
func (m *Manager) apply(gen uint64, cfg *config.DHCPServerConfig, restartInactive bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if gen <= m.lastAppliedGen {
		// A newer desired state has already been applied (or
		// attempted). Skipping is correct, not an error: the caller's
		// state was superseded before it reached the reconcile body.
		m.staleApplySkips.Add(1)
		slog.Debug("skipping superseded DHCP server apply",
			"gen", gen, "last_applied_gen", m.lastAppliedGen)
		return nil
	}

	var errs []error

	want4 := cfg != nil && cfg.DHCPLocalServer != nil && len(cfg.DHCPLocalServer.Groups) > 0
	want6 := cfg != nil && cfg.DHCPv6LocalServer != nil && len(cfg.DHCPv6LocalServer.Groups) > 0

	if want4 {
		if err := m.generateKea4Config(cfg); err != nil {
			errs = append(errs, fmt.Errorf("generate kea4 config: %w", err))
		} else if restartInactive || m.unitActive(kea4Svc) {
			if err := m.runSystemctl("restart", kea4Svc); err != nil {
				errs = append(errs, fmt.Errorf("restart %s: %w", kea4Svc, err))
			}
		}
	} else if err := m.clearFamilyLocked(kea4Svc, m.confPath4); err != nil {
		errs = append(errs, err)
	}

	if want6 {
		if err := m.generateKea6Config(cfg); err != nil {
			errs = append(errs, fmt.Errorf("generate kea6 config: %w", err))
		} else if restartInactive || m.unitActive(kea6Svc) {
			if err := m.runSystemctl("restart", kea6Svc); err != nil {
				errs = append(errs, fmt.Errorf("restart %s: %w", kea6Svc, err))
			}
		}
	} else if err := m.clearFamilyLocked(kea6Svc, m.confPath6); err != nil {
		errs = append(errs, err)
	}

	m.lastAppliedGen = gen
	return errors.Join(errs...)
}

// ApplyAsync enqueues an authoritative Apply for cfg and returns
// immediately (#1835 F2). The VRRP event loop calls the Kea manager on
// MASTER/BACKUP transitions; running Apply inline there would hold the
// loop for up to 15s per systemctl shell-out. Instead, desired states
// go through a 1-slot latest-wins mailbox drained by a single worker
// goroutine (started lazily, once per Manager).
//
// Latest-wins coalescing is correct because Apply is an idempotent
// reconcile to the desired state: when transitions arrive faster than
// systemctl completes, intermediate states may be skipped, but the
// newest desired state always wins — the mailbox slot is monotonic in
// gen, and the shared apply body skips any request superseded by a
// newer applier (sync OR async). Pass cfg == nil for an authoritative
// clear (same semantics as Apply(nil)). Errors are logged by the
// worker with the supplied reason; callers that need fail-closed
// errors (the commit path) use the synchronous Apply instead.
func (m *Manager) ApplyAsync(cfg *config.DHCPServerConfig, reason string) {
	m.enqueueAsync(&asyncApplyReq{
		gen:    m.applyGen.Add(1),
		cfg:    cfg,
		reason: reason,
	})
}

// enqueueAsync installs req in the pending slot iff it is the newest
// async request seen, then wakes the singleton worker. Split from
// ApplyAsync so tests can inject a request whose gen was allocated
// earlier (modeling a producer preempted between call entry and
// enqueue — the interleaving behind Codex hole 1).
//
// The gen guard on the overwrite (not unconditional) closes the
// async-vs-async ABA residue: two producers can allocate gens in one
// order and reach this mutex in the other; an unconditional overwrite
// would let the older gen replace the newer one, and with the newer
// gen never applied the lastAppliedGen check could not save it.
func (m *Manager) enqueueAsync(req *asyncApplyReq) {
	m.asyncOnce.Do(func() {
		m.asyncNotify = make(chan struct{}, 1)
		m.asyncWorkerStarts.Add(1)
		go m.applyAsyncWorker()
	})
	m.asyncMu.Lock()
	if m.pendingAsync == nil || req.gen > m.pendingAsync.gen {
		m.pendingAsync = req
	}
	m.asyncMu.Unlock()
	// Non-blocking wake: a token already in flight covers this set
	// too (the worker re-reads pendingAsync after every wake).
	select {
	case m.asyncNotify <- struct{}{}:
	default:
	}
}

// applyAsyncWorker is the singleton consumer for ApplyAsync. It runs
// for the daemon's lifetime (the wake channel is never closed); each
// wake takes the pending desired state (leaving the slot empty) and
// runs the shared gen-checked apply body under the normal m.mu
// serialization with synchronous appliers.
func (m *Manager) applyAsyncWorker() {
	for range m.asyncNotify {
		m.asyncMu.Lock()
		req := m.pendingAsync
		m.pendingAsync = nil
		m.asyncMu.Unlock()
		if req == nil {
			continue
		}
		if err := m.apply(req.gen, req.cfg, true); err != nil {
			slog.Warn("async DHCP server apply failed",
				"reason", req.reason, "gen", req.gen, "err", err)
		}
	}
}

// clearFamilyLocked stops one Kea unit if systemd reports it active
// and removes its generated config file. Caller must hold m.mu.
func (m *Manager) clearFamilyLocked(svc, confPath string) error {
	var err error
	if m.unitActive(svc) {
		if e := m.runSystemctl("stop", svc); e != nil {
			err = fmt.Errorf("stop %s: %w", svc, e)
			slog.Warn("failed to stop Kea unit", "service", svc, "err", e)
		} else {
			slog.Info("stopped Kea unit not in current config", "service", svc)
		}
	}
	os.Remove(confPath)
	return err
}

// Clear stops both Kea units (if systemd reports them active) and
// removes the generated configs. Stop failures are logged at Warn by
// clearFamilyLocked; callers on the VRRP transition path (daemon_ha)
// cannot fail a state transition, so Clear keeps a void signature.
// Commit-path callers use Apply(nil) instead, which returns errors.
func (m *Manager) Clear() {
	// Delegate to Apply(nil) so a Clear participates in the same
	// generation ordering as every other applier (#1835 F2 redesign)
	// instead of silently bypassing supersession. Errors are already
	// logged at Warn by clearFamilyLocked.
	_ = m.Apply(nil)
}

// IsRunning returns true if any Kea server unit is active per systemd
// (authoritative — survives xpfd restarts, unlike the pre-#1778
// process-local booleans).
func (m *Manager) IsRunning() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.unitActive(kea4Svc) || m.unitActive(kea6Svc)
}

// Lease represents a DHCP lease from Kea's lease database.
type Lease struct {
	Address    string
	HWAddress  string
	Hostname   string
	ValidLife  string
	ExpireTime string
	SubnetID   string
}

// GetLeases4 reads Kea DHCPv4 lease file and returns active leases.
func (m *Manager) GetLeases4() ([]Lease, error) {
	return parseLeaseCSV("/var/lib/kea/kea-leases4.csv")
}

// GetLeases6 reads Kea DHCPv6 lease file and returns active leases.
func (m *Manager) GetLeases6() ([]Lease, error) {
	return parseLeaseCSV("/var/lib/kea/kea-leases6.csv")
}

func parseLeaseCSV(path string) ([]Lease, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.FieldsPerRecord = -1 // memfile rows can vary across Kea versions
	r.Comment = '#'
	records, err := r.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(records) < 2 {
		return nil, nil
	}

	// Parse CSV header to find column indices
	cols := make(map[string]int)
	for i, h := range records[0] {
		cols[h] = i
	}

	var leases []Lease
	for _, fields := range records[1:] {
		l := Lease{}
		if idx, ok := cols["address"]; ok && idx < len(fields) {
			l.Address = fields[idx]
		}
		if idx, ok := cols["hwaddr"]; ok && idx < len(fields) {
			l.HWAddress = fields[idx]
		}
		if idx, ok := cols["hostname"]; ok && idx < len(fields) {
			l.Hostname = fields[idx]
		}
		if idx, ok := cols["valid_lifetime"]; ok && idx < len(fields) {
			l.ValidLife = fields[idx]
		}
		if idx, ok := cols["expire"]; ok && idx < len(fields) {
			l.ExpireTime = fields[idx]
		}
		if idx, ok := cols["subnet_id"]; ok && idx < len(fields) {
			l.SubnetID = fields[idx]
		}
		if l.Address != "" {
			leases = append(leases, l)
		}
	}
	return leases, nil
}

// subnetInterface returns the per-subnet interface binding for a
// group. Kea allows at most ONE interface per subnet; for a
// single-interface group binding it explicitly is the most robust
// selection. For multi-interface groups the binding is omitted so Kea
// falls back to address-based subnet selection (matching the address
// of the receiving interface against the subnet prefix) — the
// pre-#1778 renderer silently bound only the first interface,
// breaking the others. All group interfaces are always listed in
// interfaces-config, so Kea listens on every one either way.
func subnetInterface(group *config.DHCPServerGroup) string {
	if len(group.Interfaces) == 1 {
		return group.Interfaces[0]
	}
	return ""
}

// warnAmbiguousV4SubnetSelection warns when two DIFFERENT groups render
// the same or overlapping v4 subnets while at least one of the involved
// groups emits no per-subnet interface selector (multi-interface groups,
// see subnetInterface). Kea's subnet selection is then ambiguous: a
// DISCOVER arriving on a shared interface can match either subnet, so
// which pool answers is undefined. This stays a WARNING, not an error —
// such configs were accepted before #1778 and must keep committing.
func (m *Manager) warnAmbiguousV4SubnetSelection(srv *config.DHCPLocalServerConfig) {
	type subnetRef struct {
		group    string
		subnet   string
		prefix   netip.Prefix
		selector bool // group emits a per-subnet interface selector
	}
	var refs []subnetRef
	for name, group := range srv.Groups {
		sel := subnetInterface(group) != ""
		for _, pool := range group.Pools {
			p, err := netip.ParsePrefix(pool.Subnet)
			if err != nil {
				continue // Kea rejects the malformed subnet itself
			}
			refs = append(refs, subnetRef{
				group: name, subnet: pool.Subnet,
				prefix: p.Masked(), selector: sel,
			})
		}
	}
	for i := 0; i < len(refs); i++ {
		for j := i + 1; j < len(refs); j++ {
			a, b := refs[i], refs[j]
			if a.group == b.group || (a.selector && b.selector) {
				continue
			}
			if a.prefix.Overlaps(b.prefix) {
				m.warn("ambiguous Kea subnet selection: overlapping subnets across groups without per-subnet interface selectors",
					"group_a", a.group, "subnet_a", a.subnet,
					"group_b", b.group, "subnet_b", b.subnet)
			}
		}
	}
}

func (m *Manager) generateKea4Config(cfg *config.DHCPServerConfig) error {
	type keaPool struct {
		Pool string `json:"pool"`
	}
	type keaOpt struct {
		Name string `json:"name"`
		Data string `json:"data"`
	}
	type keaSubnet4 struct {
		ID            int       `json:"id"`
		Subnet        string    `json:"subnet"`
		Pools         []keaPool `json:"pools,omitempty"`
		Interface     string    `json:"interface,omitempty"`
		OptionData    []keaOpt  `json:"option-data,omitempty"`
		ValidLifetime int       `json:"valid-lifetime,omitempty"`
	}

	m.warnAmbiguousV4SubnetSelection(cfg.DHCPLocalServer)

	var subnets []keaSubnet4
	subnetID := 1
	for _, group := range cfg.DHCPLocalServer.Groups {
		for _, pool := range group.Pools {
			sub := keaSubnet4{
				ID:     subnetID,
				Subnet: pool.Subnet,
			}
			subnetID++
			if pool.RangeLow != "" && pool.RangeHigh != "" {
				sub.Pools = append(sub.Pools, keaPool{
					Pool: fmt.Sprintf("%s - %s", pool.RangeLow, pool.RangeHigh),
				})
			}
			sub.Interface = subnetInterface(group)
			if pool.Router != "" {
				sub.OptionData = append(sub.OptionData, keaOpt{
					Name: "routers", Data: pool.Router,
				})
			}
			if len(pool.DNSServers) > 0 {
				sub.OptionData = append(sub.OptionData, keaOpt{
					Name: "domain-name-servers", Data: strings.Join(pool.DNSServers, ", "),
				})
			}
			if pool.Domain != "" {
				sub.OptionData = append(sub.OptionData, keaOpt{
					Name: "domain-name", Data: pool.Domain,
				})
			}
			if pool.LeaseTime > 0 {
				sub.ValidLifetime = pool.LeaseTime
			}
			subnets = append(subnets, sub)
		}
	}

	// Collect interfaces
	var ifaces []string
	for _, group := range cfg.DHCPLocalServer.Groups {
		ifaces = append(ifaces, group.Interfaces...)
	}

	keaCfg := map[string]any{
		"Dhcp4": map[string]any{
			"interfaces-config": map[string]any{
				"interfaces": ifaces,
			},
			"lease-database": map[string]any{
				"type": "memfile",
				"name": "/var/lib/kea/kea-leases4.csv",
			},
			"valid-lifetime": 86400,
			"subnet4":        subnets,
		},
	}

	return m.writeKeaConfig(m.confPath4, keaCfg)
}

func (m *Manager) generateKea6Config(cfg *config.DHCPServerConfig) error {
	type keaPool struct {
		Pool string `json:"pool"`
	}
	type keaOpt struct {
		Name string `json:"name"`
		Data string `json:"data"`
	}
	type keaSubnet6 struct {
		ID            int       `json:"id"`
		Subnet        string    `json:"subnet"`
		Pools         []keaPool `json:"pools,omitempty"`
		Interface     string    `json:"interface,omitempty"`
		OptionData    []keaOpt  `json:"option-data,omitempty"`
		ValidLifetime int       `json:"valid-lifetime,omitempty"`
	}

	var subnets []keaSubnet6
	subnetID := 1
	for _, group := range cfg.DHCPv6LocalServer.Groups {
		for _, pool := range group.Pools {
			sub := keaSubnet6{
				ID:     subnetID,
				Subnet: pool.Subnet,
			}
			subnetID++
			if pool.RangeLow != "" && pool.RangeHigh != "" {
				sub.Pools = append(sub.Pools, keaPool{
					Pool: fmt.Sprintf("%s - %s", pool.RangeLow, pool.RangeHigh),
				})
			}
			// Kea v6 subnet selection cannot fall back to address
			// matching the way v4 can (clients talk from link-local
			// source addresses), so subnet6 REQUIRES the interface
			// selector — silently omitting it for a multi-interface
			// group would orphan the subnet (Codex review on PR
			// #1835). Reject loudly; the operator splits the group.
			if len(group.Interfaces) > 1 {
				return fmt.Errorf("DHCPv6 group spanning interfaces %v: Kea subnet6 requires a single interface selector — split the group per interface", group.Interfaces)
			}
			sub.Interface = subnetInterface(group)
			if len(pool.DNSServers) > 0 {
				sub.OptionData = append(sub.OptionData, keaOpt{
					Name: "dns-servers", Data: strings.Join(pool.DNSServers, ", "),
				})
			}
			if pool.Domain != "" {
				sub.OptionData = append(sub.OptionData, keaOpt{
					Name: "domain-search", Data: pool.Domain,
				})
			}
			if pool.LeaseTime > 0 {
				sub.ValidLifetime = pool.LeaseTime
			}
			subnets = append(subnets, sub)
		}
	}

	var ifaces []string
	for _, group := range cfg.DHCPv6LocalServer.Groups {
		ifaces = append(ifaces, group.Interfaces...)
	}

	keaCfg := map[string]any{
		"Dhcp6": map[string]any{
			"interfaces-config": map[string]any{
				"interfaces": ifaces,
			},
			"lease-database": map[string]any{
				"type": "memfile",
				"name": "/var/lib/kea/kea-leases6.csv",
			},
			"valid-lifetime": 86400,
			"subnet6":        subnets,
		},
	}

	return m.writeKeaConfig(m.confPath6, keaCfg)
}

func (m *Manager) writeKeaConfig(path string, keaCfg map[string]any) error {
	data, err := json.MarshalIndent(keaCfg, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	return os.WriteFile(path, data, 0644)
}
