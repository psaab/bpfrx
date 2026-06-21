// Package dhcpserver manages Kea DHCP server configuration and lifecycle.
package dhcpserver

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/fsatomic"
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
	// Kea memfile lease databases (per family). Shared by the display
	// reader, the DDNS reconciler, and the #2239 lease-sync memfile
	// fallback so the path is defined once.
	keaLeaseFile4 = "/var/lib/kea/kea-leases4.csv"
	keaLeaseFile6 = "/var/lib/kea/kea-leases6.csv"
)

// libDHCPLeaseCmdsPath is the absolute path of the lease_cmds hook library.
// The #2239 lease-sync read/seed path issues lease{4,6}-get-all and
// lease{4,6}-add over the control socket; both require this hook loaded in the
// generated Kea config. It ships in kea-common (live-verified 3.0.3), so no new
// apt package is needed; if the file is ever absent the read path falls back to
// the memfile parser.
const libDHCPLeaseCmdsPath = "/usr/lib/x86_64-linux-gnu/kea/hooks/libdhcp_lease_cmds.so"

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

	// #2239 HA DHCP-server lease synchronization (PATH C). When
	// leaseSyncEnabled is set (cluster + `dhcp-lease-synchronization`
	// knob), the generated Kea config gains a unix control-socket and the
	// lease_cmds hook so leases can be read (lease{4,6}-get-all) and seeded
	// (lease{4,6}-add) without racing the memfile. The flag is set by the
	// daemon via SetLeaseSyncEnabled before an apply; standalone / knob-off
	// leaves the config bit-identical to pre-#2239.
	leaseSyncEnabled atomic.Bool

	// keaDial / ctrlSocket{4,6} / leaseFile{4,6} are test seams for the
	// lease-sync read/seed path (lease_sync.go). Production leaves them
	// zero, which selects net.Dial + the package-default paths.
	keaDial     keaSocketDialer
	ctrlSocket4 string
	ctrlSocket6 string
	leaseFile4  string
	leaseFile6  string
}

// SetLeaseSyncEnabled toggles emission of the Kea control-socket + lease_cmds
// hook in the generated config (#2239). It takes effect on the next apply; the
// daemon calls it from the config-apply path when the cluster
// `dhcp-lease-synchronization` knob is set.
func (m *Manager) SetLeaseSyncEnabled(enabled bool) {
	m.leaseSyncEnabled.Store(enabled)
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
	return parseLeaseCSV(m.leaseFile(4), time.Now())
}

// GetLeases6 reads Kea DHCPv6 lease file and returns active leases.
func (m *Manager) GetLeases6() ([]Lease, error) {
	return parseLeaseCSV(m.leaseFile(6), time.Now())
}

// parseLeaseCSV parses Kea's append-only memfile CSV and returns the
// CURRENT, ACTIVE leases for display (`show dhcp server leases`).
//
// Kea never rewrites the memfile in place between lease-file-cleanup
// (LFC) compactions: every renewal, re-allocation, release, decline,
// and expiry-reclaim is APPENDED as a new row, so the same address
// appears multiple times and superseded/stale rows linger until the
// next LFC. A naive "emit every row with a non-empty address" therefore
// shows duplicate and stale leases (#2085). This parser collapses the
// append log to one row per address (the LAST, i.e. newest, row wins —
// rows are chronological) and drops rows that are not currently active:
//
//   - state != 0 (declined / expired-reclaimed): Kea writes a
//     non-default state but often a FUTURE expire epoch on
//     release/decline, so an expire-only filter would still show it.
//   - expire <= now: a genuinely lapsed lease.
//
// It is LENIENT by design (this is a non-destructive display path,
// unlike the destructive DDNS reconciler's parseActiveLeases, which
// hard-errors on a mangled header): an absent or unparseable state /
// expire column degrades to "treat the row as active", preserving the
// pre-#2085 behaviour for older Kea or exotic headers rather than
// blanking the whole `show` on one odd row. now is injected so the
// expiry comparison is deterministic in tests.
func parseLeaseCSV(path string, now time.Time) ([]Lease, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	// Read the memfile RECORD-BY-RECORD rather than with ReadAll so a
	// single torn/concurrent Kea append (Kea appends a row on every
	// renewal/release/decline/reclaim while we read) does not blank the
	// entire `show dhcp server leases` (#2154). ReadAll aborts on the
	// FIRST malformed record and returns (nil, err); the per-record loop
	// logs and SKIPS the bad row, keeping every valid lease around it.
	// This is the I/O-layer companion to #2085's per-record semantic
	// leniency (dedup/expire/state) — #2085 made the SEMANTICS lenient
	// but left the READ all-or-nothing.
	//
	// FieldsPerRecord = -1 means a short concurrent line is not even an
	// error; csv.Read() also RECOVERS after a *csv.ParseError (the next
	// Read returns the following valid record or io.EOF), so the skip
	// loop terminates naturally rather than spinning.
	r := csv.NewReader(f)
	r.FieldsPerRecord = -1 // memfile rows can vary across Kea versions / torn appends
	r.Comment = '#'

	// cols maps header name -> column index; it stays nil until the
	// first successful record (the header) is read. field() reads a named
	// column out of a data row.
	var cols map[string]int
	field := func(fields []string, name string) string {
		if idx, ok := cols[name]; ok && idx >= 0 && idx < len(fields) {
			return fields[idx]
		}
		return ""
	}

	// latest holds the final disposition per address; a zero Lease
	// (empty Address) is a TOMBSTONE meaning the last row for that
	// address was inactive/expired. order keeps first-appearance order
	// so the display is stable and deterministic. Re-recording the
	// disposition on every row lets a later active append RECLAIM an
	// address an earlier row tombstoned (release-then-reallocate).
	latest := make(map[string]Lease)
	order := make([]string, 0)
	seen := make(map[string]struct{})
	nowUnix := now.Unix()

	for {
		fields, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			// Torn/concurrent Kea append or an exotic malformed row.
			// Skip just this record and keep reading the rest (#2154);
			// csv.Read recovers on the next call. Debug, not Warn: a
			// persistently corrupt file is polled once per `show`, and
			// the issue mandates debug-level so a busy network does not
			// spam the log.
			slog.Debug("dhcpserver: skipping malformed lease row",
				"path", path, "err", err)
			continue
		}
		if cols == nil {
			// First successful record is the header; build the column
			// index map and move on (mirrors the old records[0]).
			cols = make(map[string]int, len(fields))
			for i, h := range fields {
				cols[h] = i
			}
			continue
		}

		addr := field(fields, "address")
		if addr == "" {
			continue
		}
		if _, ok := seen[addr]; !ok {
			seen[addr] = struct{}{}
			order = append(order, addr)
		}

		// State filter (lenient): only Kea's default state (0 = active)
		// is displayable. A declined (1) or expired-reclaimed (2) lease
		// can still carry a FUTURE expire epoch, so this must precede the
		// expire check. An absent/unparseable state ⇒ active (Kea
		// default). A non-active row tombstones the address; a later
		// active append can still reclaim it.
		if s := field(fields, "state"); s != "" {
			if st, e := strconv.Atoi(s); e == nil && st != 0 {
				latest[addr] = Lease{}
				continue
			}
		}

		// Expire filter (lenient): drop a lease whose expire epoch has
		// lapsed. Absent/unparseable/zero expire ⇒ keep (don't hide a
		// lease over an exotic value on a display).
		expireStr := field(fields, "expire")
		if expireStr != "" {
			if exp, e := strconv.ParseInt(expireStr, 10, 64); e == nil && exp > 0 && nowUnix >= exp {
				latest[addr] = Lease{}
				continue
			}
		}

		latest[addr] = Lease{
			Address:    addr,
			HWAddress:  field(fields, "hwaddr"),
			Hostname:   field(fields, "hostname"),
			ValidLife:  field(fields, "valid_lifetime"),
			ExpireTime: expireStr,
			SubnetID:   field(fields, "subnet_id"),
		}
	}

	if cols == nil {
		// No header row was ever read (empty file, comment-only file, or
		// a file whose only line was malformed). Mirrors the old
		// len(records) < 2 ⇒ nil,nil guard. A header-only file falls
		// through with an empty order and returns nil,nil below.
		return nil, nil
	}

	leases := make([]Lease, 0, len(order))
	for _, addr := range order {
		if l := latest[addr]; l.Address != "" {
			leases = append(leases, l)
		}
	}
	if len(leases) == 0 {
		return nil, nil
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

	dhcp4 := map[string]any{
		"interfaces-config": map[string]any{
			"interfaces": ifaces,
		},
		"lease-database": map[string]any{
			"type": "memfile",
			"name": keaLeaseFile4,
		},
		"valid-lifetime": 86400,
		"subnet4":        subnets,
	}
	m.addLeaseSyncStanza(dhcp4, 4)
	keaCfg := map[string]any{"Dhcp4": dhcp4}

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

	dhcp6 := map[string]any{
		"interfaces-config": map[string]any{
			"interfaces": ifaces,
		},
		"lease-database": map[string]any{
			"type": "memfile",
			"name": keaLeaseFile6,
		},
		"valid-lifetime": 86400,
		"subnet6":        subnets,
	}
	m.addLeaseSyncStanza(dhcp6, 6)
	keaCfg := map[string]any{"Dhcp6": dhcp6}

	return m.writeKeaConfig(m.confPath6, keaCfg)
}

// addLeaseSyncStanza injects the unix control-socket + lease_cmds hook into a
// generated Kea Dhcp{4,6} object when #2239 lease sync is enabled. When the
// knob is off (or standalone) it is a no-op, so the rendered config is
// bit-identical to pre-#2239. The control socket lets the #2239 push/seed path
// read (lease{4,6}-get-all) and write (lease{4,6}-add) the live lease set
// without racing the append-only memfile. The hook (libdhcp_lease_cmds.so)
// ships in kea-common; it is additive and does not change DHCP serving
// behavior.
func (m *Manager) addLeaseSyncStanza(dhcp map[string]any, family int) {
	if !m.leaseSyncEnabled.Load() {
		return
	}
	dhcp["control-socket"] = map[string]any{
		"socket-type": "unix",
		"socket-name": m.controlSocket(family),
	}
	dhcp["hooks-libraries"] = []map[string]any{
		{"library": libDHCPLeaseCmdsPath},
	}
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
	// AtomicGeneratedConfig (#1894): regenerated on apply; Kea must
	// never parse a torn file, but the apply path pays no fsync.
	return fsatomic.WriteFileAtomic(path, data, 0644)
}
