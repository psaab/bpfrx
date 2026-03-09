package userspace

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/psaab/bpfrx/pkg/config"
	"github.com/psaab/bpfrx/pkg/dataplane"
)

var _ dataplane.DataPlane = (*Manager)(nil)

func init() {
	dataplane.RegisterBackend(dataplane.TypeUserspace, func() dataplane.DataPlane {
		return New()
	})
}

type Manager struct {
	dataplane.DataPlane
	inner *dataplane.Manager

	mu         sync.Mutex
	proc       *exec.Cmd
	cfg        config.UserspaceConfig
	generation uint64
	syncCancel context.CancelFunc
}

func New() *Manager {
	inner := dataplane.New()
	inner.XDPEntryProg = "xdp_userspace_prog"
	return &Manager{DataPlane: inner, inner: inner}
}

func (m *Manager) Load() error {
	return m.inner.Load()
}

func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopLocked()
	return m.inner.Close()
}

func (m *Manager) Teardown() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopLocked()
	return m.inner.Teardown()
}

func (m *Manager) Compile(cfg *config.Config) (*dataplane.CompileResult, error) {
	result, err := m.inner.Compile(cfg)
	if err != nil {
		return nil, err
	}
	ucfg := deriveUserspaceConfig(cfg)
	snap := buildSnapshot(cfg, ucfg, m.bumpGeneration())

	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.programBootstrapMapsLocked(ucfg); err != nil {
		return result, err
	}
	if err := m.ensureProcessLocked(ucfg); err != nil {
		return result, err
	}
	var status ProcessStatus
	if err := m.requestLocked(ControlRequest{Type: "apply_snapshot", Snapshot: snap}, &status); err != nil {
		return result, fmt.Errorf("publish userspace snapshot: %w", err)
	}
	if err := m.applyHelperStatusLocked(&status); err != nil {
		return result, fmt.Errorf("sync helper status: %w", err)
	}
	m.ensureStatusLoopLocked()
	m.cfg = ucfg
	return result, nil
}

func (m *Manager) bumpGeneration() uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.generation++
	return m.generation
}

func deriveUserspaceConfig(cfg *config.Config) config.UserspaceConfig {
	out := config.UserspaceConfig{
		Workers:       1,
		RingEntries:   1024,
		ControlSocket: filepath.Join(os.TempDir(), "bpfrx-userspace-dp", "control.sock"),
		StateFile:     filepath.Join(os.TempDir(), "bpfrx-userspace-dp", "state.json"),
	}
	if cfg != nil && cfg.System.UserspaceDataplane != nil {
		out = *cfg.System.UserspaceDataplane
	}
	if out.Workers <= 0 {
		out.Workers = 1
	}
	if out.RingEntries <= 0 {
		out.RingEntries = 1024
	}
	if out.ControlSocket == "" {
		out.ControlSocket = filepath.Join(os.TempDir(), "bpfrx-userspace-dp", "control.sock")
	}
	if out.StateFile == "" {
		out.StateFile = filepath.Join(filepath.Dir(out.ControlSocket), "state.json")
	}
	return out
}

func buildSnapshot(cfg *config.Config, ucfg config.UserspaceConfig, generation uint64) *ConfigSnapshot {
	if cfg == nil {
		return &ConfigSnapshot{
			Version:     ProtocolVersion,
			Generation:  generation,
			GeneratedAt: time.Now().UTC(),
			MapPins:     userspaceMapPins(),
			Userspace:   ucfg,
		}
	}
	policyCount := len(cfg.Security.Policies)
	return &ConfigSnapshot{
		Version:     ProtocolVersion,
		Generation:  generation,
		GeneratedAt: time.Now().UTC(),
		MapPins:     userspaceMapPins(),
		Userspace:   ucfg,
		Interfaces:  buildInterfaceSnapshots(cfg),
		Routes:      buildRouteSnapshots(cfg),
		Config:      cfg,
		Summary: SnapshotSummary{
			HostName:       cfg.System.HostName,
			DataplaneType:  cfg.System.DataplaneType,
			InterfaceCount: len(cfg.Interfaces.Interfaces),
			ZoneCount:      len(cfg.Security.Zones),
			PolicyCount:    policyCount,
			SchedulerCount: len(cfg.Schedulers),
			HAEnabled:      cfg.Chassis.Cluster != nil,
		},
	}
}

func userspaceMapPins() UserspaceMapPins {
	return UserspaceMapPins{
		Ctrl:     dataplane.UserspaceCtrlPinPath(),
		Bindings: dataplane.UserspaceBindingsPinPath(),
		XSK:      dataplane.UserspaceXSKMapPinPath(),
	}
}

func buildInterfaceSnapshots(cfg *config.Config) []InterfaceSnapshot {
	if cfg == nil || len(cfg.Interfaces.Interfaces) == 0 {
		return nil
	}
	names := make([]string, 0, len(cfg.Interfaces.Interfaces))
	for name := range cfg.Interfaces.Interfaces {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]InterfaceSnapshot, 0, len(names))
	for _, name := range names {
		iface := cfg.Interfaces.Interfaces[name]
		if iface == nil {
			continue
		}
		linuxName := config.LinuxIfName(name)
		ifindex := 0
		if link, err := net.InterfaceByName(linuxName); err == nil {
			ifindex = link.Index
		}
		out = append(out, InterfaceSnapshot{
			Name:            name,
			LinuxName:       linuxName,
			Ifindex:         ifindex,
			RXQueues:        userspaceRXQueueCount(linuxName),
			LocalFabric:     iface.LocalFabricMember,
			RedundancyGroup: iface.RedundancyGroup,
			UnitCount:       len(iface.Units),
			Tunnel:          iface.Tunnel != nil,
		})
	}
	return out
}

func userspaceRXQueueCount(linuxName string) int {
	if linuxName == "" {
		return 0
	}
	entries, err := os.ReadDir(filepath.Join("/sys/class/net", linuxName, "queues"))
	if err != nil {
		return 0
	}
	count := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if name := entry.Name(); len(name) > 3 && name[:3] == "rx-" {
			count++
		}
	}
	return count
}

func buildRouteSnapshots(cfg *config.Config) []RouteSnapshot {
	if cfg == nil {
		return nil
	}
	out := make([]RouteSnapshot, 0)
	addRoutes := func(table, family string, routes []*config.StaticRoute) {
		for _, route := range routes {
			if route == nil {
				continue
			}
			snap := RouteSnapshot{
				Table:       table,
				Family:      family,
				Destination: route.Destination,
				Discard:     route.Discard,
				NextTable:   route.NextTable,
			}
			for _, nh := range route.NextHops {
				switch {
				case nh.Address != "" && nh.Interface != "":
					snap.NextHops = append(snap.NextHops, nh.Address+"@"+nh.Interface)
				case nh.Address != "":
					snap.NextHops = append(snap.NextHops, nh.Address)
				case nh.Interface != "":
					snap.NextHops = append(snap.NextHops, "@"+nh.Interface)
				}
			}
			out = append(out, snap)
		}
	}
	addRoutes("inet.0", "inet", cfg.RoutingOptions.StaticRoutes)
	addRoutes("inet6.0", "inet6", cfg.RoutingOptions.Inet6StaticRoutes)

	if len(cfg.RoutingInstances) > 0 {
		insts := make([]*config.RoutingInstanceConfig, 0, len(cfg.RoutingInstances))
		for _, ri := range cfg.RoutingInstances {
			if ri != nil {
				insts = append(insts, ri)
			}
		}
		sort.Slice(insts, func(i, j int) bool { return insts[i].Name < insts[j].Name })
		for _, ri := range insts {
			addRoutes(ri.Name+".inet.0", "inet", ri.StaticRoutes)
			addRoutes(ri.Name+".inet6.0", "inet6", ri.Inet6StaticRoutes)
		}
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Table != out[j].Table {
			return out[i].Table < out[j].Table
		}
		if out[i].Family != out[j].Family {
			return out[i].Family < out[j].Family
		}
		return out[i].Destination < out[j].Destination
	})
	return out
}

func (m *Manager) ensureProcessLocked(cfg config.UserspaceConfig) error {
	if m.proc != nil && m.proc.Process != nil && configEqual(m.cfg, cfg) {
		if err := m.requestLocked(ControlRequest{Type: "ping"}, nil); err == nil {
			return nil
		}
		slog.Warn("userspace dataplane helper unhealthy, restarting")
		m.stopLocked()
	}
	if m.proc != nil {
		m.stopLocked()
	}
	binary, err := findBinary(cfg.Binary)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(cfg.ControlSocket), 0755); err != nil {
		return fmt.Errorf("mkdir control socket dir: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(cfg.StateFile), 0755); err != nil {
		return fmt.Errorf("mkdir state dir: %w", err)
	}
	_ = os.Remove(cfg.ControlSocket)
	cmd := exec.Command(binary,
		"--control-socket", cfg.ControlSocket,
		"--state-file", cfg.StateFile,
		"--workers", fmt.Sprintf("%d", cfg.Workers),
		"--ring-entries", fmt.Sprintf("%d", cfg.RingEntries),
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start userspace dataplane helper: %w", err)
	}
	m.cfg = cfg
	m.proc = cmd
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(cfg.ControlSocket); err == nil {
			if err := m.requestLocked(ControlRequest{Type: "ping"}, nil); err == nil {
				slog.Info("userspace dataplane helper started", "pid", cmd.Process.Pid, "socket", cfg.ControlSocket)
				return nil
			}
		}
		if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	m.stopLocked()
	return fmt.Errorf("userspace dataplane helper did not become ready at %s", cfg.ControlSocket)
}

func findBinary(explicit string) (string, error) {
	if explicit != "" {
		if _, err := os.Stat(explicit); err == nil {
			return explicit, nil
		}
		return "", fmt.Errorf("userspace dataplane binary not found: %s", explicit)
	}
	candidates := []string{
		"./bpfrx-userspace-dp",
		filepath.Join("userspace-dp", "target", "release", "bpfrx-userspace-dp"),
		filepath.Join(filepath.Dir(os.Args[0]), "bpfrx-userspace-dp"),
	}
	for _, c := range candidates {
		if c == "" {
			continue
		}
		if _, err := os.Stat(c); err == nil {
			return c, nil
		}
	}
	if p, err := exec.LookPath("bpfrx-userspace-dp"); err == nil {
		return p, nil
	}
	return "", errors.New("userspace dataplane helper binary not found; build ./cmd/bpfrx-userspace-dp or configure system dataplane binary")
}

func (m *Manager) requestLocked(req ControlRequest, status *ProcessStatus) error {
	if m.cfg.ControlSocket == "" {
		return errors.New("userspace dataplane control socket not configured")
	}
	conn, err := net.DialTimeout("unix", m.cfg.ControlSocket, 2*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if err := json.NewEncoder(conn).Encode(&req); err != nil {
		return err
	}
	var resp ControlResponse
	if err := json.NewDecoder(bufio.NewReader(conn)).Decode(&resp); err != nil {
		return err
	}
	if !resp.OK {
		if resp.Error == "" {
			resp.Error = "unknown helper error"
		}
		return errors.New(resp.Error)
	}
	if status != nil && resp.Status != nil {
		*status = *resp.Status
	}
	return nil
}

type userspaceCtrlValue struct {
	Enabled         uint32
	MetadataVersion uint32
	Workers         uint32
	Flags           uint32
}

func (m *Manager) programBootstrapMapsLocked(cfg config.UserspaceConfig) error {
	ctrlMap := m.inner.Map("userspace_ctrl")
	if ctrlMap == nil {
		return errors.New("userspace_ctrl map not loaded")
	}
	bindingsMap := m.inner.Map("userspace_bindings")
	if bindingsMap == nil {
		return errors.New("userspace_bindings map not loaded")
	}

	zero := uint32(0)
	ctrl := userspaceCtrlValue{
		Enabled:         0,
		MetadataVersion: 1,
		Workers:         uint32(cfg.Workers),
		Flags:           0,
	}
	if err := ctrlMap.Update(zero, ctrl, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update userspace_ctrl: %w", err)
	}

	var key userspaceBindingKey
	var val userspaceBindingValue
	iter := bindingsMap.Iterate()
	var keys []userspaceBindingKey
	for iter.Next(&key, &val) {
		keys = append(keys, key)
	}
	for _, key := range keys {
		if err := bindingsMap.Delete(key); err != nil {
			return fmt.Errorf("delete userspace_bindings %+v: %w", key, err)
		}
	}
	return nil
}

func (m *Manager) applyHelperStatusLocked(status *ProcessStatus) error {
	ctrlMap := m.inner.Map("userspace_ctrl")
	if ctrlMap == nil {
		return errors.New("userspace_ctrl map not loaded")
	}
	bindingsMap := m.inner.Map("userspace_bindings")
	if bindingsMap == nil {
		return errors.New("userspace_bindings map not loaded")
	}

	var key userspaceBindingKey
	var val userspaceBindingValue
	iter := bindingsMap.Iterate()
	var keys []userspaceBindingKey
	for iter.Next(&key, &val) {
		keys = append(keys, key)
	}
	for _, key := range keys {
		if err := bindingsMap.Delete(key); err != nil {
			return fmt.Errorf("delete userspace_bindings %+v: %w", key, err)
		}
	}

	zero := uint32(0)
	ctrl := userspaceCtrlValue{
		Enabled:         0,
		MetadataVersion: 1,
		Workers:         uint32(maxInt(status.Workers, 1)),
		Flags:           0,
	}
	if status.Enabled {
		ctrl.Enabled = 1
	}
	if err := ctrlMap.Update(zero, ctrl, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update userspace_ctrl from helper status: %w", err)
	}

	for _, binding := range status.Bindings {
		if binding.Ifindex <= 0 {
			continue
		}
		flags := uint32(0)
		if binding.Registered && binding.Ready {
			flags = userspaceBindingReady
		}
		key := userspaceBindingKey{
			Ifindex: uint32(binding.Ifindex),
			QueueID: binding.QueueID,
		}
		val := userspaceBindingValue{
			Slot:  binding.Slot,
			Flags: flags,
		}
		if err := bindingsMap.Update(key, val, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update userspace_bindings %+v: %w", key, err)
		}
	}
	return nil
}

const userspaceBindingReady = 1

type userspaceBindingKey struct {
	Ifindex uint32
	QueueID uint32
}

type userspaceBindingValue struct {
	Slot  uint32
	Flags uint32
}

func (m *Manager) ensureStatusLoopLocked() {
	if m.syncCancel != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.syncCancel = cancel
	go m.statusLoop(ctx)
}

func (m *Manager) statusLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.mu.Lock()
			if m.proc == nil {
				m.mu.Unlock()
				return
			}
			var status ProcessStatus
			if err := m.requestLocked(ControlRequest{Type: "status"}, &status); err == nil {
				if err := m.applyHelperStatusLocked(&status); err != nil {
					slog.Warn("userspace dataplane status sync failed", "err", err)
				}
			} else {
				slog.Warn("userspace dataplane status poll failed", "err", err)
			}
			m.mu.Unlock()
		}
	}
}

func (m *Manager) stopLocked() {
	if m.syncCancel != nil {
		m.syncCancel()
		m.syncCancel = nil
	}
	if m.proc == nil {
		return
	}
	_ = m.requestLocked(ControlRequest{Type: "shutdown"}, nil)
	done := make(chan struct{})
	go func(cmd *exec.Cmd) {
		_ = cmd.Wait()
		close(done)
	}(m.proc)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		if m.proc.Process != nil {
			_ = m.proc.Process.Signal(syscall.SIGTERM)
		}
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			if m.proc.Process != nil {
				_ = m.proc.Process.Kill()
			}
			<-done
		}
	}
	m.proc = nil
}

func configEqual(a, b config.UserspaceConfig) bool {
	return a.Binary == b.Binary &&
		a.ControlSocket == b.ControlSocket &&
		a.StateFile == b.StateFile &&
		a.Workers == b.Workers &&
		a.RingEntries == b.RingEntries
}

func (m *Manager) StartFIBSync(ctx context.Context) {
	m.inner.StartFIBSync(ctx)
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
