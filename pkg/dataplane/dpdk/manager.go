package dpdk

import (
	"context"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpruntime "github.com/psaab/xpf/pkg/dataplane/runtime"
)

// Compile-time assertion.
var _ dataplane.DataPlane = (*Manager)(nil)
var _ dataplane.ConfigSink = (*Manager)(nil)
var _ dataplane.RuntimeDataPlane = (*Manager)(nil)

// NOTE: backend registration via dataplane.RegisterBackend /
// dataplane.RegisterRuntimeBackend was removed in #1527 (Phase 2 of
// the DPDK retirement, umbrella #1525).  After this change the
// package remains compilable but no production code path constructs
// a Manager through the dataplane registry.  Phase 3 (#1528) will
// delete the package outright.

// Manager is the DPDK dataplane backend (stub implementation).
type Manager struct {
	loaded          bool
	lastCompile     *dataplane.CompileResult
	applyMu         sync.Mutex
	applyGeneration uint64
	lastApply       *dataplane.ApplyResult
	persistentNAT   *dataplane.PersistentNATTable
	platform        platformState
}

// New creates a new DPDK Manager.
func New() *Manager {
	return &Manager{
		persistentNAT: dataplane.NewPersistentNATTable(),
	}
}

// --- Common methods (build-tag independent) ---

func (m *Manager) IsLoaded() bool                                  { return m.loaded }
func (m *Manager) LastCompileResult() *dataplane.CompileResult     { return m.lastCompile }
func (m *Manager) GetPersistentNAT() *dataplane.PersistentNATTable { return m.persistentNAT }
func (m *Manager) Map(_ string) *ebpf.Map                          { return nil }

func (m *Manager) ApplyConfig(ctx context.Context, cfg *config.Config) (*dataplane.ApplyResult, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	if _, err := m.Compile(cfg); err != nil {
		return nil, err
	}
	return m.LastApplyResult(), nil
}

func (m *Manager) Start(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	return m.Load()
}

func (m *Manager) Link() dataplane.LinkController {
	return dataplane.NewDataPlaneLinkController(m)
}

func (m *Manager) HA() dataplane.HAController {
	return dataplane.NewDataPlaneHAController(m)
}

func (m *Manager) Sessions() dataplane.SessionStore {
	return dataplane.NewDataPlaneSessionStore(m)
}

func (m *Manager) SessionDeltas() dpruntime.SessionDeltaSource {
	return nil
}

func (m *Manager) Telemetry() dataplane.Telemetry {
	return dataplane.NewDataPlaneTelemetry(m)
}

func (m *Manager) LastApplyResult() *dataplane.ApplyResult {
	m.applyMu.Lock()
	defer m.applyMu.Unlock()
	return m.lastApply.Clone()
}

func (m *Manager) recordApplyResult(result *dataplane.ApplyResult) {
	if result == nil {
		return
	}
	m.applyMu.Lock()
	defer m.applyMu.Unlock()
	m.applyGeneration++
	next := result.Clone()
	next.Generation = m.applyGeneration
	m.lastApply = next
}
