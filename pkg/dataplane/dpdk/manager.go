package dpdk

import (
	"github.com/cilium/ebpf"
	"github.com/psaab/xpf/pkg/dataplane"
)

// Compile-time assertion.
var _ dataplane.DataPlane = (*Manager)(nil)

func init() {
	dataplane.RegisterBackend(dataplane.TypeDPDK, func() dataplane.DataPlane {
		return New()
	})
}

// Manager is the DPDK dataplane backend (stub implementation).
type Manager struct {
	loaded        bool
	lastCompile   *dataplane.CompileResult
	persistentNAT *dataplane.PersistentNATTable
	platform      platformState
}

// New creates a new DPDK Manager.
func New() *Manager {
	return &Manager{
		persistentNAT: dataplane.NewPersistentNATTable(),
	}
}

// --- Common methods (build-tag independent) ---

func (m *Manager) IsLoaded() bool                              { return m.loaded }
func (m *Manager) LastCompileResult() *dataplane.CompileResult  { return m.lastCompile }
func (m *Manager) GetPersistentNAT() *dataplane.PersistentNATTable { return m.persistentNAT }
func (m *Manager) Map(_ string) *ebpf.Map                      { return nil }
