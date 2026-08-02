package dataplane

import (
	"fmt"

	"github.com/cilium/ebpf"
)

// Flow-config map accessors.
// Same-package split of maps.go (#1686): global flow config (TCP MSS clamp,
// ALG flags, lo0 filter IDs) and per-index flow timeouts.

// FlowConfigValue mirrors struct flow_config in xpf_common.h.
type FlowConfigValue struct {
	TCPMSSIPsec       uint16
	TCPMSSGreIn       uint16
	TCPMSSGreOut      uint16
	AllowDNSReply     uint8
	AllowEmbeddedICMP uint8
	GREAccel          uint8
	ALGFlags          uint8  // bit 0: DNS disable, bit 1: FTP disable, bit 2: SIP disable, bit 3: TFTP disable
	Lo0FilterV4       uint16 // filter ID for lo0 inet input (0xFFFF=none)
	Lo0FilterV6       uint16 // filter ID for lo0 inet6 input (0xFFFF=none)
	TCPFlags          uint8  // retired (#2078): tcp-session knobs are config-only on the userspace dataplane; field kept for xpf_common.h layout parity, no longer populated
	AppFlags          uint8  // bit 0: AppID enabled, bit 1: pre-ID session-init log, bit 2: pre-ID session-close log
}

// Lo0FilterNone is the sentinel value meaning no lo0 filter configured.
const Lo0FilterNone = uint16(0xFFFF)

// SetFlowTimeout writes a flow timeout value (in seconds) at the given index.
func (m *Manager) SetFlowTimeout(idx, seconds uint32) error {
	zm, present, st := m.lookupMapLocked("flow_timeouts")
	if st == registryFresh {
		return fmt.Errorf("%w: flow_timeouts", ErrDataplaneNotArmed)
	}
	if !present {
		return fmt.Errorf("flow_timeouts map not found")
	}
	return zm.Update(idx, seconds, ebpf.UpdateAny)
}

// SetFlowConfig writes the global flow configuration (TCP MSS clamp, etc.).
func (m *Manager) SetFlowConfig(cfg FlowConfigValue) error {
	zm, present, st := m.lookupMapLocked("flow_config_map")
	if st == registryFresh {
		return fmt.Errorf("%w: flow_config_map", ErrDataplaneNotArmed)
	}
	if !present {
		return fmt.Errorf("flow_config_map map not found")
	}
	return zm.Update(uint32(0), cfg, ebpf.UpdateAny)
}
