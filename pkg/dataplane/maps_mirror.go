package dataplane

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
)

// Port-mirroring map accessors.
// Same-package split of maps.go (#1686): the mirror_config map, a distinct
// surface from screen/IDS (split out per #1686 round-1 review).

// SetMirrorConfig writes a port-mirroring entry for the given ingress ifindex.
func (m *Manager) SetMirrorConfig(ifindex int, mirrorIfindex int, rate uint32) error {
	zm, ok := m.maps["mirror_config"]
	if !ok {
		return fmt.Errorf("mirror_config map not found")
	}
	val := MirrorConfig{
		MirrorIfindex: uint32(mirrorIfindex),
		Rate:          rate,
	}
	return zm.Update(uint32(ifindex), val, ebpf.UpdateAny)
}

// ClearMirrorConfigs removes all mirror_config entries.
// mirror_config is a HASH (#756): iterate-and-delete existing keys.
func (m *Manager) ClearMirrorConfigs() error {
	zm, ok := m.maps["mirror_config"]
	if !ok {
		return fmt.Errorf("mirror_config map not found")
	}
	var key uint32
	var val MirrorConfig
	iter := zm.Iterate()
	var keys []uint32
	for iter.Next(&key, &val) {
		keys = append(keys, key)
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("iterate mirror_config: %w", err)
	}
	for _, k := range keys {
		if err := zm.Delete(k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("delete mirror_config %d: %w", k, err)
		}
	}
	return nil
}
