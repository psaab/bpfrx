// Package dataplane: retained Rust AF_XDP shim loader.
//
// This file holds the loader graph that survived the #1476
// mechanical source removal of the legacy XDP/TC eBPF dataplane.
// Before #1476 this graph lived alongside the legacy
// loadAllObjects() bpf2go bootstrap in loader_ebpf.go; that file
// is gone now. The retained shim is owned by the Rust
// userspace-xdp/ crate, compiled via build-userspace-xdp.sh and
// embedded into the Go binary by userspace_xdp_rust.go.
//
// Manager.LoadUserspaceShim() and Manager.CompileUserspaceShim()
// in loader.go are the production entry points; everything below
// is their plumbing.
package dataplane

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"unsafe"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

const (
	bpfPinPath                         = "/sys/fs/bpf/xpf"
	userspaceShimGenerateRemediation   = "Re-run `make generate-userspace-xdp`."
	userspaceBindingsMapName           = "userspace_bindings"
	userspaceIngressIfacesMapName      = "userspace_ingress_ifaces"
	userspaceShimCompatibilityDNATName = "dnat_table"
	// userspaceFallbackStatsMapName is the internal mixed-version compatibility
	// name for the degraded-path counter map (operator surface:
	// degraded_path_counters). #4113 changed its BPF type from Array to
	// PerCpuArray; it is a collection-pinned map, so a stale incompatible pin
	// must be reconciled on upgrade (see reconcileDisposableCollectionPin).
	userspaceFallbackStatsMapName = "userspace_fallback_stats"
)

// pinnedMaps lists maps that survive daemon restarts via BPF
// filesystem pins. Config-derived maps are repopulated from config
// on every Compile(). Infrastructure maps (per-CPU scratch,
// counters) are recreated fresh each time.
//
// After #1476 this set is narrowed to the userspace shim's shared
// maps only. The legacy PROG_ARRAY pins (xdp_progs, tc_progs) and
// the legacy per-CPU policer_states pin are dropped — they no
// longer exist as kernel objects because no legacy program loads
// them. cleanupUserspaceShimLegacyOnlyMapPins() in loader.go
// removes the stale pins from disk on first boot after upgrade.
var pinnedMaps = map[string]bool{
	"sessions":          true,
	"sessions_v6":       true,
	"dnat_table":        true,
	"dnat_table_v6":     true,
	"nat64_state":       true,
	"nat_port_counters": true, // retained shim shared state (loader_ebpf.go used to also list this — kept here)
}

// loadUserspaceShimObjects loads the retained Rust AF_XDP shim
// collection and pins the shared maps that the userspace runtime
// still exchanges with Go.
func (m *Manager) loadUserspaceShimObjects() error {
	if err := os.MkdirAll(bpfPinPath, 0700); err != nil {
		return fmt.Errorf("create pin path %s: %w", bpfPinPath, err)
	}

	if err := m.loadUserspaceShimObjectsOnce(); err != nil {
		return err
	}
	return nil
}

func (m *Manager) loadUserspaceShimObjectsOnce() (err error) {
	sharedMaps, err := loadUserspaceShimSharedMaps()
	if err != nil {
		return err
	}
	keepShared := false
	defer func() {
		if keepShared {
			return
		}
		closeUniqueMaps(sharedMaps)
	}()

	userspaceSpec, err := loadRustUserspaceXDP()
	if err != nil {
		return fmt.Errorf("load Rust xdp_userspace spec: %w", err)
	}
	if err := validateUserspaceShimSpec(userspaceSpec); err != nil {
		return err
	}
	for _, name := range userspacePinnedShimMaps() {
		if ms, ok := userspaceSpec.Maps[name]; ok {
			ms.Pinning = ebpf.PinByName
		}
	}

	// #4113 upgrade migration: userspace_fallback_stats changed from Array to
	// PerCpuArray. It is pinned by the collection load below (PinByName), whose
	// compatibility check rejects a stale Array pin from a previous daemon with
	// ErrMapIncompatible — aborting the whole shim load and bricking a rolling
	// upgrade (#1917/#1960 class). Drop the incompatible pin first so the load
	// recreates it fresh. Safe because it is a DISPOSABLE degraded-path counter
	// (resets on every reload); DATA maps are never reset here.
	if spec, ok := userspaceSpec.Maps[userspaceFallbackStatsMapName]; ok {
		pinPath := filepath.Join(bpfPinPath, userspaceFallbackStatsMapName)
		if err := reconcileDisposableCollectionPin(pinPath, spec); err != nil {
			return err
		}
	}

	opts := ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: bpfPinPath,
		},
		MapReplacements: map[string]*ebpf.Map{},
	}
	if dnat := sharedMaps["dnat_table"]; dnat != nil {
		opts.MapReplacements["dnat_table"] = dnat
	}
	// #2406: bind the shim's dnat_table_v6 reader to the Go-created/pinned
	// shared map so SNAT66-return entries published by the userspace-dp
	// helper (publish_dnat_table_entry v6 arm) are visible to the shim's
	// GRE-inner v6 classify (dnat_lookup_v6). Mirrors the v4 binding above.
	if dnatV6 := sharedMaps["dnat_table_v6"]; dnatV6 != nil {
		opts.MapReplacements["dnat_table_v6"] = dnatV6
	}
	userspaceCollection, err := ebpf.NewCollectionWithOptions(userspaceSpec, opts)
	if err != nil {
		return fmt.Errorf("load Rust xdp_userspace collection: %w", err)
	}

	userspaceProg, ok := userspaceCollection.Programs[userspaceShimEntryProg]
	if !ok {
		userspaceCollection.Close()
		return fmt.Errorf("Rust %s not found", userspaceShimEntryProg)
	}
	for _, pin := range userspaceRequiredShimPins() {
		umap := userspaceCollection.Maps[pin.name]
		if umap == nil {
			if shared := sharedMaps[pin.name]; shared != nil {
				umap = shared
			}
		}
		if err := ensureUserspaceMapPinned(pin.name, umap, pin.path); err != nil {
			userspaceCollection.Close()
			return err
		}
	}

	m.programs[userspaceShimEntryProg] = userspaceProg
	for name, umap := range userspaceCollection.Maps {
		m.maps[name] = umap
	}
	for name, smap := range sharedMaps {
		m.maps[name] = smap
	}
	keepShared = true
	return nil
}

func validateUserspaceShimSpec(userspaceSpec *ebpf.CollectionSpec) error {
	if ms, ok := userspaceSpec.Maps[userspaceBindingsMapName]; !ok {
		return fmt.Errorf("Rust xdp_userspace spec missing map userspace_bindings")
	} else if ms.MaxEntries != BindingArrayMaxEntries {
		return userspaceBindingsMaxEntriesDriftError(ms.MaxEntries)
	}
	if ms, ok := userspaceSpec.Maps[userspaceIngressIfacesMapName]; !ok {
		return fmt.Errorf("Rust xdp_userspace spec missing map userspace_ingress_ifaces")
	} else if ms.MaxEntries != MaxInterfaces {
		return userspaceIngressIfacesMaxEntriesDriftError(ms.MaxEntries)
	}
	if ms, ok := userspaceSpec.Maps[userspaceShimCompatibilityDNATName]; !ok {
		return fmt.Errorf("Rust xdp_userspace spec missing map dnat_table")
	} else if ms.MaxEntries != userspaceShimMaxSessions {
		return fmt.Errorf(
			"dnat_table max_entries drift: embedded=%d, expected=%d (userspace shim compatibility map). %s",
			ms.MaxEntries, userspaceShimMaxSessions, userspaceShimGenerateRemediation,
		)
	} else if ms.Flags&unix.BPF_F_NO_PREALLOC == 0 {
		return fmt.Errorf(
			"dnat_table flags drift: embedded=%d, expected BPF_F_NO_PREALLOC (userspace shim compatibility map). %s",
			ms.Flags, userspaceShimGenerateRemediation,
		)
	}
	return nil
}

func userspaceBindingsMaxEntriesDriftError(got uint32) error {
	return fmt.Errorf(
		"userspace_bindings max_entries drift: embedded=%d, expected=%d (MaxInterfaces=%d * BindingQueuesPerIface=%d in bpf/headers/xpf_common.h). %s",
		got, BindingArrayMaxEntries, MaxInterfaces, BindingQueuesPerIface, userspaceShimGenerateRemediation,
	)
}

func userspaceIngressIfacesMaxEntriesDriftError(got uint32) error {
	return fmt.Errorf(
		"userspace_ingress_ifaces max_entries drift: embedded=%d, expected=%d (MaxInterfaces in bpf/headers/xpf_common.h). %s",
		got, MaxInterfaces, userspaceShimGenerateRemediation,
	)
}

func userspacePinnedShimMaps() []string {
	return []string{
		"dnat_table",
		"userspace_ctrl",
		"userspace_bindings",
		"userspace_ingress_ifaces",
		"userspace_heartbeat",
		"userspace_xsk_map",
		"userspace_local_v4",
		"userspace_local_v6",
		"userspace_interface_nat_v4",
		"userspace_interface_nat_v6",
		"userspace_sessions",
		"userspace_trace",
		"userspace_fallback_stats",
		"userspace_cpumap",
	}
}

func userspaceRequiredShimPins() []struct {
	name string
	path string
} {
	names := userspacePinnedShimMaps()
	out := make([]struct {
		name string
		path string
	}, 0, len(names)+len(userspaceShimSharedMapSpecs()))
	for _, name := range names {
		out = append(out, struct {
			name string
			path string
		}{name: name, path: filepath.Join(bpfPinPath, name)})
	}
	for _, spec := range userspaceShimSharedMapSpecs() {
		out = append(out, struct {
			name string
			path string
		}{name: spec.Name, path: filepath.Join(bpfPinPath, spec.Name)})
	}
	return out
}

func loadUserspaceShimSharedMaps() (map[string]*ebpf.Map, error) {
	maps := make(map[string]*ebpf.Map)
	for _, spec := range userspaceShimSharedMapSpecs() {
		loaded, err := loadOrCreatePinnedShimMap(spec)
		if err != nil {
			closeUniqueMaps(maps)
			return nil, err
		}
		maps[spec.Name] = loaded
	}
	return maps, nil
}

func loadOrCreatePinnedShimMap(spec *ebpf.MapSpec) (*ebpf.Map, error) {
	return loadOrCreatePinnedShimMapWith(spec, bpfPinPath, ebpf.NewMapWithOptions)
}

type userspaceShimMapLoader func(*ebpf.MapSpec, ebpf.MapOptions) (*ebpf.Map, error)

func loadOrCreatePinnedShimMapWith(
	spec *ebpf.MapSpec,
	pinPath string,
	load userspaceShimMapLoader,
) (*ebpf.Map, error) {
	spec = spec.Copy()
	spec.Pinning = ebpf.PinByName
	m, err := load(spec, ebpf.MapOptions{PinPath: pinPath})
	if err == nil {
		return m, nil
	}
	if !errors.Is(err, ebpf.ErrMapIncompatible) {
		return nil, fmt.Errorf("load userspace shim shared map %s: %w", spec.Name, err)
	}
	return nil, fmt.Errorf(
		"refusing to reset incompatible userspace shim map %s at %s: %w",
		spec.Name, filepath.Join(pinPath, spec.Name), err,
	)
}

func closeUniqueMaps(maps map[string]*ebpf.Map) {
	seen := make(map[*ebpf.Map]struct{}, len(maps))
	for _, m := range maps {
		if m == nil {
			continue
		}
		if _, ok := seen[m]; ok {
			continue
		}
		seen[m] = struct{}{}
		_ = m.Close()
	}
}

func userspaceShimSharedMapSpecs() []*ebpf.MapSpec {
	return []*ebpf.MapSpec{
		// Register the conntrack maps at the on-map C/Rust ABI size
		// (ConntrackSessionValueSize{,V6}), NOT sizeOf[SessionValue].
		// SessionValue carries the sync-only Generation field (#2170) which
		// is intentionally absent from the BPF C struct; using its size would
		// inflate value_size by 8 bytes and cause an OOB copy into the Rust
		// helper's smaller lookup buffer (#2360). These constants are the
		// single source of truth shared with the test fixtures.
		hashMapSpec("sessions", sizeOf[SessionKey](), ConntrackSessionValueSize, userspaceShimMaxSessions, unix.BPF_F_NO_PREALLOC),
		hashMapSpec("sessions_v6", sizeOf[SessionKeyV6](), ConntrackSessionValueSizeV6, userspaceShimMaxSessions, unix.BPF_F_NO_PREALLOC),
		hashMapSpec("dnat_table", sizeOf[DNATKey](), sizeOf[DNATValue](), userspaceShimMaxSessions, unix.BPF_F_NO_PREALLOC),
		hashMapSpec("dnat_table_v6", sizeOf[DNATKeyV6](), sizeOf[DNATValueV6](), userspaceShimMaxSessions, unix.BPF_F_NO_PREALLOC),
		arrayMapSpec("fib_gen_map", sizeOf[uint32](), 1),
		arrayMapSpec("fabric_fwd", sizeOf[FabricFwdInfo](), 2),
		arrayMapSpec("rg_active", sizeOf[uint8](), MaxRedundancyGroups),
		arrayMapSpec("ha_watchdog", sizeOf[uint64](), MaxRedundancyGroups),
		perCPUArrayMapSpec("session_id_gen", sizeOf[uint64](), 1),
		perCPUArrayMapSpec("global_counters", sizeOf[uint64](), GlobalCtrMax),
		perCPUArrayMapSpec("flood_counters", sizeOf[FloodState](), MaxZones),
		perCPUArrayMapSpec("policy_counters", sizeOf[CounterValue](), userspaceShimMaxPolicies),
		perCPUArrayMapSpec("zone_counters", sizeOf[CounterValue](), MaxZones*2),
		perCPUArrayMapSpec("filter_counters", sizeOf[CounterValue](), MaxFilterRules),
		perCPUHashMapSpec("interface_counters", sizeOf[uint32](), sizeOf[InterfaceCounterValue](), MaxInterfaces, unix.BPF_F_NO_PREALLOC),
		perCPUArrayMapSpec("nat_port_counters", sizeOf[NATPortCounter](), userspaceShimMaxNATPools),
		perCPUArrayMapSpec("nat_rule_counters", sizeOf[CounterValue](), MaxNATRuleCounters),
	}
}

const (
	userspaceShimMaxSessions uint32 = 10000000
	userspaceShimMaxPolicies uint32 = 4096
	userspaceShimMaxNATPools uint32 = 32
)

func hashMapSpec(name string, keySize, valueSize, maxEntries, flags uint32) *ebpf.MapSpec {
	return &ebpf.MapSpec{
		Name:       name,
		Type:       ebpf.Hash,
		KeySize:    keySize,
		ValueSize:  valueSize,
		MaxEntries: maxEntries,
		Flags:      flags,
	}
}

func perCPUHashMapSpec(name string, keySize, valueSize, maxEntries, flags uint32) *ebpf.MapSpec {
	return &ebpf.MapSpec{
		Name:       name,
		Type:       ebpf.PerCPUHash,
		KeySize:    keySize,
		ValueSize:  valueSize,
		MaxEntries: maxEntries,
		Flags:      flags,
	}
}

func arrayMapSpec(name string, valueSize, maxEntries uint32) *ebpf.MapSpec {
	return &ebpf.MapSpec{
		Name:       name,
		Type:       ebpf.Array,
		KeySize:    sizeOf[uint32](),
		ValueSize:  valueSize,
		MaxEntries: maxEntries,
	}
}

func perCPUArrayMapSpec(name string, valueSize, maxEntries uint32) *ebpf.MapSpec {
	return &ebpf.MapSpec{
		Name:       name,
		Type:       ebpf.PerCPUArray,
		KeySize:    sizeOf[uint32](),
		ValueSize:  valueSize,
		MaxEntries: maxEntries,
	}
}

func sizeOf[T any]() uint32 {
	var zero T
	return uint32(unsafe.Sizeof(zero))
}

// reconcileDisposableCollectionPin removes a stale pinned map whose on-disk
// shape no longer matches the spec the collection is about to load with
// PinByName, so NewCollectionWithOptions recreates it fresh instead of failing
// with ErrMapIncompatible and bricking the shim load on a daemon upgrade.
//
// This is SAFE ONLY for DISPOSABLE maps — counters that reset to zero on every
// reload anyway (userspace_fallback_stats / degraded_path_counters). DATA maps
// (sessions, conntrack, dnat) must NEVER be silently reset; those go through
// loadOrCreatePinnedShimMapWith, which deliberately REFUSES to reset an
// incompatible pin (#2360). #4113 changed this counter's BPF type from Array to
// PerCpuArray; without this reconcile, the stale Array pin from a previous
// daemon is incompatible with the new PerCpuArray spec, PinByName's
// compatibility check fails, and the whole collection load aborts (#1917/#1960
// upgrade-brick class).
//
// A missing pin (fresh boot) or a shape-compatible pin (already migrated) is
// left untouched, so accumulated counters survive an ordinary restart.
func reconcileDisposableCollectionPin(pinPath string, spec *ebpf.MapSpec) error {
	if spec == nil {
		return nil
	}
	if _, err := os.Stat(pinPath); err != nil {
		if os.IsNotExist(err) {
			return nil // fresh boot: nothing pinned yet
		}
		return fmt.Errorf("stat disposable pin %s: %w", pinPath, err)
	}
	existing, err := ebpf.LoadPinnedMap(pinPath, nil)
	if err != nil {
		return fmt.Errorf("inspect disposable pin %s: %w", pinPath, err)
	}
	defer existing.Close()
	if disposablePinShapeMatches(existing.Type(), existing.KeySize(),
		existing.ValueSize(), existing.MaxEntries(), spec) {
		return nil
	}
	slog.Info("resetting incompatible disposable shim map pin on upgrade",
		"path", pinPath,
		"pinned_type", existing.Type().String(),
		"pinned_value_size", existing.ValueSize(),
		"pinned_max_entries", existing.MaxEntries(),
		"want_type", spec.Type.String(),
		"want_value_size", spec.ValueSize,
		"want_max_entries", spec.MaxEntries)
	if err := existing.Unpin(); err != nil {
		return fmt.Errorf("unpin incompatible disposable pin %s: %w", pinPath, err)
	}
	return nil
}

// disposablePinShapeMatches reports whether an on-disk pinned map's shape
// matches the spec closely enough that the PinByName collection load will
// accept it. It compares the discriminating fields for the #4113 migration
// (type is the changed field; key/value/entries are compared so a future shape
// change also triggers a reset). Flags are intentionally excluded: this counter
// is created with flags 0 on both sides, and a disposable map errs toward
// resetting rather than bricking.
func disposablePinShapeMatches(
	pinnedType ebpf.MapType,
	pinnedKeySize, pinnedValueSize, pinnedMaxEntries uint32,
	spec *ebpf.MapSpec,
) bool {
	return pinnedType == spec.Type &&
		pinnedKeySize == spec.KeySize &&
		pinnedValueSize == spec.ValueSize &&
		pinnedMaxEntries == spec.MaxEntries
}

func ensureUserspaceMapPinned(name string, m *ebpf.Map, path string) error {
	if m == nil {
		return fmt.Errorf("nil map for %s", path)
	}
	if _, err := os.Stat(path); err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("stat %s pin path %s: %w", name, path, err)
		}
		if err := m.Pin(path); err != nil {
			return fmt.Errorf("pin %s at %s: %w", name, path, err)
		}
	}
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("%s pin missing at %s after load: %w", name, path, err)
	}
	return nil
}
