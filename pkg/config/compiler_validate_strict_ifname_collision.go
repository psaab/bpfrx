package config

import (
	"fmt"
	"sort"
)

// maxLinuxIfNameLen is the longest interface name the Linux kernel accepts: a
// netdev name must fit in IFNAMSIZ (16) INCLUDING the trailing NUL, so the
// usable name is at most 15 bytes. A configured interface whose canonical Linux
// name exceeds this cannot be created by the kernel (the `.link` rename fails),
// so the interface — and its zone / routing identity — silently never
// materializes.
const maxLinuxIfNameLen = 15

// validateInterfaceNameCollisionStrict rejects a config in which two DISTINCT
// authored interface names canonicalize (via LinuxIfName) to the SAME Linux
// device name, or in which an authored name's canonical Linux name exceeds the
// kernel IFNAMSIZ limit (#5832).
//
// LinuxIfName only replaces '/' with '-' (types.go), which is NOT injective:
// the distinct authored names `ge-0/0/0` and `ge-0-0-0` both map to the Linux
// device `ge-0-0-0` — the same ifindex. Each authored interface still emits its
// OWN logical row into the Go forwarding snapshot (its own security zone,
// routing-instance, host-inbound, NAT, address, and tunnel metadata), but the
// Rust forwarding-state builder keys those rows by ifindex and OVERWRITES the
// earlier one. Because the snapshot is walked in Go's sorted-name order, the
// lexicographically LATER colliding name deterministically wins — SILENTLY
// changing the security zone and routing identity of every packet on that
// shared Linux device, with no commit-time signal.
//
// This is a silent zone/routing hijack, so it is a strict COMMIT REJECTION on
// the CompileConfig path (interactive / gRPC commit + commit-check): the
// operator sees the collision before it can take effect. The call site
// (runUniformGates) downgrades it to a WARNING on the tolerant load / peer-sync
// paths (opts.lenientIfNameCollision) so an already-committed or peer-synced
// config that predates this gate still boots (#1960 no-brick) — but the warning
// names which authored name wins so the silent overwrite becomes visible.
//
// The fix is a GATE, not a remapping: LinuxIfName's mapping is unchanged, so
// every existing single-name config (the overwhelming common case, where an
// authored name has no colliding sibling) compiles exactly as before.
func validateInterfaceNameCollisionStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	// Deterministic walk so the first-error commit-check message is stable
	// across map-ordered runs, matching the sibling strict validators.
	names := make([]string, 0, len(cfg.Interfaces.Interfaces))
	for name := range cfg.Interfaces.Interfaces {
		names = append(names, name)
	}
	sort.Strings(names)

	// firstByLinux maps a canonical Linux name to the FIRST (lexicographically
	// earliest) authored name that produced it. Walking `names` in ascending
	// order means the second authored name to hit an existing Linux name is the
	// lexicographically LATER one — exactly the name that wins the ifindex
	// overwrite at snapshot-build time, so it is reported as the winner.
	firstByLinux := make(map[string]string, len(names))
	for _, name := range names {
		linux := LinuxIfName(name)
		if len(linux) > maxLinuxIfNameLen {
			return fmt.Errorf(
				"interface %q canonicalizes to Linux device name %q (%d bytes), "+
					"over the kernel IFNAMSIZ limit of %d bytes; the kernel cannot "+
					"create the device, so the interface and its security-zone / "+
					"routing identity would silently never materialize — shorten "+
					"the interface name",
				name, linux, len(linux), maxLinuxIfNameLen)
		}
		if earlier, ok := firstByLinux[linux]; ok {
			// `name` is lexicographically after `earlier` (sorted walk), so
			// `name` is the winner of the ifindex overwrite.
			return fmt.Errorf(
				"interfaces %q and %q both canonicalize to the same Linux device "+
					"name %q (LinuxIfName replaces '/' with '-'); they would share "+
					"one ifindex and the lexicographically later name %q would "+
					"silently win, hijacking the security zone / routing-instance / "+
					"host-inbound / NAT identity of packets on that device — rename "+
					"one of the two interfaces",
				earlier, name, linux, name)
		}
		firstByLinux[linux] = name
	}
	return nil
}
