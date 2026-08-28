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
//
// #6964 — THE AUTHORED SET IS NOT THE DEVICE SET. An authored interface name is
// not the only way a kernel device name enters the config. A logical unit that
// carries its own `tunnel` stanza gets its OWN Linux device, named by the
// compiler as the interface's canonical name plus "u<unit>" for unit > 0
// (compiler_interfaces.go, stored verbatim in unit.Tunnel.Name). So the DERIVED
// device name of `gr-0/0/0 unit 1` is `gr-0-0-0u1`, which is byte-identical to
// the canonical name of an interface an operator is free to author as
// `gr-0/0/0u1` — `u` and digits are ordinary allowed characters
// (ValidateInterfaceName, #6834), and the two AUTHORED keys (`gr-0/0/0u1` and
// `gr-0/0/0`) are distinct, so the authored-only walk above never sees them
// touch.
//
// Measured on origin/master before this gate was widened: that pair compiles
// with err == nil and yields TWO *TunnelConfig records carrying the SAME
// Name="gr-0-0-0u1" and DIFFERENT Source/Destination.
//
// The consequence is at the ROUTING layer. pkg/routing keys ALL of its
// per-device state by TunnelConfig.Name: the desired/owned set
// (`desired[tc.Name]`), the applied-address set (`appliedAddrs[tc.Name]`), the
// VRF claim (`appliedRI[tc.Name]`), and the keepalive runner. So the two
// records collapse to ONE entry in `desired` and then reconcile the SAME device
// TWICE within one Apply. The second pass runs reconcileLinkAddrsLocked against
// the first pass's applied set, which AddrDels every non-link-local address on
// the device that is absent from the second record's Addresses — the two
// records delete each other's addresses off the shared device — and rewrites
// its VRF claim and keepalive runner on top.
//
// And which record is "second" is not fixed: collectAppliedTunnels (pkg/daemon)
// walks the cfg.Interfaces.Interfaces MAP, and BOTH orders were observed within
// a single process (174/26 over 200 calls). So this is not merely "one config
// silently wins" — there is no stable winner.
//
// Scope of that claim, checked rather than assumed: the endpoint-comparing
// delete+recreate in applyKernelTunnelLocked (legacyTunnelMatches) is NOT the
// production path. The daemon always sets AnchorOnly, so applyAnchorLocked runs
// instead, and anchorReusable ignores tunnel endpoints — the TUN is reused in
// place. The name-keyed address / VRF / keepalive overwrite above is common to
// both paths; the additional link flap belongs to the standalone-CLI path only.
//
// So the gate compares the EFFECTIVE DEVICE-NAME SET: every authored canonical
// name PLUS every per-unit tunnel device name. Both halves share the strict /
// lenient split, so a config already committed with this shape still boots with
// a warning naming the collision rather than bricking (#1960).
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

	// Second pass: the DERIVED per-unit tunnel device names (#6964).
	//
	// The device name is read from unit.Tunnel.Name — the value the compiler
	// actually assigned — rather than re-deriving base + "u" + N here. Binding
	// to the assigned value means the gate cannot drift from the naming scheme
	// it is policing: if compiler_interfaces.go ever changes how a per-unit
	// tunnel device is named, this walk follows for free, where a re-derivation
	// would silently start checking a name nothing creates.
	//
	// A unit whose tunnel device name IS the interface's own canonical name is
	// SKIPPED, not reported. That is unit 0: `unit 0 { tunnel }` deliberately
	// collapses onto the base device, which the authored pass above already
	// claimed for this same interface. Reporting it would reject the ordinary
	// single-tunnel config — every `gr-0/0/0 unit 0 tunnel` in the tree — which
	// is the over-rejection this gate must not commit.
	derivedOwner := make(map[string]string)
	for _, name := range names {
		ifc := cfg.Interfaces.Interfaces[name]
		if ifc == nil {
			continue
		}
		base := LinuxIfName(name)
		unitNums := make([]int, 0, len(ifc.Units))
		for unitNum := range ifc.Units {
			unitNums = append(unitNums, unitNum)
		}
		sort.Ints(unitNums)
		for _, unitNum := range unitNums {
			unit := ifc.Units[unitNum]
			if unit == nil || unit.Tunnel == nil || unit.Tunnel.Name == "" {
				continue
			}
			dev := unit.Tunnel.Name
			if dev == base {
				// Unit 0: shares the interface's own device by design.
				continue
			}
			ref := fmt.Sprintf("%s.%d", name, unitNum)
			if len(dev) > maxLinuxIfNameLen {
				return fmt.Errorf(
					"per-unit tunnel %s needs Linux device name %q (%d bytes), over the "+
						"kernel IFNAMSIZ limit of %d bytes; the device name is the "+
						"interface's canonical name plus \"u<unit>\", so the kernel cannot "+
						"create it and the tunnel endpoint would silently never "+
						"materialize — shorten the interface name or renumber the unit",
					ref, dev, len(dev), maxLinuxIfNameLen)
			}
			if owner, ok := firstByLinux[dev]; ok {
				return fmt.Errorf(
					"interface %q and per-unit tunnel %s both resolve to the same Linux "+
						"device name %q (a unit>0 tunnel device is the interface's canonical "+
						"name plus \"u<unit>\"); pkg/routing keys the device's addresses, "+
						"VRF claim and keepalive by that name, so the two would reconcile ONE "+
						"kernel device twice per commit and delete each other's addresses off "+
						"it — and the order is the interface map's, so there is no stable "+
						"winner — rename one of the two",
					owner, ref, dev)
			}
			// REACHABILITY, stated honestly: this derived-vs-derived branch
			// cannot fire today and therefore carries no test cell. A device
			// name decomposes uniquely into base + "u" + <digits> (split at the
			// last 'u' followed only by digits), so two per-unit tunnels can
			// only collide when their BASES collide — and colliding bases are
			// caught by the authored pass above, which returns first. It is
			// retained rather than deleted because this walk reads the
			// compiler-ASSIGNED unit.Tunnel.Name instead of re-deriving it: a
			// future change to the per-unit device-naming scheme (a separator
			// other than "u", a non-numeric suffix) would break the uniqueness
			// argument, and the hole must not reopen silently.
			if other, ok := derivedOwner[dev]; ok {
				return fmt.Errorf(
					"per-unit tunnels %s and %s both resolve to the same Linux device name "+
						"%q (a unit>0 tunnel device is the interface's canonical name plus "+
						"\"u<unit>\"); they would reconcile ONE kernel device twice per "+
						"commit, with no stable winner — rename one of the two interfaces",
					other, ref, dev)
			}
			derivedOwner[dev] = ref
		}
	}
	return nil
}
