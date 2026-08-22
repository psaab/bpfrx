// Package devicemap implements the #1956 bare-metal device-map identity
// resolver: it binds host NICs (by stable identity — PCI bus address with
// permanent-MAC fallback) to xpf logical names. The resolver core is pure
// (caller supplies the NIC inventory) so it is unit-testable without
// sysfs/netlink; EnumeratePresentNICs reads the live host inventory. Both
// the daemon (rename + pre-flight) and the CLI (`show chassis device-map`)
// import this package so there is ONE resolution discipline.
package devicemap

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// PresentNIC is one live host NIC as seen at resolve time. Captured as plain
// data so the resolver core is unit-testable without sysfs/netlink.
type PresentNIC struct {
	Name       string // current kernel name (post-udev, pre-xpf-rename)
	PCIAddr    string // PCI bus address ("" if none)
	PermMAC    string // permanent/factory MAC ("" if unavailable)
	RunningMAC string // current running MAC (diagnostic only)
	LinkUp     bool   // operational/admin state (diagnostic; for `candidates`)
}

// BindStatus classifies how a device-map entry resolved.
type BindStatus int

const (
	BindBound        BindStatus = iota // resolved cleanly to a present NIC
	BindBoundPCIOnly                   // PCI matched, no perm-MAC to cross-check
	BindBoundViaMAC                    // PCI missed, perm-MAC matched (PCI moved)
	BindUnbound                        // no present NIC matches the identity
	BindRefusedAmbig                   // PCI matched but perm-MAC mismatched, or ambiguous MAC
	// BindRefusedDupName: two or more entries resolved to the SAME logical
	// name (#6546). It is its own status rather than BindRefusedAmbig because
	// the operator-facing remedy is the opposite one: nothing is wrong with
	// the hardware and re-pinning an identity fixes nothing — the MAP has two
	// entries claiming one interface name and one of them must go.
	BindRefusedDupName
)

func (s BindStatus) String() string {
	switch s {
	case BindBound:
		return "bound"
	case BindBoundPCIOnly:
		return "bound (PCI-only, unverified — no permanent MAC)"
	case BindBoundViaMAC:
		return "bound (via MAC fallback — PCI moved, re-pin)"
	case BindUnbound:
		return "UNBOUND (no NIC at identity)"
	case BindRefusedAmbig:
		return "REFUSED (topology changed — card swapped at this identity)"
	case BindRefusedDupName:
		return "REFUSED (logical name claimed by more than one device-map entry)"
	default:
		return "unknown"
	}
}

// Decisive reports whether the status is a final outcome (bound or refused),
// vs an unbound result that should fall through to the next key. Both refusal
// statuses are decisive: a refusal means the pinned identity WAS matched, it
// just must not be acted on.
func (s BindStatus) Decisive() bool {
	return s != BindUnbound
}

// Refused reports whether the status is one of the refusal variants. Callers
// that hard-stop on a refusal must use this rather than comparing against a
// single sentinel, so a new refusal reason cannot slip past a `== BindRefusedAmbig`
// check and be silently treated as a clean result (#6546).
func (s BindStatus) Refused() bool {
	return s == BindRefusedAmbig || s == BindRefusedDupName
}

// Bound reports whether the status is one of the three bound variants.
func (s BindStatus) Bound() bool {
	return s == BindBound || s == BindBoundPCIOnly || s == BindBoundViaMAC
}

// Binding is the outcome of resolving one device-map entry.
type Binding struct {
	Entry      config.DeviceMapEntry
	Logical    string // Linux logical name (ge-0-0-3), "" if unbound/refused
	CurrentNIC string // the NIC's CURRENT kernel name, "" if unbound/refused
	Status     BindStatus
}

// Resolve resolves every entry against the present NICs using each entry's
// key order, applying topology-change detection (PCI hit but perm-MAC
// mismatch => REFUSE, never silent hijack — R-1/AGY HIGH-3). RETH members
// are restricted to PCI matching (their MAC alternates physical<->virtual,
// R-6); the strict commit validator already rejects key mac on a RETH
// member, so here the MAC leg is skipped for them as defense in depth.
func Resolve(entries []config.DeviceMapEntry, nics []PresentNIC, rethMembers map[string]bool) []Binding {
	byPCI := make(map[string][]*PresentNIC)
	byPermMAC := make(map[string][]*PresentNIC)
	for i := range nics {
		n := &nics[i]
		if n.PCIAddr != "" {
			lp := strings.ToLower(n.PCIAddr)
			byPCI[lp] = append(byPCI[lp], n)
		}
		if n.PermMAC != "" {
			lm := strings.ToLower(n.PermMAC)
			byPermMAC[lm] = append(byPermMAC[lm], n)
		}
	}

	out := make([]Binding, 0, len(entries))
	for _, e := range entries {
		logical := config.LinuxIfName(e.LogicalName)
		isRETH := rethMembers[e.LogicalName]
		rb := Binding{Entry: e, Status: BindUnbound}

		allowMAC := e.MAC != "" && !isRETH
		allowPCI := e.PCIAddr != ""

		// Order-INDEPENDENT refusals (run BEFORE the key loop so NO key order
		// can bypass them — Codex HIGH-1 / r2 HIGH-B):
		if allowPCI {
			pm := byPCI[strings.ToLower(e.PCIAddr)]
			// (a) Same-PCI ambiguity: two present NICs share this entry's PCI
			// address. Refuse regardless of key order (a `key mac` /
			// `mac-then-pci` entry would otherwise bind via MAC and never
			// reach the PCI arm's len>1 guard).
			if len(pm) > 1 {
				rb.Status, rb.CurrentNIC, rb.Logical = BindRefusedAmbig, "", ""
				out = append(out, rb)
				continue
			}
			// (b) Topology change: a single present NIC at the pinned PCI
			// whose permanent MAC mismatches the entry's MAC means a card was
			// swapped into the slot. Refuse regardless of key order. Skip for
			// RETH members (MAC is not a usable key for them) and when either
			// side lacks a perm-MAC to compare.
			if e.MAC != "" && !isRETH && len(pm) == 1 &&
				pm[0].PermMAC != "" && !strings.EqualFold(pm[0].PermMAC, e.MAC) {
				rb.Status, rb.CurrentNIC, rb.Logical = BindRefusedAmbig, "", ""
				out = append(out, rb)
				continue
			}
		}

		pciTried := false
		for _, key := range keySequence(e, allowPCI, allowMAC) {
			switch key {
			case config.DeviceMapKeyPCI:
				pciTried = true
				pm := byPCI[strings.ToLower(e.PCIAddr)]
				if len(pm) > 1 {
					// Two present NICs share one PCI address — ambiguous,
					// refuse rather than bind a non-deterministic one.
					rb.Status, rb.CurrentNIC, rb.Logical = BindRefusedAmbig, "", ""
				} else if len(pm) == 1 {
					nic := pm[0]
					if e.MAC != "" && nic.PermMAC != "" {
						if strings.EqualFold(nic.PermMAC, e.MAC) {
							rb.Status, rb.CurrentNIC, rb.Logical = BindBound, nic.Name, logical
						} else {
							rb.Status, rb.CurrentNIC, rb.Logical = BindRefusedAmbig, "", ""
						}
					} else {
						rb.Status, rb.CurrentNIC, rb.Logical = BindBoundPCIOnly, nic.Name, logical
					}
				}
			case config.DeviceMapKeyMAC:
				matches := byPermMAC[strings.ToLower(e.MAC)]
				if len(matches) == 1 {
					// "via MAC fallback (PCI moved, re-pin)" is only true when
					// MAC was reached as a FALLBACK after a PCI miss — i.e. PCI
					// was tried first and did not bind (Copilot). For a MAC-
					// primary key order (key mac / mac-then-pci) the MAC bind
					// is the intended primary, so report a clean BindBound.
					st := BindBound
					if pciTried {
						st = BindBoundViaMAC
					}
					rb.Status, rb.CurrentNIC, rb.Logical = st, matches[0].Name, logical
				} else if len(matches) > 1 {
					rb.Status, rb.CurrentNIC, rb.Logical = BindRefusedAmbig, "", ""
				}
			}
			if rb.Status.Decisive() {
				break
			}
		}
		out = append(out, rb)
	}

	// Post-pass (Codex r2 HIGH-C): two DIFFERENT entries can resolve to the
	// SAME present NIC via cross-key identities (entry A keyed by PCI, entry B
	// keyed by that same NIC's permanent MAC) — the strict compile-time
	// duplicate checks compare PCI-to-PCI and MAC-to-MAC and miss this. Left
	// alone, the daemon's desiredByCurrent would last-wins one logical name
	// onto the NIC. Detect the collision here and REFUSE every entry that
	// landed on a multiply-claimed NIC, rather than silently dropping one.
	claims := make(map[string]int)
	// #6546: the SYMMETRIC collision. The NIC-claim pass above catches two
	// entries landing on one NIC; nothing caught two entries landing on one
	// LOGICAL NAME, so a map with a duplicate name bound BOTH entries and the
	// daemon's rename loop (device_map.go, keyed by CurrentNIC) then renamed
	// two different NICs to the same final name — whichever the map iteration
	// reached last won, durably, via the `.link` files it writes. On bare
	// metal that can strand management or put a NIC in the wrong zone, and the
	// SAME config can bind differently across boots.
	//
	// The count keys on the RESOLVED Linux name, not Entry.LogicalName: the
	// Junos slash form and the kernel dash form (`ge-0/0/3` / `ge-0-0-3`) are
	// two spellings of one interface, and before the companion fix in
	// validateDeviceMapStrict the raw-string compare let that pair through the
	// strict commit gate as well as the tolerant one.
	nameClaims := make(map[string]int)
	for i := range out {
		if out[i].Status.Bound() {
			claims[out[i].CurrentNIC]++
			nameClaims[out[i].Logical]++
		}
	}
	for i := range out {
		if !out[i].Status.Bound() {
			continue
		}
		// Duplicate-name is checked FIRST so the more precise refusal wins
		// when an entry is caught by both passes: "re-pin the identity" is
		// the wrong instruction for a map that names one interface twice.
		if nameClaims[out[i].Logical] > 1 {
			out[i].Status, out[i].CurrentNIC, out[i].Logical = BindRefusedDupName, "", ""
			continue
		}
		if claims[out[i].CurrentNIC] > 1 {
			out[i].Status, out[i].CurrentNIC, out[i].Logical = BindRefusedAmbig, "", ""
		}
	}
	return out
}

// keySequence returns the ordered identity keys to try for an entry, filtered
// by which keys are usable (allowPCI/allowMAC).
func keySequence(e config.DeviceMapEntry, allowPCI, allowMAC bool) []string {
	var raw []string
	switch e.EffectiveKeyOrder() {
	case config.DeviceMapKeyPCI:
		raw = []string{config.DeviceMapKeyPCI}
	case config.DeviceMapKeyMAC:
		raw = []string{config.DeviceMapKeyMAC}
	case config.DeviceMapKeyMACThenPCI:
		raw = []string{config.DeviceMapKeyMAC, config.DeviceMapKeyPCI}
	default: // pci-then-mac
		raw = []string{config.DeviceMapKeyPCI, config.DeviceMapKeyMAC}
	}
	out := make([]string, 0, len(raw))
	for _, k := range raw {
		if k == config.DeviceMapKeyPCI && !allowPCI {
			continue
		}
		if k == config.DeviceMapKeyMAC && !allowMAC {
			continue
		}
		out = append(out, k)
	}
	return out
}

// RethMembersFromConfig returns the set of logical names that are RETH
// members in the config (RedundantParent set).
func RethMembersFromConfig(cfg *config.Config) map[string]bool {
	m := make(map[string]bool)
	if cfg == nil {
		return m
	}
	for _, ifc := range cfg.Interfaces.Interfaces {
		if ifc != nil && ifc.RedundantParent != "" {
			m[ifc.Name] = true
		}
	}
	return m
}

// ExtractPCIAddr extracts the last canonical PCI address (DDDD:BB:DD.F) from
// a sysfs path. Mirrors the daemon's extractPCIAddr so a committed key
// resolves against the live enumeration without normalization drift.
func ExtractPCIAddr(path string) string {
	parts := strings.Split(path, "/")
	var last string
	for _, p := range parts {
		if len(p) >= 11 && p[4] == ':' && p[7] == ':' && p[10] == '.' {
			last = p
		}
	}
	return last
}

// classifyNetdev decides whether a /sys/class/net entry is a mappable physical
// NIC and extracts its PCI address (empty for a non-PCI bus). devErr is the
// error from resolving the entry's `device` symlink and devReal its resolved
// target when devErr == nil.
//
// A physical NIC — PCI, USB, platform, or SoC — exposes a `device` symlink and
// is KEPT even when it has no PCI address, so a `key mac` device-map entry can
// still bind it (#4884). Before this, ANY NIC without a PCI address was dropped
// from the inventory BEFORE its permanent MAC was read, so on a bare-metal /
// SoC / USB-NIC appliance a valid MAC-only mapping never saw its target and the
// interface was stranded (marked unbound). A purely virtual netdev — loopback,
// bridge, veth, bond, vlan, vrf, tun/tap, and the xpf-created VRF/tunnel
// devices — has no `device` symlink and is dropped: it is not a mappable
// hardware NIC and would only flood the inventory / `candidates` list.
func classifyNetdev(name, devReal string, devErr error) (pci string, keep bool) {
	if name == "lo" {
		return "", false
	}
	if devErr != nil {
		return "", false // virtual netdev — no backing hardware device
	}
	return ExtractPCIAddr(devReal), true
}

// EnumeratePresentNICs builds the present-NIC inventory from sysfs + netlink:
// current kernel name, PCI address (empty for non-PCI buses), permanent
// (factory) MAC, running MAC, and link state. Sorted by PCI address, then
// kernel name, for stable output (non-PCI NICs share an empty PCI address, so
// the name tiebreak keeps their order deterministic).
func EnumeratePresentNICs() ([]PresentNIC, error) {
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return nil, err
	}
	var nics []PresentNIC
	for _, e := range entries {
		name := e.Name()
		devReal, derr := filepath.EvalSymlinks(filepath.Join("/sys/class/net", name, "device"))
		pci, keep := classifyNetdev(name, devReal, derr)
		if !keep {
			continue
		}
		nic := PresentNIC{Name: name, PCIAddr: pci}
		if link, err := netlink.LinkByName(name); err == nil {
			a := link.Attrs()
			nic.RunningMAC = a.HardwareAddr.String()
			if len(a.PermHWAddr) != 0 {
				nic.PermMAC = a.PermHWAddr.String()
			}
			nic.LinkUp = a.OperState == netlink.OperUp || a.Flags&1 != 0 // IFF_UP
		}
		nics = append(nics, nic)
	}
	sort.Slice(nics, func(i, j int) bool {
		if nics[i].PCIAddr != nics[j].PCIAddr {
			return nics[i].PCIAddr < nics[j].PCIAddr
		}
		return nics[i].Name < nics[j].Name
	})
	return nics, nil
}
