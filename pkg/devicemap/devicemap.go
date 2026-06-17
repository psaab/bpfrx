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
	default:
		return "unknown"
	}
}

// Decisive reports whether the status is a final outcome (bound or refused),
// vs an unbound result that should fall through to the next key.
func (s BindStatus) Decisive() bool {
	return s != BindUnbound
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

		// Order-INDEPENDENT topology-change refusal (Codex HIGH-1): when an
		// entry pins BOTH a PCI address and a MAC, a present NIC at that PCI
		// whose permanent MAC mismatches means a card was swapped into the
		// pinned slot. That must REFUSE regardless of key order — otherwise a
		// `mac-then-pci` (or any MAC-first) entry would bind via MAC and
		// silently skip the slot-swap check. Skip for RETH members (MAC is
		// not a usable key for them) and when either side lacks a perm-MAC to
		// compare (PCI-only-unverified is handled in the key loop).
		if allowPCI && e.MAC != "" && !isRETH {
			if pm := byPCI[strings.ToLower(e.PCIAddr)]; len(pm) == 1 &&
				pm[0].PermMAC != "" && !strings.EqualFold(pm[0].PermMAC, e.MAC) {
				rb.Status, rb.CurrentNIC, rb.Logical = BindRefusedAmbig, "", ""
				out = append(out, rb)
				continue
			}
		}

		for _, key := range keySequence(e, allowPCI, allowMAC) {
			switch key {
			case config.DeviceMapKeyPCI:
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
					// BindBoundViaMAC means MAC matched as a FALLBACK after PCI
					// missed. Only set it when the effective key order is
					// pci-then-mac (PCI was tried first). For key=mac or
					// key=mac-then-pci, MAC is the primary identity key and
					// BindBound is the correct status.
					st := BindBound
					if allowPCI && e.EffectiveKeyOrder() == config.DeviceMapKeyPCIThenMAC {
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

// EnumeratePresentNICs builds the present-NIC inventory from sysfs + netlink:
// current kernel name, PCI address, permanent (factory) MAC, running MAC, and
// link state. Sorted by PCI address for stable output.
func EnumeratePresentNICs() ([]PresentNIC, error) {
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return nil, err
	}
	var nics []PresentNIC
	for _, e := range entries {
		name := e.Name()
		if name == "lo" {
			continue
		}
		devReal, err := filepath.EvalSymlinks(filepath.Join("/sys/class/net", name, "device"))
		if err != nil {
			continue // not a PCI device
		}
		pci := ExtractPCIAddr(devReal)
		if pci == "" {
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
	sort.Slice(nics, func(i, j int) bool { return nics[i].PCIAddr < nics[j].PCIAddr })
	return nics, nil
}
