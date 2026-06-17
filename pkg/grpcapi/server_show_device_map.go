package grpcapi

import (
	"fmt"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/devicemap"
)

// showChassisDeviceMap renders the #1956 bare-metal device-map's resolved
// bindings for the remote CLI (`show chassis device-map`). It resolves the
// active config's device-map against the live host NIC inventory using the
// shared devicemap resolver, so local and remote CLI render identically.
func (s *Server) showChassisDeviceMap(cfg *config.Config, buf *strings.Builder) {
	var dm *config.DeviceMapConfig
	if cfg != nil {
		dm = cfg.Chassis.DeviceMap
	}
	if !dm.Active() {
		buf.WriteString("Device-map: not configured (positional interface naming is in effect).\n")
		buf.WriteString("Run 'show chassis device-map candidates' to list NICs, then\n")
		buf.WriteString("'set chassis device-map interface <name> pci <addr>' to author a map.\n")
		return
	}
	nics, err := devicemap.EnumeratePresentNICs()
	if err != nil {
		fmt.Fprintf(buf, "device-map: enumerate NICs failed: %v\n", err)
		return
	}
	bindings := devicemap.Resolve(dm.Entries, nics, devicemap.RethMembersFromConfig(cfg))
	fmt.Fprintf(buf, "Device-map (unmapped-interface-policy: %s):\n\n", dm.EffectiveUnmappedPolicy())
	fmt.Fprintf(buf, "%-12s %-24s %-16s %s\n", "Logical", "Identity (key)", "Resolved kernel", "Status")
	fmt.Fprintf(buf, "%-12s %-24s %-16s %s\n", "-------", "--------------", "---------------", "------")
	for _, b := range bindings {
		ident := b.Entry.PCIAddr
		if ident == "" {
			ident = b.Entry.MAC
		} else if b.Entry.MAC != "" {
			ident += " (+mac)"
		}
		resolved := b.CurrentNIC
		if resolved == "" {
			resolved = "—"
		} else {
			resolved = fmt.Sprintf("%s→%s", resolved, b.Logical)
		}
		fmt.Fprintf(buf, "%-12s %-24s %-16s %s\n", b.Entry.LogicalName, ident, resolved, b.Status.String())
	}
}

// showChassisDeviceMapCandidates lists every present NIC's identity for the
// remote CLI (`show chassis device-map candidates`).
func (s *Server) showChassisDeviceMapCandidates(buf *strings.Builder) {
	nics, err := devicemap.EnumeratePresentNICs()
	if err != nil {
		fmt.Fprintf(buf, "device-map: enumerate NICs failed: %v\n", err)
		return
	}
	if len(nics) == 0 {
		buf.WriteString("No PCI network interfaces found.\n")
		return
	}
	buf.WriteString("Device-map candidates (copy a PCI address into a map entry):\n\n")
	fmt.Fprintf(buf, "%-16s %-18s %-14s %s\n", "PCI address", "Permanent MAC", "Current name", "Link")
	fmt.Fprintf(buf, "%-16s %-18s %-14s %s\n", "-----------", "-------------", "------------", "----")
	for _, n := range nics {
		perm := n.PermMAC
		if perm == "" {
			perm = "(none)"
		}
		link := "down"
		if n.LinkUp {
			link = "up"
		}
		fmt.Fprintf(buf, "%-16s %-18s %-14s %s\n", n.PCIAddr, perm, n.Name, link)
	}
	buf.WriteString("\nExample:\n")
	fmt.Fprintf(buf, "  set chassis device-map interface ge-0/0/3 pci %s\n", nics[0].PCIAddr)
	buf.WriteString("  set chassis device-map unmapped-interface-policy leave-alone\n")
}
