package userspace

import (
	"fmt"
	"log/slog"
	"sort"

	"github.com/psaab/xpf/pkg/config"
)

func buildMirrorConfigSnapshotsFailClosed(cfg *config.Config, interfaces []InterfaceSnapshot) []MirrorConfigSnapshot {
	mirrors, err := buildMirrorConfigSnapshots(cfg, interfaces)
	if err != nil {
		// The mirror table contract is one output per ingress ifindex. Keep
		// snapshot publication fail-closed by omitting an ambiguous mirror table
		// if this helper is called on an invalid config.
		slog.Warn("userspace snapshot: invalid port-mirroring config skipped", "err", err)
		return nil
	}
	return mirrors
}

func buildMirrorConfigSnapshots(cfg *config.Config, interfaces []InterfaceSnapshot) ([]MirrorConfigSnapshot, error) {
	if cfg == nil || cfg.ForwardingOptions.PortMirroring == nil || len(cfg.ForwardingOptions.PortMirroring.Instances) == 0 {
		return nil, nil
	}
	ifindexByName := make(map[string]int, len(interfaces))
	for _, iface := range interfaces {
		if iface.Ifindex > 0 {
			ifindexByName[iface.Name] = iface.Ifindex
			if iface.LinuxName != "" {
				ifindexByName[iface.LinuxName] = iface.Ifindex
			}
		}
	}

	instanceNames := make([]string, 0, len(cfg.ForwardingOptions.PortMirroring.Instances))
	for name := range cfg.ForwardingOptions.PortMirroring.Instances {
		instanceNames = append(instanceNames, name)
	}
	sort.Strings(instanceNames)

	seenIngress := make(map[int]string)
	out := make([]MirrorConfigSnapshot, 0)
	for _, name := range instanceNames {
		inst := cfg.ForwardingOptions.PortMirroring.Instances[name]
		if inst == nil {
			continue
		}
		if inst.Output == "" {
			slog.Warn("port-mirroring instance has no output interface", "name", name)
			continue
		}
		outputIfindex := ifindexByName[inst.Output]
		if outputIfindex <= 0 {
			outputIfindex = ifindexByName[config.LinuxIfName(inst.Output)]
		}
		if outputIfindex <= 0 {
			slog.Warn("port-mirroring output interface not found",
				"name", name, "interface", inst.Output)
			continue
		}

		for _, input := range inst.Input {
			ingressIfindex := ifindexByName[input]
			if ingressIfindex <= 0 {
				ingressIfindex = ifindexByName[config.LinuxIfName(input)]
			}
			if ingressIfindex <= 0 {
				slog.Warn("port-mirroring input interface not found",
					"name", name, "interface", input)
				continue
			}
			if previous, ok := seenIngress[ingressIfindex]; ok {
				return nil, fmt.Errorf("duplicate port-mirroring ingress ifindex %d in instances %q and %q", ingressIfindex, previous, name)
			}
			if inst.InputRate < 0 {
				return nil, fmt.Errorf("port-mirroring instance %q has negative input rate %d", name, inst.InputRate)
			}
			seenIngress[ingressIfindex] = name
			out = append(out, MirrorConfigSnapshot{
				IngressIfindex: ingressIfindex,
				OutputIfindex:  outputIfindex,
				Rate:           uint32(inst.InputRate),
			})
		}
	}
	return out, nil
}
