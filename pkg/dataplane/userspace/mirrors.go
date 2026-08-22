package userspace

import (
	"log/slog"
	"sort"

	"github.com/psaab/xpf/pkg/config"
)

// buildMirrorConfigSnapshots resolves forwarding-options port-mirroring into
// the per-ingress mirror table. The table contract is one output per ingress
// ifindex, so a duplicate ingress ifindex (the same physical interface used as
// an ingress source by more than one instance) or a negative sampling rate is
// a SCOPE-DROP: the offending entry is skipped with a specific warning and the
// remaining valid entries are still published (#3972). One typo must never
// silently disable ALL mirroring.
//
// config.compilePortMirroring already HARD-REJECTS these cases at commit time,
// so this scope-drop is defense-in-depth for a config that reaches the
// snapshot builder without passing the commit gate (e.g. a stale on-disk
// config written by an older build). It replaces the pre-#3972
// whole-table-fail-closed-on-warn behavior that dropped every valid mirror
// session on a single bad entry.
func buildMirrorConfigSnapshots(cfg *config.Config, interfaces []InterfaceSnapshot) []MirrorConfigSnapshot {
	if cfg == nil || cfg.ForwardingOptions.PortMirroring == nil || len(cfg.ForwardingOptions.PortMirroring.Instances) == 0 {
		return nil
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
		// Config-decidable drops: no output interface, or a negative rate that
		// would wrap in uint32(inst.InputRate) below. Drop only this instance;
		// the commit gate (validateSamplingInputRateStrict) rejects it up
		// front, so this is the lenient load / peer-sync backstop.
		//
		// #6534: the verdict is config.PortMirroringInstanceExcludedReason so
		// this builder and BOTH port-mirroring show surfaces cannot disagree
		// about which instances are armed. The two interface-resolution drops
		// below are NOT in that predicate — they depend on the runtime ifindex
		// table, which a config-only renderer cannot reach.
		if reason := config.PortMirroringInstanceExcludedReason(inst); reason != "" {
			slog.Warn("port-mirroring: skipping instance (fail-closed)",
				"name", name, "reason", reason, "rate", inst.InputRate, "output", inst.Output)
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
				// One output per ingress ifindex: the first instance (sorted
				// by name) owns it. Skip the conflicting entry, keep the rest.
				slog.Warn("port-mirroring: skipping duplicate ingress interface (one output per ingress interface)",
					"name", name, "interface", input, "ifindex", ingressIfindex, "owner", previous)
				continue
			}
			seenIngress[ingressIfindex] = name
			out = append(out, MirrorConfigSnapshot{
				IngressIfindex: ingressIfindex,
				OutputIfindex:  outputIfindex,
				Rate:           uint32(inst.InputRate),
			})
		}
	}
	return out
}
