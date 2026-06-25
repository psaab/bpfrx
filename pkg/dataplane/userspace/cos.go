package userspace

import (
	"log/slog"
	"sort"

	"github.com/psaab/xpf/pkg/config"
)

func buildClassOfServiceSnapshot(cfg *config.Config) *ClassOfServiceSnapshot {
	if cfg == nil || cfg.ClassOfService == nil {
		return nil
	}
	cos := cfg.ClassOfService
	if len(cos.ForwardingClasses) == 0 && len(cos.DSCPClassifiers) == 0 && len(cos.IEEE8021Classifiers) == 0 && len(cos.DSCPRewriteRules) == 0 && len(cos.Schedulers) == 0 && len(cos.SchedulerMaps) == 0 && len(cos.Interfaces) == 0 {
		return nil
	}
	snap := &ClassOfServiceSnapshot{}

	if len(cos.ForwardingClasses) > 0 {
		names := make([]string, 0, len(cos.ForwardingClasses))
		for name := range cos.ForwardingClasses {
			names = append(names, name)
		}
		sort.Strings(names)
		snap.ForwardingClasses = make([]CoSForwardingClassSnapshot, 0, len(names))
		for _, name := range names {
			class := cos.ForwardingClasses[name]
			if class == nil {
				continue
			}
			snap.ForwardingClasses = append(snap.ForwardingClasses, CoSForwardingClassSnapshot{
				Name:  class.Name,
				Queue: class.Queue,
			})
		}
	}

	if len(cos.DSCPClassifiers) > 0 {
		names := make([]string, 0, len(cos.DSCPClassifiers))
		for name := range cos.DSCPClassifiers {
			names = append(names, name)
		}
		sort.Strings(names)
		snap.DSCPClassifiers = make([]CoSDSCPClassifierSnapshot, 0, len(names))
		for _, name := range names {
			classifier := cos.DSCPClassifiers[name]
			if classifier == nil {
				continue
			}
			classifierSnap := CoSDSCPClassifierSnapshot{Name: classifier.Name}
			for _, entry := range classifier.Entries {
				if entry == nil {
					continue
				}
				classifierSnap.Entries = append(classifierSnap.Entries, CoSDSCPClassifierEntrySnapshot{
					ForwardingClass: entry.ForwardingClass,
					LossPriority:    entry.LossPriority,
					DSCPValues:      append([]uint8(nil), entry.DSCPValues...),
				})
			}
			snap.DSCPClassifiers = append(snap.DSCPClassifiers, classifierSnap)
		}
	}

	if len(cos.IEEE8021Classifiers) > 0 {
		names := make([]string, 0, len(cos.IEEE8021Classifiers))
		for name := range cos.IEEE8021Classifiers {
			names = append(names, name)
		}
		sort.Strings(names)
		snap.IEEE8021Classifiers = make([]CoSIEEE8021ClassifierSnapshot, 0, len(names))
		for _, name := range names {
			classifier := cos.IEEE8021Classifiers[name]
			if classifier == nil {
				continue
			}
			classifierSnap := CoSIEEE8021ClassifierSnapshot{Name: classifier.Name}
			for _, entry := range classifier.Entries {
				if entry == nil {
					continue
				}
				classifierSnap.Entries = append(classifierSnap.Entries, CoSIEEE8021ClassifierEntrySnapshot{
					ForwardingClass: entry.ForwardingClass,
					LossPriority:    entry.LossPriority,
					CodePoints:      append([]uint8(nil), entry.CodePoints...),
				})
			}
			snap.IEEE8021Classifiers = append(snap.IEEE8021Classifiers, classifierSnap)
		}
	}

	if len(cos.DSCPRewriteRules) > 0 {
		names := make([]string, 0, len(cos.DSCPRewriteRules))
		for name := range cos.DSCPRewriteRules {
			names = append(names, name)
		}
		sort.Strings(names)
		snap.DSCPRewriteRules = make([]CoSDSCPRewriteRuleSnapshot, 0, len(names))
		for _, name := range names {
			rewriteRule := cos.DSCPRewriteRules[name]
			if rewriteRule == nil {
				continue
			}
			rewriteSnap := CoSDSCPRewriteRuleSnapshot{Name: rewriteRule.Name}
			for _, entry := range rewriteRule.Entries {
				if entry == nil {
					continue
				}
				rewriteSnap.Entries = append(rewriteSnap.Entries, CoSDSCPRewriteRuleEntrySnapshot{
					ForwardingClass: entry.ForwardingClass,
					LossPriority:    entry.LossPriority,
					DSCPValue:       entry.DSCPValue,
				})
			}
			snap.DSCPRewriteRules = append(snap.DSCPRewriteRules, rewriteSnap)
		}
	}

	if len(cos.Schedulers) > 0 {
		names := make([]string, 0, len(cos.Schedulers))
		for name := range cos.Schedulers {
			names = append(names, name)
		}
		sort.Strings(names)
		snap.Schedulers = make([]CoSSchedulerSnapshot, 0, len(names))
		for _, name := range names {
			sched := cos.Schedulers[name]
			if sched == nil {
				continue
			}
			snap.Schedulers = append(snap.Schedulers, CoSSchedulerSnapshot{
				Name:                  sched.Name,
				TransmitRateBytes:     sched.TransmitRateBytes,
				TransmitRateExact:     sched.TransmitRateExact,
				Priority:              sched.Priority,
				BufferSizeBytes:       sched.BufferSizeBytes,
				BufferSizePercent:     sched.BufferSizePercent,
				SurplusSharing:        sched.SurplusSharing,
				EqualFlowEnforcement:  sched.EqualFlowEnforcement,
				EqualFlowTargetPolicy: sched.EqualFlowTargetPolicy,
				CodelTargetNS:         sched.CodelTargetNS,
			})
		}
	}

	if len(cos.SchedulerMaps) > 0 {
		names := make([]string, 0, len(cos.SchedulerMaps))
		for name := range cos.SchedulerMaps {
			names = append(names, name)
		}
		sort.Strings(names)
		snap.SchedulerMaps = make([]CoSSchedulerMapSnapshot, 0, len(names))
		for _, name := range names {
			schedMap := cos.SchedulerMaps[name]
			if schedMap == nil {
				continue
			}
			entryNames := make([]string, 0, len(schedMap.Entries))
			for className := range schedMap.Entries {
				entryNames = append(entryNames, className)
			}
			sort.Strings(entryNames)
			mapSnap := CoSSchedulerMapSnapshot{Name: schedMap.Name}
			for _, className := range entryNames {
				entry := schedMap.Entries[className]
				if entry == nil {
					continue
				}
				// #2409: a scheduler-map entry referencing a forwarding-class
				// that is not defined in `class-of-service forwarding-classes`
				// is only a NON-FATAL warning at commit time
				// (compiler_validate_warn.go; the strict gate rejects only
				// buffer-percent overcommit, not undefined-class refs). So this
				// is a SUPPORTED, committable config shape — not corruption.
				// Skip the undefined entry here (degrade visibly, preserving the
				// historical "install the valid subset" semantics) with a
				// slog.Warn so the loss is no longer SILENT (the #2409
				// complaint was the silence, not the partial install). Keeping
				// the entry OFF THE WIRE means the Rust
				// SchedulerMapUnknownClass hard-error stays a true never-fires
				// drift backstop — it now fires only on a version/snapshot-
				// drifted helper that receives an entry this emitter would have
				// filtered, consistent with the VLAN/TTL/queue/address sites
				// (corruption a valid config never produces).
				if _, ok := cos.ForwardingClasses[entry.ForwardingClass]; !ok {
					slog.Warn("cos scheduler-map references undefined forwarding-class; skipping entry (degraded shaping)",
						"scheduler_map", schedMap.Name,
						"forwarding_class", entry.ForwardingClass,
					)
					continue
				}
				mapSnap.Entries = append(mapSnap.Entries, CoSSchedulerMapEntrySnapshot{
					ForwardingClass: entry.ForwardingClass,
					Scheduler:       entry.Scheduler,
				})
			}
			snap.SchedulerMaps = append(snap.SchedulerMaps, mapSnap)
		}
	}

	return snap
}
