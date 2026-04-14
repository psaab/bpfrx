package userspace

import (
	"fmt"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/psaab/xpf/pkg/config"
)

type cosInterfaceView struct {
	name           string
	unit           int
	cosUnit        *config.CoSInterfaceUnit
	interfaceUnit  *config.InterfaceUnit
	interfaceState *CoSInterfaceStatus
}

type cosQueueView struct {
	queueID         int
	forwardingClass string
	priority        string
	exact           bool
	transmitRate    uint64
	bufferBytes     uint64
	queuedPackets   uint64
	queuedBytes     uint64
	runnable        int
	parked          int
	nextWakeupTick  uint64
	surplusDeficit  uint64
}

func FormatCoSInterfaceSummary(cfg *config.Config, status *ProcessStatus, selector string) string {
	if cfg == nil {
		return "No active configuration\n"
	}
	if cfg.ClassOfService == nil || len(cfg.ClassOfService.Interfaces) == 0 {
		return "No class-of-service interfaces configured\n"
	}

	views := configuredCoSInterfaceViews(cfg, status, selector)
	if len(views) == 0 {
		if selector == "" {
			return "No class-of-service interfaces configured\n"
		}
		return fmt.Sprintf("No class-of-service interface matches %s\n", selector)
	}

	var b strings.Builder
	for idx, view := range views {
		if idx > 0 {
			b.WriteString("\n")
		}
		fmt.Fprintf(&b, "Interface: %s\n", view.name)
		if view.cosUnit != nil {
			fmt.Fprintf(&b, "  Scheduler map:            %s\n", emptyDash(view.cosUnit.SchedulerMap))
			fmt.Fprintf(&b, "  Shaping rate:             %s\n", formatCoSRate(view.cosUnit.ShapingRateBytes))
			fmt.Fprintf(&b, "  Burst size:               %s\n", formatCoSBytes(view.cosUnit.BurstSizeBytes))
		}
		if view.interfaceUnit != nil {
			if view.interfaceUnit.FilterInputV4 != "" {
				fmt.Fprintf(&b, "  Input filter (inet):      %s\n", view.interfaceUnit.FilterInputV4)
			}
			if view.interfaceUnit.FilterOutputV4 != "" {
				fmt.Fprintf(&b, "  Output filter (inet):     %s\n", view.interfaceUnit.FilterOutputV4)
			}
			if view.interfaceUnit.FilterInputV6 != "" {
				fmt.Fprintf(&b, "  Input filter (inet6):     %s\n", view.interfaceUnit.FilterInputV6)
			}
			if view.interfaceUnit.FilterOutputV6 != "" {
				fmt.Fprintf(&b, "  Output filter (inet6):    %s\n", view.interfaceUnit.FilterOutputV6)
			}
		}
		if view.interfaceState == nil {
			b.WriteString("  Runtime:                  unavailable\n")
		} else {
			fmt.Fprintf(&b, "  Owner worker:             %s\n", formatOptionalWorkerID(view.interfaceState.OwnerWorkerID))
			fmt.Fprintf(&b, "  Runtime workers:          %d\n", view.interfaceState.WorkerInstances)
			fmt.Fprintf(&b, "  Runtime queues:           nonempty=%d runnable=%d\n",
				view.interfaceState.NonemptyQueues,
				view.interfaceState.RunnableQueues)
			fmt.Fprintf(&b, "  Timer wheel sleepers:     level0=%d level1=%d\n",
				view.interfaceState.TimerLevel0Sleepers,
				view.interfaceState.TimerLevel1Sleepers)
		}
		queues := buildCoSQueueViews(cfg, view)
		if len(queues) == 0 {
			b.WriteString("  Queues:                   none\n")
			continue
		}
		b.WriteString("  Queues:\n")
		tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "    Queue\tClass\tPriority\tExact\tTransmit rate\tBuffer\tQueued pkts\tQueued bytes\tRunnable\tParked\tNext wake\tSurplus deficit")
		for _, queue := range queues {
			fmt.Fprintf(tw, "    %d\t%s\t%s\t%s\t%s\t%s\t%d\t%s\t%d\t%d\t%s\t%s\n",
				queue.queueID,
				emptyDash(queue.forwardingClass),
				queue.priority,
				yesNo(queue.exact),
				formatCoSRate(queue.transmitRate),
				formatCoSBytes(queue.bufferBytes),
				queue.queuedPackets,
				formatCoSBytes(queue.queuedBytes),
				queue.runnable,
				queue.parked,
				formatWakeTick(queue.nextWakeupTick),
				formatCoSBytes(queue.surplusDeficit),
			)
		}
		_ = tw.Flush()
	}
	return b.String()
}

func configuredCoSInterfaceViews(cfg *config.Config, status *ProcessStatus, selector string) []cosInterfaceView {
	runtimeByName := make(map[string]*CoSInterfaceStatus)
	if status != nil {
		for i := range status.CoSInterfaces {
			iface := &status.CoSInterfaces[i]
			runtimeByName[iface.InterfaceName] = iface
		}
	}
	selector = strings.TrimSpace(selector)
	views := make([]cosInterfaceView, 0)
	for ifName, iface := range cfg.ClassOfService.Interfaces {
		for unitNum, cosUnit := range iface.Units {
			logicalName := fmt.Sprintf("%s.%d", ifName, unitNum)
			if selector != "" && selector != ifName && selector != logicalName {
				continue
			}
			var interfaceUnit *config.InterfaceUnit
			if cfg.Interfaces.Interfaces != nil {
				if intf := cfg.Interfaces.Interfaces[ifName]; intf != nil && intf.Units != nil {
					interfaceUnit = intf.Units[unitNum]
				}
			}
			views = append(views, cosInterfaceView{
				name:           logicalName,
				unit:           unitNum,
				cosUnit:        cosUnit,
				interfaceUnit:  interfaceUnit,
				interfaceState: runtimeByName[logicalName],
			})
		}
	}
	sort.Slice(views, func(i, j int) bool { return views[i].name < views[j].name })
	return views
}

func buildCoSQueueViews(cfg *config.Config, view cosInterfaceView) []cosQueueView {
	queueViews := make(map[int]cosQueueView)
	if cfg.ClassOfService != nil && view.cosUnit != nil {
		schedulerMap := cfg.ClassOfService.SchedulerMaps[view.cosUnit.SchedulerMap]
		if schedulerMap != nil {
			for className, entry := range schedulerMap.Entries {
				class := cfg.ClassOfService.ForwardingClasses[className]
				if class == nil {
					continue
				}
				qv := queueViews[class.Queue]
				qv.queueID = class.Queue
				qv.forwardingClass = className
				if sched := cfg.ClassOfService.Schedulers[entry.Scheduler]; sched != nil {
					qv.exact = sched.TransmitRateExact
					qv.transmitRate = sched.TransmitRateBytes
					qv.bufferBytes = sched.BufferSizeBytes
					if sched.Priority != "" {
						qv.priority = sched.Priority
					}
				}
				queueViews[class.Queue] = qv
			}
		}
	}
	if view.interfaceState != nil {
		for _, runtimeQueue := range view.interfaceState.Queues {
			qv := queueViews[int(runtimeQueue.QueueID)]
			qv.queueID = int(runtimeQueue.QueueID)
			if runtimeQueue.ForwardingClass != "" {
				qv.forwardingClass = runtimeQueue.ForwardingClass
			}
			qv.priority = fmt.Sprintf("%d", runtimeQueue.Priority)
			qv.exact = runtimeQueue.Exact
			if runtimeQueue.TransmitRateBytes > 0 {
				qv.transmitRate = runtimeQueue.TransmitRateBytes
			}
			if runtimeQueue.BufferBytes > 0 {
				qv.bufferBytes = runtimeQueue.BufferBytes
			}
			qv.queuedPackets = runtimeQueue.QueuedPackets
			qv.queuedBytes = runtimeQueue.QueuedBytes
			qv.runnable = runtimeQueue.RunnableInstances
			qv.parked = runtimeQueue.ParkedInstances
			qv.nextWakeupTick = runtimeQueue.NextWakeupTick
			qv.surplusDeficit = runtimeQueue.SurplusDeficitBytes
			queueViews[qv.queueID] = qv
		}
	}
	out := make([]cosQueueView, 0, len(queueViews))
	for _, queue := range queueViews {
		if queue.priority == "" {
			queue.priority = "-"
		}
		out = append(out, queue)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].queueID < out[j].queueID })
	return out
}

func formatCoSRate(bytesPerSecond uint64) string {
	if bytesPerSecond == 0 {
		return "-"
	}
	bitsPerSecond := float64(bytesPerSecond) * 8
	units := []string{"b/s", "Kb/s", "Mb/s", "Gb/s", "Tb/s"}
	unitIdx := 0
	for bitsPerSecond >= 1000 && unitIdx < len(units)-1 {
		bitsPerSecond /= 1000
		unitIdx++
	}
	return fmt.Sprintf("%.2f %s", bitsPerSecond, units[unitIdx])
}

func formatOptionalWorkerID(workerID *uint32) string {
	if workerID == nil {
		return "-"
	}
	return fmt.Sprintf("%d", *workerID)
}

func formatCoSBytes(bytes uint64) string {
	if bytes == 0 {
		return "-"
	}
	value := float64(bytes)
	units := []string{"B", "KiB", "MiB", "GiB", "TiB"}
	unitIdx := 0
	for value >= 1024 && unitIdx < len(units)-1 {
		value /= 1024
		unitIdx++
	}
	return fmt.Sprintf("%.2f %s", value, units[unitIdx])
}

func formatWakeTick(tick uint64) string {
	if tick == 0 {
		return "-"
	}
	return fmt.Sprintf("%d", tick)
}

func emptyDash(value string) string {
	if value == "" {
		return "-"
	}
	return value
}

func yesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}
