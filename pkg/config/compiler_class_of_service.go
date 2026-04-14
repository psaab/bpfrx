package config

import "strconv"

func compileClassOfService(node *Node, cos *ClassOfServiceConfig) error {
	if cos == nil {
		return nil
	}
	if cos.ForwardingClasses == nil {
		cos.ForwardingClasses = make(map[string]*CoSForwardingClass)
	}
	if cos.Schedulers == nil {
		cos.Schedulers = make(map[string]*CoSScheduler)
	}
	if cos.SchedulerMaps == nil {
		cos.SchedulerMaps = make(map[string]*CoSSchedulerMap)
	}
	if cos.Interfaces == nil {
		cos.Interfaces = make(map[string]*CoSInterface)
	}

	if fcNode := node.FindChild("forwarding-classes"); fcNode != nil {
		for _, queueNode := range fcNode.FindChildren("queue") {
			if len(queueNode.Keys) < 3 {
				continue
			}
			queue, err := strconv.Atoi(queueNode.Keys[1])
			if err != nil {
				continue
			}
			name := queueNode.Keys[2]
			cos.ForwardingClasses[name] = &CoSForwardingClass{
				Name:  name,
				Queue: queue,
			}
		}
	}

	for _, inst := range namedInstances(node.FindChildren("schedulers")) {
		sched := &CoSScheduler{Name: inst.name}
		for _, child := range inst.node.Children {
			switch child.Name() {
			case "transmit-rate":
				rate, exact := parseCoSTransmitRate(child)
				if rate > 0 {
					sched.TransmitRateBytes = rate
				}
				sched.TransmitRateExact = sched.TransmitRateExact || exact
			case "priority":
				sched.Priority = nodeVal(child)
			case "buffer-size":
				if v := nodeVal(child); v != "" {
					sched.BufferSizeBytes = parseBurstSizeLimit(v)
				}
			}
		}
		cos.Schedulers[sched.Name] = sched
	}

	for _, inst := range namedInstances(node.FindChildren("scheduler-maps")) {
		schedMap := &CoSSchedulerMap{
			Name:    inst.name,
			Entries: make(map[string]*CoSSchedulerMapEntry),
		}
		for _, child := range inst.node.Children {
			if child.Name() != "forwarding-class" || len(child.Keys) < 2 {
				continue
			}
			className := child.Keys[1]
			scheduler := ""
			if len(child.Keys) >= 4 && child.Keys[2] == "scheduler" {
				scheduler = child.Keys[3]
			} else if schedNode := child.FindChild("scheduler"); schedNode != nil {
				scheduler = nodeVal(schedNode)
			}
			schedMap.Entries[className] = &CoSSchedulerMapEntry{
				ForwardingClass: className,
				Scheduler:       scheduler,
			}
		}
		cos.SchedulerMaps[schedMap.Name] = schedMap
	}

	for _, inst := range namedInstances(node.FindChildren("interfaces")) {
		iface := &CoSInterface{
			Name:  inst.name,
			Units: make(map[int]*CoSInterfaceUnit),
		}
		for _, unitNode := range inst.node.FindChildren("unit") {
			if len(unitNode.Keys) < 2 {
				continue
			}
			unitID, err := strconv.Atoi(unitNode.Keys[1])
			if err != nil {
				continue
			}
			unit := &CoSInterfaceUnit{Unit: unitID}
			if shapingNode := unitNode.FindChild("shaping-rate"); shapingNode != nil {
				if v := nodeVal(shapingNode); v != "" {
					unit.ShapingRateBytes = parseBandwidthLimit(v)
				}
				if burstNode := shapingNode.FindChild("burst-size"); burstNode != nil {
					if v := nodeVal(burstNode); v != "" {
						unit.BurstSizeBytes = parseBurstSizeLimit(v)
					}
				}
			}
			if schedMapNode := unitNode.FindChild("scheduler-map"); schedMapNode != nil {
				unit.SchedulerMap = nodeVal(schedMapNode)
			}
			if unit.ShapingRateBytes > 0 || unit.BurstSizeBytes > 0 || unit.SchedulerMap != "" {
				iface.Units[unitID] = unit
			}
		}
		if len(iface.Units) > 0 {
			cos.Interfaces[iface.Name] = iface
		}
	}

	return nil
}

func parseCoSTransmitRate(node *Node) (uint64, bool) {
	var rate uint64
	exact := false
	for _, key := range node.Keys[1:] {
		if key == "exact" {
			exact = true
			continue
		}
		if parsed := parseBandwidthLimit(key); parsed > 0 {
			rate = parsed
		}
	}
	if node.FindChild("exact") != nil {
		exact = true
	}
	return rate, exact
}
