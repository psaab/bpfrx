package userspace

type FirewallFilterTermCounterKey struct {
	Family     string
	FilterName string
	TermName   string
}

func BuildFirewallFilterTermCounterIndex(status *ProcessStatus) map[FirewallFilterTermCounterKey]FirewallFilterTermCounterStatus {
	index := make(map[FirewallFilterTermCounterKey]FirewallFilterTermCounterStatus)
	if status == nil {
		return index
	}
	for _, counter := range status.FilterTermCounters {
		key := FirewallFilterTermCounterKey{
			Family:     counter.Family,
			FilterName: counter.FilterName,
			TermName:   counter.TermName,
		}
		index[key] = counter
	}
	return index
}
