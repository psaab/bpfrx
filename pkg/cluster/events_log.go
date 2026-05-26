package cluster

// RecordEvent records a cluster event to the history ring buffer.
func (m *Manager) RecordEvent(cat EventCategory, rgID int, msg string) {
	m.history.Record(cat, rgID, msg)
}

// EventHistoryFor returns the event history for a given category.
func (m *Manager) EventHistoryFor(cat EventCategory) []HistoryEvent {
	return m.history.Events(cat)
}
