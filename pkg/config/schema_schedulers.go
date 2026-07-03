package config

// schemaSchedulers models the top-level `[edit schedulers]` policy
// time-range stanza (F-013 — previously absent from setSchema, so flat-set
// `set schedulers scheduler X daily start-time ...` packed the whole line
// onto ONE leaf node and the compiler dropped it). Adding it here makes
// SetPath group flat-set scheduler config into the same nested AST the
// hierarchical parser produces, so compileSchedulers descends into the
// `daily {}`/weekday containers for both shapes.
//
// The time/date value slots are typed (ValueTimeOfDay/ValueDate) so a
// malformed window is rejected at commit — the fail-closed half of #3849.
var schemaSchedulerDay = &schemaNode{
	desc: "Time window for this day (start-time/stop-time, all-day, or exclude)",
	children: map[string]*schemaNode{
		"start-time": {
			desc:          "Window start time (24-hour HH:MM:SS)",
			args:          1,
			placeholder:   "<HH:MM:SS>",
			valueType:     ValueTimeOfDay,
			valueDesc:     "Time of day the window opens (24-hour HH:MM:SS)",
			valueExamples: []string{"09:00:00", "17:30:00", "22:00:00"},
			validator:     ValidateTimeOfDay,
			children:      nil,
		},
		"stop-time": {
			desc:          "Window stop time (24-hour HH:MM:SS; exclusive)",
			args:          1,
			placeholder:   "<HH:MM:SS>",
			valueType:     ValueTimeOfDay,
			valueDesc:     "Time of day the window closes (24-hour HH:MM:SS)",
			valueExamples: []string{"17:00:00", "06:00:00"},
			validator:     ValidateTimeOfDay,
			children:      nil,
		},
		"all-day": {desc: "Active for the entire day", children: nil},
		"exclude": {desc: "Never active on this day", children: nil},
	},
}

var schemaSchedulers = &schemaNode{
	desc: "Policy time-range schedulers ([edit schedulers])",
	children: map[string]*schemaNode{
		"scheduler": {
			desc:        "Named scheduler bound to a policy via scheduler-name",
			args:        1,
			multi:       true,
			placeholder: "<scheduler-name>",
			children: map[string]*schemaNode{
				// Legacy simplified shape: start-time/stop-time as direct
				// children of the scheduler (the daily window).
				"start-time": {
					desc:          "Daily window start time (24-hour HH:MM:SS)",
					args:          1,
					placeholder:   "<HH:MM:SS>",
					valueType:     ValueTimeOfDay,
					valueDesc:     "Time of day the daily window opens (24-hour HH:MM:SS)",
					valueExamples: []string{"09:00:00", "17:30:00"},
					validator:     ValidateTimeOfDay,
					children:      nil,
				},
				"stop-time": {
					desc:          "Daily window stop time (24-hour HH:MM:SS; exclusive)",
					args:          1,
					placeholder:   "<HH:MM:SS>",
					valueType:     ValueTimeOfDay,
					valueDesc:     "Time of day the daily window closes (24-hour HH:MM:SS)",
					valueExamples: []string{"17:00:00", "06:00:00"},
					validator:     ValidateTimeOfDay,
					children:      nil,
				},
				"start-date": {
					desc:          "Calendar range start date (YYYY-MM-DD)",
					args:          1,
					placeholder:   "<YYYY-MM-DD>",
					valueType:     ValueDate,
					valueDesc:     "First date the scheduler is active (YYYY-MM-DD)",
					valueExamples: []string{"2026-03-01"},
					validator:     ValidateDate,
					children:      nil,
				},
				"stop-date": {
					desc:          "Calendar range stop date (YYYY-MM-DD; inclusive)",
					args:          1,
					placeholder:   "<YYYY-MM-DD>",
					valueType:     ValueDate,
					valueDesc:     "Last date the scheduler is active (YYYY-MM-DD, inclusive)",
					valueExamples: []string{"2026-03-31"},
					validator:     ValidateDate,
					children:      nil,
				},
				// Junos day containers. `daily` applies to every weekday with
				// no specific override; a weekday container overrides `daily`
				// for that day. All share the same window sub-schema.
				"daily":     schemaSchedulerDay,
				"monday":    schemaSchedulerDay,
				"tuesday":   schemaSchedulerDay,
				"wednesday": schemaSchedulerDay,
				"thursday":  schemaSchedulerDay,
				"friday":    schemaSchedulerDay,
				"saturday":  schemaSchedulerDay,
				"sunday":    schemaSchedulerDay,
			},
		},
	},
}
