// Package eventengine implements Junos-style event-options policy execution.
// It watches RPM probe events and applies configuration changes when policies match.
package eventengine

import (
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/psaab/bpfrx/pkg/config"
	"github.com/psaab/bpfrx/pkg/configstore"
	"github.com/psaab/bpfrx/pkg/rpm"
)

// ApplyFn is called after a successful commit to apply the new configuration.
type ApplyFn func(*config.Config)

// Engine evaluates event-options policies against RPM events.
type Engine struct {
	mu       sync.Mutex
	policies []*config.EventPolicy
	store    *configstore.Store
	applyFn  ApplyFn

	// Temporal tracking: policy name → event name → sliding window of timestamps
	windows map[string]map[string][]time.Time

	// Cooldown tracking: policy name → last trigger time
	lastTrigger map[string]time.Time
}

// Minimum time between successive triggers of the same policy.
const policyCooldown = 30 * time.Second

// New creates an event engine.
func New(store *configstore.Store, applyFn ApplyFn) *Engine {
	return &Engine{
		store:       store,
		applyFn:     applyFn,
		windows:     make(map[string]map[string][]time.Time),
		lastTrigger: make(map[string]time.Time),
	}
}

// Apply loads new event-options policies. Resets temporal state.
func (e *Engine) Apply(policies []*config.EventPolicy) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.policies = policies
	e.windows = make(map[string]map[string][]time.Time)
	e.lastTrigger = make(map[string]time.Time)
}

// HandleEvent is the callback for RPM events.
func (e *Engine) HandleEvent(ev rpm.Event) {
	// Evaluate under lock, but execute commands without lock to avoid
	// deadlock: executeCommands → applyFn → applyConfig → Apply() → e.mu.Lock.
	triggered := e.evaluateEvent(ev)
	for _, pol := range triggered {
		e.executeCommands(pol)
	}
}

// evaluateEvent checks policies under lock and returns any that should trigger.
func (e *Engine) evaluateEvent(ev rpm.Event) []*config.EventPolicy {
	e.mu.Lock()
	defer e.mu.Unlock()

	var triggered []*config.EventPolicy
	for _, pol := range e.policies {
		if !e.eventMatches(pol, ev) {
			continue
		}

		if !e.attributesMatch(pol, ev) {
			continue
		}

		// Record this event in the temporal window
		if e.windows[pol.Name] == nil {
			e.windows[pol.Name] = make(map[string][]time.Time)
		}
		now := time.Now()
		e.windows[pol.Name][ev.Name] = append(e.windows[pol.Name][ev.Name], now)

		if !e.withinMatches(pol, ev.Name, now) {
			continue
		}

		// Cooldown: don't re-trigger the same policy too quickly
		if last, ok := e.lastTrigger[pol.Name]; ok && now.Sub(last) < policyCooldown {
			continue
		}
		e.lastTrigger[pol.Name] = now

		slog.Info("event-options policy triggered",
			"policy", pol.Name,
			"event", ev.Name,
			"test-owner", ev.TestOwner,
			"test-name", ev.TestName)

		triggered = append(triggered, pol)
	}
	return triggered
}

// eventMatches checks if the event name is in the policy's event list.
func (e *Engine) eventMatches(pol *config.EventPolicy, ev rpm.Event) bool {
	for _, name := range pol.Events {
		if name == ev.Name {
			return true
		}
	}
	return false
}

// attributesMatch checks if the event attributes match the policy's filters.
// Format: "ping_test_failed.test-owner matches <pattern>"
func (e *Engine) attributesMatch(pol *config.EventPolicy, ev rpm.Event) bool {
	for _, attr := range pol.AttributesMatch {
		// Parse "event.field matches pattern"
		parts := strings.SplitN(attr, " matches ", 2)
		if len(parts) != 2 {
			continue
		}
		fieldSpec := parts[0]
		pattern := parts[1]

		// Extract field name from "event_name.field_name"
		dotIdx := strings.LastIndex(fieldSpec, ".")
		if dotIdx < 0 {
			continue
		}
		field := fieldSpec[dotIdx+1:]

		var value string
		switch field {
		case "test-owner":
			value = ev.TestOwner
		case "test-name":
			value = ev.TestName
		default:
			continue
		}

		if value != pattern {
			return false
		}
	}
	return true
}

// withinMatches evaluates temporal trigger clauses.
// "within N { trigger on M }" — fires when M events happen within N seconds.
// "within N { trigger until M }" — fires until M events happen within N seconds, then stops.
func (e *Engine) withinMatches(pol *config.EventPolicy, eventName string, now time.Time) bool {
	if len(pol.WithinClauses) == 0 {
		return true // no temporal filter
	}

	timestamps := e.windows[pol.Name][eventName]

	for _, wc := range pol.WithinClauses {
		window := time.Duration(wc.Seconds) * time.Second

		// Count events within the window
		count := 0
		for _, ts := range timestamps {
			if now.Sub(ts) <= window {
				count++
			}
		}

		if wc.TriggerOn > 0 {
			// "trigger on N" — must have at least N events in window
			if count < wc.TriggerOn {
				return false
			}
		}

		if wc.TriggerUntil > 0 {
			// "trigger until N" — stop triggering once N events reached in window
			if count >= wc.TriggerUntil {
				return false
			}
		}
	}

	// Prune old timestamps to prevent unbounded growth
	e.pruneWindows(pol.Name, eventName, now)

	return true
}

// pruneWindows removes timestamps older than the maximum within window.
func (e *Engine) pruneWindows(polName, eventName string, now time.Time) {
	pol := e.findPolicy(polName)
	if pol == nil {
		return
	}

	maxWindow := time.Duration(0)
	for _, wc := range pol.WithinClauses {
		w := time.Duration(wc.Seconds) * time.Second
		if w > maxWindow {
			maxWindow = w
		}
	}
	if maxWindow == 0 {
		maxWindow = 60 * time.Second
	}

	timestamps := e.windows[polName][eventName]
	pruned := timestamps[:0]
	for _, ts := range timestamps {
		if now.Sub(ts) <= maxWindow {
			pruned = append(pruned, ts)
		}
	}
	e.windows[polName][eventName] = pruned
}

func (e *Engine) findPolicy(name string) *config.EventPolicy {
	for _, p := range e.policies {
		if p.Name == name {
			return p
		}
	}
	return nil
}

// executeCommands applies the change-configuration commands.
func (e *Engine) executeCommands(pol *config.EventPolicy) {
	if len(pol.ThenCommands) == 0 {
		return
	}

	// Enter configure mode
	if err := e.store.EnterConfigure(); err != nil {
		slog.Warn("event-options: failed to enter configure mode", "policy", pol.Name, "err", err)
		return
	}

	// Apply each command
	for _, cmd := range pol.ThenCommands {
		cmd = strings.TrimSpace(cmd)
		if cmd == "" {
			continue
		}

		// Commands in event-options are full "set ..." strings
		if strings.HasPrefix(cmd, "set ") {
			input := strings.TrimPrefix(cmd, "set ")
			if err := e.store.SetFromInput(input); err != nil {
				slog.Warn("event-options: set command failed",
					"policy", pol.Name, "cmd", cmd, "err", err)
			}
		} else if strings.HasPrefix(cmd, "delete ") {
			input := strings.TrimPrefix(cmd, "delete ")
			path, err := config.ParseSetCommand("set " + input)
			if err != nil {
				slog.Warn("event-options: delete parse failed",
					"policy", pol.Name, "cmd", cmd, "err", err)
				continue
			}
			if err := e.store.Delete(path); err != nil {
				// "path not found" is expected when the element doesn't exist
				if strings.Contains(err.Error(), "path not found") {
					slog.Debug("event-options: delete skipped (path not found)",
						"policy", pol.Name, "cmd", cmd)
				} else {
					slog.Warn("event-options: delete command failed",
						"policy", pol.Name, "cmd", cmd, "err", err)
				}
			}
		} else {
			slog.Warn("event-options: unsupported command type",
				"policy", pol.Name, "cmd", cmd)
		}
	}

	// Commit
	compiled, err := e.store.Commit()
	if err != nil {
		slog.Warn("event-options: commit failed", "policy", pol.Name, "err", err)
		e.store.ExitConfigure()
		return
	}

	// Exit configure mode to release the lock
	e.store.ExitConfigure()

	slog.Info("event-options: configuration committed",
		"policy", pol.Name,
		"commands", fmt.Sprintf("%d", len(pol.ThenCommands)))

	// Apply the new configuration
	if e.applyFn != nil && compiled != nil {
		e.applyFn(compiled)
	}
}
