// Package eventengine implements Junos-style event-options policy execution.
// It watches RPM probe events and applies configuration changes when policies match.
package eventengine

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/rpm"
)

// CommitFn atomically promotes the candidate to active and applies
// it to the dataplane. The daemon's commitAndApply implementation
// holds the apply semaphore across both steps so the engine's
// commit can't interleave with another caller's commit/apply pair.
type CommitFn func(ctx context.Context, comment string) (*config.Config, error)

// Engine evaluates event-options policies against RPM events.
type Engine struct {
	mu       sync.Mutex
	policies []*config.EventPolicy
	store    *configstore.Store
	commitFn CommitFn

	// Temporal tracking: policy name → event name → sliding window of timestamps
	windows map[string]map[string][]time.Time

	// Cooldown tracking: policy name → last trigger time
	lastTrigger map[string]time.Time

	// Compiled attributes-match regexes, keyed by the raw pattern string.
	// Built once at Apply() time so the hot HandleEvent path never compiles
	// a regex per event. Patterns are also validated at commit
	// (config.ValidateConfig), so a bad pattern never reaches here; the
	// fallback in attributesMatch is defensive only.
	regexCache map[string]*regexp.Regexp
}

// Minimum time between successive triggers of the same policy.
const policyCooldown = 30 * time.Second

// New creates an event engine. commitFn is the daemon's atomic
// commit+apply callback (see #846); when non-nil, the engine routes
// its committed configs through it so they serialize with HTTP/gRPC
// commits. When nil (tests), commits succeed but no apply runs.
func New(store *configstore.Store, commitFn CommitFn) *Engine {
	return &Engine{
		store:       store,
		commitFn:    commitFn,
		windows:     make(map[string]map[string][]time.Time),
		lastTrigger: make(map[string]time.Time),
		regexCache:  make(map[string]*regexp.Regexp),
	}
}

// Apply loads new event-options policies. Resets temporal state and
// rebuilds the compiled-regex cache for every attributes-match pattern so
// the event hot path (HandleEvent) never compiles a regex per event.
func (e *Engine) Apply(policies []*config.EventPolicy) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.policies = policies
	e.windows = make(map[string]map[string][]time.Time)
	e.lastTrigger = make(map[string]time.Time)
	e.regexCache = make(map[string]*regexp.Regexp)
	for _, pol := range policies {
		for _, attr := range pol.AttributesMatch {
			pattern, ok := config.EventAttributesMatchPattern(attr)
			if !ok {
				continue
			}
			if _, cached := e.regexCache[pattern]; cached {
				continue
			}
			// Patterns are validated at commit; a compile failure here
			// should not happen. Log and skip so a single bad pattern
			// can never wedge the engine.
			re, err := regexp.Compile(pattern)
			if err != nil {
				slog.Warn("event-options: skipping uncompilable attributes-match pattern",
					"policy", pol.Name, "pattern", pattern, "err", err)
				continue
			}
			e.regexCache[pattern] = re
		}
	}
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
// Format: "ping_test_failed.test-owner matches <pattern>".
//
// Junos `attributes-match ... matches ...` semantics are a REGEX match, not
// literal equality (this was a parity defect, #2008 M7). The operator's
// pattern is treated as an RE2 regular expression compiled once at Apply()
// time and cached here. An unanchored pattern is a substring match (Junos
// behavior): `foo` matches `foobar`; anchor with `^foo$` for exact match.
//
// Note this is NOT a behavior-preserving change from the previous literal
// equality: a stored pattern containing regex metacharacters (`.`, `*`,
// `[`, ...) now matches as a regex. That is the correct Junos behavior;
// commit-time validation (config.ValidateEventAttributesMatch) rejects an
// invalid regex so the operator gets immediate feedback.
func (e *Engine) attributesMatch(pol *config.EventPolicy, ev rpm.Event) bool {
	for _, attr := range pol.AttributesMatch {
		field, pattern, ok := config.ParseEventAttributesMatch(attr)
		if !ok {
			continue
		}

		// Only test-owner and test-name are currently exposed on the event
		// (rpm.Event). Any other field reference is silently ignored, as it
		// was before — there is nothing to match it against yet.
		var value string
		switch field {
		case "test-owner":
			value = ev.TestOwner
		case "test-name":
			value = ev.TestName
		default:
			continue
		}

		re := e.regexCache[pattern]
		if re == nil {
			// Defensive: pattern was not cached (commit validation should
			// have rejected an uncompilable pattern, and Apply caches every
			// valid one). Compile on demand rather than silently dropping
			// the constraint; on failure fall back to literal equality so a
			// pathological pattern fails closed (constraint stays in force).
			compiled, err := regexp.Compile(pattern)
			if err != nil {
				if value != pattern {
					return false
				}
				continue
			}
			re = compiled
		}

		if !re.MatchString(value) {
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

	// #846: route through the daemon's atomic commit+apply so this
	// commit serializes with HTTP/gRPC commits. Without this, the
	// engine's store.Commit could interleave between another caller's
	// commit and apply, leaving configstore/kernel divergent.
	if e.commitFn == nil {
		// Standalone (tests): just commit; no apply.
		if _, err := e.store.Commit(); err != nil {
			slog.Warn("event-options: commit failed", "policy", pol.Name, "err", err)
		}
		e.store.ExitConfigure()
		return
	}
	if _, err := e.commitFn(context.Background(), ""); err != nil {
		slog.Warn("event-options: commit failed", "policy", pol.Name, "err", err)
		e.store.ExitConfigure()
		return
	}
	e.store.ExitConfigure()

	slog.Info("event-options: configuration committed",
		"policy", pol.Name,
		"commands", fmt.Sprintf("%d", len(pol.ThenCommands)))
}
