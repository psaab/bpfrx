package logging

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
)

// SyslogSlogHandler is an slog.Handler that forwards log records to remote
// syslog servers in addition to a wrapped base handler (typically stderr).
type SyslogSlogHandler struct {
	base    slog.Handler
	mu      sync.RWMutex
	clients []*SyslogClient
	attrs   []slog.Attr
	groups  []string
	// forwarding is the set of goroutine IDs currently inside the
	// syslog-forwarding section of Handle. It is the re-entrancy guard
	// (#2287): if a client's Send emits an slog record (e.g. a drop warning),
	// slog routes it back through this handler on the SAME goroutine; the
	// guard skips re-forwarding it to syslog so no under-lock or transitive
	// slog call can wedge the daemon. Forwarding to the base handler (stderr)
	// stays unconditional. Shared by pointer across WithAttrs/WithGroup
	// derivatives so a nested Handle through a derived handler is also caught.
	forwarding *sync.Map // map[uint64]struct{}
}

// NewSyslogSlogHandler wraps a base slog.Handler with syslog forwarding.
func NewSyslogSlogHandler(base slog.Handler) *SyslogSlogHandler {
	return &SyslogSlogHandler{base: base, forwarding: &sync.Map{}}
}

// SetClients replaces the set of syslog clients. Old clients are closed.
func (h *SyslogSlogHandler) SetClients(clients []*SyslogClient) {
	h.mu.Lock()
	old := h.clients
	h.clients = clients
	h.mu.Unlock()

	for _, c := range old {
		c.Close()
	}
}

// Close closes all syslog clients.
func (h *SyslogSlogHandler) Close() {
	h.mu.Lock()
	clients := h.clients
	h.clients = nil
	h.mu.Unlock()

	for _, c := range clients {
		c.Close()
	}
}

// Enabled implements slog.Handler.
func (h *SyslogSlogHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.base.Enabled(ctx, level)
}

// Handle implements slog.Handler.
func (h *SyslogSlogHandler) Handle(ctx context.Context, r slog.Record) error {
	// Always forward to the base handler (stderr) — unconditionally, even on a
	// re-entrant call, so the record is never lost from local logs.
	err := h.base.Handle(ctx, r)

	// Re-entrancy guard (#2287): if this goroutine is already inside the
	// syslog-forwarding section (a client Send emitted an slog record that
	// routed back here), skip re-forwarding to syslog. Defense-in-depth so no
	// under-lock or transitive slog call from the send path can wedge the
	// daemon by recursing into a client's Send.
	if h.forwarding != nil {
		gid := goID()
		if _, busy := h.forwarding.Load(gid); busy {
			return err
		}
		h.forwarding.Store(gid, struct{}{})
		defer h.forwarding.Delete(gid)
	}

	// Forward to syslog clients
	h.mu.RLock()
	clients := h.clients
	h.mu.RUnlock()

	if len(clients) > 0 {
		severity := slogLevelToSyslog(r.Level)
		msg := formatRecord(r, h.attrs, h.groups)
		for _, c := range clients {
			if c.ShouldSend(severity) {
				c.Send(severity, msg)
			}
		}
	}

	return err
}

// WithAttrs implements slog.Handler.
func (h *SyslogSlogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &SyslogSlogHandler{
		base:       h.base.WithAttrs(attrs),
		clients:    h.clients,
		attrs:      append(append([]slog.Attr{}, h.attrs...), attrs...),
		groups:     h.groups,
		forwarding: h.forwarding, // share the re-entrancy guard (#2287)
	}
}

// WithGroup implements slog.Handler.
func (h *SyslogSlogHandler) WithGroup(name string) slog.Handler {
	return &SyslogSlogHandler{
		base:       h.base.WithGroup(name),
		clients:    h.clients,
		attrs:      h.attrs,
		groups:     append(append([]string{}, h.groups...), name),
		forwarding: h.forwarding, // share the re-entrancy guard (#2287)
	}
}

// slogLevelToSyslog maps slog levels to syslog severity values.
func slogLevelToSyslog(level slog.Level) int {
	switch {
	case level >= slog.LevelError:
		return SyslogError
	case level >= slog.LevelWarn:
		return SyslogWarning
	default:
		return SyslogInfo
	}
}

// formatRecord produces a compact text representation of a log record.
func formatRecord(r slog.Record, preAttrs []slog.Attr, groups []string) string {
	var b strings.Builder
	b.WriteString(r.Message)

	for _, a := range preAttrs {
		fmt.Fprintf(&b, " %s=%s", a.Key, a.Value.String())
	}

	r.Attrs(func(a slog.Attr) bool {
		key := a.Key
		if len(groups) > 0 {
			key = strings.Join(groups, ".") + "." + key
		}
		fmt.Fprintf(&b, " %s=%s", key, a.Value.String())
		return true
	})

	return b.String()
}
