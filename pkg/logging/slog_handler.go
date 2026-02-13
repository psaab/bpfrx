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
}

// NewSyslogSlogHandler wraps a base slog.Handler with syslog forwarding.
func NewSyslogSlogHandler(base slog.Handler) *SyslogSlogHandler {
	return &SyslogSlogHandler{base: base}
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
	// Always forward to the base handler (stderr)
	err := h.base.Handle(ctx, r)

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
		base:    h.base.WithAttrs(attrs),
		clients: h.clients,
		attrs:   append(append([]slog.Attr{}, h.attrs...), attrs...),
		groups:  h.groups,
	}
}

// WithGroup implements slog.Handler.
func (h *SyslogSlogHandler) WithGroup(name string) slog.Handler {
	return &SyslogSlogHandler{
		base:    h.base.WithGroup(name),
		clients: h.clients,
		attrs:   h.attrs,
		groups:  append(append([]string{}, h.groups...), name),
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
