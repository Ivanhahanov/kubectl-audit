// Package logging provides this tool's one CLI-facing diagnostic logger,
// built on the standard library's log/slog rather than a third-party
// logging dependency. It renders as plain, single-line "warning: .../
// debug: ..." text — this is a CLI tool's stderr stream for a human
// running it interactively, not a server's structured log aggregation
// target, so slog's default timestamp/level=/key=value text format would
// be noise here. slog's leveling and Logger API are still used as-is:
// only the Handler's rendering is customized.
package logging

import (
	"context"
	"fmt"
	"io"
	"log/slog"
)

// New returns a logger that writes to w. Debug-level records are dropped
// entirely unless verbose is true — everything at Warn and above is
// always shown, matching this tool's pre-existing default behavior
// (every warnf call site predates this package and stays visible by
// default).
func New(w io.Writer, verbose bool) *slog.Logger {
	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}
	return slog.New(&handler{w: w, level: level})
}

// handler renders a slog.Record as a single "<prefix><message> key=value
// ...\n" line. Deliberately minimal: no timestamps, no source location,
// no nested groups — this tool has no structured-log consumer today, only
// a person reading a terminal.
type handler struct {
	w     io.Writer
	level slog.Level
	attrs []slog.Attr
}

func (h *handler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level
}

func (h *handler) Handle(_ context.Context, r slog.Record) error {
	msg := levelPrefix(r.Level) + r.Message
	for _, a := range h.attrs {
		msg += formatAttr(a)
	}
	r.Attrs(func(a slog.Attr) bool {
		msg += formatAttr(a)
		return true
	})
	_, err := fmt.Fprintln(h.w, msg)
	return err
}

func (h *handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	merged := make([]slog.Attr, 0, len(h.attrs)+len(attrs))
	merged = append(merged, h.attrs...)
	merged = append(merged, attrs...)
	return &handler{w: h.w, level: h.level, attrs: merged}
}

// WithGroup is a no-op: this handler has no nested-group rendering, and
// nothing in this codebase currently calls Logger.WithGroup.
func (h *handler) WithGroup(string) slog.Handler {
	return h
}

func formatAttr(a slog.Attr) string {
	return fmt.Sprintf(" %s=%v", a.Key, a.Value.Any())
}

func levelPrefix(l slog.Level) string {
	switch {
	case l >= slog.LevelError:
		return "error: "
	case l >= slog.LevelWarn:
		return "warning: "
	case l >= slog.LevelInfo:
		return ""
	default:
		return "debug: "
	}
}
