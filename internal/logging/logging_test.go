package logging_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ivanhahanov/kubectl-audit/internal/logging"
)

func TestNew_DebugHiddenByDefault(t *testing.T) {
	var buf bytes.Buffer
	log := logging.New(&buf, false)

	log.Debug("resolved version", "group", "cilium.io")
	log.Warn("skipping resource", "kind", "Widget")

	out := buf.String()
	if strings.Contains(out, "debug:") {
		t.Errorf("expected debug line to be suppressed without verbose, got: %q", out)
	}
	if !strings.Contains(out, "warning: skipping resource kind=Widget") {
		t.Errorf("expected warning line, got: %q", out)
	}
}

func TestNew_DebugShownWhenVerbose(t *testing.T) {
	var buf bytes.Buffer
	log := logging.New(&buf, true)

	log.Debug("resolved version", "group", "cilium.io")

	out := buf.String()
	if !strings.Contains(out, "debug: resolved version group=cilium.io") {
		t.Errorf("expected debug line with verbose enabled, got: %q", out)
	}
}

func TestNew_ErrorPrefix(t *testing.T) {
	var buf bytes.Buffer
	log := logging.New(&buf, false)

	log.Error("fetch failed", "err", "boom")

	if got := buf.String(); !strings.Contains(got, "error: fetch failed err=boom") {
		t.Errorf("expected error-prefixed line, got: %q", got)
	}
}

func TestNew_WithAttrsCarriedAcrossCalls(t *testing.T) {
	var buf bytes.Buffer
	log := logging.New(&buf, false).With("source", "loader")

	log.Warn("skipping resource")

	if got := buf.String(); !strings.Contains(got, "warning: skipping resource source=loader") {
		t.Errorf("expected With()-bound attr on the line, got: %q", got)
	}
}
