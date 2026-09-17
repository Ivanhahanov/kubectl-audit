package triage

import (
	"path/filepath"
	"testing"
	"time"
)

func TestFileStore_RoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "triage-state.yaml")
	store := FileStore{Path: path}

	state, err := store.Load()
	if err != nil {
		t.Fatalf("Load (missing file): %v", err)
	}
	if len(state.Entries) != 0 {
		t.Fatalf("expected an empty State for a missing file, got %+v", state.Entries)
	}

	state.Entries["f1"] = Entry{FindingID: "f1", Status: StatusConfirmed, LastUpdated: time.Now()}
	if err := store.Save(state); err != nil {
		t.Fatalf("Save: %v", err)
	}

	reloaded, err := store.Load()
	if err != nil {
		t.Fatalf("Load (after save): %v", err)
	}
	if reloaded.Entries["f1"].Status != StatusConfirmed {
		t.Errorf("Status = %q, want confirmed", reloaded.Entries["f1"].Status)
	}
	if store.Label() != path {
		t.Errorf("Label() = %q, want %q", store.Label(), path)
	}
}
