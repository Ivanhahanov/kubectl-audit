package triage

// Store abstracts where a triage State's bytes actually live — a local
// file (FileStore, the only option before the server existed) or a central
// kubectl-audit-server instance (ServerStore, see serverstore.go). Every
// other part of this package (Merge, GroupKey, State's own methods) is
// unchanged either way: a Store only decides how State is loaded/saved, it
// never changes what State means or how it's mutated in memory. `--triage-
// server` on the CLI selects ServerStore; omitting it keeps today's
// FileStore behavior exactly as it always was — running the TUI/export/
// jira-sync without a server is still fully supported, permanently.
type Store interface {
	Load() (*State, error)
	Save(*State) error
	// Label describes where this Store persists state, for display only
	// (e.g. the TUI's header) — a file path or a server URL.
	Label() string
}

// FileStore is the original, file-based Store: a thin wrapper around
// LoadState/SaveState so call sites can depend on the Store interface
// uniformly instead of branching on "do we have a server configured."
type FileStore struct {
	Path string
}

func (f FileStore) Load() (*State, error) { return LoadState(f.Path) }
func (f FileStore) Save(s *State) error   { return SaveState(f.Path, s) }
func (f FileStore) Label() string         { return f.Path }
