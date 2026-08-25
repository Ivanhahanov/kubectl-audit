// Package triage implements the expert triage workflow on top of a scan's
// findings.json: joining findings with a persisted decision (confirmed /
// false positive / won't fix / ...), grouping near-duplicate findings for
// bulk action, and exporting the confirmed subset — including to Jira. See
// docs/triage.md.
package triage

import (
	"fmt"
	"os"
	"time"

	"sigs.k8s.io/yaml"

	"github.com/ivanhahanov/kubectl-audit/internal/findings"
)

// Status is a triage decision. The zero value (StatusNew) is never written
// to disk — an Entry only exists in State once a human has actually looked
// at the finding (or Merge has determined it's Resolved); a finding nobody
// has triaged yet simply has no Entry at all.
type Status string

const (
	StatusNew           Status = "new"
	StatusConfirmed     Status = "confirmed"
	StatusFalsePositive Status = "false_positive"
	StatusWontFix       Status = "wont_fix"
	StatusDuplicate     Status = "duplicate"
	StatusNeedsInfo     Status = "needs_info"
	// StatusResolved is computed by Merge, never set directly by a human:
	// the finding's ID was in a prior State but is no longer produced by
	// the latest scan, meaning the underlying issue was fixed (or the
	// resource was deleted). Surfaced instead of silently dropping the
	// row, so a triager can see what got fixed since the last review.
	StatusResolved Status = "resolved"
)

// ValidHumanStatuses are the statuses a human can set via the TUI/CLI —
// excludes StatusNew (the implicit default, never persisted) and
// StatusResolved (computed only).
var ValidHumanStatuses = map[Status]bool{
	StatusConfirmed:     true,
	StatusFalsePositive: true,
	StatusWontFix:       true,
	StatusDuplicate:     true,
	StatusNeedsInfo:     true,
}

// Entry is one finding's triage record. PolicyID/Resource/Title are a
// snapshot taken when the entry was first created — kept so a finding that
// later disappears (see StatusResolved) can still be rendered without
// needing the original, no-longer-produced findings.Finding.
type Entry struct {
	FindingID    string               `json:"findingId"`
	PolicyID     string               `json:"policyId"`
	Resource     findings.ResourceRef `json:"resource"`
	Title        string               `json:"title"`
	Status       Status               `json:"status"`
	Note         string               `json:"note,omitempty"`
	Tags         []string             `json:"tags,omitempty"`
	JiraIssueKey string               `json:"jiraIssueKey,omitempty"`
	JiraIssueURL string               `json:"jiraIssueUrl,omitempty"`
	Reviewer     string               `json:"reviewer,omitempty"`
	FirstSeen    time.Time            `json:"firstSeen"`
	LastUpdated  time.Time            `json:"lastUpdated"`
}

// State is the full triage record for one findings.json, persisted as a
// local YAML file (git-diffable, reviewable in a PR — see docs/triage.md)
// keyed by Finding.ID, which is a stable content hash (policy + resource
// identity, see findings.NewID) so state survives across re-scans as long
// as the same policy keeps producing the same finding.
type State struct {
	Entries map[string]Entry `json:"entries"`
}

// LoadState reads a triage state file. A missing file is not an error —
// it's simply an empty, fresh State (the common case: the first time
// `kubectl audit triage` runs against a given findings.json).
func LoadState(path string) (*State, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &State{Entries: map[string]Entry{}}, nil
		}
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	var s State
	if err := yaml.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	if s.Entries == nil {
		s.Entries = map[string]Entry{}
	}
	return &s, nil
}

// SaveState writes a triage state file as YAML (0o644 — this is a
// non-secret, git-committable artifact, same treatment as audit.yaml).
func SaveState(path string, s *State) error {
	data, err := yaml.Marshal(s)
	if err != nil {
		return fmt.Errorf("marshaling triage state: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}

// SetStatus records a human triage decision for a finding, creating the
// Entry if it doesn't exist yet (from its snapshot fields) or updating an
// existing one. Returns an error if status isn't a valid human-settable
// status (see ValidHumanStatuses) — StatusNew/StatusResolved are never set
// this way.
func (s *State) SetStatus(f findings.Finding, status Status, now time.Time) error {
	if !ValidHumanStatuses[status] {
		return fmt.Errorf("triage: %q is not a status a human can set (see ValidHumanStatuses)", status)
	}
	e, ok := s.Entries[f.ID]
	if !ok {
		e = Entry{
			FindingID: f.ID,
			PolicyID:  f.PolicyID,
			Resource:  f.Resource,
			Title:     f.Title,
			FirstSeen: now,
		}
	}
	e.Status = status
	e.LastUpdated = now
	s.Entries[f.ID] = e
	return nil
}

// ResetStatus reverts a finding's triage decision back to "new" — undoing
// a previous SetStatus (a mis-click, or a bulk action that got applied more
// broadly than intended). Unlike SetStatus, StatusNew is allowed here: this
// is the one legitimate way to persist it, so SetStatus itself can keep
// refusing it (see ValidHumanStatuses) and "new" can keep meaning "nobody
// has decided yet" everywhere else. Creates the Entry if it doesn't exist
// yet, same as SetStatus, so a straight revert on a never-triaged finding
// is a harmless no-op rather than an error.
func (s *State) ResetStatus(f findings.Finding, now time.Time) {
	e := s.entryOrNew(f, now)
	e.Status = StatusNew
	e.LastUpdated = now
	s.Entries[f.ID] = e
}

// SetNote and SetTags mirror SetStatus for the other human-editable
// fields — also create the Entry from f's snapshot if it doesn't exist yet
// (e.g. a triager adds a note before ever setting a status), defaulting a
// freshly created entry's Status to StatusNew (still not persisted-
// meaningful on its own, but keeps the Entry internally consistent rather
// than leaving Status as the Go zero value "").
func (s *State) SetNote(f findings.Finding, note string, now time.Time) {
	e := s.entryOrNew(f, now)
	e.Note = note
	e.LastUpdated = now
	s.Entries[f.ID] = e
}

func (s *State) SetTags(f findings.Finding, tags []string, now time.Time) {
	e := s.entryOrNew(f, now)
	e.Tags = tags
	e.LastUpdated = now
	s.Entries[f.ID] = e
}

func (s *State) entryOrNew(f findings.Finding, now time.Time) Entry {
	e, ok := s.Entries[f.ID]
	if ok {
		return e
	}
	return Entry{
		FindingID: f.ID,
		PolicyID:  f.PolicyID,
		Resource:  f.Resource,
		Title:     f.Title,
		Status:    StatusNew,
		FirstSeen: now,
	}
}
