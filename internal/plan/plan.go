// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 noir017

// Package plan holds reorganisation plans: what an agent proposes, how it
// is checked, and where plans live on disk.
//
// A plan only ever moves files (a rename is a move within one directory)
// or moves them into quarantine. There is no delete operation.
//
// Plans are written by the agent-facing server into the plans directory
// and read by the executor, which trusts nothing in them beyond the list
// of requested operations: it resolves and validates every operation
// again itself, and computes the digest that approvals are bound to.
package plan

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Operation kinds.
const (
	OpMove       = "move"
	OpQuarantine = "quarantine"
	// OpRestore only appears in undo plans built by the executor.
	OpRestore = "restore"
)

// Plan kinds.
const (
	KindPlan = "plan"
	KindUndo = "undo"
)

// State is a plan's lifecycle state. Drafts and submissions are recorded
// by the server; everything after submission by the executor.
type State string

const (
	Draft           State = "draft"
	Submitted       State = "submitted"
	PendingApproval State = "pending_approval"
	Approved        State = "approved"
	Executing       State = "executing"
	Done            State = "done"
	Failed          State = "failed"
	Rejected        State = "rejected"
	Expired         State = "expired"
)

// Finished reports whether no further transition can happen.
func (s State) Finished() bool {
	return s == Done || s == Failed || s == Rejected || s == Expired
}

// Op is one requested operation, in the agent's terms: a file id and a
// redacted destination directory.
type Op struct {
	Op    string `json:"op" jsonschema:"move or quarantine"`
	File  int64  `json:"file" jsonschema:"file id from an earlier result"`
	ToDir string `json:"to_dir,omitempty" jsonschema:"move only: destination directory as a redacted path; pseudonym segments must name existing directories, other segments are created as needed; empty means the root"`
	Name  string `json:"name,omitempty" jsonschema:"move only: new file name; empty keeps the current name"`
}

// Plan is a plan as stored in the plans directory.
type Plan struct {
	ID      string    `json:"id"`
	Kind    string    `json:"kind"`
	Target  string    `json:"target,omitempty"` // the plan an undo plan reverts
	Title   string    `json:"title"`
	Created time.Time `json:"created"`
	State   State     `json:"state"`
	Ops     []Op      `json:"ops"`
}

// OpError reports why one operation was refused. Messages never contain
// real paths: they are shown to agents.
type OpError struct {
	Index int    `json:"index"`
	Error string `json:"error"`
}

// Status is what the executor publishes about a submitted plan, for the
// server to relay to agents. It carries counts and generic messages only.
type Status struct {
	ID      string    `json:"id"`
	State   State     `json:"state"`
	Updated time.Time `json:"updated"`
	Total   int       `json:"total"`
	Done    int       `json:"done"`
	Failed  int       `json:"failed"`
	Errors  []OpError `json:"errors,omitempty"`
	Note    string    `json:"note,omitempty"`
}

var idPattern = regexp.MustCompile(`^p[0-9]{8}-[0-9a-f]{6}$`)

// ValidID reports whether id is a well-formed plan id. Ids become file
// names, so anything else is refused before it touches the filesystem.
func ValidID(id string) bool { return idPattern.MatchString(id) }

// NewID returns a fresh plan id such as "p20260926-7f3a1c".
func NewID(now time.Time) string {
	b := make([]byte, 3)
	rand.Read(b)
	return "p" + now.Format("20060102") + "-" + hex.EncodeToString(b)
}

// ErrNotFound is returned for unknown plan ids.
var ErrNotFound = errors.New("plan not found")

// Store is a directory of plan files: <id>.json for the plan and
// <id>.status.json for what the executor reports about it.
type Store struct{ Dir string }

func (s Store) path(id, suffix string) (string, error) {
	if !ValidID(id) {
		return "", fmt.Errorf("invalid plan id %q", id)
	}
	return filepath.Join(s.Dir, id+suffix), nil
}

// Create starts a new plan of the given kind in state st.
func (s Store) Create(kind, title, target string, st State) (*Plan, error) {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return nil, err
	}
	now := time.Now()
	p := &Plan{ID: NewID(now), Kind: kind, Target: target, Title: title, Created: now, State: st, Ops: []Op{}}
	return p, s.Save(p)
}

// Load reads a plan.
func (s Store) Load(id string) (*Plan, error) {
	p := &Plan{}
	if err := s.read(id, ".json", p); err != nil {
		return nil, err
	}
	return p, nil
}

// Save writes a plan atomically.
func (s Store) Save(p *Plan) error { return s.write(p.ID, ".json", p) }

// Delete removes a plan file.
func (s Store) Delete(id string) error {
	p, err := s.path(id, ".json")
	if err != nil {
		return err
	}
	return os.Remove(p)
}

// LoadStatus reads the executor's status for a plan; ErrNotFound if the
// executor has not picked the plan up yet.
func (s Store) LoadStatus(id string) (*Status, error) {
	st := &Status{}
	if err := s.read(id, ".status.json", st); err != nil {
		return nil, err
	}
	return st, nil
}

// SaveStatus writes a plan's status atomically.
func (s Store) SaveStatus(st *Status) error { return s.write(st.ID, ".status.json", st) }

// List returns all plans, newest first.
func (s Store) List() ([]*Plan, error) {
	entries, err := os.ReadDir(s.Dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []*Plan
	for _, e := range entries {
		id, ok := strings.CutSuffix(e.Name(), ".json")
		if !ok || !ValidID(id) {
			continue // status files and strays
		}
		if p, err := s.Load(id); err == nil {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.After(out[j].Created) })
	return out, nil
}

func (s Store) read(id, suffix string, v any) error {
	p, err := s.path(id, suffix)
	if err != nil {
		return err
	}
	b, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func (s Store) write(id, suffix string, v any) error {
	p, err := s.path(id, suffix)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return WriteFileAtomic(p, b)
}

// WriteFileAtomic writes data to a temporary file, syncs it and renames it
// into place, so readers never see a half-written file.
func WriteFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
