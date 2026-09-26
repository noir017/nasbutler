// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 noir017

// Package approval puts plans in front of a human and brings back their
// decision. Approval is enforced by the executor, never by the MCP client:
// agents often run with confirmations switched off.
package approval

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Line is one operation as a human reviews it.
type Line struct {
	Op   string `json:"op"`
	From string `json:"from"`
	To   string `json:"to"`
}

// Summary is everything an approver shows about a plan.
type Summary struct {
	PlanID  string    `json:"plan_id"`
	Digest  string    `json:"digest"`
	Kind    string    `json:"kind"` // "plan" or "undo"
	Target  string    `json:"target,omitempty"`
	Title   string    `json:"title"`
	Lines   []Line    `json:"lines"`
	Bytes   int64     `json:"bytes"`
	Expires time.Time `json:"expires"`
}

// Ticket identifies a delivered approval request.
type Ticket struct {
	PlanID string `json:"plan_id"`
	Ref    string `json:"ref,omitempty"` // approver-specific, e.g. a message id
}

// Decision is a human's answer. Digest must match the plan's current
// digest for the executor to accept it.
type Decision struct {
	PlanID  string `json:"plan_id"`
	Digest  string `json:"digest"`
	Approve bool   `json:"approve"`
	By      string `json:"by"`
}

// Outcome is what happened after a decision, for the approver to show.
type Outcome struct {
	State  string `json:"state"`
	Done   int    `json:"done"`
	Failed int    `json:"failed"`
	Total  int    `json:"total"`
	Note   string `json:"note,omitempty"`
}

// Approver is one way of asking a human.
type Approver interface {
	// Name is used in configuration and logs, e.g. "feishu".
	Name() string
	// Run delivers decisions to decide until ctx ends. decide returns an
	// error when the executor refuses a decision (expired, plan changed);
	// approvers should show it to whoever made the decision.
	Run(ctx context.Context, decide func(context.Context, Decision) error) error
	// Request asks for a decision on a plan.
	Request(ctx context.Context, s Summary) (Ticket, error)
	// Update shows how a plan ended up (executing, done, rejected, …).
	Update(ctx context.Context, t Ticket, s Summary, o Outcome) error
}

// Local takes decisions from files that `nasbutler plan approve|reject`
// writes on the machine itself. It needs no network and no credentials,
// and serves tests and setups without Feishu.
type Local struct {
	Dir  string        // decision drop directory, inside the executor's state
	Poll time.Duration // defaults to one second
	Log  func(msg string, args ...any)
}

func (l *Local) Name() string { return "local" }

func (l *Local) log(msg string, args ...any) {
	if l.Log != nil {
		l.Log(msg, args...)
	}
}

// Request only logs: the human is expected to run the CLI.
func (l *Local) Request(_ context.Context, s Summary) (Ticket, error) {
	l.log("approval requested; run `nasbutler plan show "+s.PlanID+"` then `nasbutler plan approve "+s.PlanID+"`",
		"plan", s.PlanID, "ops", len(s.Lines))
	return Ticket{PlanID: s.PlanID}, nil
}

// Update only logs.
func (l *Local) Update(_ context.Context, t Ticket, _ Summary, o Outcome) error {
	l.log("plan "+o.State, "plan", t.PlanID, "done", o.Done, "failed", o.Failed, "note", o.Note)
	return nil
}

// Run consumes decision files as they appear.
func (l *Local) Run(ctx context.Context, decide func(context.Context, Decision) error) error {
	poll := l.Poll
	if poll == 0 {
		poll = time.Second
	}
	if err := os.MkdirAll(l.Dir, 0o700); err != nil {
		return err
	}
	t := time.NewTicker(poll)
	defer t.Stop()
	for {
		entries, err := os.ReadDir(l.Dir)
		if err != nil {
			return err
		}
		for _, e := range entries {
			if !strings.HasSuffix(e.Name(), ".json") {
				continue
			}
			p := filepath.Join(l.Dir, e.Name())
			b, err := os.ReadFile(p)
			os.Remove(p) // one decision per file, consumed exactly once
			var d Decision
			if err != nil || json.Unmarshal(b, &d) != nil {
				l.log("ignoring unreadable decision file", "file", e.Name())
				continue
			}
			if err := decide(ctx, d); err != nil {
				l.log("decision refused", "plan", d.PlanID, "err", err)
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

// WriteDecision drops a decision for a Local approver to pick up.
func WriteDecision(dir string, d Decision) error {
	if d.PlanID == "" || strings.ContainsAny(d.PlanID, `/\`) {
		return errors.New("invalid plan id")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(d)
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, "."+d.PlanID+".tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, d.PlanID+".json"))
}
