// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 noir017

// Package executor is the only part of nasbutler that changes files.
//
// It picks up plans the server has submitted, re-resolves and re-validates
// them itself, asks a human through an approval.Approver, and executes
// approved plans one operation at a time with a write-ahead journal, so
// every completed operation can be undone. It never deletes: the only
// deletion in nasbutler is Purge, which a human runs by hand.
//
// Its state directory holds real paths and must not be writable by the
// agent-facing server.
package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/noir017/nasbutler/internal/approval"
	"github.com/noir017/nasbutler/internal/catalog"
	"github.com/noir017/nasbutler/internal/fsx"
	"github.com/noir017/nasbutler/internal/plan"
	"github.com/noir017/nasbutler/internal/rules"
)

// Options configures an Engine.
type Options struct {
	Root       string // resolved absolute root
	Quarantine string // absolute quarantine directory
	PlansDir   string // written by the server; read here
	Dir        string // this engine's own state
	DB         *catalog.DB
	Rules      *rules.Set
	Approver   approval.Approver
	TTL        time.Duration // how long an approval request stays valid
	MaxOps     int
	// Rescan, if set, runs after a plan changed files so that agents see
	// the new layout.
	Rescan func(context.Context) error
	Poll   time.Duration
	Log    *slog.Logger
}

// Record is the executor's view of a plan. It holds real paths.
type Record struct {
	ID        string          `json:"id"`
	Kind      string          `json:"kind"`
	Target    string          `json:"target,omitempty"`
	Title     string          `json:"title"`
	State     plan.State      `json:"state"`
	Digest    string          `json:"digest,omitempty"`
	Ops       []plan.Resolved `json:"ops"`
	Ticket    approval.Ticket `json:"ticket"`
	Requested time.Time       `json:"requested"`
	Expires   time.Time       `json:"expires,omitzero"`
	Decided   time.Time       `json:"decided,omitzero"`
	DecidedBy string          `json:"decided_by,omitempty"`
	Finished  time.Time       `json:"finished,omitzero"`
	Done      int             `json:"done"`
	Failed    int             `json:"failed"`
	Errors    []plan.OpError  `json:"errors,omitempty"`
	Note      string          `json:"note,omitempty"`
	// RemoveDirs are directories a plan created, emptied again by its undo.
	RemoveDirs []string `json:"remove_dirs,omitempty"`
}

// Engine runs the executor.
type Engine struct {
	o     Options
	store plan.Store
	val   *plan.Validator
	mu    sync.Mutex // serialises record state transitions
	annMu sync.Mutex // serialises announcements, so the last one wins
	bg    sync.WaitGroup
	wake  chan struct{}
}

// New prepares the state directory.
func New(o Options) (*Engine, error) {
	if o.Poll == 0 {
		o.Poll = 2 * time.Second
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	for _, d := range []string{recordsDir(o.Dir), journalDir(o.Dir)} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, err
		}
	}
	return &Engine{
		o:     o,
		store: plan.Store{Dir: o.PlansDir},
		val:   &plan.Validator{DB: o.DB, Rules: o.Rules, Root: o.Root, Quarantine: o.Quarantine, CheckFS: true},
		wake:  make(chan struct{}, 1),
	}, nil
}

func recordsDir(dir string) string { return filepath.Join(dir, "plans") }
func journalDir(dir string) string { return filepath.Join(dir, "journal") }

// DecisionsDir is where a Local approver looks for decision files.
func DecisionsDir(dir string) string { return filepath.Join(dir, "decisions") }

// LoadRecord reads one record from an executor state directory.
func LoadRecord(dir, id string) (*Record, error) {
	if !plan.ValidID(id) {
		return nil, fmt.Errorf("invalid plan id %q", id)
	}
	b, err := os.ReadFile(filepath.Join(recordsDir(dir), id+".json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, plan.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	r := &Record{}
	return r, json.Unmarshal(b, r)
}

// ListRecords returns all records, oldest request first.
func ListRecords(dir string) ([]*Record, error) {
	entries, err := os.ReadDir(recordsDir(dir))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []*Record
	for _, e := range entries {
		id, ok := cutSuffix(e.Name(), ".json")
		if !ok || !plan.ValidID(id) {
			continue
		}
		if r, err := LoadRecord(dir, id); err == nil {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Requested.Before(out[j].Requested) })
	return out, nil
}

func cutSuffix(s, suffix string) (string, bool) {
	if len(s) < len(suffix) || s[len(s)-len(suffix):] != suffix {
		return s, false
	}
	return s[:len(s)-len(suffix)], true
}

func (e *Engine) save(r *Record) error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return plan.WriteFileAtomic(filepath.Join(recordsDir(e.o.Dir), r.ID+".json"), b)
}

// Run executes until ctx ends: it recovers interrupted plans, runs the
// approver, takes in submissions, expires stale requests and executes
// approved plans one at a time.
func (e *Engine) Run(ctx context.Context) error {
	if err := e.recover(ctx); err != nil {
		return err
	}
	approverDone := make(chan error, 1)
	go func() { approverDone <- e.o.Approver.Run(ctx, e.Decide) }()
	workerDone := make(chan struct{})
	go func() { e.worker(ctx); close(workerDone) }()
	defer func() {
		<-workerDone
		e.bg.Wait()
	}()

	t := time.NewTicker(e.o.Poll)
	defer t.Stop()
	for {
		e.Tick(ctx)
		select {
		case <-ctx.Done():
			return nil
		case err := <-approverDone:
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("approver %s stopped: %v", e.o.Approver.Name(), err)
		case <-t.C:
		}
	}
}

// Tick takes in new submissions and expires stale approval requests.
func (e *Engine) Tick(ctx context.Context) {
	plans, err := e.store.List()
	if err != nil {
		e.o.Log.Error("listing plans", "err", err)
	}
	for _, p := range plans {
		if p.State != plan.Submitted {
			continue
		}
		if _, err := LoadRecord(e.o.Dir, p.ID); err == nil {
			continue // already taken in
		}
		e.admit(ctx, p)
	}
	e.expire(ctx)
}

// admit validates a submission and, if it holds up, asks for approval.
func (e *Engine) admit(ctx context.Context, p *plan.Plan) {
	now := time.Now()
	r := &Record{ID: p.ID, Kind: p.Kind, Target: p.Target, Title: p.Title, Requested: now}
	var errs []plan.OpError
	switch p.Kind {
	case plan.KindPlan:
		switch {
		case len(p.Ops) == 0:
			errs = []plan.OpError{{Index: -1, Error: "the plan has no operations"}}
		case len(p.Ops) > e.o.MaxOps:
			errs = []plan.OpError{{Index: -1, Error: fmt.Sprintf("the plan has %d operations; the limit is %d", len(p.Ops), e.o.MaxOps)}}
		default:
			r.Ops, errs = e.val.Resolve(p.ID, p.Ops)
		}
	case plan.KindUndo:
		errs = e.undoOps(r)
	default:
		errs = []plan.OpError{{Index: -1, Error: "unknown plan kind"}}
	}
	e.mu.Lock()
	if len(errs) > 0 {
		r.State, r.Errors, r.Finished = plan.Failed, errs, now
		r.Note = "validation failed; nothing was changed"
		e.saveLocked(r)
		e.mu.Unlock()
		e.publish(r)
		return
	}
	r.Digest = plan.Digest(r.ID, r.Kind, r.Ops)
	r.State, r.Expires = plan.PendingApproval, now.Add(e.o.TTL)
	e.saveLocked(r) // before the request goes out: a quick click must find it
	e.mu.Unlock()
	e.publish(r)

	t, err := e.o.Approver.Request(ctx, e.summary(r))
	e.mu.Lock()
	defer e.mu.Unlock()
	cur, lerr := LoadRecord(e.o.Dir, r.ID)
	if lerr != nil {
		cur = r
	}
	if err != nil {
		e.o.Log.Error("approval request failed", "plan", r.ID, "err", err)
		if cur.State == plan.PendingApproval {
			cur.State, cur.Finished = plan.Failed, time.Now()
			cur.Note = "could not reach the approver; nothing was changed"
		}
	}
	cur.Ticket = t
	e.saveLocked(cur)
	if err != nil {
		e.publish(cur)
	}
}

func (e *Engine) saveLocked(r *Record) {
	if err := e.save(r); err != nil {
		e.o.Log.Error("saving plan record", "plan", r.ID, "err", err)
	}
}

// Decide applies a human's decision. It is called by the approver, often
// from a callback that must answer within seconds, so execution happens
// later on the worker.
func (e *Engine) Decide(ctx context.Context, d approval.Decision) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	r, err := LoadRecord(e.o.Dir, d.PlanID)
	if err != nil {
		return errors.New("unknown plan")
	}
	switch {
	case r.State != plan.PendingApproval:
		return fmt.Errorf("the plan is already %s", r.State)
	case time.Now().After(r.Expires):
		return errors.New("the approval request has expired")
	case d.Digest != r.Digest:
		return errors.New("the plan changed after this request was sent")
	}
	r.Decided, r.DecidedBy = time.Now(), d.By
	if d.Approve {
		r.State = plan.Approved
	} else {
		r.State, r.Finished = plan.Rejected, time.Now()
	}
	if err := e.save(r); err != nil {
		return errors.New("could not record the decision")
	}
	e.o.Log.Info("decision recorded", "plan", r.ID, "approved", d.Approve)
	e.bg.Add(1)
	go func() {
		defer e.bg.Done()
		e.announce(r.ID)
	}()
	if d.Approve {
		select {
		case e.wake <- struct{}{}:
		default:
		}
	}
	return nil
}

func (e *Engine) worker(ctx context.Context) {
	for {
		for ctx.Err() == nil {
			id := e.nextApproved()
			if id == "" {
				break
			}
			e.execute(ctx, id)
		}
		select {
		case <-ctx.Done():
			return
		case <-e.wake:
		case <-time.After(e.o.Poll):
		}
	}
}

func (e *Engine) nextApproved() string {
	recs, _ := ListRecords(e.o.Dir)
	for _, r := range recs {
		if r.State == plan.Approved {
			return r.ID
		}
	}
	return ""
}

func (e *Engine) expire(ctx context.Context) {
	recs, _ := ListRecords(e.o.Dir)
	for _, r := range recs {
		if r.State != plan.PendingApproval || time.Now().Before(r.Expires) {
			continue
		}
		e.mu.Lock()
		cur, err := LoadRecord(e.o.Dir, r.ID)
		if err != nil || cur.State != plan.PendingApproval {
			e.mu.Unlock()
			continue
		}
		cur.State, cur.Finished = plan.Expired, time.Now()
		e.saveLocked(cur)
		e.mu.Unlock()
		e.announce(cur.ID)
	}
}

// summary is what the approver shows. Paths are real (relative to the
// root) and decoded for display.
func (e *Engine) summary(r *Record) approval.Summary {
	s := approval.Summary{PlanID: r.ID, Digest: r.Digest, Kind: r.Kind, Target: r.Target, Title: r.Title, Expires: r.Expires}
	for _, op := range r.Ops {
		s.Lines = append(s.Lines, approval.Line{Op: op.Op, From: fsx.DisplayPath(op.FromRel), To: fsx.DisplayPath(op.ToRel)})
		s.Bytes += op.Size
	}
	return s
}

// announce reports a plan's current state to the server (and through it
// the agent) and to the approver. Announcements are serialised and always
// read the record afresh, so a slow announcement of an earlier state can
// never overwrite a later one.
func (e *Engine) announce(id string) {
	e.annMu.Lock()
	defer e.annMu.Unlock()
	r, err := LoadRecord(e.o.Dir, id)
	if err != nil {
		e.o.Log.Error("loading plan record", "plan", id, "err", err)
		return
	}
	e.publish(r)
	if r.Ticket.PlanID == "" {
		return // no approval request went out
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	o := approval.Outcome{State: string(r.State), Done: r.Done, Failed: r.Failed, Total: len(r.Ops), Note: r.Note}
	if err := e.o.Approver.Update(ctx, r.Ticket, e.summary(r), o); err != nil {
		e.o.Log.Warn("updating the approval message failed", "plan", id, "err", err)
	}
}

// publish writes the status file the server relays to agents. It carries
// counts and generic messages only.
func (e *Engine) publish(r *Record) {
	st := &plan.Status{ID: r.ID, State: r.State, Updated: time.Now(), Total: len(r.Ops),
		Done: r.Done, Failed: r.Failed, Errors: r.Errors, Note: r.Note}
	if err := e.store.SaveStatus(st); err != nil {
		e.o.Log.Error("publishing plan status", "plan", r.ID, "err", err)
	}
}
