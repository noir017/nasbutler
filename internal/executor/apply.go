// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 noir017

package executor

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/noir017/nasbutler/internal/fsx"
	"github.com/noir017/nasbutler/internal/plan"
)

// entry is one journal line. Journals are append-only and synced after
// every line, so after a crash they say exactly which operations happened.
type entry struct {
	I     int    `json:"i"` // position in Record.Ops
	Event string `json:"event"`
	From  string `json:"from,omitempty"`
	To    string `json:"to,omitempty"`
	Dir   string `json:"dir,omitempty"`
	Inode int64  `json:"inode,omitempty"`
	Err   string `json:"err,omitempty"`
}

// Journal events.
const (
	evMkdir = "mkdir"
	evBegin = "begin"
	evDone  = "done"
	evFail  = "fail"
)

type journal struct{ f *os.File }

func journalPath(dir, id string) string { return filepath.Join(journalDir(dir), id+".jsonl") }

func openJournal(dir, id string) (*journal, error) {
	f, err := os.OpenFile(journalPath(dir, id), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	return &journal{f}, nil
}

func (j *journal) add(e entry) error {
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if _, err := j.f.Write(append(b, '\n')); err != nil {
		return err
	}
	return j.f.Sync()
}

func (j *journal) Close() error { return j.f.Close() }

func readJournal(dir, id string) ([]entry, error) {
	f, err := os.Open(journalPath(dir, id))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []entry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		var e entry
		if json.Unmarshal(sc.Bytes(), &e) == nil { // a torn last line is ignored
			out = append(out, e)
		}
	}
	return out, sc.Err()
}

// safeError carries a message that is fit for agents as it is.
type safeError struct{ error }

// describe turns an execution error into a message without paths.
func describe(err error) string {
	var s safeError
	switch {
	case errors.As(err, &s):
		return s.Error()
	case errors.Is(err, fs.ErrExist):
		return "the destination appeared just before the move; nothing was overwritten"
	case errors.Is(err, syscall.EXDEV):
		return "the destination is on a different filesystem; nothing is ever copied"
	case errors.Is(err, fs.ErrPermission):
		return "permission denied"
	}
	return "the move failed (details are in the executor log)"
}

func (e *Engine) execute(ctx context.Context, id string) {
	e.mu.Lock()
	r, err := LoadRecord(e.o.Dir, id)
	if err != nil || r.State != plan.Approved {
		e.mu.Unlock()
		return
	}
	r.State = plan.Executing
	e.saveLocked(r)
	e.mu.Unlock()
	e.announce(id)
	e.o.Log.Info("executing plan", "plan", id, "ops", len(r.Ops))

	j, err := openJournal(e.o.Dir, id)
	if err != nil {
		e.o.Log.Error("opening journal", "plan", id, "err", err)
		r.Note = "the journal could not be opened; nothing was changed"
	} else {
		for i, op := range r.Ops {
			if ctx.Err() != nil {
				r.Note = "stopped by shutdown; completed operations can be undone"
				break
			}
			if err := e.apply(j, i, op); err != nil {
				e.o.Log.Error("operation failed", "plan", id, "op", op.Index, "err", err)
				r.Failed++
				r.Errors = append(r.Errors, plan.OpError{Index: op.Index, Error: describe(err)})
				r.Note = "stopped at the first failure; completed operations can be undone"
				break
			}
			r.Done++
		}
		j.Close()
	}
	if r.Done == len(r.Ops) {
		r.State = plan.Done
		for _, d := range r.RemoveDirs {
			os.Remove(d) // an undo's leftover directories; Remove only takes empty ones
		}
	} else {
		r.State = plan.Failed
	}
	r.Finished = time.Now()
	if r.Done > 0 && e.o.Rescan != nil {
		if err := e.o.Rescan(ctx); err != nil {
			e.o.Log.Warn("rescan after execution failed", "plan", id, "err", err)
			r.Note = strings.TrimPrefix(r.Note+"; the catalog is stale until the next scan", "; ")
		}
	}
	e.mu.Lock()
	e.saveLocked(r)
	e.mu.Unlock()
	e.announce(id)
	e.o.Log.Info("plan finished", "plan", id, "state", r.State, "done", r.Done, "failed", r.Failed)
}

// apply performs one operation: recheck, create missing directories,
// journal, rename without replacing, journal.
func (e *Engine) apply(j *journal, i int, op plan.Resolved) error {
	if err := e.val.Recheck(op); err != nil {
		return safeError{err}
	}
	var missing []string
	for d := filepath.Dir(op.To); d != filepath.Dir(d); d = filepath.Dir(d) {
		if _, err := os.Lstat(d); err == nil {
			break
		} else if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		missing = append(missing, d)
	}
	for k := len(missing) - 1; k >= 0; k-- {
		if err := j.add(entry{I: i, Event: evMkdir, Dir: missing[k]}); err != nil {
			return err
		}
		if err := os.Mkdir(missing[k], 0o755); err != nil && !errors.Is(err, fs.ErrExist) {
			return err
		}
	}
	if err := j.add(entry{I: i, Event: evBegin, From: op.From, To: op.To, Inode: op.Inode}); err != nil {
		return err
	}
	if err := fsx.RenameNoReplace(op.From, op.To); err != nil {
		j.add(entry{I: i, Event: evFail, Err: err.Error()})
		return err
	}
	return j.add(entry{I: i, Event: evDone})
}

// undoOps fills an undo record with the reverse of every operation its
// target completed, newest first, after checking each file is still the
// one that was moved and its original place is free.
func (e *Engine) undoOps(r *Record) []plan.OpError {
	fail := func(msg string) []plan.OpError { return []plan.OpError{{Index: -1, Error: msg}} }
	t, err := LoadRecord(e.o.Dir, r.Target)
	if err != nil {
		return fail("the plan to undo is unknown to the executor")
	}
	if t.Kind != plan.KindPlan {
		return fail("an undo cannot itself be undone; make a new plan instead")
	}
	if t.State != plan.Done && t.State != plan.Failed {
		return fail("only executed plans can be undone")
	}
	recs, _ := ListRecords(e.o.Dir)
	for _, o := range recs {
		if o.Kind == plan.KindUndo && o.Target == t.ID && o.ID != r.ID && (o.State == plan.Done || !o.State.Finished()) {
			return fail("this plan has already been undone, or an undo is pending")
		}
	}
	if r.Title == "" {
		r.Title = "undo: " + t.Title
	}
	entries, err := readJournal(e.o.Dir, t.ID)
	if err != nil {
		return fail("the plan's journal cannot be read")
	}
	begin := map[int]entry{}
	var done []int
	var dirs []string
	for _, en := range entries {
		switch en.Event {
		case evBegin:
			begin[en.I] = en
		case evDone:
			if _, ok := begin[en.I]; ok && en.I < len(t.Ops) {
				done = append(done, en.I)
			}
		case evMkdir:
			dirs = append(dirs, en.Dir)
		}
	}
	if len(done) == 0 {
		return fail("nothing to undo: the plan completed no operations")
	}
	var errs []plan.OpError
	for k := len(done) - 1; k >= 0; k-- {
		idx := len(done) - 1 - k
		b, orig := begin[done[k]], t.Ops[done[k]]
		op := plan.Resolved{Index: idx, Op: plan.OpRestore, FileID: orig.FileID,
			From: b.To, To: b.From, FromRel: orig.ToRel, ToRel: orig.FromRel}
		st, err := os.Lstat(op.From)
		if err != nil || !st.Mode().IsRegular() || fsx.Inode(st) != b.Inode {
			errs = append(errs, plan.OpError{Index: idx, Error: "a moved file has since been changed, moved or removed, so it cannot be restored"})
			continue
		}
		op.Size, op.MTime, op.Inode = st.Size(), st.ModTime().UnixNano(), fsx.Inode(st)
		if err := e.val.Recheck(op); err != nil {
			errs = append(errs, plan.OpError{Index: idx, Error: err.Error()})
			continue
		}
		r.Ops = append(r.Ops, op)
	}
	for k := len(dirs) - 1; k >= 0; k-- {
		r.RemoveDirs = append(r.RemoveDirs, dirs[k])
	}
	return errs
}

// recover settles plans that were executing when the executor stopped.
// Each operation is a single rename, so it either happened or it did not;
// the disk says which. Such plans end as failed, never resumed: a human
// or agent decides what happens next.
func (e *Engine) recover(ctx context.Context) error {
	recs, err := ListRecords(e.o.Dir)
	if err != nil {
		return err
	}
	for _, r := range recs {
		if r.State != plan.Executing {
			continue
		}
		entries, err := readJournal(e.o.Dir, r.ID)
		if err != nil {
			return err
		}
		begun := map[int]entry{}
		ended := map[int]string{}
		for _, en := range entries {
			switch en.Event {
			case evBegin:
				begun[en.I] = en
			case evDone, evFail:
				ended[en.I] = en.Event
			}
		}
		j, err := openJournal(e.o.Dir, r.ID)
		if err != nil {
			return err
		}
		for i, b := range begun {
			if _, ok := ended[i]; ok {
				continue
			}
			to, errTo := os.Lstat(b.To)
			if errTo == nil && fsx.Inode(to) == b.Inode {
				// Moved. A link+unlink fallback may have left the old
				// name behind as a second link to the same inode.
				if from, err := os.Lstat(b.From); err == nil && fsx.Inode(from) == b.Inode {
					os.Remove(b.From)
				}
				ended[i] = evDone
			} else {
				ended[i] = evFail
			}
			j.add(entry{I: i, Event: ended[i], Err: "interrupted"})
		}
		j.Close()
		r.Done, r.Failed = 0, 0
		for _, ev := range ended {
			if ev == evDone {
				r.Done++
			} else {
				r.Failed++
			}
		}
		r.State, r.Finished = plan.Failed, time.Now()
		r.Note = "interrupted: the executor stopped during this plan; completed operations can be undone"
		e.mu.Lock()
		e.saveLocked(r)
		e.mu.Unlock()
		e.announce(r.ID)
		e.o.Log.Warn("recovered an interrupted plan", "plan", r.ID, "done", r.Done, "failed", r.Failed)
	}
	return nil
}
