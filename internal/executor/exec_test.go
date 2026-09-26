// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 noir017

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/noir017/nasbutler/internal/approval"
	"github.com/noir017/nasbutler/internal/catalog"
	"github.com/noir017/nasbutler/internal/fixture"
	"github.com/noir017/nasbutler/internal/plan"
	"github.com/noir017/nasbutler/internal/redact"
	"github.com/noir017/nasbutler/internal/rules"
	"github.com/noir017/nasbutler/internal/scan"
	"github.com/noir017/nasbutler/internal/server"
)

// world is a whole deployment in one process: catalog, MCP server with
// plan tools, executor with a local approver.
type world struct {
	t       *testing.T
	root    string
	store   plan.Store
	execDir string
	eng     *Engine
	cs      *mcp.ClientSession
	audit   bytes.Buffer
	outs    []string
	ids     map[string]int64  // real relative path -> id
	rpaths  map[string]string // real relative path -> redacted path
	wdb     *catalog.DB
}

func newWorld(t *testing.T, ttl time.Duration) *world {
	t.Helper()
	root := fixture.Build(t)
	root, _ = filepath.EvalSymlinks(root)
	state := t.TempDir()
	rs, err := rules.Compile(rules.Patterns{Hidden: fixture.Hidden, Opaque: fixture.Opaque})
	if err != nil {
		t.Fatal(err)
	}
	red := redact.New([]byte(strings.Repeat("k", 32)))
	dbPath := filepath.Join(state, "catalog.db")
	wdb, err := catalog.Open(dbPath, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { wdb.Close() })
	scanOpts := scan.Options{Root: root, Rules: rs, Redactor: red, MaxContent: 1 << 20}
	if _, err := scan.Run(context.Background(), wdb, scanOpts); err != nil {
		t.Fatal(err)
	}
	rdb, err := catalog.Open(dbPath, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rdb.Close() })

	w := &world{t: t, root: root, store: plan.Store{Dir: filepath.Join(state, "plans")}, execDir: filepath.Join(state, "exec"), wdb: wdb}
	quarantine := filepath.Join(root, rules.StateDir, "quarantine")
	ms := server.New(server.Options{
		DB: rdb, Redactor: red, Root: root, Audit: &w.audit, MaxResultBytes: 64 << 10, MaxLimit: 200, Version: "test",
		Plans:     w.store,
		Validator: &plan.Validator{DB: rdb, Rules: rs, Root: root, Quarantine: quarantine},
		MaxOps:    100,
	})
	st, ct := mcp.NewInMemoryTransports()
	if _, err := ms.Connect(context.Background(), st, nil); err != nil {
		t.Fatal(err)
	}
	if w.cs, err = mcp.NewClient(&mcp.Implementation{Name: "test", Version: "v0"}, nil).Connect(context.Background(), ct, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { w.cs.Close() })

	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	w.eng, err = New(Options{
		Root: root, Quarantine: quarantine, PlansDir: w.store.Dir, Dir: w.execDir, DB: wdb, Rules: rs,
		Approver: &approval.Local{Dir: DecisionsDir(w.execDir), Poll: 10 * time.Millisecond},
		TTL:      ttl, MaxOps: 100, Poll: 10 * time.Millisecond, Log: quiet,
		Rescan: func(ctx context.Context) error {
			_, err := scan.Run(ctx, wdb, scanOpts)
			return err
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	w.index()
	return w
}

func (w *world) index() {
	files, _, _ := w.wdb.Query(catalog.Query{Limit: 1000})
	w.ids, w.rpaths = map[string]int64{}, map[string]string{}
	for _, f := range files {
		w.ids[string(f.Path)] = f.ID
		w.rpaths[string(f.Path)] = f.RPath
	}
}

func (w *world) start() {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { w.eng.Run(ctx); close(done) }()
	w.t.Cleanup(func() { cancel(); <-done })
}

func (w *world) call(name string, args map[string]any, out any) (isError bool, text string) {
	w.t.Helper()
	res, err := w.cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		w.t.Fatalf("%s: %v", name, err)
	}
	for _, c := range res.Content {
		text += c.(*mcp.TextContent).Text
	}
	w.outs = append(w.outs, text)
	if !res.IsError && out != nil {
		if err := json.Unmarshal([]byte(text), out); err != nil {
			w.t.Fatalf("%s: %v in %s", name, err, text)
		}
	}
	return res.IsError, text
}

func (w *world) waitState(id string, want plan.State) *plan.Status {
	w.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if st, err := w.store.LoadStatus(id); err == nil && st.State == want {
			return st
		}
		time.Sleep(10 * time.Millisecond)
	}
	st, _ := w.store.LoadStatus(id)
	w.t.Fatalf("plan %s did not reach %s; status %+v", id, want, st)
	return nil
}

func (w *world) decide(id string, approve bool) {
	w.t.Helper()
	r, err := LoadRecord(w.execDir, id)
	if err != nil {
		w.t.Fatal(err)
	}
	if err := approval.WriteDecision(DecisionsDir(w.execDir), approval.Decision{PlanID: id, Digest: r.Digest, Approve: approve, By: "test"}); err != nil {
		w.t.Fatal(err)
	}
}

func (w *world) exists(rel string) bool {
	_, err := os.Lstat(filepath.Join(w.root, filepath.FromSlash(rel)))
	return err == nil
}

func (w *world) assertNoLeaks() {
	w.t.Helper()
	all := strings.Join(w.outs, "\n") + w.audit.String()
	for _, bad := range fixture.Forbidden(w.root) {
		if strings.Contains(all, bad) {
			w.t.Errorf("agent-visible output contains %q", bad)
		}
	}
}

const jpg = "photos/2024/IMG_20240101_123045.jpg"

func TestPlanLifecycle(t *testing.T) {
	w := newWorld(t, time.Hour)
	w.start()
	clientsDir := filepath.Dir(w.rpaths["clients/"+fixture.Phone+"/invoice.pdf"])

	var created server.PlanView
	w.call("plan_create", map[string]any{"title": "tidy photos"}, &created)
	var added server.PlanAddOut
	w.call("plan_add", map[string]any{"plan_id": created.ID, "ops": []map[string]any{
		{"op": "move", "file": w.ids[jpg], "to_dir": "sorted/2024"},
		{"op": "quarantine", "file": w.ids["photos/2024/Thumbs.db"]},
		{"op": "move", "file": w.ids["docs/notes.md"], "to_dir": clientsDir, "name": "notes.md"},
		{"op": "move", "file": w.ids["docs/api.txt"], "to_dir": "x"}, // secret: refused
	}}, &added)
	if added.Accepted != 3 || len(added.Rejected) != 1 || added.Rejected[0].Index != 3 {
		t.Fatalf("plan_add = %+v", added)
	}
	var shown server.PlanView
	w.call("plan_show", map[string]any{"plan_id": created.ID}, &shown)
	if len(shown.Ops) != 3 || shown.Ops[2].To != clientsDir+"/notes.md" || len(shown.Issues) != 0 {
		t.Fatalf("plan_show = %+v", shown)
	}

	w.call("plan_submit", map[string]any{"plan_id": created.ID}, nil)
	if isErr, _ := w.call("plan_add", map[string]any{"plan_id": created.ID, "ops": []map[string]any{}}, nil); !isErr {
		t.Error("a submitted plan accepted changes")
	}
	w.waitState(created.ID, plan.PendingApproval)
	if w.exists("sorted") {
		t.Fatal("files moved before approval")
	}
	if err := w.eng.Decide(context.Background(), approval.Decision{PlanID: created.ID, Digest: "forged", Approve: true}); err == nil {
		t.Fatal("a decision with the wrong digest was accepted")
	}

	w.decide(created.ID, true)
	st := w.waitState(created.ID, plan.Done)
	if st.Done != 3 || st.Failed != 0 {
		t.Fatalf("status = %+v", st)
	}
	if err := w.eng.Decide(context.Background(), approval.Decision{PlanID: created.ID, Digest: "x", Approve: true}); err == nil {
		t.Fatal("a second decision was accepted")
	}
	for rel, want := range map[string]bool{
		jpg: false, "sorted/2024/IMG_20240101_123045.jpg": true,
		"photos/2024/Thumbs.db": false, ".nasbutler/quarantine/" + created.ID + "/photos/2024/Thumbs.db": true,
		"docs/notes.md": false, "clients/" + fixture.Phone + "/notes.md": true,
	} {
		if w.exists(rel) != want {
			t.Errorf("%s exists = %v, want %v", rel, !want, want)
		}
	}
	// The executor rescanned: the agent sees the new layout.
	var sorted catalog.Survey
	if isErr, text := w.call("survey", map[string]any{"dir": "sorted/2024"}, &sorted); isErr || sorted.Total.Files != 1 {
		t.Fatalf("survey after execution: %s", text)
	}

	var undo server.PlanView
	w.call("undo_request", map[string]any{"plan_id": created.ID}, &undo)
	w.waitState(undo.ID, plan.PendingApproval)
	w.decide(undo.ID, true)
	if st := w.waitState(undo.ID, plan.Done); st.Done != 3 {
		t.Fatalf("undo status = %+v", st)
	}
	for _, rel := range []string{jpg, "photos/2024/Thumbs.db", "docs/notes.md"} {
		if !w.exists(rel) {
			t.Errorf("%s not restored", rel)
		}
	}
	for _, rel := range []string{"sorted", ".nasbutler", "clients/" + fixture.Phone + "/notes.md"} {
		if w.exists(rel) {
			t.Errorf("%s left behind after undo", rel)
		}
	}
	if isErr, _ := w.call("undo_request", map[string]any{"plan_id": undo.ID}, nil); !isErr {
		t.Error("an undo of an undo was accepted")
	}
	var again server.PlanView
	w.call("undo_request", map[string]any{"plan_id": created.ID}, &again)
	if st := w.waitState(again.ID, plan.Failed); !strings.Contains(st.Errors[0].Error, "already been undone") {
		t.Errorf("second undo: %+v", st)
	}

	var list server.PlanListOut
	w.call("plan_list", nil, &list)
	if len(list.Plans) != 3 {
		t.Errorf("plan_list = %d plans", len(list.Plans))
	}
	w.assertNoLeaks()

	// The card and the journal, unlike the agent, see real paths.
	r, _ := LoadRecord(w.execDir, created.ID)
	if !strings.Contains(w.eng.summary(r).Lines[2].To, fixture.Phone) {
		t.Error("the approver should see real paths")
	}
}

func TestRejectAndExpire(t *testing.T) {
	w := newWorld(t, time.Minute)
	w.start()
	submit := func() string {
		var p server.PlanView
		w.call("plan_create", map[string]any{"title": "t"}, &p)
		w.call("plan_add", map[string]any{"plan_id": p.ID, "ops": []map[string]any{{"op": "move", "file": w.ids[jpg], "to_dir": "elsewhere"}}}, nil)
		w.call("plan_submit", map[string]any{"plan_id": p.ID}, nil)
		w.waitState(p.ID, plan.PendingApproval)
		return p.ID
	}
	rejected := submit()
	w.decide(rejected, false)
	w.waitState(rejected, plan.Rejected)
	if !w.exists(jpg) {
		t.Fatal("a rejected plan moved files")
	}

	stale := submit()
	r, _ := LoadRecord(w.execDir, stale)
	r.Expires = time.Now().Add(-time.Second)
	w.eng.save(r)
	w.waitState(stale, plan.Expired)
	if err := w.eng.Decide(context.Background(), approval.Decision{PlanID: stale, Digest: r.Digest, Approve: true}); err == nil {
		t.Fatal("an expired plan was approved")
	}
}

func TestFilesChangedAfterSubmission(t *testing.T) {
	w := newWorld(t, time.Hour)
	w.start()
	var p server.PlanView
	w.call("plan_create", map[string]any{"title": "t"}, &p)
	w.call("plan_add", map[string]any{"plan_id": p.ID, "ops": []map[string]any{
		{"op": "move", "file": w.ids["docs/notes.md"], "to_dir": "a"},
		{"op": "move", "file": w.ids[jpg], "to_dir": "a"},
	}}, nil)
	w.call("plan_submit", map[string]any{"plan_id": p.ID}, nil)
	w.waitState(p.ID, plan.PendingApproval)
	// Someone edits the second file before the approval comes in.
	os.WriteFile(filepath.Join(w.root, jpg), []byte("edited"), 0o644)
	w.decide(p.ID, true)
	st := w.waitState(p.ID, plan.Failed)
	if st.Done != 1 || st.Failed != 1 || !strings.Contains(st.Errors[0].Error, "changed since the last scan") {
		t.Fatalf("status = %+v", st)
	}
	if got, _ := os.ReadFile(filepath.Join(w.root, jpg)); string(got) != "edited" {
		t.Fatal("the edited file was touched")
	}
}

func TestRecoverInterruptedPlan(t *testing.T) {
	w := newWorld(t, time.Hour)
	rs, errs := w.eng.val.Resolve("p20260926-aaaaaa", []plan.Op{
		{Op: plan.OpMove, File: w.ids["docs/notes.md"], ToDir: "moved"},
		{Op: plan.OpMove, File: w.ids[jpg], ToDir: "moved"},
	})
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	r := &Record{ID: "p20260926-aaaaaa", Kind: plan.KindPlan, State: plan.Executing, Ops: rs, Requested: time.Now()}
	w.eng.save(r)
	// Simulate a crash after the first rename, before its "done" line.
	j, _ := openJournal(w.execDir, r.ID)
	os.Mkdir(filepath.Join(w.root, "moved"), 0o755)
	j.add(entry{I: 0, Event: evBegin, From: rs[0].From, To: rs[0].To, Inode: rs[0].Inode})
	os.Rename(rs[0].From, rs[0].To)
	j.add(entry{I: 1, Event: evBegin, From: rs[1].From, To: rs[1].To, Inode: rs[1].Inode}) // never happened
	j.Close()

	if err := w.eng.recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, _ := LoadRecord(w.execDir, r.ID)
	if got.State != plan.Failed || got.Done != 1 || got.Failed != 1 || !strings.Contains(got.Note, "interrupted") {
		t.Fatalf("recovered record = %+v", got)
	}
}

func TestPurge(t *testing.T) {
	w := newWorld(t, time.Hour)
	w.start()
	var p server.PlanView
	w.call("plan_create", map[string]any{"title": "junk"}, &p)
	w.call("plan_add", map[string]any{"plan_id": p.ID, "ops": []map[string]any{{"op": "quarantine", "file": w.ids["photos/2024/Thumbs.db"]}}}, nil)
	w.call("plan_submit", map[string]any{"plan_id": p.ID}, nil)
	w.waitState(p.ID, plan.PendingApproval)
	w.decide(p.ID, true)
	w.waitState(p.ID, plan.Done)

	q := filepath.Join(w.root, rules.StateDir, "quarantine")
	os.MkdirAll(filepath.Join(q, "not-a-plan"), 0o755) // unknown directories are never touched
	if got, _ := Purge(w.execDir, q, time.Hour, false); len(got) != 0 {
		t.Fatal("purged a plan younger than the cutoff")
	}
	got, err := Purge(w.execDir, q, 0, true)
	if err != nil || len(got) != 1 || got[0].Files != 1 || !w.exists(".nasbutler/quarantine/"+p.ID) {
		t.Fatalf("dry run = %+v, %v", got, err)
	}
	if got, _ := Purge(w.execDir, q, 0, false); len(got) != 1 || w.exists(".nasbutler/quarantine/"+p.ID) {
		t.Fatal("purge did not remove the quarantine directory")
	}
	if !w.exists(".nasbutler/quarantine/not-a-plan") {
		t.Fatal("purge removed a directory that is not a plan")
	}
	if _, err := Purge(w.execDir, "/", 0, false); err == nil {
		t.Fatal("purge accepted /")
	}
}
