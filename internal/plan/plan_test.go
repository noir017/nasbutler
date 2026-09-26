// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 noir017

package plan

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/noir017/nasbutler/internal/catalog"
	"github.com/noir017/nasbutler/internal/fixture"
	"github.com/noir017/nasbutler/internal/redact"
	"github.com/noir017/nasbutler/internal/rules"
	"github.com/noir017/nasbutler/internal/scan"
)

type env struct {
	root string
	db   *catalog.DB
	v    *Validator
	ids  map[string]int64 // real relative path -> file id
	rel  map[string]string
}

func setup(t *testing.T) *env {
	t.Helper()
	root := fixture.Build(t)
	root, _ = filepath.EvalSymlinks(root)
	// Two directories that display the same: "中文" in UTF-8 and in GBK.
	for rel, data := range map[string]string{"amb/中文/a.txt": "a", "amb/\xd6\xd0\xce\xc4/b.txt": "b", "archive/final/x.txt": "x"} {
		p := filepath.Join(root, rel)
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte(data), 0o644)
	}
	os.Symlink(t.TempDir(), filepath.Join(root, "linkdir"))
	rs, err := rules.Compile(rules.Patterns{Hidden: fixture.Hidden, Opaque: fixture.Opaque, Protected: []string{"/archive/final"}})
	if err != nil {
		t.Fatal(err)
	}
	db, err := catalog.Open(filepath.Join(t.TempDir(), "catalog.db"), false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	red := redact.New([]byte(strings.Repeat("k", 32)))
	if _, err := scan.Run(context.Background(), db, scan.Options{Root: root, Rules: rs, Redactor: red, MaxContent: 1 << 20}); err != nil {
		t.Fatal(err)
	}
	files, _, _ := db.Query(catalog.Query{Limit: 1000})
	e := &env{root: root, db: db, ids: map[string]int64{}, rel: map[string]string{}}
	for _, f := range files {
		e.ids[string(f.Path)] = f.ID
		e.rel[string(f.Path)] = f.RPath
	}
	e.v = &Validator{DB: db, Rules: rs, Root: root, Quarantine: filepath.Join(root, ".nasbutler", "quarantine"), CheckFS: true}
	return e
}

func (e *env) id(t *testing.T, rel string) int64 {
	t.Helper()
	id, ok := e.ids[rel]
	if !ok {
		t.Fatalf("%s not cataloged", rel)
	}
	return id
}

const jpg = "photos/2024/IMG_20240101_123045.jpg"

func TestResolveMoves(t *testing.T) {
	e := setup(t)
	invoiceDir := filepath.Dir(e.rel["clients/"+fixture.Phone+"/invoice.pdf"]) // "clients/[phone#…]"
	ops := []Op{
		{Op: OpMove, File: e.id(t, jpg), ToDir: "sorted/2024"},
		{Op: OpMove, File: e.id(t, "docs/notes.md"), ToDir: invoiceDir, Name: "notes-2024.md"},
		{Op: OpQuarantine, File: e.id(t, "photos/2024/Thumbs.db")},
	}
	rs, errs := e.v.Resolve("p20260926-000001", ops)
	if len(errs) != 0 {
		t.Fatalf("errors: %+v", errs)
	}
	want := []string{
		"sorted/2024/IMG_20240101_123045.jpg",
		"clients/" + fixture.Phone + "/notes-2024.md",
		"[quarantine]/p20260926-000001/photos/2024/Thumbs.db",
	}
	for i, r := range rs {
		if r.ToRel != want[i] {
			t.Errorf("op %d: ToRel = %q, want %q", i, r.ToRel, want[i])
		}
	}
	if rs[2].To != filepath.Join(e.root, ".nasbutler", "quarantine", "p20260926-000001", "photos", "2024", "Thumbs.db") {
		t.Errorf("quarantine To = %q", rs[2].To)
	}
	d1 := Digest("p20260926-000001", KindPlan, rs)
	if d1 != Digest("p20260926-000001", KindPlan, rs) || d1 == Digest("p20260926-000001", KindPlan, rs[:2]) {
		t.Error("digest unstable or insensitive to the operations")
	}
}

func TestResolveRefusals(t *testing.T) {
	e := setup(t)
	secretDir := strings.Split(e.rel["Phone Backup/WeChat Files/wxid_"+fixture.SecretName+"/Msg/chat.db"], "/")[:2]
	cases := []struct {
		name string
		op   Op
		want string
	}{
		{"unknown id", Op{Op: OpMove, File: 999999, ToDir: "x"}, "unknown file id"},
		{"unknown op", Op{Op: "delete", File: e.id(t, jpg)}, "unknown op"},
		{"secret file", Op{Op: OpMove, File: e.id(t, "docs/api.txt"), ToDir: "x"}, "secret files"},
		{"into hidden", Op{Op: OpMove, File: e.id(t, jpg), ToDir: "private"}, "protected, hidden"},
		{"into opaque", Op{Op: OpMove, File: e.id(t, jpg), ToDir: "backup/new"}, "protected, hidden"},
		{"into protected", Op{Op: OpMove, File: e.id(t, jpg), ToDir: "archive/final"}, "protected, hidden"},
		{"into own state dir", Op{Op: OpMove, File: e.id(t, jpg), ToDir: ".nasbutler"}, "protected, hidden"},
		{"into secret dir", Op{Op: OpMove, File: e.id(t, jpg), ToDir: strings.Join(secretDir, "/")}, "protected, hidden"},
		{"from protected", Op{Op: OpMove, File: e.id(t, "archive/final/x.txt"), ToDir: "x"}, "source is in a protected"},
		{"unknown pseudonym", Op{Op: OpMove, File: e.id(t, jpg), ToDir: "clients/[phone#deadbeef]"}, "pseudonym"},
		{"ambiguous dir", Op{Op: OpMove, File: e.id(t, jpg), ToDir: "amb/中文"}, "ambiguous"},
		{"slash in name", Op{Op: OpMove, File: e.id(t, jpg), ToDir: "x", Name: "a/b"}, "slash"},
		{"dot dot", Op{Op: OpMove, File: e.id(t, jpg), ToDir: "x/../..", Name: ""}, "invalid name"},
		{"trailing dot", Op{Op: OpMove, File: e.id(t, jpg), Name: "x."}, "ends with"},
		{"no-op", Op{Op: OpMove, File: e.id(t, jpg), ToDir: "photos/2024"}, "same"},
		{"exists", Op{Op: OpMove, File: e.id(t, "docs/notes.md"), ToDir: "docs", Name: "contacts.txt"}, "already exists"},
		{"through symlink", Op{Op: OpMove, File: e.id(t, jpg), ToDir: "linkdir/sub"}, "blocked by a file or symlink"},
		{"quarantine with dest", Op{Op: OpQuarantine, File: e.id(t, jpg), ToDir: "x"}, "no destination"},
	}
	for _, c := range cases {
		_, errs := e.v.Resolve("p20260926-000002", []Op{c.op})
		if len(errs) != 1 || !strings.Contains(errs[0].Error, c.want) {
			t.Errorf("%s: errors = %+v, want %q", c.name, errs, c.want)
			continue
		}
		for _, bad := range append(fixture.Forbidden(e.root), "WeChat") {
			if strings.Contains(errs[0].Error, bad) {
				t.Errorf("%s: error leaks %q: %s", c.name, bad, errs[0].Error)
			}
		}
	}
}

func TestResolveConflicts(t *testing.T) {
	e := setup(t)
	a, b := e.id(t, jpg), e.id(t, "photos/2024/copy/IMG_20240101_123045.jpg")
	_, errs := e.v.Resolve("p20260926-000003", []Op{
		{Op: OpMove, File: a, ToDir: "sorted"},
		{Op: OpMove, File: b, ToDir: "sorted"}, // same destination
		{Op: OpQuarantine, File: a},            // same file again
		{Op: OpMove, File: e.id(t, "docs/notes.md"), ToDir: "photos/2024/copy", Name: "IMG_20240101_123045.jpg"}, // onto b's source
	})
	if len(errs) != 3 || errs[0].Index != 1 || errs[1].Index != 2 || errs[2].Index != 3 {
		t.Fatalf("conflict errors = %+v", errs)
	}
}

func TestChangedFileRefused(t *testing.T) {
	e := setup(t)
	os.WriteFile(filepath.Join(e.root, "docs", "notes.md"), []byte("edited after the scan"), 0o644)
	_, errs := e.v.Resolve("p20260926-000004", []Op{{Op: OpMove, File: e.id(t, "docs/notes.md"), ToDir: "x"}})
	if len(errs) != 1 || !strings.Contains(errs[0].Error, "changed since the last scan") {
		t.Fatalf("errors = %+v", errs)
	}
	e.v.CheckFS = false // the server's view: catalog only
	if _, errs := e.v.Resolve("p20260926-000004", []Op{{Op: OpMove, File: e.id(t, "docs/notes.md"), ToDir: "x"}}); len(errs) != 0 {
		t.Fatalf("catalog-only validation looked at the filesystem: %+v", errs)
	}
}

func TestStore(t *testing.T) {
	s := Store{Dir: filepath.Join(t.TempDir(), "plans")}
	p, err := s.Create(KindPlan, "tidy", "", Draft)
	if err != nil || !ValidID(p.ID) {
		t.Fatalf("Create = %+v, %v", p, err)
	}
	p.Ops = append(p.Ops, Op{Op: OpMove, File: 1, ToDir: "x"})
	if err := s.Save(p); err != nil {
		t.Fatal(err)
	}
	got, err := s.Load(p.ID)
	if err != nil || len(got.Ops) != 1 || got.Title != "tidy" {
		t.Fatalf("Load = %+v, %v", got, err)
	}
	if st, _ := os.Stat(filepath.Join(s.Dir, p.ID+".json")); st.Mode().Perm() != 0o600 {
		t.Errorf("plan file mode %v", st.Mode().Perm())
	}
	if _, err := s.LoadStatus(p.ID); err != ErrNotFound {
		t.Errorf("LoadStatus before the executor = %v", err)
	}
	s.SaveStatus(&Status{ID: p.ID, State: Done})
	if list, _ := s.List(); len(list) != 1 {
		t.Errorf("List = %d plans (status files must not count)", len(list))
	}
	for _, bad := range []string{"../etc/passwd", "p1", "p20260926-XYZ123", ""} {
		if _, err := s.Load(bad); err == nil || err == ErrNotFound {
			t.Errorf("Load(%q) = %v, want invalid id", bad, err)
		}
	}
}
