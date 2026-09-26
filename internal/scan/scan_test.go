// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 noir017

package scan

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/noir017/nasbutler/internal/catalog"
	"github.com/noir017/nasbutler/internal/detect"
	"github.com/noir017/nasbutler/internal/fixture"
	"github.com/noir017/nasbutler/internal/redact"
	"github.com/noir017/nasbutler/internal/rules"
)

type env struct {
	root string
	db   *catalog.DB
	opts Options
}

func setup(t *testing.T) *env {
	t.Helper()
	root := fixture.Build(t)
	db, err := catalog.Open(filepath.Join(t.TempDir(), "catalog.db"), false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	rs, err := rules.Compile(rules.Patterns{Hidden: fixture.Hidden, Opaque: fixture.Opaque})
	if err != nil {
		t.Fatal(err)
	}
	return &env{root: root, db: db, opts: Options{
		Root:       root,
		Rules:      rs,
		Redactor:   redact.New([]byte(strings.Repeat("k", 32))),
		MaxContent: 1 << 20,
		Hash:       true,
	}}
}

func (e *env) scan(t *testing.T) Stats {
	t.Helper()
	st, err := Run(context.Background(), e.db, e.opts)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// byPath maps real relative paths to rows.
func (e *env) byPath(t *testing.T) map[string]catalog.File {
	t.Helper()
	files, _, err := e.db.Query(catalog.Query{Limit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]catalog.File{}
	for _, f := range files {
		m[string(f.Path)] = f
	}
	return m
}

func TestClassification(t *testing.T) {
	e := setup(t)
	st := e.scan(t)
	if st.Opaque != 1 || st.Hidden != 1 || st.Special != 1 {
		t.Errorf("stats = %+v, want 1 opaque, 1 hidden, 1 special (symlink)", st)
	}
	m := e.byPath(t)

	check := func(rel string, level detect.Level, kind string) catalog.File {
		t.Helper()
		f, ok := m[rel]
		if !ok {
			t.Fatalf("%s not cataloged", rel)
		}
		if detect.Level(f.Level) != level || (kind != "" && f.Kind != kind) {
			t.Errorf("%s: level %v kind %s, want %v %s", rel, detect.Level(f.Level), f.Kind, level, kind)
		}
		return f
	}
	check("photos/2024/IMG_20240101_123045.jpg", detect.Normal, "image")
	check("photos/2024/Thumbs.db", detect.Normal, "junk")
	check("docs/empty.txt", detect.Normal, "empty")
	check("docs/notes.md", detect.Normal, "text")
	if f := check("docs/contacts.txt", detect.Personal, "text"); f.Findings["cn_mobile"] != 1 || !f.ContentScanned {
		t.Errorf("contacts findings = %v scanned=%v", f.Findings, f.ContentScanned)
	}
	id := check("docs/ID_"+fixture.CNID+".jpg", detect.Personal, "image")
	if !strings.HasPrefix(id.RPath, "docs/ID_[cn-id#") {
		t.Errorf("id rpath = %q", id.RPath)
	}
	for _, rel := range []string{"docs/api.txt", "app/.env", "vault/renamed.dat"} {
		f := check(rel, detect.Secret, "")
		dir := rel[:strings.LastIndexByte(rel, '/')+1]
		if !strings.HasPrefix(f.RPath, dir+"[secret#") || f.RName != f.RPath[len(dir):] {
			t.Errorf("%s: rpath %q rname %q", rel, f.RPath, f.RName)
		}
	}
	chat := check("Phone Backup/WeChat Files/wxid_"+fixture.SecretName+"/Msg/chat.db", detect.Secret, "")
	parts := strings.Split(chat.RPath, "/")
	if len(parts) != 3 || parts[0] != "Phone Backup" || !strings.HasPrefix(parts[1], "[secret-dir#") || !strings.HasPrefix(parts[2], "[secret#") {
		t.Errorf("secret-dir file rpath = %q, want Phone Backup/[secret-dir#…]/[secret#…]", chat.RPath)
	}
	if chat.Findings != nil {
		t.Errorf("secret-by-path content was read: %v", chat.Findings)
	}
	if f := check("docs/\xd6\xd0\xce\xc4.txt", detect.Normal, "text"); f.RPath != "docs/中文.txt" {
		t.Errorf("GBK name displayed as %q", f.RPath)
	}
	for rel := range m {
		if strings.HasPrefix(rel, "private/") || strings.HasPrefix(rel, "backup/") || rel == "docs/link" {
			t.Errorf("%s must not be cataloged", rel)
		}
	}

	s, err := e.db.Status()
	if err != nil {
		t.Fatal(err)
	}
	if s.OpaqueDirs != 1 || s.OpaqueFiles != 2 || s.ScanInProgress {
		t.Errorf("status = %+v", s)
	}
}

func TestDuplicates(t *testing.T) {
	e := setup(t)
	e.scan(t)
	d, err := e.db.Duplicates("", 1, 10, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if d.GroupCount != 2 {
		t.Fatalf("groups = %+v, want 2 (small jpg pair, big mp4 pair)", d.Groups)
	}
	for _, g := range d.Groups {
		for _, m := range g.Members {
			if strings.Contains(m.Path, "big-diff") {
				t.Errorf("big-diff.mp4 differs only in the middle but was grouped: %+v", g)
			}
		}
	}
	if d.Groups[0].Size != 200<<10 || d.WastedBytes != 200<<10+int64(len("jpeg-bytes-A")) {
		t.Errorf("ordering/wasted wrong: %+v", d)
	}
	// Scoped to a directory that holds one copy of each pair.
	if d, _ := e.db.Duplicates("photos/2024/copy", 1, 10, 0, 10); d.GroupCount != 1 {
		t.Errorf("scoped groups = %d, want 1", d.GroupCount)
	}
}

func TestIncremental(t *testing.T) {
	e := setup(t)
	e.scan(t)

	if st := e.scan(t); st.Reclassified != 0 || st.Removed != 0 {
		t.Fatalf("unchanged rescan reclassified %d, removed %d", st.Reclassified, st.Removed)
	}

	notes := filepath.Join(e.root, "docs", "notes.md")
	if err := os.WriteFile(notes, []byte("now with a@b.cn inside\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	os.Remove(filepath.Join(e.root, "docs", "empty.txt"))
	st := e.scan(t)
	if st.Reclassified != 1 || st.Removed != 1 {
		t.Fatalf("rescan after edit: reclassified %d removed %d, want 1 and 1", st.Reclassified, st.Removed)
	}
	if f := e.byPath(t)["docs/notes.md"]; detect.Level(f.Level) != detect.Personal {
		t.Errorf("edited notes.md level = %v", detect.Level(f.Level))
	}

	// Hiding a directory removes what was cataloged beneath it.
	rs, _ := rules.Compile(rules.Patterns{Hidden: append([]string{"docs"}, fixture.Hidden...), Opaque: fixture.Opaque})
	e.opts.Rules = rs
	e.scan(t)
	for rel := range e.byPath(t) {
		if strings.HasPrefix(rel, "docs/") {
			t.Fatalf("%s still cataloged after docs became hidden", rel)
		}
	}

	// New secret rules reclassify everything.
	rs, _ = rules.Compile(rules.Patterns{Hidden: fixture.Hidden, Opaque: fixture.Opaque, Secret: []string{"photos/2023"}})
	e.opts.Rules = rs
	e.scan(t)
	if f := e.byPath(t)["photos/2023/big.mp4"]; detect.Level(f.Level) != detect.Secret {
		t.Errorf("big.mp4 not secret after rule change: %v", detect.Level(f.Level))
	}
}

func TestNewKeyRedactsAgain(t *testing.T) {
	e := setup(t)
	first := e.scan(t)
	before := e.byPath(t)["docs/ID_"+fixture.CNID+".jpg"].RPath
	e.opts.Redactor = redact.New([]byte(strings.Repeat("z", 32)))
	if st := e.scan(t); st.Reclassified != first.Files {
		t.Fatalf("new key reclassified %d of %d files", st.Reclassified, first.Files)
	}
	if after := e.byPath(t)["docs/ID_"+fixture.CNID+".jpg"].RPath; after == before {
		t.Errorf("rpath kept the old key's pseudonym: %q", after)
	}
}

func TestCancel(t *testing.T) {
	e := setup(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Run(ctx, e.db, e.opts); err == nil {
		t.Fatal("cancelled scan reported success")
	}
	s, _ := e.db.Status()
	if !s.ScanInProgress {
		t.Error("aborted scan not reflected in status")
	}
}
