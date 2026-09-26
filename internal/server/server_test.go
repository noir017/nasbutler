// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 noir017

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/noir017/nasbutler/internal/catalog"
	"github.com/noir017/nasbutler/internal/fixture"
	"github.com/noir017/nasbutler/internal/redact"
	"github.com/noir017/nasbutler/internal/rules"
	"github.com/noir017/nasbutler/internal/scan"
)

type harness struct {
	t      *testing.T
	root   string
	ms     *mcp.Server
	cs     *mcp.ClientSession
	audit  *bytes.Buffer
	outs   []string
	errors int
}

func newHarness(t *testing.T, maxBytes int) *harness {
	t.Helper()
	root := fixture.Build(t)
	root, _ = filepath.EvalSymlinks(root)
	dbPath := filepath.Join(t.TempDir(), "catalog.db")
	red := redact.New([]byte(strings.Repeat("k", 32)))
	rs, err := rules.Compile(rules.Patterns{Hidden: fixture.Hidden, Opaque: fixture.Opaque})
	if err != nil {
		t.Fatal(err)
	}
	wdb, err := catalog.Open(dbPath, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := scan.Run(context.Background(), wdb, scan.Options{Root: root, Rules: rs, Redactor: red, MaxContent: 1 << 20, Hash: true}); err != nil {
		t.Fatal(err)
	}
	wdb.Close()
	db, err := catalog.Open(dbPath, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	h := &harness{t: t, root: root, audit: &bytes.Buffer{}}
	h.ms = New(Options{DB: db, Redactor: red, Root: root, Audit: h.audit, MaxResultBytes: maxBytes, MaxLimit: 200, FFprobe: "", Version: "test"})
	return h
}

func (h *harness) connect() {
	h.t.Helper()
	ctx := context.Background()
	st, ct := mcp.NewInMemoryTransports()
	if _, err := h.ms.Connect(ctx, st, nil); err != nil {
		h.t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "v0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { cs.Close() })
	h.cs = cs
}

// call invokes a tool and decodes its JSON text result into out (if not
// nil). It returns whether the tool reported an error.
func (h *harness) call(name string, args map[string]any, out any) (isError bool, text string) {
	h.t.Helper()
	res, err := h.cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		h.t.Fatalf("%s: %v", name, err)
	}
	for _, c := range res.Content {
		text += c.(*mcp.TextContent).Text
	}
	if sc, err := json.Marshal(res.StructuredContent); err == nil {
		h.outs = append(h.outs, string(sc))
	}
	h.outs = append(h.outs, text)
	if res.IsError {
		h.errors++
		return true, text
	}
	if out != nil {
		if err := json.Unmarshal([]byte(text), out); err != nil {
			h.t.Fatalf("%s: decoding %q: %v", name, text, err)
		}
	}
	return false, text
}

func (h *harness) assertNoLeaks() {
	h.t.Helper()
	all := strings.Join(h.outs, "\n") + h.audit.String()
	for _, bad := range fixture.Forbidden(h.root) {
		if strings.Contains(all, bad) {
			h.t.Errorf("output contains forbidden value %q", bad)
		}
	}
}

func entryNames(s catalog.Survey) map[string]catalog.Entry {
	m := map[string]catalog.Entry{}
	for _, e := range s.Entries {
		m[e.Name] = e
	}
	return m
}

func TestToolsNeverLeak(t *testing.T) {
	h := newHarness(t, 64<<10)
	h.connect()

	var st StatusOut
	h.call("status", nil, &st)
	if st.Files == 0 || st.SecretFiles < 4 || st.OpaqueDirs != 1 || !strings.Contains(st.Mode, "metadata-only") {
		t.Errorf("status = %+v", st)
	}

	var root catalog.Survey
	h.call("survey", map[string]any{}, &root)
	names := entryNames(root)
	for _, want := range []string{"photos", "docs", "app", "vault", "Phone Backup", "backup"} {
		if _, ok := names[want]; !ok {
			t.Errorf("root survey lacks %q: %v", want, names)
		}
	}
	if !names["backup"].Opaque || names["backup"].Files != 2 {
		t.Errorf("backup entry = %+v, want opaque with 2 files", names["backup"])
	}
	if _, ok := names["private"]; ok {
		t.Error("hidden directory listed")
	}

	var opaque catalog.Survey
	h.call("survey", map[string]any{"dir": "backup"}, &opaque)
	if !opaque.Opaque || len(opaque.Entries) != 0 {
		t.Errorf("opaque survey = %+v", opaque)
	}
	if isErr, _ := h.call("survey", map[string]any{"dir": "private"}, nil); !isErr {
		t.Error("hidden directory surveyable")
	}

	var phone catalog.Survey
	h.call("survey", map[string]any{"dir": "Phone Backup"}, &phone)
	if len(phone.Entries) != 1 || !strings.HasPrefix(phone.Entries[0].Name, "[secret-dir#") || phone.Entries[0].Secret != 1 {
		t.Fatalf("Phone Backup survey = %+v", phone.Entries)
	}
	var inside catalog.Survey
	h.call("survey", map[string]any{"dir": "Phone Backup/" + phone.Entries[0].Name}, &inside)
	if len(inside.Entries) != 1 || inside.Entries[0].Dir || !strings.HasPrefix(inside.Entries[0].Name, "[secret#") {
		t.Errorf("secret dir contents = %+v", inside.Entries)
	}

	var secrets QueryOut
	h.call("query", map[string]any{"level": "secret", "limit": 100}, &secrets)
	if secrets.Total != 4 {
		t.Errorf("secret files = %d, want 4", secrets.Total)
	}
	for _, f := range secrets.Files {
		if f.Ext != "" || !strings.Contains(f.Path, "[secret") {
			t.Errorf("secret file exposed: %+v", f)
		}
	}
	var byExt QueryOut
	h.call("query", map[string]any{"exts": []string{"env", "dat"}}, &byExt)
	if byExt.Total != 0 {
		t.Errorf("extension filter found secret files: %+v", byExt.Files)
	}
	var probing QueryOut
	h.call("query", map[string]any{"name_contains": fixture.CNID[:10]}, &probing)
	if probing.Total != 0 {
		t.Error("name filter matched against the unredacted name")
	}
	var videos QueryOut
	h.call("query", map[string]any{"kinds": []string{"video"}, "sort": "size", "desc": true}, &videos)
	if videos.Total != 3 {
		t.Fatalf("videos = %+v", videos)
	}

	var ins InspectOut
	h.call("inspect", map[string]any{"id": videos.Files[0].ID}, &ins)
	if ins.MediaNote == "" {
		t.Error("expected a media note without ffprobe")
	}
	if len(ins.SameContent) != 1 && !strings.Contains(ins.File.Path, "diff") {
		t.Errorf("same_content = %+v for %s", ins.SameContent, ins.File.Path)
	}
	var sec InspectOut
	h.call("inspect", map[string]any{"id": secrets.Files[0].ID}, &sec)
	if sec.Media != nil || sec.MediaNote != "not probed: secret file" && sec.MediaNote != "" {
		t.Errorf("secret file inspect = %+v", sec)
	}
	if isErr, _ := h.call("inspect", map[string]any{"id": 999999}, nil); !isErr {
		t.Error("unknown id accepted")
	}

	var dups catalog.Duplicates
	h.call("duplicates", map[string]any{}, &dups)
	if dups.GroupCount != 2 {
		t.Errorf("duplicate groups = %d", dups.GroupCount)
	}

	var exts ExtensionsOut
	h.call("extensions", map[string]any{}, &exts)
	for _, e := range exts.Extensions {
		// Thumbs.db is ordinary junk; the secret chat.db would be "database".
		if e.Ext == "env" || e.Ext == "dat" || (e.Ext == "db" && e.Kind != "junk") {
			t.Errorf("extensions include a secret file's extension: %+v", e)
		}
	}

	var sens catalog.Sensitive
	h.call("sensitive_report", map[string]any{}, &sens)
	if sens.Total.Personal < 2 || sens.Total.Secret != 4 || sens.Total.Findings["cn_mobile"] != 1 {
		t.Errorf("sensitive report = %+v", sens.Total)
	}

	h.assertNoLeaks()
	if lines := strings.Count(h.audit.String(), "\n"); lines != len(h.outs)/2 {
		t.Errorf("audit has %d lines for %d calls", lines, len(h.outs)/2)
	}
}

// A tool that forgets to redact must still not leak: the egress filter
// catches it and records the late redaction.
func TestEgressCatchesLeaks(t *testing.T) {
	h := newHarness(t, 64<<10)
	type out struct {
		Note string `json:"note"`
	}
	mcp.AddTool(h.ms, &mcp.Tool{Name: "leaky"}, func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, out, error) {
		return nil, out{Note: "call " + fixture.Phone + " about " + fixture.SKToken}, nil
	})
	mcp.AddTool(h.ms, &mcp.Tool{Name: "leaky_error"}, func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, out, error) {
		return nil, out{}, &json.UnsupportedValueError{Str: "id " + fixture.CNID}
	})
	h.connect()
	h.call("leaky", nil, nil)
	h.call("leaky_error", nil, nil)
	h.assertNoLeaks()
	if !strings.Contains(h.audit.String(), `"late_redactions":`) {
		t.Error("late redaction not recorded in the audit log")
	}
	if !strings.Contains(strings.Join(h.outs, ""), "[phone#") {
		t.Error("leaked value was dropped instead of pseudonymised")
	}
}

func TestResultSizeCap(t *testing.T) {
	h := newHarness(t, 300)
	h.connect()
	isErr, text := h.call("survey", map[string]any{}, nil)
	if !isErr || !strings.Contains(text, "too large") {
		t.Fatalf("oversized result not refused: %v %q", isErr, text)
	}
}

func TestRequireToken(t *testing.T) {
	token := strings.Repeat("t", 32)
	h := RequireToken(token, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) }))
	for _, c := range []struct {
		header string
		want   int
	}{
		{"", http.StatusUnauthorized},
		{"Bearer wrong", http.StatusUnauthorized},
		{"bearer " + token, http.StatusUnauthorized},
		{"Bearer " + token, http.StatusTeapot},
	} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/mcp", nil)
		if c.header != "" {
			req.Header.Set("Authorization", c.header)
		}
		h.ServeHTTP(rec, req)
		if rec.Code != c.want {
			t.Errorf("Authorization %q: status %d, want %d", c.header, rec.Code, c.want)
		}
	}
}

func TestServeHTTPRejectsShortToken(t *testing.T) {
	if err := ServeHTTP(context.Background(), nil, "127.0.0.1:0", "short", nil); err == nil {
		t.Fatal("short token accepted")
	}
}
