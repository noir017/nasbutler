// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 noir017

package server

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/noir017/nasbutler/internal/catalog"
	"github.com/noir017/nasbutler/internal/detect"
	"github.com/noir017/nasbutler/internal/probe"
)

// FileOut is a file as agents see it.
type FileOut struct {
	ID             int64          `json:"id"`
	Path           string         `json:"path"`
	Size           int64          `json:"size"`
	Modified       string         `json:"modified"`
	Kind           string         `json:"kind"`
	Ext            string         `json:"ext,omitempty"`
	Level          string         `json:"level"`
	Findings       map[string]int `json:"findings,omitempty"`
	ContentScanned bool           `json:"content_scanned"`
	Unreadable     bool           `json:"unreadable,omitempty"`
}

func fileOut(f catalog.File) FileOut {
	o := FileOut{
		ID:             f.ID,
		Path:           f.RPath,
		Size:           f.Size,
		Modified:       catalog.Timestamp(f.MTime),
		Kind:           f.Kind,
		Level:          detect.Level(f.Level).String(),
		Findings:       f.Findings,
		ContentScanned: f.ContentScanned,
		Unreadable:     f.Unreadable,
	}
	if detect.Level(f.Level) != detect.Secret {
		o.Ext = f.Ext // a secret file's extension is part of what is withheld
	}
	return o
}

func readOnly(title string) *mcp.ToolAnnotations {
	no := false
	return &mcp.ToolAnnotations{Title: title, ReadOnlyHint: true, IdempotentHint: true, DestructiveHint: &no, OpenWorldHint: &no}
}

func (s *Server) limit(n, def int) int {
	if n <= 0 {
		n = def
	}
	if n > s.o.MaxLimit {
		n = s.o.MaxLimit
	}
	return n
}

// notFound turns catalog.ErrNotFound into an agent-friendly error.
func notFound(err error, what string) error {
	if errors.Is(err, catalog.ErrNotFound) {
		return fmt.Errorf("%s not found in the catalog", what)
	}
	return err
}

type StatusIn struct{}

type StatusOut struct {
	*catalog.Status
	Mode           string `json:"mode"`
	Version        string `json:"version"`
	ProbeAvailable bool   `json:"media_probe_available"`
}

type DirIn struct {
	Dir    string `json:"dir,omitempty" jsonschema:"redacted directory path taken from an earlier result; empty means the root"`
	Limit  int    `json:"limit,omitempty" jsonschema:"maximum number of entries to return"`
	Offset int    `json:"offset,omitempty" jsonschema:"number of entries to skip, for paging"`
}

type QueryIn struct {
	Dir            string   `json:"dir,omitempty" jsonschema:"only files below this redacted directory (recursive); empty means everywhere"`
	Kinds          []string `json:"kinds,omitempty" jsonschema:"file kinds: image video audio document text code archive disk_image database executable font junk empty other"`
	Exts           []string `json:"exts,omitempty" jsonschema:"extensions without the dot, e.g. [\"mp4\",\"dav\"]"`
	MinSize        int64    `json:"min_size,omitempty" jsonschema:"minimum size in bytes"`
	MaxSize        int64    `json:"max_size,omitempty" jsonschema:"maximum size in bytes"`
	ModifiedAfter  string   `json:"modified_after,omitempty" jsonschema:"YYYY-MM-DD or RFC 3339, inclusive"`
	ModifiedBefore string   `json:"modified_before,omitempty" jsonschema:"YYYY-MM-DD or RFC 3339, exclusive"`
	Level          string   `json:"level,omitempty" jsonschema:"normal, personal or secret"`
	NameContains   string   `json:"name_contains,omitempty" jsonschema:"substring of the redacted file name (ASCII case-insensitive)"`
	Sort           string   `json:"sort,omitempty" jsonschema:"size, modified or path (default path)"`
	Desc           bool     `json:"desc,omitempty" jsonschema:"sort descending"`
	Limit          int      `json:"limit,omitempty" jsonschema:"maximum number of files to return"`
	Offset         int      `json:"offset,omitempty" jsonschema:"number of files to skip, for paging"`
}

type QueryOut struct {
	Total  int64     `json:"total"`
	Offset int       `json:"offset"`
	Files  []FileOut `json:"files"`
}

type InspectIn struct {
	ID int64 `json:"id" jsonschema:"file id from an earlier result"`
}

type FileRef struct {
	ID   int64  `json:"id"`
	Path string `json:"path"`
}

type InspectOut struct {
	File        FileOut      `json:"file"`
	Media       *probe.Media `json:"media,omitempty"`
	MediaNote   string       `json:"media_note,omitempty"`
	SameContent []FileRef    `json:"same_content,omitempty"`
}

type DuplicatesIn struct {
	Dir     string `json:"dir,omitempty" jsonschema:"only groups with at least one copy below this redacted directory"`
	MinSize int64  `json:"min_size,omitempty" jsonschema:"ignore files smaller than this many bytes (default 1)"`
	Limit   int    `json:"limit,omitempty" jsonschema:"maximum number of groups to return"`
	Offset  int    `json:"offset,omitempty" jsonschema:"number of groups to skip, for paging"`
}

type ExtensionsOut struct {
	Dir        string            `json:"dir"`
	Extensions []catalog.ExtStat `json:"extensions"`
}

func (s *Server) register(ms *mcp.Server) {
	mcp.AddTool(ms, &mcp.Tool{
		Name:        "status",
		Description: "Catalog totals (files, bytes, sensitive and duplicate counts), when the last scan and hash pass ran, and the server mode. Call this first.",
		Annotations: readOnly("Catalog status"),
	}, s.status)
	mcp.AddTool(ms, &mcp.Tool{
		Name:        "survey",
		Description: "List the children of a directory, largest first, with file count, bytes, date range, per-kind totals and sensitive-file counts. Start with an empty dir and drill down.",
		Annotations: readOnly("Survey a directory"),
	}, s.survey)
	mcp.AddTool(ms, &mcp.Tool{
		Name:        "query",
		Description: "Find files by directory, kind, extension, size, modification date, sensitivity level or name substring. Returns one page of files and the total match count.",
		Annotations: readOnly("Query files"),
	}, s.query)
	mcp.AddTool(ms, &mcp.Tool{
		Name:        "inspect",
		Description: "Metadata of one file by id: kind, size, dates, sensitivity findings, identical copies, and for media the container, duration, codecs, resolution and frame rate.",
		Annotations: readOnly("Inspect a file"),
	}, s.inspect)
	mcp.AddTool(ms, &mcp.Tool{
		Name:        "duplicates",
		Description: "Groups of files with identical content, ordered by wasted space. Only complete once a scan's hash pass has finished (see status).",
		Annotations: readOnly("Find duplicates"),
	}, s.duplicates)
	mcp.AddTool(ms, &mcp.Tool{
		Name:        "extensions",
		Description: "Totals by file extension below a directory, largest first. Useful to discover formats such as camera footage (.dav, .264) or disk images. Secret files are not included.",
		Annotations: readOnly("Extension totals"),
	}, s.extensions)
	mcp.AddTool(ms, &mcp.Tool{
		Name:        "sensitive_report",
		Description: "Where personal and secret files are: per child directory, how many files contain each kind of sensitive value, and how many documents were not content-scanned. Never reveals the values or secret names.",
		Annotations: readOnly("Sensitive data report"),
	}, s.sensitive)
}

func (s *Server) status(ctx context.Context, _ *mcp.CallToolRequest, _ StatusIn) (*mcp.CallToolResult, StatusOut, error) {
	st, err := s.o.DB.Status()
	if err != nil {
		return nil, StatusOut{}, err
	}
	return nil, StatusOut{Status: st, Mode: "metadata-only, read-only", Version: s.o.Version, ProbeAvailable: s.probeOK}, nil
}

func (s *Server) survey(ctx context.Context, _ *mcp.CallToolRequest, in DirIn) (*mcp.CallToolResult, *catalog.Survey, error) {
	out, err := s.o.DB.Survey(in.Dir, s.limit(in.Limit, 50), max(in.Offset, 0))
	return nil, out, notFound(err, "directory")
}

func (s *Server) query(ctx context.Context, _ *mcp.CallToolRequest, in QueryIn) (*mcp.CallToolResult, QueryOut, error) {
	q := catalog.Query{
		Dir: in.Dir, Kinds: in.Kinds, Exts: in.Exts, MinSize: in.MinSize, MaxSize: in.MaxSize,
		Level: in.Level, NameContains: in.NameContains, Sort: in.Sort, Desc: in.Desc,
		Limit: s.limit(in.Limit, 50), Offset: max(in.Offset, 0),
	}
	var err error
	if q.After, err = parseDate(in.ModifiedAfter); err != nil {
		return nil, QueryOut{}, err
	}
	if q.Before, err = parseDate(in.ModifiedBefore); err != nil {
		return nil, QueryOut{}, err
	}
	files, total, err := s.o.DB.Query(q)
	if err != nil {
		return nil, QueryOut{}, err
	}
	out := QueryOut{Total: total, Offset: q.Offset, Files: make([]FileOut, 0, len(files))}
	for _, f := range files {
		out.Files = append(out.Files, fileOut(f))
	}
	return nil, out, nil
}

func parseDate(s string) (int64, error) {
	if s == "" {
		return 0, nil
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02"} {
		if t, err := time.ParseInLocation(layout, s, time.Local); err == nil {
			return t.UnixNano(), nil
		}
	}
	return 0, fmt.Errorf("bad date %q: use YYYY-MM-DD or RFC 3339", s)
}

func (s *Server) inspect(ctx context.Context, _ *mcp.CallToolRequest, in InspectIn) (*mcp.CallToolResult, InspectOut, error) {
	f, err := s.o.DB.Get(in.ID)
	if err != nil {
		return nil, InspectOut{}, notFound(err, "file id")
	}
	out := InspectOut{File: fileOut(f)}
	same, err := s.o.DB.SameContent(f.ID, 20)
	if err != nil {
		return nil, InspectOut{}, err
	}
	for _, x := range same {
		out.SameContent = append(out.SameContent, FileRef{ID: x.ID, Path: x.RPath})
	}
	switch {
	case detect.Level(f.Level) == detect.Secret:
		out.MediaNote = "not probed: secret file"
	case f.Kind != "video" && f.Kind != "audio" && f.Kind != "image":
	case !s.probeOK:
		out.MediaNote = "not probed: ffprobe unavailable"
	default:
		if abs, err := s.resolve(f); err != nil {
			out.MediaNote = "not probed: " + err.Error()
		} else if out.Media, err = probe.Run(ctx, s.o.FFprobe, abs); err != nil {
			out.MediaNote = err.Error()
		}
	}
	return nil, out, nil
}

// resolve maps a cataloged file back to its absolute path, refusing
// anything that is no longer a regular file inside the root. Errors never
// mention the path.
func (s *Server) resolve(f catalog.File) (string, error) {
	rel := filepath.FromSlash(string(f.Path))
	if !filepath.IsLocal(rel) {
		return "", errors.New("invalid path")
	}
	abs := filepath.Join(s.o.Root, rel)
	info, err := os.Lstat(abs)
	if err != nil || !info.Mode().IsRegular() {
		return "", errors.New("file changed since the last scan")
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil || !strings.HasPrefix(real, s.o.Root+string(filepath.Separator)) {
		return "", errors.New("file changed since the last scan")
	}
	return real, nil
}

func (s *Server) duplicates(ctx context.Context, _ *mcp.CallToolRequest, in DuplicatesIn) (*mcp.CallToolResult, *catalog.Duplicates, error) {
	out, err := s.o.DB.Duplicates(in.Dir, max(in.MinSize, 1), s.limit(in.Limit, 20), max(in.Offset, 0), 10)
	return nil, out, err
}

func (s *Server) extensions(ctx context.Context, _ *mcp.CallToolRequest, in DirIn) (*mcp.CallToolResult, ExtensionsOut, error) {
	exts, err := s.o.DB.Extensions(in.Dir, s.limit(in.Limit, 50))
	return nil, ExtensionsOut{Dir: catalog.CleanDir(in.Dir), Extensions: exts}, err
}

func (s *Server) sensitive(ctx context.Context, _ *mcp.CallToolRequest, in DirIn) (*mcp.CallToolResult, *catalog.Sensitive, error) {
	out, err := s.o.DB.Sensitive(in.Dir, s.limit(in.Limit, 50))
	return nil, out, err
}
