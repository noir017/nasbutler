// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 noir017

package catalog

import (
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/noir017/nasbutler/internal/detect"
)

// ErrNotFound is returned for directories or ids that are not cataloged.
var ErrNotFound = errors.New("not found")

// CleanDir normalises a redacted directory argument.
func CleanDir(dir string) string { return strings.Trim(dir, "/") }

// under returns a WHERE fragment selecting rows below dir, and the 1-based
// character position where the part of rpath below dir starts.
func under(dir string) (where string, args []any, start int) {
	if dir == "" {
		return "1=1", nil, 1
	}
	p := dir + "/"
	// '0' is the byte after '/', so [dir/, dir0) is exactly the subtree.
	return "rpath >= ? AND rpath < ?", []any{p, dir + "0"}, utf8.RuneCountInString(p) + 1
}

func day(ns int64) string {
	if ns == 0 {
		return ""
	}
	return time.Unix(0, ns).Format("2006-01-02")
}

// Timestamp formats a catalog mtime for output.
func Timestamp(ns int64) string { return time.Unix(0, ns).Format(time.RFC3339) }

// KindStat totals one kind of file.
type KindStat struct {
	Files int64 `json:"files"`
	Bytes int64 `json:"bytes"`
}

// Entry summarises one child of a surveyed directory.
type Entry struct {
	Name     string              `json:"name"`
	Dir      bool                `json:"dir"`
	Opaque   bool                `json:"opaque,omitempty"`
	Files    int64               `json:"files"`
	Bytes    int64               `json:"bytes"`
	Personal int64               `json:"personal_files,omitempty"`
	Secret   int64               `json:"secret_files,omitempty"`
	Oldest   string              `json:"oldest,omitempty"`
	Newest   string              `json:"newest,omitempty"`
	Kinds    map[string]KindStat `json:"kinds,omitempty"`

	oldest, newest int64
}

func (e *Entry) add(kind string, level int, files, bytes, oldest, newest int64) {
	e.Files += files
	e.Bytes += bytes
	switch detect.Level(level) {
	case detect.Personal:
		e.Personal += files
	case detect.Secret:
		e.Secret += files
	}
	if kind != "" {
		if e.Kinds == nil {
			e.Kinds = map[string]KindStat{}
		}
		k := e.Kinds[kind]
		k.Files += files
		k.Bytes += bytes
		e.Kinds[kind] = k
	}
	if oldest != 0 && (e.oldest == 0 || oldest < e.oldest) {
		e.oldest = oldest
	}
	if newest > e.newest {
		e.newest = newest
	}
}

func (e *Entry) finish() {
	e.Oldest, e.Newest = day(e.oldest), day(e.newest)
}

// Survey lists a directory's children with totals.
type Survey struct {
	Dir        string  `json:"dir"`
	Opaque     bool    `json:"opaque,omitempty"`
	Total      Entry   `json:"total"`
	Entries    []Entry `json:"entries"`
	EntryCount int     `json:"entry_count"`
	Offset     int     `json:"offset"`
}

// Survey summarises dir ("" for the root), children sorted by size.
func (d *DB) Survey(dir string, limit, offset int) (*Survey, error) {
	dir = CleanDir(dir)
	out := &Survey{Dir: dir, Entries: []Entry{}, Offset: offset}
	out.Total.Name, out.Total.Dir = dir, true
	if dir != "" {
		var files, bytes int64
		err := d.db.QueryRow(`SELECT files, bytes FROM opaque WHERE rpath = ?`, dir).Scan(&files, &bytes)
		if err == nil {
			out.Opaque, out.Total.Opaque = true, true
			out.Total.Files, out.Total.Bytes = files, bytes
			return out, nil
		}
		if err != sql.ErrNoRows {
			return nil, err
		}
	}

	where, args, start := under(dir)
	rows, err := d.db.Query(fmt.Sprintf(`
		SELECT CASE WHEN p > 0 THEN substr(rest, 1, p - 1) ELSE rest END, p > 0, kind, level,
		       COUNT(*), SUM(size), MIN(mtime), MAX(mtime)
		FROM (SELECT substr(rpath, %d) AS rest, instr(substr(rpath, %d), '/') AS p, kind, level, size, mtime
		      FROM files WHERE %s)
		GROUP BY 1, 2, 3, 4`, start, start, where), args...)
	if err != nil {
		return nil, err
	}
	type key struct {
		name string
		dir  bool
	}
	entries := map[key]*Entry{}
	get := func(k key) *Entry {
		e := entries[k]
		if e == nil {
			e = &Entry{Name: k.name, Dir: k.dir}
			entries[k] = e
		}
		return e
	}
	for rows.Next() {
		var k key
		var kind string
		var level int
		var files, bytes, oldest, newest int64
		if err := rows.Scan(&k.name, &k.dir, &kind, &level, &files, &bytes, &oldest, &newest); err != nil {
			rows.Close()
			return nil, err
		}
		get(k).add(kind, level, files, bytes, oldest, newest)
		out.Total.add(kind, level, files, bytes, oldest, newest)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	orows, err := d.db.Query(`SELECT rpath, files, bytes FROM opaque WHERE `+where, args...)
	if err != nil {
		return nil, err
	}
	prefix := ""
	if dir != "" {
		prefix = dir + "/"
	}
	for orows.Next() {
		var rpath string
		var files, bytes int64
		if err := orows.Scan(&rpath, &files, &bytes); err != nil {
			orows.Close()
			return nil, err
		}
		child, _, nested := strings.Cut(strings.TrimPrefix(rpath, prefix), "/")
		e := get(key{child, true})
		e.add("", 0, files, bytes, 0, 0)
		if !nested {
			e.Opaque = true
		}
		out.Total.add("", 0, files, bytes, 0, 0)
	}
	orows.Close()
	if err := orows.Err(); err != nil {
		return nil, err
	}
	if len(entries) == 0 && dir != "" {
		return nil, ErrNotFound
	}

	list := make([]Entry, 0, len(entries))
	for _, e := range entries {
		e.finish()
		list = append(list, *e)
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].Bytes != list[j].Bytes {
			return list[i].Bytes > list[j].Bytes
		}
		return list[i].Name < list[j].Name
	})
	out.Total.finish()
	out.EntryCount = len(list)
	out.Entries = page(list, limit, offset)
	return out, nil
}

func page[T any](list []T, limit, offset int) []T {
	if offset >= len(list) {
		return []T{}
	}
	list = list[offset:]
	if limit < len(list) {
		list = list[:limit]
	}
	return list
}

const fileColumns = `id, path, rpath, rname, ext, size, mtime, inode, kind, level, findings, content_scanned, unreadable, rules`

func scanFile(r interface{ Scan(...any) error }) (File, error) {
	var f File
	var findings string
	err := r.Scan(&f.ID, &f.Path, &f.RPath, &f.RName, &f.Ext, &f.Size, &f.MTime, &f.Inode, &f.Kind, &f.Level,
		&findings, &f.ContentScanned, &f.Unreadable, &f.Rules)
	f.Findings = decodeFindings(findings)
	return f, err
}

func (d *DB) files(q string, args ...any) ([]File, error) {
	rows, err := d.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []File{}
	for rows.Next() {
		f, err := scanFile(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// Get returns one file by id.
func (d *DB) Get(id int64) (File, error) {
	f, err := scanFile(d.db.QueryRow(`SELECT `+fileColumns+` FROM files WHERE id = ?`, id))
	if err == sql.ErrNoRows {
		return f, ErrNotFound
	}
	return f, err
}

// ErrAmbiguous means a redacted directory path stands for more than one
// real directory (say, one name in UTF-8 and one in GBK that displays the
// same). Plans must not guess between them.
var ErrAmbiguous = errors.New("redacted path matches more than one directory")

// ResolveDir maps a redacted directory path to the real relative path of
// the directory it stands for. Redacted and real paths correspond segment
// by segment, so the answer is the first k segments of any file below it;
// the smallest and largest real paths below it must agree on those k
// segments, or the redacted path is ambiguous. ok is false when no
// cataloged file lies below the directory.
func (d *DB) ResolveDir(rdir string) (real string, ok bool, err error) {
	rdir = CleanDir(rdir)
	if rdir == "" {
		return "", true, nil
	}
	where, args, _ := under(rdir)
	var lo, hi []byte
	err = d.db.QueryRow(`SELECT MIN(path), MAX(path) FROM files WHERE `+where, args...).Scan(&lo, &hi)
	if err != nil {
		return "", false, err
	}
	if lo == nil {
		return "", false, nil
	}
	k := strings.Count(rdir, "/") + 1
	a, b := prefix(string(lo), k), prefix(string(hi), k)
	if a == "" || a != b {
		return "", false, ErrAmbiguous
	}
	return a, true, nil
}

// prefix returns the first k slash-separated segments of p, or "" if p has
// no more than k segments (the prefix must be a directory, not the file).
func prefix(p string, k int) string {
	segs := strings.Split(p, "/")
	if len(segs) <= k {
		return ""
	}
	return strings.Join(segs[:k], "/")
}

// SameContent returns up to limit other files with the same full hash.
func (d *DB) SameContent(id int64, limit int) ([]File, error) {
	return d.files(`SELECT `+fileColumns+` FROM files
		WHERE fhash = (SELECT fhash FROM files WHERE id = ?1 AND fhash IS NOT NULL) AND id != ?1
		ORDER BY rpath LIMIT ?2`, id, limit)
}

// Query filters files. Zero values mean "no constraint".
type Query struct {
	Dir          string
	Kinds        []string
	Exts         []string
	MinSize      int64
	MaxSize      int64
	After        int64 // unix ns, inclusive
	Before       int64 // unix ns, exclusive
	Level        string
	NameContains string
	Sort         string // "size", "modified" or "path"
	Desc         bool
	Limit        int
	Offset       int
}

// Query returns one page of matching files and the total match count.
func (d *DB) Query(q Query) ([]File, int64, error) {
	where, args, _ := under(CleanDir(q.Dir))
	conds := []string{where}
	in := func(col string, vals []string) {
		if len(vals) == 0 {
			return
		}
		conds = append(conds, col+" IN ("+strings.TrimSuffix(strings.Repeat("?,", len(vals)), ",")+")")
		for _, v := range vals {
			args = append(args, v)
		}
	}
	in("kind", q.Kinds)
	if len(q.Exts) > 0 {
		exts := make([]string, len(q.Exts))
		for i, e := range q.Exts {
			exts[i] = strings.ToLower(strings.TrimPrefix(e, "."))
		}
		in("ext", exts)
		// A secret file's extension is part of what its pseudonym hides.
		conds = append(conds, "level < 2")
	}
	add := func(cond string, v any) {
		conds = append(conds, cond)
		args = append(args, v)
	}
	if q.MinSize > 0 {
		add("size >= ?", q.MinSize)
	}
	if q.MaxSize > 0 {
		add("size <= ?", q.MaxSize)
	}
	if q.After != 0 {
		add("mtime >= ?", q.After)
	}
	if q.Before != 0 {
		add("mtime < ?", q.Before)
	}
	if q.Level != "" {
		l, ok := detect.ParseLevel(q.Level)
		if !ok {
			return nil, 0, fmt.Errorf("unknown level %q", q.Level)
		}
		add("level = ?", int(l))
	}
	if q.NameContains != "" {
		esc := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(q.NameContains)
		add(`rname LIKE ? ESCAPE '\'`, "%"+esc+"%")
	}
	whereAll := strings.Join(conds, " AND ")

	var total int64
	if err := d.db.QueryRow(`SELECT COUNT(*) FROM files WHERE `+whereAll, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	order := map[string]string{"size": "size", "modified": "mtime", "path": "rpath"}[q.Sort]
	if order == "" {
		order = "rpath"
	}
	dir := "ASC"
	if q.Desc {
		dir = "DESC"
	}
	files, err := d.files(fmt.Sprintf(`SELECT %s FROM files WHERE %s ORDER BY %s %s, id LIMIT ? OFFSET ?`,
		fileColumns, whereAll, order, dir), append(args, q.Limit, q.Offset)...)
	return files, total, err
}

// ExtStat totals one extension.
type ExtStat struct {
	Ext   string `json:"ext"`
	Kind  string `json:"kind"`
	Files int64  `json:"files"`
	Bytes int64  `json:"bytes"`
}

// Extensions totals non-secret files under dir by extension, largest first.
func (d *DB) Extensions(dir string, limit int) ([]ExtStat, error) {
	where, args, _ := under(CleanDir(dir))
	rows, err := d.db.Query(`SELECT ext, kind, COUNT(*), SUM(size) FROM files WHERE `+where+` AND level < 2
		GROUP BY ext, kind ORDER BY SUM(size) DESC, ext LIMIT ?`, append(args, limit)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ExtStat{}
	for rows.Next() {
		var e ExtStat
		if err := rows.Scan(&e.Ext, &e.Kind, &e.Files, &e.Bytes); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// DupMember is one copy in a duplicate group.
type DupMember struct {
	ID       int64  `json:"id"`
	Path     string `json:"path"`
	Modified string `json:"modified"`
	Level    string `json:"level"`
}

// DupGroup is a set of files with identical content. It carries no hash:
// even a hash prefix would let someone holding a candidate file confirm
// that the archive contains it.
type DupGroup struct {
	Size        int64       `json:"size"`
	Count       int64       `json:"count"`
	Wasted      int64       `json:"wasted_bytes"`
	Members     []DupMember `json:"members"`
	MoreMembers int64       `json:"more_members,omitempty"`
}

// Duplicates is one page of duplicate groups.
type Duplicates struct {
	Groups      []DupGroup `json:"groups"`
	GroupCount  int64      `json:"group_count"`
	WastedBytes int64      `json:"wasted_bytes"`
	Offset      int        `json:"offset"`
}

// Duplicates lists groups of identical files, most wasted space first.
// With dir set, only groups with at least one copy under dir are listed.
func (d *DB) Duplicates(dir string, minSize int64, limit, offset, memberLimit int) (*Duplicates, error) {
	where, args, _ := under(CleanDir(dir))
	groups := `SELECT fhash, size, COUNT(*) AS c FROM files WHERE fhash IS NOT NULL AND size >= ? GROUP BY fhash, size HAVING c > 1`
	gargs := []any{minSize}
	filter := ""
	if where != "1=1" {
		filter = ` WHERE fhash IN (SELECT fhash FROM files WHERE fhash IS NOT NULL AND ` + where + `)`
		gargs = append(gargs, args...)
	}
	out := &Duplicates{Groups: []DupGroup{}, Offset: offset}
	if err := d.db.QueryRow(`WITH g AS (`+groups+`) SELECT COUNT(*), COALESCE(SUM(size * (c - 1)), 0) FROM g`+filter, gargs...).
		Scan(&out.GroupCount, &out.WastedBytes); err != nil {
		return nil, err
	}
	rows, err := d.db.Query(`WITH g AS (`+groups+`) SELECT fhash, size, c FROM g`+filter+
		` ORDER BY size * (c - 1) DESC, fhash LIMIT ? OFFSET ?`, append(gargs, limit, offset)...)
	if err != nil {
		return nil, err
	}
	type grp struct {
		hash []byte
		g    DupGroup
	}
	var gs []grp
	for rows.Next() {
		var x grp
		if err := rows.Scan(&x.hash, &x.g.Size, &x.g.Count); err != nil {
			rows.Close()
			return nil, err
		}
		x.g.Wasted = x.g.Size * (x.g.Count - 1)
		gs = append(gs, x)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, x := range gs {
		files, err := d.files(`SELECT `+fileColumns+` FROM files WHERE fhash = ? AND size = ? ORDER BY rpath LIMIT ?`,
			x.hash, x.g.Size, memberLimit)
		if err != nil {
			return nil, err
		}
		for _, f := range files {
			x.g.Members = append(x.g.Members, DupMember{ID: f.ID, Path: f.RPath, Modified: Timestamp(f.MTime), Level: detect.Level(f.Level).String()})
		}
		x.g.MoreMembers = x.g.Count - int64(len(x.g.Members))
		out.Groups = append(out.Groups, x.g)
	}
	return out, nil
}

// SensEntry counts sensitive files in one child of a directory.
type SensEntry struct {
	Name          string           `json:"name"`
	Dir           bool             `json:"dir"`
	Personal      int64            `json:"personal_files"`
	Secret        int64            `json:"secret_files"`
	Findings      map[string]int64 `json:"files_with,omitempty"`
	UnscannedDocs int64            `json:"unscanned_documents,omitempty"`
}

// Sensitive reports where sensitive files are, without naming them.
type Sensitive struct {
	Dir     string      `json:"dir"`
	Total   SensEntry   `json:"total"`
	Entries []SensEntry `json:"entries"`
}

// Sensitive counts personal and secret files, per finding type, below each
// child of dir. Children with nothing to report are left out.
func (d *DB) Sensitive(dir string, limit int) (*Sensitive, error) {
	dir = CleanDir(dir)
	where, args, start := under(dir)
	cols := make([]string, 0, len(detect.Types))
	for _, t := range detect.Types {
		cols = append(cols, fmt.Sprintf("SUM(findings LIKE '%%%s:%%')", t))
	}
	rows, err := d.db.Query(fmt.Sprintf(`
		SELECT CASE WHEN p > 0 THEN substr(rest, 1, p - 1) ELSE rest END, p > 0,
		       SUM(level = 1), SUM(level = 2), %s, SUM(kind = 'document' AND content_scanned = 0)
		FROM (SELECT substr(rpath, %d) AS rest, instr(substr(rpath, %d), '/') AS p, level, findings, kind, content_scanned
		      FROM files WHERE %s)
		GROUP BY 1, 2`, strings.Join(cols, ", "), start, start, where), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := &Sensitive{Dir: dir, Total: SensEntry{Name: dir, Dir: true}, Entries: []SensEntry{}}
	for rows.Next() {
		e := SensEntry{}
		counts := make([]int64, len(detect.Types))
		dst := []any{&e.Name, &e.Dir, &e.Personal, &e.Secret}
		for i := range counts {
			dst = append(dst, &counts[i])
		}
		dst = append(dst, &e.UnscannedDocs)
		if err := rows.Scan(dst...); err != nil {
			return nil, err
		}
		for i, t := range detect.Types {
			if counts[i] > 0 {
				if e.Findings == nil {
					e.Findings = map[string]int64{}
				}
				e.Findings[string(t)] = counts[i]
				if out.Total.Findings == nil {
					out.Total.Findings = map[string]int64{}
				}
				out.Total.Findings[string(t)] += counts[i]
			}
		}
		out.Total.Personal += e.Personal
		out.Total.Secret += e.Secret
		out.Total.UnscannedDocs += e.UnscannedDocs
		if e.Personal+e.Secret+e.UnscannedDocs > 0 {
			out.Entries = append(out.Entries, e)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.Slice(out.Entries, func(i, j int) bool {
		a, b := out.Entries[i], out.Entries[j]
		if a.Secret+a.Personal != b.Secret+b.Personal {
			return a.Secret+a.Personal > b.Secret+b.Personal
		}
		return a.Name < b.Name
	})
	out.Entries = page(out.Entries, limit, 0)
	return out, nil
}

// Status summarises the catalog.
type Status struct {
	Files           int64  `json:"files"`
	Bytes           int64  `json:"bytes"`
	PersonalFiles   int64  `json:"personal_files"`
	SecretFiles     int64  `json:"secret_files"`
	OpaqueDirs      int64  `json:"opaque_dirs"`
	OpaqueFiles     int64  `json:"opaque_files"`
	OpaqueBytes     int64  `json:"opaque_bytes"`
	ScanGeneration  string `json:"scan_generation"`
	ScanStarted     string `json:"scan_started,omitempty"`
	ScanFinished    string `json:"scan_finished,omitempty"`
	ScanInProgress  bool   `json:"scan_in_progress_or_aborted"`
	HashFinished    string `json:"hash_finished,omitempty"`
	HashedFiles     int64  `json:"hashed_files"`
	DuplicateGroups int64  `json:"duplicate_groups"`
	DuplicateBytes  int64  `json:"duplicate_wasted_bytes"`
}

// Status returns catalog-wide totals and scan bookkeeping.
func (d *DB) Status() (*Status, error) {
	s := &Status{}
	if err := d.db.QueryRow(`SELECT COUNT(*), COALESCE(SUM(size), 0), COALESCE(SUM(level = 1), 0), COALESCE(SUM(level = 2), 0),
		COALESCE(SUM(fhash IS NOT NULL), 0) FROM files`).Scan(&s.Files, &s.Bytes, &s.PersonalFiles, &s.SecretFiles, &s.HashedFiles); err != nil {
		return nil, err
	}
	if err := d.db.QueryRow(`SELECT COUNT(*), COALESCE(SUM(files), 0), COALESCE(SUM(bytes), 0) FROM opaque`).
		Scan(&s.OpaqueDirs, &s.OpaqueFiles, &s.OpaqueBytes); err != nil {
		return nil, err
	}
	if err := d.db.QueryRow(`SELECT COUNT(*), COALESCE(SUM(size * (c - 1)), 0) FROM
		(SELECT size, COUNT(*) AS c FROM files WHERE fhash IS NOT NULL GROUP BY fhash, size HAVING c > 1)`).
		Scan(&s.DuplicateGroups, &s.DuplicateBytes); err != nil {
		return nil, err
	}
	var err error
	for _, m := range []struct {
		dst *string
		key string
	}{
		{&s.ScanGeneration, metaGeneration}, {&s.ScanStarted, metaScanStarted},
		{&s.ScanFinished, metaScanFinished}, {&s.HashFinished, metaHashFinished},
	} {
		if *m.dst, err = d.meta(m.key); err != nil {
			return nil, err
		}
	}
	// RFC 3339 strings in one zone sort chronologically.
	s.ScanInProgress = s.ScanStarted != "" && s.ScanFinished < s.ScanStarted
	return s, nil
}

// Rules returns the rule fingerprint of the last scan.
func (d *DB) Rules() (string, error) { return d.meta(metaRules) }
