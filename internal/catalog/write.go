// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 noir017

package catalog

import (
	"database/sql"
	"sort"
	"strconv"
	"strings"
)

// File is one catalog row.
type File struct {
	ID             int64
	Path           []byte // real relative path: server-side use only
	RPath, RName   string
	Ext            string
	Size           int64
	MTime          int64 // unix nanoseconds
	Inode          int64
	Kind           string
	Level          int
	Findings       map[string]int
	ContentScanned bool
	Unreadable     bool
	Rules          string
}

// EncodeFindings renders finding counts as "type:n,type:n" in a stable order.
func EncodeFindings(m map[string]int) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+":"+strconv.Itoa(m[k]))
	}
	return strings.Join(parts, ",")
}

func decodeFindings(s string) map[string]int {
	if s == "" {
		return nil
	}
	m := map[string]int{}
	for _, p := range strings.Split(s, ",") {
		k, v, _ := strings.Cut(p, ":")
		n, _ := strconv.Atoi(v)
		m[k] = n
	}
	return m
}

// Writer batches scanner writes into transactions.
type Writer struct {
	db      *sql.DB
	gen     int64
	tx      *sql.Tx
	pending int
	lookup  *sql.Stmt
	touch   *sql.Stmt
	upsert  *sql.Stmt
	opaque  *sql.Stmt
}

const batchSize = 5000

// NewWriter returns a Writer for scan generation gen.
func (d *DB) NewWriter(gen int64) (*Writer, error) {
	w := &Writer{db: d.db, gen: gen}
	return w, w.begin()
}

func (w *Writer) begin() error {
	tx, err := w.db.Begin()
	if err != nil {
		return err
	}
	w.tx = tx
	for _, s := range []struct {
		dst **sql.Stmt
		sql string
	}{
		{&w.lookup, `SELECT id, size, mtime, inode, rules FROM files WHERE path = ?`},
		{&w.touch, `UPDATE files SET seen = ? WHERE id = ?`},
		{&w.upsert, `INSERT INTO files(path, rpath, rname, ext, size, mtime, inode, kind, level, findings, content_scanned, unreadable, rules, phash, fhash, seen)
			VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?)
			ON CONFLICT(path) DO UPDATE SET rpath = excluded.rpath, rname = excluded.rname, ext = excluded.ext,
				size = excluded.size, mtime = excluded.mtime, inode = excluded.inode, kind = excluded.kind,
				level = excluded.level, findings = excluded.findings, content_scanned = excluded.content_scanned,
				unreadable = excluded.unreadable, rules = excluded.rules, phash = NULL, fhash = NULL, seen = excluded.seen`},
		{&w.opaque, `INSERT INTO opaque(path, rpath, files, bytes, seen) VALUES(?, ?, ?, ?, ?)
			ON CONFLICT(path) DO UPDATE SET rpath = excluded.rpath, files = excluded.files, bytes = excluded.bytes, seen = excluded.seen`},
	} {
		if *s.dst, err = tx.Prepare(s.sql); err != nil {
			tx.Rollback()
			return err
		}
	}
	return nil
}

// Unchanged reports whether path is already cataloged with the same size,
// mtime, inode and rules; if so it marks the row as seen and returns true.
func (w *Writer) Unchanged(path []byte, size, mtime, inode int64, rules string) (bool, error) {
	var id, s, m, i int64
	var r string
	err := w.lookup.QueryRow(path).Scan(&id, &s, &m, &i, &r)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if s != size || m != mtime || i != inode || r != rules {
		return false, nil
	}
	if _, err := w.touch.Exec(w.gen, id); err != nil {
		return false, err
	}
	return true, w.tick()
}

// Put inserts or replaces a file row, clearing its hashes.
func (w *Writer) Put(f File) error {
	_, err := w.upsert.Exec(f.Path, f.RPath, f.RName, f.Ext, f.Size, f.MTime, f.Inode, f.Kind, f.Level,
		EncodeFindings(f.Findings), f.ContentScanned, f.Unreadable, f.Rules, w.gen)
	if err != nil {
		return err
	}
	return w.tick()
}

// PutOpaque records the totals of an opaque directory.
func (w *Writer) PutOpaque(path []byte, rpath string, files, bytes int64) error {
	if _, err := w.opaque.Exec(path, rpath, files, bytes, w.gen); err != nil {
		return err
	}
	return w.tick()
}

func (w *Writer) tick() error {
	w.pending++
	if w.pending < batchSize {
		return nil
	}
	if err := w.tx.Commit(); err != nil {
		return err
	}
	w.pending = 0
	return w.begin()
}

// Close commits outstanding writes.
func (w *Writer) Close() error {
	if w.tx == nil {
		return nil
	}
	err := w.tx.Commit()
	w.tx = nil
	return err
}

// Abort discards outstanding writes.
func (w *Writer) Abort() {
	if w.tx != nil {
		w.tx.Rollback()
		w.tx = nil
	}
}

// HashJob is a file that needs hashing.
type HashJob struct {
	ID   int64
	Path []byte
	Size int64
}

// PartialJobs returns files that share their size with another file and
// have no partial hash yet, in id order after afterID.
func (d *DB) PartialJobs(minSize, afterID int64, limit int) ([]HashJob, error) {
	return d.jobs(`SELECT id, path, size FROM files
		WHERE id > ? AND phash IS NULL AND size >= ?
		  AND size IN (SELECT size FROM files WHERE size >= ? GROUP BY size HAVING COUNT(*) > 1)
		ORDER BY id LIMIT ?`, afterID, minSize, minSize, limit)
}

// FullJobs returns files whose (size, partial hash) collides with another
// file and that have no full hash yet.
func (d *DB) FullJobs(afterID int64, limit int) ([]HashJob, error) {
	return d.jobs(`SELECT id, path, size FROM files
		WHERE id > ? AND fhash IS NULL AND phash IS NOT NULL
		  AND (size, phash) IN (SELECT size, phash FROM files WHERE phash IS NOT NULL GROUP BY size, phash HAVING COUNT(*) > 1)
		ORDER BY id LIMIT ?`, afterID, limit)
}

func (d *DB) jobs(q string, args ...any) ([]HashJob, error) {
	rows, err := d.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []HashJob
	for rows.Next() {
		var j HashJob
		if err := rows.Scan(&j.ID, &j.Path, &j.Size); err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

// SetPartial stores a partial hash. When the partial hash covered the
// whole file, it is the full hash too.
func (d *DB) SetPartial(id int64, h []byte, whole bool) error {
	q := `UPDATE files SET phash = ? WHERE id = ?`
	if whole {
		q = `UPDATE files SET phash = ?1, fhash = ?1 WHERE id = ?2`
	}
	_, err := d.db.Exec(q, h, id)
	return err
}

// SetFull stores a full-content hash.
func (d *DB) SetFull(id int64, h []byte) error {
	_, err := d.db.Exec(`UPDATE files SET fhash = ? WHERE id = ?`, h, id)
	return err
}

// MarkUnreadable flags a file that could not be read while hashing.
func (d *DB) MarkUnreadable(id int64) error {
	_, err := d.db.Exec(`UPDATE files SET unreadable = 1 WHERE id = ?`, id)
	return err
}
