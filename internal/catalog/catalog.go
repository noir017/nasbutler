// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 noir017

// Package catalog is the SQLite index of everything under the root.
//
// Each file row carries two paths: path, the real relative path (a BLOB, so
// names in legacy encodings survive byte for byte), and rpath, the redacted
// path agents see and navigate by. The real path is only read back by the
// scanner and by server-side probes; it must never be returned to an agent.
package catalog

import (
	"database/sql"
	"fmt"
	"os"
	"strconv"
	"time"

	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS meta (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS files (
	id              INTEGER PRIMARY KEY,
	path            BLOB    NOT NULL UNIQUE,
	rpath           TEXT    NOT NULL,
	rname           TEXT    NOT NULL,
	ext             TEXT    NOT NULL,
	size            INTEGER NOT NULL,
	mtime           INTEGER NOT NULL,
	inode           INTEGER NOT NULL,
	kind            TEXT    NOT NULL,
	level           INTEGER NOT NULL,
	findings        TEXT    NOT NULL,
	content_scanned INTEGER NOT NULL,
	unreadable      INTEGER NOT NULL,
	rules           TEXT    NOT NULL,
	phash           BLOB,
	fhash           BLOB,
	seen            INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS files_rpath ON files(rpath);
CREATE INDEX IF NOT EXISTS files_size  ON files(size);
CREATE INDEX IF NOT EXISTS files_fhash ON files(fhash) WHERE fhash IS NOT NULL;
CREATE TABLE IF NOT EXISTS opaque (
	path  BLOB    PRIMARY KEY,
	rpath TEXT    NOT NULL,
	files INTEGER NOT NULL,
	bytes INTEGER NOT NULL,
	seen  INTEGER NOT NULL
);
`

// Meta keys.
const (
	metaGeneration   = "generation"
	metaScanStarted  = "scan_started"
	metaScanFinished = "scan_finished"
	metaHashFinished = "hash_finished"
	metaRules        = "rules"
)

// DB wraps the catalog database.
type DB struct {
	db *sql.DB
}

// Open opens (creating if needed) the catalog at path. A read-only handle
// refuses writes at the SQLite level (query_only), which is what the MCP
// server uses: it can then not alter the catalog even through a bug.
func Open(path string, readOnly bool) (*DB, error) {
	// The catalog holds real paths: create it owner-only. SQLite gives its
	// -wal and -shm files the same mode as the database file.
	if f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600); err == nil {
		f.Close()
	}
	dsn := "file:" + path + "?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("catalog schema: %w", err)
	}
	if readOnly {
		// Re-open with query_only so every pooled connection inherits it.
		db.Close()
		db, err = sql.Open("sqlite", dsn+"&_pragma=query_only(1)")
		if err != nil {
			return nil, err
		}
		db.SetMaxOpenConns(4)
	} else {
		// One writer connection: the scanner is sequential, and a single
		// connection sees its own uncommitted rows.
		db.SetMaxOpenConns(1)
	}
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}
	return &DB{db: db}, nil
}

// Close closes the database.
func (d *DB) Close() error { return d.db.Close() }

func (d *DB) meta(key string) (string, error) {
	var v string
	err := d.db.QueryRow(`SELECT value FROM meta WHERE key = ?`, key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return v, err
}

func setMeta(x execer, key, value string) error {
	_, err := x.Exec(`INSERT INTO meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

type execer interface {
	Exec(query string, args ...any) (sql.Result, error)
}

func now() string { return time.Now().Format(time.RFC3339) }

// BeginScan starts a scan generation and returns its number. Rows not
// touched by the time FinishScan runs are deleted.
func (d *DB) BeginScan(rules string) (int64, error) {
	v, err := d.meta(metaGeneration)
	if err != nil {
		return 0, err
	}
	gen, _ := strconv.ParseInt(v, 10, 64)
	gen++
	tx, err := d.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	for k, v := range map[string]string{metaGeneration: strconv.FormatInt(gen, 10), metaScanStarted: now(), metaRules: rules} {
		if err := setMeta(tx, k, v); err != nil {
			return 0, err
		}
	}
	return gen, tx.Commit()
}

// FinishScan drops rows that the completed walk no longer saw (deleted
// files, and files now under hidden or opaque rules).
func (d *DB) FinishScan(gen int64) (removed int64, err error) {
	tx, err := d.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	res, err := tx.Exec(`DELETE FROM files WHERE seen < ?`, gen)
	if err != nil {
		return 0, err
	}
	removed, _ = res.RowsAffected()
	if _, err := tx.Exec(`DELETE FROM opaque WHERE seen < ?`, gen); err != nil {
		return 0, err
	}
	if err := setMeta(tx, metaScanFinished, now()); err != nil {
		return 0, err
	}
	return removed, tx.Commit()
}

// FinishHash records that duplicate hashing completed.
func (d *DB) FinishHash() error { return setMeta(d.db, metaHashFinished, now()) }
