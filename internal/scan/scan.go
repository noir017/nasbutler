// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 noir017

// Package scan walks the root and brings the catalog up to date.
//
// The walk is read-only: files are opened O_RDONLY|O_NOFOLLOW (and
// O_NOATIME where permitted), symlinks are never followed, and nothing
// under the root is ever written. Unchanged files (same size, mtime, inode
// and rules) are not reopened, so a rescan costs little more than a
// directory listing.
package scan

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"time"

	"github.com/noir017/nasbutler/internal/catalog"
	"github.com/noir017/nasbutler/internal/detect"
	"github.com/noir017/nasbutler/internal/fsx"
	"github.com/noir017/nasbutler/internal/kind"
	"github.com/noir017/nasbutler/internal/redact"
	"github.com/noir017/nasbutler/internal/rules"
)

// Options configures a scan.
type Options struct {
	Root        string
	Rules       *rules.Set
	Redactor    *redact.Redactor
	MaxContent  int64 // bytes of a text file inspected for secrets
	Hash        bool  // find duplicates after the walk
	HashMinSize int64
	// Progress, if set, is called every few seconds and once at the end.
	Progress func(Stats)
}

// Stats counts what a scan did.
type Stats struct {
	Phase        string `json:"phase"`
	Dirs         int64  `json:"dirs"`
	Files        int64  `json:"files"`
	Bytes        int64  `json:"bytes"`
	Reclassified int64  `json:"reclassified"`
	Hidden       int64  `json:"hidden"`
	Opaque       int64  `json:"opaque_dirs"`
	Special      int64  `json:"special"`
	Errors       int64  `json:"errors"`
	Removed      int64  `json:"removed"`
	Hashed       int64  `json:"hashed"`
}

const headSize = 4096

type scanner struct {
	o     Options
	w     *catalog.Writer
	fp    string
	dirs  map[string]dirState
	st    Stats
	last  time.Time
	chunk int64
}

type dirState struct {
	rpath  string
	secret bool
}

// Run scans o.Root into db.
func Run(ctx context.Context, db *catalog.DB, o Options) (Stats, error) {
	s := &scanner{
		o: o,
		// Rows remember the rules and the pseudonym key they were redacted
		// under; a change to either reclassifies them.
		fp:    o.Rules.Fingerprint() + ":" + o.Redactor.Token("key", ""),
		dirs:  map[string]dirState{".": {}},
		chunk: 64 << 10,
		last:  time.Now(),
	}
	gen, err := db.BeginScan(o.Rules.Fingerprint())
	if err != nil {
		return s.st, err
	}
	if s.w, err = db.NewWriter(gen); err != nil {
		return s.st, err
	}
	s.st.Phase = "walk"
	if err := filepath.WalkDir(o.Root, func(p string, d fs.DirEntry, err error) error {
		return s.visit(ctx, p, d, err)
	}); err != nil {
		s.w.Abort()
		return s.st, err
	}
	if err := s.w.Close(); err != nil {
		return s.st, err
	}
	if s.st.Removed, err = db.FinishScan(gen); err != nil {
		return s.st, err
	}
	if o.Hash {
		s.st.Phase = "hash"
		if err := s.hash(ctx, db); err != nil {
			return s.st, err
		}
	}
	s.st.Phase = "done"
	s.progress(true)
	return s.st, nil
}

func (s *scanner) progress(force bool) {
	if s.o.Progress == nil || (!force && time.Since(s.last) < 5*time.Second) {
		return
	}
	s.last = time.Now()
	s.o.Progress(s.st)
}

func (s *scanner) visit(ctx context.Context, p string, d fs.DirEntry, walkErr error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if walkErr != nil {
		if p == s.o.Root {
			return walkErr
		}
		s.st.Errors++
		return nil // WalkDir skips an unreadable directory by itself
	}
	rel, err := filepath.Rel(s.o.Root, p)
	if err != nil {
		return err
	}
	rel = filepath.ToSlash(rel)
	if rel == "." {
		return nil
	}
	parent := s.dirs[path.Dir(rel)]
	s.progress(false)

	switch {
	case d.IsDir():
		if s.o.Rules.Hidden(rel) {
			s.st.Hidden++
			return fs.SkipDir
		}
		s.st.Dirs++
		if parent.secret {
			// Everything below a secret directory collapses into it.
			s.dirs[rel] = parent
			return nil
		}
		if s.o.Rules.Opaque(rel) {
			files, bytes := s.countTree(p)
			s.st.Opaque++
			if err := s.w.PutOpaque([]byte(rel), join(parent.rpath, s.segment(d.Name())), files, bytes); err != nil {
				return err
			}
			return fs.SkipDir
		}
		if s.o.Rules.Secret(rel) {
			s.dirs[rel] = dirState{rpath: join(parent.rpath, s.o.Redactor.Token("secret-dir", rel)), secret: true}
		} else {
			s.dirs[rel] = dirState{rpath: join(parent.rpath, s.segment(d.Name()))}
		}
		return nil
	case d.Type().IsRegular():
		if s.o.Rules.Hidden(rel) {
			s.st.Hidden++
			return nil
		}
		info, err := d.Info()
		if err != nil {
			s.st.Errors++
			return nil
		}
		return s.file(p, rel, info, parent)
	default:
		s.st.Special++ // symlinks, sockets, devices: never followed
		return nil
	}
}

// countTree totals an opaque directory without recording its contents.
func (s *scanner) countTree(root string) (files, bytes int64) {
	filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(s.o.Root, p)
		if s.o.Rules.Hidden(filepath.ToSlash(rel)) {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.Type().IsRegular() {
			if info, err := d.Info(); err == nil {
				files++
				bytes += info.Size()
			}
		}
		return nil
	})
	return files, bytes
}

func (s *scanner) file(abs, rel string, info fs.FileInfo, parent dirState) error {
	name := info.Name()
	f := catalog.File{
		Path:  []byte(rel),
		Ext:   kind.Ext(name),
		Size:  info.Size(),
		MTime: info.ModTime().UnixNano(),
		Inode: fsx.Inode(info),
		Rules: s.fp,
	}
	s.st.Files++
	s.st.Bytes += f.Size
	if same, err := s.w.Unchanged(f.Path, f.Size, f.MTime, f.Inode, s.fp); err != nil || same {
		return err
	}
	s.st.Reclassified++

	k, known := kind.Guess(name, f.Size)
	level := detect.Normal
	findings := map[string]int{}
	note := func(fs []detect.Finding) {
		for _, x := range fs {
			findings[string(x.Type)]++
			if l := x.Type.Level(); l > level {
				level = l
			}
		}
	}
	if parent.secret || s.o.Rules.Secret(rel) {
		// Secret by path: its content is not even read.
		level = detect.Secret
	} else {
		if f.Size > 0 && kind.NeedsHead(name, k, known) {
			var err error
			k, f.ContentScanned, err = s.inspect(abs, name, k, known, note)
			if err != nil {
				f.Unreadable = true
				s.st.Errors++
			}
		}
		note(detect.FindString(fsx.DisplayName(name)))
	}
	f.Kind, f.Level, f.Findings = string(k), int(level), findings
	if level == detect.Secret {
		f.RPath = join(parent.rpath, s.o.Redactor.Token("secret", rel))
	} else {
		f.RPath = join(parent.rpath, s.segment(name))
	}
	f.RName = path.Base(f.RPath)
	return s.w.Put(f)
}

// inspect reads the head of a file to classify it and, for text, up to
// MaxContent bytes to look for sensitive values.
func (s *scanner) inspect(abs, name string, k kind.Kind, known bool, note func([]detect.Finding)) (kind.Kind, bool, error) {
	fh, err := fsx.OpenRead(abs)
	if err != nil {
		return k, false, err
	}
	defer fh.Close()
	head := make([]byte, headSize)
	n, err := io.ReadFull(fh, head)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return k, false, err
	}
	head = head[:n]
	if t, ok := detect.Sniff(head); ok {
		note([]detect.Finding{{Type: t}})
		return k, false, nil
	}
	k, mime := kind.Refine(name, k, known, head)
	if !kind.TextLike(k, mime) {
		return k, false, nil
	}
	content := head
	if rest := s.o.MaxContent - int64(n); rest > 0 && n == headSize {
		more, err := io.ReadAll(io.LimitReader(fh, rest))
		if err != nil {
			return k, false, err
		}
		content = append(content, more...)
	}
	note(detect.Find(content))
	return k, true, nil
}

// segment is the redacted display form of one path component.
func (s *scanner) segment(name string) string {
	r, _ := s.o.Redactor.String(fsx.DisplayName(name))
	return r
}

func join(dir, name string) string {
	if dir == "" {
		return name
	}
	return dir + "/" + name
}

// hash finds duplicates in two passes: a cheap partial hash for files that
// share a size, then a full hash only where partial hashes collide.
func (s *scanner) hash(ctx context.Context, db *catalog.DB) error {
	type pass struct {
		jobs    func(after int64) ([]catalog.HashJob, error)
		compute func(catalog.HashJob) (sum []byte, whole bool, err error)
		store   func(id int64, sum []byte, whole bool) error
	}
	for _, p := range []pass{
		{
			jobs:    func(after int64) ([]catalog.HashJob, error) { return db.PartialJobs(s.o.HashMinSize, after, 1000) },
			compute: func(j catalog.HashJob) ([]byte, bool, error) { return s.partialHash(ctx, j) },
			store:   db.SetPartial,
		},
		{
			jobs: func(after int64) ([]catalog.HashJob, error) { return db.FullJobs(after, 1000) },
			compute: func(j catalog.HashJob) ([]byte, bool, error) {
				sum, err := s.fullHash(ctx, j)
				return sum, true, err
			},
			store: func(id int64, sum []byte, _ bool) error { return db.SetFull(id, sum) },
		},
	} {
		var after int64
		for {
			jobs, err := p.jobs(after)
			if err != nil {
				return err
			}
			if len(jobs) == 0 {
				break
			}
			for _, j := range jobs {
				after = j.ID
				sum, whole, err := p.compute(j)
				if err := ctx.Err(); err != nil {
					return err
				}
				if err != nil {
					s.st.Errors++
					if err := db.MarkUnreadable(j.ID); err != nil {
						return err
					}
					continue
				}
				if err := p.store(j.ID, sum, whole); err != nil {
					return err
				}
				s.st.Hashed++
				s.progress(false)
			}
		}
	}
	return db.FinishHash()
}

// openJob opens a hash job's file and checks it still has the cataloged
// size; a file that changed since the walk is skipped until the next scan.
func (s *scanner) openJob(j catalog.HashJob) (*os.File, error) {
	fh, err := fsx.OpenRead(filepath.Join(s.o.Root, filepath.FromSlash(string(j.Path))))
	if err != nil {
		return nil, err
	}
	st, err := fh.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() != j.Size {
		fh.Close()
		return nil, fmt.Errorf("file changed since the walk")
	}
	return fh, nil
}

func (s *scanner) partialHash(ctx context.Context, j catalog.HashJob) (sum []byte, whole bool, err error) {
	fh, err := s.openJob(j)
	if err != nil {
		return nil, false, err
	}
	defer fh.Close()
	h := sha256.New()
	binary.Write(h, binary.LittleEndian, j.Size)
	whole = j.Size <= 2*s.chunk
	if whole {
		if _, err := io.Copy(h, ctxReader{ctx, fh}); err != nil {
			return nil, false, err
		}
		return h.Sum(nil), true, nil
	}
	ra := fh
	buf := make([]byte, s.chunk)
	for _, off := range []int64{0, j.Size - s.chunk} {
		if _, err := ra.ReadAt(buf, off); err != nil {
			return nil, false, err
		}
		h.Write(buf)
	}
	return h.Sum(nil), false, nil
}

func (s *scanner) fullHash(ctx context.Context, j catalog.HashJob) ([]byte, error) {
	fh, err := s.openJob(j)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	h := sha256.New()
	binary.Write(h, binary.LittleEndian, j.Size)
	if _, err := io.CopyBuffer(h, ctxReader{ctx, fh}, make([]byte, 1<<20)); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

// ctxReader stops long reads when the scan is cancelled.
type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}
