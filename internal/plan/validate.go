// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 noir017

package plan

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/noir017/nasbutler/internal/catalog"
	"github.com/noir017/nasbutler/internal/detect"
	"github.com/noir017/nasbutler/internal/fsx"
	"github.com/noir017/nasbutler/internal/rules"
)

// Resolved is an operation bound to real paths. It exists only inside the
// executor (and transiently in the server during validation) and is never
// returned to an agent.
type Resolved struct {
	Index   int    `json:"index"`
	Op      string `json:"op"`
	FileID  int64  `json:"file_id"`
	From    string `json:"from"`     // absolute
	To      string `json:"to"`       // absolute
	FromRel string `json:"from_rel"` // for humans: relative to root, or "[quarantine]/…"
	ToRel   string `json:"to_rel"`
	Size    int64  `json:"size"`
	MTime   int64  `json:"mtime"`
	Inode   int64  `json:"inode"`
}

// Validator checks operations against the catalog, the rules and, in the
// executor, the filesystem.
type Validator struct {
	DB         *catalog.DB
	Rules      *rules.Set
	Root       string // resolved absolute root
	Quarantine string // absolute quarantine directory
	// CheckFS adds filesystem checks: source unchanged since the scan,
	// destination free, no symlinks on the way, same filesystem.
	CheckFS bool
}

// QuarantineLabel prefixes quarantine paths shown to humans.
const QuarantineLabel = "[quarantine]"

// Resolve validates ops for plan id and returns the valid ones, resolved,
// plus one error per refused operation.
func (v *Validator) Resolve(id string, ops []Op) ([]Resolved, []OpError) {
	var out []Resolved
	var errs []OpError
	seenFile := map[int64]bool{}
	seenTo := map[string]bool{}
	from := map[string]bool{}
	for _, op := range ops {
		if f, err := v.DB.Get(op.File); err == nil {
			from[string(f.Path)] = true
		}
	}
	for i, op := range ops {
		r, err := v.one(id, i, op)
		switch {
		case err != nil:
		case seenFile[r.FileID]:
			err = errors.New("this file already appears earlier in the plan")
		case seenTo[r.To]:
			err = errors.New("another operation already targets this destination")
		case r.Op == OpMove && from[r.ToRel]:
			err = errors.New("the destination is the source of another operation; split this into two plans")
		}
		if err != nil {
			errs = append(errs, OpError{Index: i, Error: err.Error()})
			continue
		}
		seenFile[r.FileID], seenTo[r.To] = true, true
		out = append(out, r)
	}
	return out, errs
}

func (v *Validator) one(id string, i int, op Op) (Resolved, error) {
	r := Resolved{Index: i, Op: op.Op}
	f, err := v.DB.Get(op.File)
	if errors.Is(err, catalog.ErrNotFound) {
		return r, errors.New("unknown file id (use an id from a recent result)")
	}
	if err != nil {
		return r, errors.New("catalog lookup failed")
	}
	if detect.Level(f.Level) == detect.Secret {
		return r, errors.New("secret files cannot be moved in this version")
	}
	src := string(f.Path)
	if v.Rules.Path(src).Off() {
		return r, errors.New("the source is in a protected area")
	}
	r.FileID, r.Size, r.MTime, r.Inode = f.ID, f.Size, f.MTime, f.Inode
	r.From, r.FromRel = v.abs(src), src

	switch op.Op {
	case OpMove:
		dst, err := v.destination(op, src)
		if err != nil {
			return r, err
		}
		if dst == src {
			return r, errors.New("the source and destination are the same")
		}
		if v.Rules.Path(dst).Off() {
			return r, errors.New("the destination is in a protected, hidden, opaque or secret area")
		}
		r.To, r.ToRel = v.abs(dst), dst
	case OpQuarantine:
		if op.ToDir != "" || op.Name != "" {
			return r, errors.New("quarantine takes no destination")
		}
		r.To = filepath.Join(v.Quarantine, id, filepath.FromSlash(src))
		r.ToRel = QuarantineLabel + "/" + id + "/" + src
	default:
		return r, fmt.Errorf("unknown op %q (use %q or %q)", op.Op, OpMove, OpQuarantine)
	}
	if v.CheckFS {
		if err := v.checkFS(r); err != nil {
			return r, err
		}
	}
	return r, nil
}

func (v *Validator) abs(rel string) string { return filepath.Join(v.Root, filepath.FromSlash(rel)) }

// destination turns a redacted to_dir plus optional name into a real
// relative path. The longest prefix of to_dir that the catalog can resolve
// is an existing directory; the remaining segments are new directories.
func (v *Validator) destination(op Op, src string) (string, error) {
	var segs []string
	if dir := catalog.CleanDir(op.ToDir); dir != "" {
		segs = strings.Split(dir, "/")
	}
	base, rest := "", segs
	for k := len(segs); k > 0; k-- {
		real, ok, err := v.DB.ResolveDir(strings.Join(segs[:k], "/"))
		if errors.Is(err, catalog.ErrAmbiguous) {
			return "", errors.New("the destination directory is ambiguous (two directories display the same); pick another")
		}
		if err != nil {
			return "", errors.New("catalog lookup failed")
		}
		if ok {
			base, rest = real, segs[k:]
			break
		}
	}
	for _, s := range rest {
		if err := CheckName(s); err != nil {
			return "", fmt.Errorf("to_dir: %w", err)
		}
	}
	name := op.Name
	if name == "" {
		name = path.Base(src)
	} else if err := CheckName(name); err != nil {
		return "", fmt.Errorf("name: %w", err)
	}
	parts := append([]string{}, rest...)
	if base != "" {
		parts = append([]string{base}, parts...)
	}
	return strings.Join(append(parts, name), "/"), nil
}

var pseudonym = regexp.MustCompile(`\[[a-z-]+#[0-9a-f]{8}\]`)

// CheckName validates a directory or file name chosen by an agent.
func CheckName(s string) error {
	switch {
	case s == "" || s == "." || s == "..":
		return fmt.Errorf("invalid name %q", s)
	case len(s) > 255:
		return errors.New("name longer than 255 bytes")
	case !utf8.ValidString(s):
		return errors.New("name is not valid UTF-8")
	case pseudonym.MatchString(s):
		return errors.New("contains a pseudonym that matches no cataloged directory; pseudonyms can only refer to existing directories")
	case strings.HasSuffix(s, " ") || strings.HasSuffix(s, "."):
		return errors.New("name ends with a space or dot (breaks SMB clients)")
	}
	for _, c := range s {
		if c < 0x20 || c == 0x7f || c == '/' || c == '\\' {
			return errors.New("name contains a slash, backslash or control character")
		}
	}
	return nil
}

// Recheck repeats the filesystem checks for one resolved operation right
// before it is executed.
func (v *Validator) Recheck(r Resolved) error { return v.checkFS(r) }

// checkFS is the executor's view: the source must be exactly the file that
// was cataloged, the destination must be free, every existing directory on
// the way must be a real directory (not a symlink that leads elsewhere),
// and the move must stay on one filesystem.
func (v *Validator) checkFS(r Resolved) error {
	src, err := os.Lstat(r.From)
	if err != nil || !src.Mode().IsRegular() || src.Size() != r.Size ||
		src.ModTime().UnixNano() != r.MTime || fsx.Inode(src) != r.Inode {
		return errors.New("the file changed since the last scan; rescan first")
	}
	if _, err := os.Lstat(r.To); err == nil {
		return errors.New("the destination already exists")
	} else if !errors.Is(err, fs.ErrNotExist) {
		return errors.New("the destination cannot be checked")
	}
	boundary := v.Root
	if !within(r.To, v.Root) {
		boundary = filepath.Dir(v.Quarantine)
	}
	var nearest fs.FileInfo
	for d := filepath.Dir(r.To); ; d = filepath.Dir(d) {
		st, err := os.Lstat(d)
		switch {
		case err == nil && (st.Mode()&fs.ModeSymlink != 0 || !st.IsDir()):
			return errors.New("the destination path is blocked by a file or symlink")
		case err == nil && nearest == nil:
			nearest = st
		case err != nil && !errors.Is(err, fs.ErrNotExist):
			return errors.New("the destination cannot be checked")
		}
		if d == boundary || !within(d, boundary) {
			break
		}
	}
	if nearest == nil || fsx.Dev(nearest) != fsx.Dev(src) {
		return errors.New("the destination is on a different filesystem; nothing is ever copied")
	}
	return nil
}

func within(p, dir string) bool {
	return p == dir || strings.HasPrefix(p, dir+string(filepath.Separator))
}

// Digest identifies exactly what a plan will do. Approvals are bound to
// it, so a plan whose files or destinations change needs a new approval.
func Digest(id, kind string, rs []Resolved) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\x00%s\n", id, kind)
	for _, r := range rs {
		fmt.Fprintf(h, "%s\x00%d\x00%s\x00%s\x00%d\n", r.Op, r.FileID, r.From, r.To, r.Inode)
	}
	return hex.EncodeToString(h.Sum(nil))
}
