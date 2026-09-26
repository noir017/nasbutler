// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 noir017

// Package rules decides, from a path alone, whether a file or directory is
// hidden, opaque or secret.
//
// Patterns follow .gitignore conventions and match case-insensitively
// against slash-separated paths relative to the root:
//
//   - a pattern without a slash matches a name at any depth ("*.kdbx");
//   - a leading slash anchors to the root ("/backup");
//   - a trailing "/**" or "/" is dropped: matching a directory already
//     covers everything below it.
package rules

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
)

// Version changes whenever built-in rules, the detectors or path redaction
// change, so catalogs classified by an older build get reclassified.
const Version = "1"

// Set is a compiled rule set.
type Set struct {
	hidden, opaque, secret []string
	fingerprint            string
}

// Compile validates user patterns and adds the built-in secret rules.
func Compile(hidden, opaque, secret []string) (*Set, error) {
	s := &Set{}
	var err error
	if s.hidden, err = compileAll("hidden", hidden); err != nil {
		return nil, err
	}
	if s.opaque, err = compileAll("opaque", opaque); err != nil {
		return nil, err
	}
	if s.secret, err = compileAll("secret", append(append([]string{}, BuiltinSecret...), secret...)); err != nil {
		return nil, err
	}
	sorted := append([]string{}, s.secret...)
	sort.Strings(sorted)
	h := sha256.Sum256([]byte(Version + "\x00" + strings.Join(sorted, "\x00")))
	s.fingerprint = hex.EncodeToString(h[:8])
	return s, nil
}

func compileAll(kind string, pats []string) ([]string, error) {
	out := make([]string, 0, len(pats))
	for _, p := range pats {
		c, err := compile(p)
		if err != nil {
			return nil, fmt.Errorf("rules.%s: %q: %w", kind, p, err)
		}
		out = append(out, c)
	}
	return out, nil
}

func compile(p string) (string, error) {
	p = strings.ToLower(strings.TrimSpace(p))
	for strings.HasSuffix(p, "/**") {
		p = strings.TrimSuffix(p, "/**")
	}
	p = strings.TrimSuffix(p, "/")
	switch {
	case strings.HasPrefix(p, "/"):
		p = strings.TrimLeft(p, "/")
	case !strings.Contains(p, "/"):
		p = "**/" + p
	}
	if strings.Trim(p, "*/") == "" {
		return "", fmt.Errorf("pattern matches everything")
	}
	if !doublestar.ValidatePattern(p) {
		return "", fmt.Errorf("invalid pattern")
	}
	return p, nil
}

// Hidden reports whether rel must be skipped entirely.
func (s *Set) Hidden(rel string) bool { return matchAny(s.hidden, rel) }

// Opaque reports whether the directory rel is only counted, never listed.
func (s *Set) Opaque(rel string) bool { return matchAny(s.opaque, rel) }

// Secret reports whether rel is a secret file or secret directory.
func (s *Set) Secret(rel string) bool { return matchAny(s.secret, rel) }

// Fingerprint identifies the classification-relevant rules. It covers only
// secret rules: hidden and opaque changes take effect by the walk itself.
func (s *Set) Fingerprint() string { return s.fingerprint }

// SecretCount is the number of secret patterns, built-ins included.
func (s *Set) SecretCount() int { return len(s.secret) }

func matchAny(pats []string, rel string) bool {
	rel = strings.ToLower(rel)
	for _, p := range pats {
		if ok, _ := doublestar.Match(p, rel); ok {
			return true
		}
	}
	return false
}
