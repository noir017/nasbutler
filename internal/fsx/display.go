// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 noir017

package fsx

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/encoding/simplifiedchinese"
)

// DisplayName turns a file name into valid UTF-8 for display. Names
// written by old Chinese Windows systems are usually GBK; anything else
// undecodable has its bad bytes percent-escaped, which keeps distinct
// names distinct.
func DisplayName(name string) string {
	if utf8.ValidString(name) {
		return name
	}
	if d, err := simplifiedchinese.GB18030.NewDecoder().String(name); err == nil && utf8.ValidString(d) && !strings.ContainsRune(d, utf8.RuneError) {
		return d
	}
	var sb strings.Builder
	for i := 0; i < len(name); {
		r, size := utf8.DecodeRuneInString(name[i:])
		if r == utf8.RuneError && size <= 1 {
			fmt.Fprintf(&sb, "%%%02X", name[i])
			i++
			continue
		}
		sb.WriteString(name[i : i+size])
		i += size
	}
	return sb.String()
}

// DisplayPath applies DisplayName to every segment of a slash-separated path.
func DisplayPath(p string) string {
	segs := strings.Split(p, "/")
	for i, s := range segs {
		segs[i] = DisplayName(s)
	}
	return strings.Join(segs, "/")
}
