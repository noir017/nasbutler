// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 noir017

package kind

import "testing"

func TestGuess(t *testing.T) {
	cases := []struct {
		name  string
		size  int64
		want  Kind
		known bool
	}{
		{"IMG_0001.JPG", 10, Image, true},
		{"ch01_20240101.dav", 10, Video, true},
		{"report.docx", 10, Document, true},
		{"Thumbs.db", 10, Junk, true},
		{"~$report.docx", 10, Junk, true},
		{"._IMG_0001.jpg", 10, Junk, true},
		{"movie.mkv.part", 10, Junk, true},
		{"anything.jpg", 0, Empty, true},
		{"README", 10, Other, false},
		{"archive.tar.gz", 10, Archive, true},
	}
	for _, c := range cases {
		k, known := Guess(c.name, c.size)
		if k != c.want || known != c.known {
			t.Errorf("Guess(%q) = %v, %v; want %v, %v", c.name, k, known, c.want, c.known)
		}
	}
}

func TestRefine(t *testing.T) {
	if k, _ := Refine("clip.ts", Video, true, []byte{0x47, 0x40, 0x11}); k != Video {
		t.Errorf("MPEG-TS classified as %v", k)
	}
	if k, _ := Refine("main.ts", Video, true, []byte("export const x = 1;\n")); k != Code {
		t.Errorf("TypeScript classified as %v", k)
	}
	if k, mime := Refine("README", Other, false, []byte("hello world\n")); k != Text || !TextLike(k, mime) {
		t.Errorf("plain text classified as %v (%s)", k, mime)
	}
	if k, _ := Refine("blob", Other, false, []byte("%PDF-1.7\n")); k != Document {
		t.Errorf("PDF classified as %v", k)
	}
}

func TestNeedsHead(t *testing.T) {
	if NeedsHead("a.jpg", Image, true) {
		t.Error("images should not need a head read")
	}
	if !NeedsHead("a.ts", Video, true) || !NeedsHead("notes.txt", Text, true) || !NeedsHead("x", Other, false) {
		t.Error("head read missing where needed")
	}
}
