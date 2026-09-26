// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 noir017

package redact

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testRedactor() *Redactor { return New([]byte(strings.Repeat("k", keySize))) }

func TestStringConsistentPseudonyms(t *testing.T) {
	r := testRedactor()
	a, n := r.String("call 13812345678 now")
	if n != 1 || strings.Contains(a, "13812345678") || !strings.Contains(a, "[phone#") {
		t.Fatalf("String = %q, %d", a, n)
	}
	b, _ := r.String("+86 spaced: 138 1234 5678")
	tok := a[strings.Index(a, "[") : strings.Index(a, "]")+1]
	if !strings.Contains(b, tok) {
		t.Fatalf("spellings of one number got different pseudonyms: %q vs %q", a, b)
	}
	other := New([]byte(strings.Repeat("z", keySize)))
	if c, _ := other.String("13812345678"); strings.Contains(c, tok) {
		t.Fatal("pseudonym does not depend on the key")
	}
}

func TestStringNoFindings(t *testing.T) {
	if s, n := testRedactor().String("holiday/IMG_20240101_123045.jpg"); n != 0 || s != "holiday/IMG_20240101_123045.jpg" {
		t.Fatalf("String changed a clean value: %q, %d", s, n)
	}
}

func TestJSONKeepsNumbers(t *testing.T) {
	doc := []byte(`{"size":13812345678,"path":"a/13812345678.txt","13812345678":["x@y.cn",1.5]}`)
	out, n, err := testRedactor().JSON(doc)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if n != 3 {
		t.Fatalf("redactions = %d, want 3 (path, key, email): %s", n, s)
	}
	if !strings.Contains(s, `"size":13812345678`) || !strings.Contains(s, "1.5") {
		t.Fatalf("numbers were altered: %s", s)
	}
	if strings.Count(s, "13812345678") != 1 || strings.Contains(s, "x@y.cn") {
		t.Fatalf("strings were not redacted: %s", s)
	}
}

func TestJSONRejectsNonContainers(t *testing.T) {
	r := testRedactor()
	for _, doc := range []string{"13812345678", `"13812345678"`, `{"a":1} 13812345678`, ""} {
		if _, _, err := r.JSON([]byte(doc)); err == nil {
			t.Errorf("JSON(%q) accepted; callers would skip string redaction", doc)
		}
	}
}

func TestLoadOrCreateKey(t *testing.T) {
	p := filepath.Join(t.TempDir(), "key")
	k1, err := LoadOrCreateKey(p)
	if err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("key mode = %v", st.Mode().Perm())
	}
	k2, err := LoadOrCreateKey(p)
	if err != nil || string(k1) != string(k2) {
		t.Fatal("key was not reused")
	}
	os.WriteFile(p, []byte("short"), 0o600)
	if _, err := LoadOrCreateKey(p); err == nil {
		t.Fatal("truncated key accepted")
	}
}
