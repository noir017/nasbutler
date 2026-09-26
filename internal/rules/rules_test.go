// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 noir017

package rules

import "testing"

func TestSemantics(t *testing.T) {
	s, err := Compile(
		[]string{"/private/**"},
		[]string{"/backup/"},
		[]string{"病历", "work/hr/salary.xlsx"},
	)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		rel                    string
		hidden, opaque, secret bool
	}{
		{"private", true, false, false},
		{"a/private", false, false, false}, // anchored
		{"backup", false, true, false},
		{"old/backup", false, false, false}, // anchored
		{"docs/病历", false, false, true},     // unanchored: any depth
		{"病历", false, false, true},
		{"work/hr/salary.xlsx", false, false, true},
		{"x/work/hr/salary.xlsx", false, false, false}, // slash in the middle anchors
		{"home/.ssh", false, false, true},
		{"Backup Phone/WeChat Files", false, false, true}, // case-insensitive
		{"vault/Passwords.KDBX", false, false, true},
		{"photos/2024/IMG_0001.jpg", false, false, false},
		{"notes/keystore.txt", false, false, false},
	}
	for _, c := range cases {
		if got := s.Hidden(c.rel); got != c.hidden {
			t.Errorf("Hidden(%q) = %v", c.rel, got)
		}
		if got := s.Opaque(c.rel); got != c.opaque {
			t.Errorf("Opaque(%q) = %v", c.rel, got)
		}
		if got := s.Secret(c.rel); got != c.secret {
			t.Errorf("Secret(%q) = %v", c.rel, got)
		}
	}
}

func TestRejectsBadPatterns(t *testing.T) {
	for _, p := range []string{"**", "/", "  ", "a/[b"} {
		if _, err := Compile([]string{p}, nil, nil); err == nil {
			t.Errorf("Compile accepted %q", p)
		}
	}
}

func TestFingerprint(t *testing.T) {
	a, _ := Compile(nil, nil, []string{"x", "y"})
	b, _ := Compile([]string{"h"}, []string{"o"}, []string{"y", "x"})
	c, _ := Compile(nil, nil, []string{"x"})
	if a.Fingerprint() != b.Fingerprint() {
		t.Error("fingerprint depends on hidden/opaque rules or on order")
	}
	if a.Fingerprint() == c.Fingerprint() {
		t.Error("fingerprint ignores secret rules")
	}
}
