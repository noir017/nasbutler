// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 noir017

package rules

import "testing"

func TestSemantics(t *testing.T) {
	s, err := Compile(Patterns{
		Hidden: []string{"/private/**"},
		Opaque: []string{"/backup/"},
		Secret: []string{"病历", "work/hr/salary.xlsx"},
	})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		rel                    string
		hidden, opaque, secret bool
	}{
		{"private", true, false, false},
		{"a/private", false, false, false}, // anchored
		{".nasbutler", true, false, false}, // built in
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

func TestPathChecksAncestors(t *testing.T) {
	s, err := Compile(Patterns{Hidden: []string{"/private"}, Opaque: []string{"/backup"}, Protected: []string{"/archive/final"}})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		rel string
		off bool
	}{
		{"private/deep/file.txt", true},
		{"backup/server1/etc/app.conf", true},
		{"home/.ssh/config", true},
		{"archive/final/2020/a.jpg", true},
		{"archive/draft/a.jpg", false},
		{".nasbutler/quarantine/p1/a.jpg", true},
		{"photos/2024/a.jpg", false},
	}
	for _, c := range cases {
		if got := s.Path(c.rel).Off(); got != c.off {
			t.Errorf("Path(%q).Off() = %v, want %v (%+v)", c.rel, got, c.off, s.Path(c.rel))
		}
	}
}

func TestRejectsBadPatterns(t *testing.T) {
	for _, p := range []string{"**", "/", "  ", "a/[b"} {
		if _, err := Compile(Patterns{Hidden: []string{p}}); err == nil {
			t.Errorf("Compile accepted %q", p)
		}
		if _, err := Compile(Patterns{Protected: []string{p}}); err == nil {
			t.Errorf("Compile accepted protected %q", p)
		}
	}
}

func TestFingerprint(t *testing.T) {
	a, _ := Compile(Patterns{Secret: []string{"x", "y"}})
	b, _ := Compile(Patterns{Hidden: []string{"h"}, Opaque: []string{"o"}, Protected: []string{"p"}, Secret: []string{"y", "x"}})
	c, _ := Compile(Patterns{Secret: []string{"x"}})
	if a.Fingerprint() != b.Fingerprint() {
		t.Error("fingerprint depends on hidden/opaque/protected rules or on order")
	}
	if a.Fingerprint() == c.Fingerprint() {
		t.Error("fingerprint ignores secret rules")
	}
}
