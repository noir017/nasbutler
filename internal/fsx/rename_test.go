// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 noir017

package fsx

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestRenameNoReplace(t *testing.T) {
	dir := t.TempDir()
	a, b, c := filepath.Join(dir, "a"), filepath.Join(dir, "b"), filepath.Join(dir, "c")
	os.WriteFile(a, []byte("a"), 0o644)
	os.WriteFile(b, []byte("b"), 0o644)
	if err := RenameNoReplace(a, b); !errors.Is(err, os.ErrExist) {
		t.Fatalf("rename over an existing file: err = %v, want ErrExist", err)
	}
	if got, _ := os.ReadFile(b); string(got) != "b" {
		t.Fatal("destination was overwritten")
	}
	if err := RenameNoReplace(a, c); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(a); !errors.Is(err, os.ErrNotExist) {
		t.Error("source still present")
	}
	if got, _ := os.ReadFile(c); string(got) != "a" {
		t.Error("content not moved")
	}
	for _, f := range []func(string, string) error{RenameNoReplace, linkUnlink} {
		if err := f(c, b); !errors.Is(err, os.ErrExist) {
			t.Errorf("err = %v, want ErrExist", err)
		}
	}
}
