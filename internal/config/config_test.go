// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 noir017

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadDefaults(t *testing.T) {
	root, state := t.TempDir(), filepath.Join(t.TempDir(), "state")
	c, err := Load(write(t, "root = '"+root+"'\nstate_dir = '"+state+"'\n[rules]\nopaque = ['/backup']\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Scan.MaxContentBytes != 1<<20 || !*c.Scan.Hash || c.Serve.Listen != "127.0.0.1:8765" || *c.Serve.FFprobe != "ffprobe" {
		t.Errorf("defaults not applied: %+v", c)
	}
	if st, err := os.Stat(state); err != nil || st.Mode().Perm() != 0o700 {
		t.Errorf("state dir not created 0700: %v", err)
	}
	if !c.RuleSet.Opaque("backup") {
		t.Error("rules not compiled")
	}
	if c.Exec.QuarantineDir != filepath.Join(c.Root, ".nasbutler", "quarantine") || c.Exec.Approver != "feishu" ||
		c.Plans.Dir != filepath.Join(c.StateDir, "plans") || c.ApprovalTTL.Hours() != 24 {
		t.Errorf("v0.2 defaults not applied: %+v %+v %v", c.Exec, c.Plans, c.ApprovalTTL)
	}
}

func TestLoadRejects(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(t.TempDir(), "s")
	for name, body := range map[string]string{
		"unknown key":     "root = '" + root + "'\nstate_dir = '" + state + "'\n[rules]\nhiden = ['x']\n",
		"relative root":   "root = 'data'\nstate_dir = '" + state + "'\n",
		"state in root":   "root = '" + root + "'\nstate_dir = '" + filepath.Join(root, "state") + "'\n",
		"root in state":   "root = '" + filepath.Join(state, "r") + "'\nstate_dir = '" + state + "'\n",
		"bad pattern":     "root = '" + root + "'\nstate_dir = '" + state + "'\n[rules]\nsecret = ['a/[b']\n",
		"missing root":    "state_dir = '" + state + "'\n",
		"tiny result cap": "root = '" + root + "'\nstate_dir = '" + state + "'\n[serve]\nmax_result_bytes = 10\n",
		"bad approver":    "root = '" + root + "'\nstate_dir = '" + state + "'\n[exec]\napprover = 'email'\n",
		"short ttl":       "root = '" + root + "'\nstate_dir = '" + state + "'\n[exec]\napproval_ttl = '5s'\n",
		"visible quarantine": "root = '" + root + "'\nstate_dir = '" + state + "'\n[exec]\nquarantine_dir = '" +
			filepath.Join(root, "trash") + "'\n",
		"plans in root": "root = '" + root + "'\nstate_dir = '" + state + "'\n[plans]\ndir = '" + filepath.Join(root, "plans") + "'\n",
		"shared dirs":   "root = '" + root + "'\nstate_dir = '" + state + "'\n[plans]\ndir = '/tmp/x'\n[exec]\ndir = '/tmp/x'\n",
	} {
		if name == "root in state" {
			os.MkdirAll(filepath.Join(state, "r"), 0o700)
		}
		if _, err := Load(write(t, body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestToken(t *testing.T) {
	root, state := t.TempDir(), filepath.Join(t.TempDir(), "s")
	tokenFile := filepath.Join(t.TempDir(), "token")
	c, err := Load(write(t, "root = '"+root+"'\nstate_dir = '"+state+"'\n[serve]\ntoken_file = '"+tokenFile+"'\n"))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(TokenEnv, "")
	os.WriteFile(tokenFile, []byte(strings.Repeat("a", 32)+"\n"), 0o644)
	if _, _, err := c.Token(); err == nil {
		t.Error("world-readable token file accepted")
	}
	os.Chmod(tokenFile, 0o600)
	if tok, src, err := c.Token(); err != nil || tok != strings.Repeat("a", 32) || src != tokenFile {
		t.Errorf("Token() = %q, %q, %v", tok, src, err)
	}
	t.Setenv(TokenEnv, "from-env")
	if tok, _, _ := c.Token(); tok != "from-env" {
		t.Error("environment does not override the token file")
	}
}
