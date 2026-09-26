// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 noir017

// Package config loads and validates nasbutler's TOML configuration.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/noir017/nasbutler/internal/rules"
)

// Config is the parsed configuration file.
type Config struct {
	Root     string `toml:"root"`
	StateDir string `toml:"state_dir"`
	Rules    struct {
		Hidden    []string `toml:"hidden"`
		Opaque    []string `toml:"opaque"`
		Secret    []string `toml:"secret"`
		Protected []string `toml:"protected"`
	} `toml:"rules"`
	Scan struct {
		MaxContentBytes int64 `toml:"max_content_bytes"`
		Hash            *bool `toml:"hash"`
		HashMinSize     int64 `toml:"hash_min_size"`
	} `toml:"scan"`
	Serve struct {
		Listen         string  `toml:"listen"`
		TokenFile      string  `toml:"token_file"`
		MaxResultBytes int     `toml:"max_result_bytes"`
		MaxLimit       int     `toml:"max_limit"`
		FFprobe        *string `toml:"ffprobe"`
	} `toml:"serve"`
	Plans struct {
		Dir    string `toml:"dir"`
		MaxOps int    `toml:"max_ops"`
	} `toml:"plans"`
	Exec struct {
		Dir           string `toml:"dir"`
		QuarantineDir string `toml:"quarantine_dir"`
		Approver      string `toml:"approver"`
		ApprovalTTL   string `toml:"approval_ttl"`
		Rescan        *bool  `toml:"rescan"`
	} `toml:"exec"`
	Feishu struct {
		AppID          string `toml:"app_id"`
		AppSecretFile  string `toml:"app_secret_file"`
		ApproverOpenID string `toml:"approver_open_id"`
		BaseURL        string `toml:"base_url"`
	} `toml:"feishu"`

	// RuleSet is compiled from Rules by Load.
	RuleSet *rules.Set `toml:"-"`
	// ApprovalTTL is parsed from Exec.ApprovalTTL by Load.
	ApprovalTTL time.Duration `toml:"-"`
}

// Environment variables that override secret files.
const (
	TokenEnv        = "NASBUTLER_TOKEN"
	FeishuSecretEnv = "NASBUTLER_FEISHU_APP_SECRET"
)

// Load reads, defaults and validates the file at path. Unknown keys are an
// error: a misspelt rule in a privacy tool must not be silently ignored.
func Load(path string) (*Config, error) {
	var c Config
	md, err := toml.DecodeFile(path, &c)
	if err != nil {
		return nil, err
	}
	if und := md.Undecoded(); len(und) > 0 {
		keys := make([]string, len(und))
		for i, k := range und {
			keys[i] = k.String()
		}
		sort.Strings(keys)
		return nil, fmt.Errorf("%s: unknown keys: %s", path, strings.Join(keys, ", "))
	}
	c.defaults()
	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &c, nil
}

func (c *Config) defaults() {
	if c.Scan.MaxContentBytes == 0 {
		c.Scan.MaxContentBytes = 1 << 20
	}
	if c.Scan.Hash == nil {
		t := true
		c.Scan.Hash = &t
	}
	if c.Scan.HashMinSize == 0 {
		c.Scan.HashMinSize = 1
	}
	if c.Serve.Listen == "" {
		c.Serve.Listen = "127.0.0.1:8765"
	}
	if c.Serve.MaxResultBytes == 0 {
		c.Serve.MaxResultBytes = 64 << 10
	}
	if c.Serve.MaxLimit == 0 {
		c.Serve.MaxLimit = 200
	}
	if c.Serve.FFprobe == nil {
		f := "ffprobe"
		c.Serve.FFprobe = &f
	}
	if c.Plans.MaxOps == 0 {
		c.Plans.MaxOps = 5000
	}
	if c.Exec.Approver == "" {
		c.Exec.Approver = "feishu"
	}
	if c.Exec.ApprovalTTL == "" {
		c.Exec.ApprovalTTL = "24h"
	}
	if c.Exec.Rescan == nil {
		t := true
		c.Exec.Rescan = &t
	}
	if c.Feishu.BaseURL == "" {
		c.Feishu.BaseURL = "https://open.feishu.cn"
	}
}

func (c *Config) validate() error {
	if c.Root == "" || !filepath.IsAbs(c.Root) {
		return errors.New("root must be an absolute path")
	}
	if c.StateDir == "" || !filepath.IsAbs(c.StateDir) {
		return errors.New("state_dir must be an absolute path")
	}
	root, err := filepath.EvalSymlinks(c.Root)
	if err != nil {
		return fmt.Errorf("root: %w", err)
	}
	if st, err := os.Stat(root); err != nil || !st.IsDir() {
		return errors.New("root is not a directory")
	}
	c.Root = root
	if err := os.MkdirAll(c.StateDir, 0o700); err != nil {
		return fmt.Errorf("state_dir: %w", err)
	}
	if c.StateDir, err = filepath.EvalSymlinks(c.StateDir); err != nil {
		return fmt.Errorf("state_dir: %w", err)
	}
	if within(c.StateDir, c.Root) || within(c.Root, c.StateDir) {
		return errors.New("state_dir and root must not contain each other")
	}
	if c.Scan.MaxContentBytes < 4096 {
		return errors.New("scan.max_content_bytes must be at least 4096")
	}
	if c.Serve.MaxResultBytes < 1024 || c.Serve.MaxLimit < 1 {
		return errors.New("serve.max_result_bytes must be at least 1024 and serve.max_limit at least 1")
	}
	if c.Plans.MaxOps < 1 {
		return errors.New("plans.max_ops must be at least 1")
	}
	if c.Exec.Approver != "feishu" && c.Exec.Approver != "local" {
		return fmt.Errorf("exec.approver must be \"feishu\" or \"local\", not %q", c.Exec.Approver)
	}
	if c.ApprovalTTL, err = time.ParseDuration(c.Exec.ApprovalTTL); err != nil || c.ApprovalTTL < time.Minute {
		return fmt.Errorf("exec.approval_ttl %q must be a duration of at least 1m", c.Exec.ApprovalTTL)
	}
	if c.Plans.Dir == "" {
		c.Plans.Dir = filepath.Join(c.StateDir, "plans")
	}
	if c.Exec.Dir == "" {
		c.Exec.Dir = filepath.Join(c.StateDir, "exec")
	}
	if c.Exec.QuarantineDir == "" {
		c.Exec.QuarantineDir = filepath.Join(c.Root, rules.StateDir, "quarantine")
	}
	for name, p := range map[string]string{"plans.dir": c.Plans.Dir, "exec.dir": c.Exec.Dir, "exec.quarantine_dir": c.Exec.QuarantineDir} {
		if !filepath.IsAbs(p) {
			return fmt.Errorf("%s must be an absolute path", name)
		}
	}
	if within(c.Plans.Dir, c.Root) || within(c.Exec.Dir, c.Root) {
		return errors.New("plans.dir and exec.dir must be outside root")
	}
	if c.Plans.Dir == c.Exec.Dir {
		return errors.New("plans.dir and exec.dir must differ: they belong to different processes")
	}
	c.RuleSet, err = rules.Compile(rules.Patterns{
		Hidden: c.Rules.Hidden, Opaque: c.Rules.Opaque, Secret: c.Rules.Secret, Protected: c.Rules.Protected,
	})
	if err != nil {
		return err
	}
	// A quarantine inside the root must be hidden, or the scanner would
	// catalog quarantined files as if they were still part of the archive.
	if q := c.Exec.QuarantineDir; within(q, c.Root) {
		rel, _ := filepath.Rel(c.Root, q)
		if rel == "." || !c.RuleSet.Path(filepath.ToSlash(rel)).Hidden {
			return errors.New("exec.quarantine_dir inside root must be under a hidden directory (the default .nasbutler/ is)")
		}
	}
	return nil
}

func within(p, dir string) bool {
	return p == dir || strings.HasPrefix(p, dir+string(filepath.Separator))
}

// CatalogPath is the SQLite catalog.
func (c *Config) CatalogPath() string { return filepath.Join(c.StateDir, "catalog.db") }

// KeyPath is the pseudonym key.
func (c *Config) KeyPath() string { return filepath.Join(c.StateDir, "pseudonym.key") }

// AuditPath is the egress audit log.
func (c *Config) AuditPath() string { return filepath.Join(c.StateDir, "egress.jsonl") }

// LockPath serialises scans.
func (c *Config) LockPath() string { return filepath.Join(c.StateDir, "scan.lock") }

// Token returns the HTTP bearer token and where it came from.
func (c *Config) Token() (token, source string, err error) {
	return secret(TokenEnv, c.Serve.TokenFile, "serve.token_file")
}

// FeishuSecret returns the Feishu app secret and where it came from.
func (c *Config) FeishuSecret() (secretValue, source string, err error) {
	return secret(FeishuSecretEnv, c.Feishu.AppSecretFile, "feishu.app_secret_file")
}

// secret reads a credential from env, else from an owner-only file.
func secret(env, file, key string) (string, string, error) {
	if t := strings.TrimSpace(os.Getenv(env)); t != "" {
		return t, "$" + env, nil
	}
	if file == "" {
		return "", "", fmt.Errorf("not configured: set $%s or %s", env, key)
	}
	st, err := os.Stat(file)
	if err != nil {
		return "", "", err
	}
	if st.Mode().Perm()&0o077 != 0 {
		return "", "", fmt.Errorf("%s must not be readable by group or others (chmod 600)", file)
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return "", "", err
	}
	return strings.TrimSpace(string(b)), file, nil
}
