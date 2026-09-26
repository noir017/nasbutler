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

	"github.com/BurntSushi/toml"

	"github.com/noir017/nasbutler/internal/rules"
)

// Config is the parsed configuration file.
type Config struct {
	Root     string `toml:"root"`
	StateDir string `toml:"state_dir"`
	Rules    struct {
		Hidden []string `toml:"hidden"`
		Opaque []string `toml:"opaque"`
		Secret []string `toml:"secret"`
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

	// RuleSet is compiled from Rules by Load.
	RuleSet *rules.Set `toml:"-"`
}

// TokenEnv overrides serve.token_file.
const TokenEnv = "NASBUTLER_TOKEN"

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
	c.RuleSet, err = rules.Compile(c.Rules.Hidden, c.Rules.Opaque, c.Rules.Secret)
	return err
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
	if t := strings.TrimSpace(os.Getenv(TokenEnv)); t != "" {
		return t, "$" + TokenEnv, nil
	}
	if c.Serve.TokenFile == "" {
		return "", "", fmt.Errorf("no token: set $%s or serve.token_file", TokenEnv)
	}
	st, err := os.Stat(c.Serve.TokenFile)
	if err != nil {
		return "", "", err
	}
	if st.Mode().Perm()&0o077 != 0 {
		return "", "", fmt.Errorf("%s must not be readable by group or others (chmod 600)", c.Serve.TokenFile)
	}
	b, err := os.ReadFile(c.Serve.TokenFile)
	if err != nil {
		return "", "", err
	}
	return strings.TrimSpace(string(b)), c.Serve.TokenFile, nil
}
