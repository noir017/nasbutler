// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 noir017

// Command nasbutler catalogs a personal file archive and lets AI agents
// explore it over MCP without seeing sensitive data.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/noir017/nasbutler/internal/catalog"
	"github.com/noir017/nasbutler/internal/config"
	"github.com/noir017/nasbutler/internal/probe"
	"github.com/noir017/nasbutler/internal/redact"
	"github.com/noir017/nasbutler/internal/rules"
	"github.com/noir017/nasbutler/internal/scan"
	"github.com/noir017/nasbutler/internal/server"
)

var version = "dev"

const usage = `nasbutler — let AI agents explore a file archive without seeing sensitive data

Usage:
  nasbutler scan  -c config.toml [-no-hash]   bring the catalog up to date
  nasbutler serve -c config.toml [-stdio]     serve the catalog over MCP (HTTP by default)
  nasbutler check -c config.toml              validate the config and show the catalog state
  nasbutler version
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	switch cmd, args := os.Args[1], os.Args[2:]; cmd {
	case "scan":
		err = runScan(ctx, log, args)
	case "serve":
		err = runServe(ctx, log, args)
	case "check":
		err = runCheck(os.Stdout, args)
	case "version", "-v", "--version":
		fmt.Println("nasbutler", version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
	if err != nil {
		log.Error(err.Error())
		os.Exit(1)
	}
}

func loadConfig(name string, args []string, extra func(*flag.FlagSet)) (*config.Config, error) {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	path := fs.String("c", "config.toml", "config file")
	if extra != nil {
		extra(fs)
	}
	fs.Parse(args)
	return config.Load(*path)
}

func runScan(ctx context.Context, log *slog.Logger, args []string) error {
	var noHash bool
	c, err := loadConfig("scan", args, func(fs *flag.FlagSet) {
		fs.BoolVar(&noHash, "no-hash", false, "skip duplicate hashing")
	})
	if err != nil {
		return err
	}
	unlock, err := lockFile(c.LockPath())
	if err != nil {
		return err
	}
	defer unlock()
	key, err := redact.LoadOrCreateKey(c.KeyPath())
	if err != nil {
		return err
	}
	db, err := catalog.Open(c.CatalogPath(), false)
	if err != nil {
		return err
	}
	defer db.Close()
	log.Info("scan started", "rules", c.RuleSet.Fingerprint(), "secret_rules", c.RuleSet.SecretCount())
	st, err := scan.Run(ctx, db, scan.Options{
		Root:        c.Root,
		Rules:       c.RuleSet,
		Redactor:    redact.New(key),
		MaxContent:  c.Scan.MaxContentBytes,
		Hash:        *c.Scan.Hash && !noHash,
		HashMinSize: c.Scan.HashMinSize,
		Progress: func(st scan.Stats) {
			log.Info("scan progress", "phase", st.Phase, "files", st.Files, "bytes", st.Bytes,
				"reclassified", st.Reclassified, "hashed", st.Hashed, "errors", st.Errors)
		},
	})
	if err != nil {
		return fmt.Errorf("scan aborted: %w", err)
	}
	log.Info("scan finished", "files", st.Files, "dirs", st.Dirs, "removed", st.Removed,
		"hidden", st.Hidden, "opaque_dirs", st.Opaque, "skipped_special", st.Special, "errors", st.Errors)
	return nil
}

func runServe(ctx context.Context, log *slog.Logger, args []string) error {
	var stdio bool
	c, err := loadConfig("serve", args, func(fs *flag.FlagSet) {
		fs.BoolVar(&stdio, "stdio", false, "serve one client over stdin/stdout instead of HTTP")
	})
	if err != nil {
		return err
	}
	for _, p := range []string{c.CatalogPath(), c.KeyPath()} {
		if _, err := os.Stat(p); err != nil {
			return fmt.Errorf("%w (run `nasbutler scan` first)", err)
		}
	}
	key, err := redact.LoadOrCreateKey(c.KeyPath())
	if err != nil {
		return err
	}
	db, err := catalog.Open(c.CatalogPath(), true)
	if err != nil {
		return err
	}
	defer db.Close()
	if fp, err := db.Rules(); err == nil && fp != c.RuleSet.Fingerprint() {
		log.Warn("secret rules changed since the last scan; run `nasbutler scan` to reclassify")
	}
	audit, err := os.OpenFile(c.AuditPath(), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	defer audit.Close()

	ms := server.New(server.Options{
		DB:             db,
		Redactor:       redact.New(key),
		Root:           c.Root,
		Audit:          audit,
		MaxResultBytes: c.Serve.MaxResultBytes,
		MaxLimit:       c.Serve.MaxLimit,
		FFprobe:        *c.Serve.FFprobe,
		Version:        version,
		Logger:         log,
	})
	if stdio {
		return server.ServeStdio(ctx, ms)
	}
	token, source, err := c.Token()
	if err != nil {
		return err
	}
	log.Info("token loaded", "source", source)
	return server.ServeHTTP(ctx, ms, c.Serve.Listen, token, log)
}

func runCheck(w io.Writer, args []string) error {
	c, err := loadConfig("check", args, nil)
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "config OK\n  root       %s\n  state_dir  %s\n", c.Root, c.StateDir)
	fmt.Fprintf(w, "  rules      %d hidden, %d opaque, %d secret (%d built in), fingerprint %s\n",
		len(c.Rules.Hidden), len(c.Rules.Opaque), c.RuleSet.SecretCount(), len(rules.BuiltinSecret), c.RuleSet.Fingerprint())
	fmt.Fprintf(w, "  ffprobe    %v\n", probe.Available(*c.Serve.FFprobe))
	if _, source, err := c.Token(); err != nil {
		fmt.Fprintf(w, "  token      none (%v); only -stdio will work\n", err)
	} else {
		fmt.Fprintf(w, "  token      from %s\n", source)
	}
	if _, err := os.Stat(c.CatalogPath()); errors.Is(err, os.ErrNotExist) {
		fmt.Fprintln(w, "  catalog    not created yet: run `nasbutler scan`")
		return nil
	}
	db, err := catalog.Open(c.CatalogPath(), true)
	if err != nil {
		return err
	}
	defer db.Close()
	st, err := db.Status()
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "  catalog    %d files, %d bytes, %d personal, %d secret, %d opaque dirs\n",
		st.Files, st.Bytes, st.PersonalFiles, st.SecretFiles, st.OpaqueDirs)
	fmt.Fprintf(w, "  last scan  started %s, finished %s, hashing finished %s\n", st.ScanStarted, st.ScanFinished, st.HashFinished)
	return nil
}
