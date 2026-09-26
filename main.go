// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 noir017

// Command nasbutler catalogs a personal file archive and lets AI agents
// explore and reorganise it over MCP without seeing sensitive data.
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
	"strings"
	"syscall"

	"github.com/noir017/nasbutler/internal/catalog"
	"github.com/noir017/nasbutler/internal/config"
	"github.com/noir017/nasbutler/internal/lock"
	"github.com/noir017/nasbutler/internal/plan"
	"github.com/noir017/nasbutler/internal/probe"
	"github.com/noir017/nasbutler/internal/redact"
	"github.com/noir017/nasbutler/internal/rules"
	"github.com/noir017/nasbutler/internal/scan"
	"github.com/noir017/nasbutler/internal/server"
)

var version = "dev"

const usage = `nasbutler — let AI agents organise a file archive without seeing sensitive data

Usage:
  nasbutler scan  -c config.toml [-no-hash]       bring the catalog up to date
  nasbutler serve -c config.toml [-stdio]         serve the catalog over MCP (HTTP by default)
  nasbutler exec  -c config.toml                  run the executor: approvals and approved plans
  nasbutler plan  list|show|approve|reject [id] -c config.toml
                                                  inspect plans (real paths); approve/reject with the local approver
  nasbutler purge -c config.toml [-older-than 720h] [-dry-run]
                                                  delete quarantine directories of old finished plans
  nasbutler feishu test -c config.toml [-open-id ID | -email ADDR]
                                                  send a test card and report who clicks it
  nasbutler check -c config.toml                  validate the config and show the catalog state
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
	case "exec":
		err = runExec(ctx, log, args)
	case "plan":
		err = runPlan(os.Stdout, args)
	case "purge":
		err = runPurge(os.Stdout, args)
	case "feishu":
		err = runFeishu(ctx, log, args)
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

// loadConfig parses flags (plus any extra ones) and loads the config. A
// leading non-flag argument is returned as a positional argument, so both
// `plan show ID -c x` and `plan show -c x ID` work.
func loadConfig(name string, args []string, extra func(*flag.FlagSet)) (*config.Config, string, error) {
	var pos string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		pos, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	path := fs.String("c", "config.toml", "config file")
	if extra != nil {
		extra(fs)
	}
	fs.Parse(args)
	if pos == "" {
		pos = fs.Arg(0)
	}
	c, err := config.Load(*path)
	return c, pos, err
}

func scanOptions(c *config.Config, red *redact.Redactor, hash bool, log *slog.Logger) scan.Options {
	return scan.Options{
		Root:        c.Root,
		Rules:       c.RuleSet,
		Redactor:    red,
		MaxContent:  c.Scan.MaxContentBytes,
		Hash:        hash,
		HashMinSize: c.Scan.HashMinSize,
		Progress: func(st scan.Stats) {
			log.Info("scan progress", "phase", st.Phase, "files", st.Files, "bytes", st.Bytes,
				"reclassified", st.Reclassified, "hashed", st.Hashed, "errors", st.Errors)
		},
	}
}

// requireCatalog checks that a scan has run.
func requireCatalog(c *config.Config) error {
	for _, p := range []string{c.CatalogPath(), c.KeyPath()} {
		if _, err := os.Stat(p); err != nil {
			return fmt.Errorf("%w (run `nasbutler scan` first)", err)
		}
	}
	return nil
}

func runScan(ctx context.Context, log *slog.Logger, args []string) error {
	var noHash bool
	c, _, err := loadConfig("scan", args, func(fs *flag.FlagSet) {
		fs.BoolVar(&noHash, "no-hash", false, "skip duplicate hashing")
	})
	if err != nil {
		return err
	}
	unlock, err := lock.File(c.LockPath())
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
	st, err := scan.Run(ctx, db, scanOptions(c, redact.New(key), *c.Scan.Hash && !noHash, log))
	if err != nil {
		return fmt.Errorf("scan aborted: %w", err)
	}
	log.Info("scan finished", "files", st.Files, "dirs", st.Dirs, "removed", st.Removed,
		"hidden", st.Hidden, "opaque_dirs", st.Opaque, "skipped_special", st.Special, "errors", st.Errors)
	return nil
}

func runServe(ctx context.Context, log *slog.Logger, args []string) error {
	var stdio bool
	c, _, err := loadConfig("serve", args, func(fs *flag.FlagSet) {
		fs.BoolVar(&stdio, "stdio", false, "serve one client over stdin/stdout instead of HTTP")
	})
	if err != nil {
		return err
	}
	if err := requireCatalog(c); err != nil {
		return err
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
	if err := os.MkdirAll(c.Plans.Dir, 0o700); err != nil {
		return err
	}

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
		Plans:          plan.Store{Dir: c.Plans.Dir},
		// The server validates against the catalog only; the executor
		// repeats everything with filesystem checks.
		Validator: &plan.Validator{DB: db, Rules: c.RuleSet, Root: c.Root, Quarantine: c.Exec.QuarantineDir},
		MaxOps:    c.Plans.MaxOps,
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
	c, _, err := loadConfig("check", args, nil)
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "config OK\n  root        %s\n  state_dir   %s\n", c.Root, c.StateDir)
	fmt.Fprintf(w, "  rules       %d hidden, %d opaque, %d protected, %d secret (%d built in), fingerprint %s\n",
		len(c.Rules.Hidden), len(c.Rules.Opaque), len(c.Rules.Protected), c.RuleSet.SecretCount(), len(rules.BuiltinSecret), c.RuleSet.Fingerprint())
	fmt.Fprintf(w, "  plans       %s (max %d ops)\n  exec        %s\n  quarantine  %s\n", c.Plans.Dir, c.Plans.MaxOps, c.Exec.Dir, c.Exec.QuarantineDir)
	fmt.Fprintf(w, "  approver    %s, requests valid for %s\n", c.Exec.Approver, c.ApprovalTTL)
	if c.Exec.Approver == "feishu" {
		_, source, err := c.FeishuSecret()
		switch {
		case c.Feishu.AppID == "" || c.Feishu.ApproverOpenID == "":
			fmt.Fprintln(w, "  feishu      feishu.app_id and feishu.approver_open_id are required")
		case err != nil:
			fmt.Fprintf(w, "  feishu      app secret: %v\n", err)
		default:
			fmt.Fprintf(w, "  feishu      app %s, secret from %s, base %s\n", c.Feishu.AppID, source, c.Feishu.BaseURL)
		}
	}
	fmt.Fprintf(w, "  ffprobe     %v\n", probe.Available(*c.Serve.FFprobe))
	if _, source, err := c.Token(); err != nil {
		fmt.Fprintf(w, "  token       none (%v); only -stdio will work\n", err)
	} else {
		fmt.Fprintf(w, "  token       from %s\n", source)
	}
	if _, err := os.Stat(c.CatalogPath()); errors.Is(err, os.ErrNotExist) {
		fmt.Fprintln(w, "  catalog     not created yet: run `nasbutler scan`")
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
	fmt.Fprintf(w, "  catalog     %d files, %d bytes, %d personal, %d secret, %d opaque dirs\n",
		st.Files, st.Bytes, st.PersonalFiles, st.SecretFiles, st.OpaqueDirs)
	fmt.Fprintf(w, "  last scan   started %s, finished %s, hashing finished %s\n", st.ScanStarted, st.ScanFinished, st.HashFinished)
	return nil
}
