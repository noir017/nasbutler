// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 noir017

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync/atomic"
	"text/tabwriter"
	"time"

	"github.com/noir017/nasbutler/internal/approval"
	"github.com/noir017/nasbutler/internal/approval/feishu"
	"github.com/noir017/nasbutler/internal/catalog"
	"github.com/noir017/nasbutler/internal/config"
	"github.com/noir017/nasbutler/internal/executor"
	"github.com/noir017/nasbutler/internal/fsx"
	"github.com/noir017/nasbutler/internal/lock"
	"github.com/noir017/nasbutler/internal/plan"
	"github.com/noir017/nasbutler/internal/redact"
	"github.com/noir017/nasbutler/internal/scan"
)

func newApprover(c *config.Config, log *slog.Logger) (approval.Approver, error) {
	switch c.Exec.Approver {
	case "local":
		return &approval.Local{Dir: executor.DecisionsDir(c.Exec.Dir), Log: func(msg string, args ...any) { log.Info(msg, args...) }}, nil
	case "feishu":
		return newFeishu(c, log, nil)
	}
	return nil, fmt.Errorf("unknown approver %q", c.Exec.Approver)
}

func newFeishu(c *config.Config, log *slog.Logger, onTest func(string)) (*feishu.Approver, error) {
	if c.Feishu.AppID == "" {
		return nil, errors.New("feishu.app_id is not set")
	}
	secret, _, err := c.FeishuSecret()
	if err != nil {
		return nil, fmt.Errorf("feishu app secret: %w", err)
	}
	return feishu.New(feishu.Config{
		AppID: c.Feishu.AppID, AppSecret: secret, ApproverOpenID: c.Feishu.ApproverOpenID,
		BaseURL: c.Feishu.BaseURL, Log: log, OnTest: onTest,
	}), nil
}

func runExec(ctx context.Context, log *slog.Logger, args []string) error {
	c, _, err := loadConfig("exec", args, nil)
	if err != nil {
		return err
	}
	if err := requireCatalog(c); err != nil {
		return err
	}
	if err := os.MkdirAll(c.Exec.Dir, 0o700); err != nil {
		return err
	}
	unlock, err := lock.File(filepath.Join(c.Exec.Dir, "exec.lock"))
	if err != nil {
		return err
	}
	defer unlock()
	if c.Exec.Approver == "feishu" && c.Feishu.ApproverOpenID == "" {
		return errors.New("feishu.approver_open_id is not set (find it with `nasbutler feishu test`)")
	}
	ap, err := newApprover(c, log)
	if err != nil {
		return err
	}
	key, err := redact.LoadOrCreateKey(c.KeyPath())
	if err != nil {
		return err
	}
	db, err := catalog.Open(c.CatalogPath(), false)
	if err != nil {
		return err
	}
	defer db.Close()
	red := redact.New(key)

	var rescan func(context.Context) error
	if *c.Exec.Rescan {
		rescan = func(ctx context.Context) error {
			unlock, err := lock.File(c.LockPath())
			if err != nil {
				log.Warn("skipping rescan after execution: " + err.Error())
				return nil
			}
			defer unlock()
			_, err = scan.Run(ctx, db, scanOptions(c, red, *c.Scan.Hash, log))
			return err
		}
	}
	eng, err := executor.New(executor.Options{
		Root: c.Root, Quarantine: c.Exec.QuarantineDir, PlansDir: c.Plans.Dir, Dir: c.Exec.Dir,
		DB: db, Rules: c.RuleSet, Approver: ap, TTL: c.ApprovalTTL, MaxOps: c.Plans.MaxOps,
		Rescan: rescan, Log: log,
	})
	if err != nil {
		return err
	}
	log.Info("executor started", "approver", ap.Name(), "quarantine", c.Exec.QuarantineDir)
	return eng.Run(ctx)
}

// runPlan is for the human on the machine: it shows real paths.
func runPlan(w io.Writer, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: nasbutler plan list|show|approve|reject [id] -c config.toml")
	}
	sub := args[0]
	c, id, err := loadConfig("plan "+sub, args[1:], nil)
	if err != nil {
		return err
	}
	switch sub {
	case "list":
		return planList(w, c)
	case "show":
		return planShow(w, c, id)
	case "approve", "reject":
		if c.Exec.Approver != "local" {
			return fmt.Errorf("exec.approver is %q: decide on the approval card instead", c.Exec.Approver)
		}
		r, err := executor.LoadRecord(c.Exec.Dir, id)
		if err != nil {
			return fmt.Errorf("plan %s: %w (has the executor picked it up?)", id, err)
		}
		if r.State != plan.PendingApproval {
			return fmt.Errorf("plan %s is %s, not pending approval", id, r.State)
		}
		user := os.Getenv("USER")
		if user == "" {
			user = "cli"
		}
		d := approval.Decision{PlanID: id, Digest: r.Digest, Approve: sub == "approve", By: "local:" + user}
		if err := approval.WriteDecision(executor.DecisionsDir(c.Exec.Dir), d); err != nil {
			return err
		}
		fmt.Fprintf(w, "decision recorded; the executor applies it within seconds\n")
		return nil
	}
	return fmt.Errorf("unknown plan subcommand %q", sub)
}

func planList(w io.Writer, c *config.Config) error {
	recs, err := executor.ListRecords(c.Exec.Dir)
	if err != nil {
		return err
	}
	known := map[string]bool{}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tKIND\tSTATE\tOPS\tDONE\tREQUESTED\tTITLE")
	for _, r := range recs {
		known[r.ID] = true
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%d\t%s\t%s\n", r.ID, r.Kind, r.State, len(r.Ops), r.Done, r.Requested.Format("01-02 15:04"), r.Title)
	}
	plans, _ := plan.Store{Dir: c.Plans.Dir}.List()
	for _, p := range plans {
		if !known[p.ID] {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t-\t-\t%s\n", p.ID, p.Kind, p.State, len(p.Ops), p.Title)
		}
	}
	return tw.Flush()
}

func planShow(w io.Writer, c *config.Config, id string) error {
	r, err := executor.LoadRecord(c.Exec.Dir, id)
	if errors.Is(err, plan.ErrNotFound) {
		p, err := plan.Store{Dir: c.Plans.Dir}.Load(id)
		if err != nil {
			return err
		}
		fmt.Fprintf(w, "%s  %s  %s  (not yet taken in by the executor)\n", p.ID, p.State, p.Title)
		for i, op := range p.Ops {
			fmt.Fprintf(w, "  %3d  %-10s file %d → %s %s\n", i, op.Op, op.File, op.ToDir, op.Name)
		}
		return nil
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "%s  %s  %s\n", r.ID, r.State, r.Title)
	fmt.Fprintf(w, "  requested %s", r.Requested.Format(time.RFC3339))
	if !r.Expires.IsZero() {
		fmt.Fprintf(w, ", expires %s", r.Expires.Format(time.RFC3339))
	}
	if r.DecidedBy != "" {
		fmt.Fprintf(w, ", decided by %s", r.DecidedBy)
	}
	fmt.Fprintf(w, "\n  done %d, failed %d of %d\n", r.Done, r.Failed, len(r.Ops))
	for _, op := range r.Ops {
		fmt.Fprintf(w, "  %3d  %-10s %s\n       → %s\n", op.Index, op.Op, fsx.DisplayPath(op.FromRel), fsx.DisplayPath(op.ToRel))
	}
	for _, e := range r.Errors {
		fmt.Fprintf(w, "  error at %d: %s\n", e.Index, e.Error)
	}
	if r.Note != "" {
		fmt.Fprintf(w, "  note: %s\n", r.Note)
	}
	return nil
}

func runPurge(w io.Writer, args []string) error {
	var olderThan time.Duration
	var dryRun bool
	c, _, err := loadConfig("purge", args, func(fs *flag.FlagSet) {
		fs.DurationVar(&olderThan, "older-than", 30*24*time.Hour, "only plans finished at least this long ago")
		fs.BoolVar(&dryRun, "dry-run", false, "only report what would be deleted")
	})
	if err != nil {
		return err
	}
	purged, err := executor.Purge(c.Exec.Dir, c.Exec.QuarantineDir, olderThan, dryRun)
	var files, bytes int64
	for _, p := range purged {
		fmt.Fprintf(w, "%s  %d files, %d bytes\n", p.ID, p.Files, p.Bytes)
		files += p.Files
		bytes += p.Bytes
	}
	verb := "deleted"
	if dryRun {
		verb = "would delete"
	}
	fmt.Fprintf(w, "%s %d quarantine directories: %d files, %d bytes\n", verb, len(purged), files, bytes)
	return err
}

func runFeishu(ctx context.Context, log *slog.Logger, args []string) error {
	if len(args) == 0 || args[0] != "test" {
		return errors.New("usage: nasbutler feishu test -c config.toml [-open-id ID | -email ADDR]")
	}
	var openID, email string
	var wait time.Duration
	c, _, err := loadConfig("feishu test", args[1:], func(fs *flag.FlagSet) {
		fs.StringVar(&openID, "open-id", "", "send the test card to this open_id (default: feishu.approver_open_id)")
		fs.StringVar(&email, "email", "", "send the test card to this e-mail address instead")
		fs.DurationVar(&wait, "wait", 10*time.Minute, "how long to listen for clicks")
	})
	if err != nil {
		return err
	}
	var clicks atomic.Int32
	ap, err := newFeishu(c, log, func(id string) {
		n := clicks.Add(1)
		match := ""
		if id == c.Feishu.ApproverOpenID {
			match = " (this is feishu.approver_open_id)"
		}
		fmt.Printf("click #%d from open_id %s%s\n", n, id, match)
	})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- ap.Run(ctx, func(context.Context, approval.Decision) error { return errors.New("test mode") })
	}()

	typ, to := "open_id", openID
	switch {
	case email != "":
		typ, to = "email", email
	case to == "":
		to = c.Feishu.ApproverOpenID
	}
	if to == "" {
		return errors.New("no recipient: pass -open-id or -email, or set feishu.approver_open_id")
	}
	if err := ap.SendTest(ctx, typ, to); err != nil {
		return fmt.Errorf("sending the test card: %w", err)
	}
	fmt.Printf("test card sent to %s %s; click its button (several times). Ctrl-C to stop.\n", typ, to)
	err = <-done
	fmt.Printf("received %d click(s)\n", clicks.Load())
	return err
}
