// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 noir017

package executor

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/noir017/nasbutler/internal/plan"
)

// PurgedPlan is one quarantine directory that was (or would be) removed.
type PurgedPlan struct {
	ID    string
	Files int64
	Bytes int64
}

// Purge deletes the quarantine directories of plans that finished more
// than olderThan ago. It is the only code in nasbutler that deletes files,
// and it is reachable only from the command line, never over MCP.
// Directories that do not belong to a finished plan are left alone.
func Purge(dir, quarantine string, olderThan time.Duration, dryRun bool) ([]PurgedPlan, error) {
	if !filepath.IsAbs(quarantine) || filepath.Dir(quarantine) == quarantine {
		return nil, fmt.Errorf("refusing to purge %q", quarantine)
	}
	entries, err := os.ReadDir(quarantine)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []PurgedPlan
	for _, e := range entries {
		id := e.Name()
		if !e.IsDir() || !plan.ValidID(id) {
			continue
		}
		r, err := LoadRecord(dir, id)
		if err != nil || !r.State.Finished() || r.Finished.IsZero() || time.Since(r.Finished) < olderThan {
			continue
		}
		p := PurgedPlan{ID: id}
		target := filepath.Join(quarantine, id)
		filepath.WalkDir(target, func(_ string, d fs.DirEntry, err error) error {
			if err == nil && d.Type().IsRegular() {
				if info, err := d.Info(); err == nil {
					p.Files++
					p.Bytes += info.Size()
				}
			}
			return nil
		})
		if !dryRun {
			if err := os.RemoveAll(target); err != nil { // never follows symlinks
				return out, err
			}
		}
		out = append(out, p)
	}
	return out, nil
}
