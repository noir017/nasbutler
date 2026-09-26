// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 noir017

//go:build unix

package main

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// lockFile takes an exclusive lock so overlapping scans (say, a slow scan
// still running when cron fires the next one) fail fast instead of racing.
func lockFile(path string) (unlock func(), err error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, fmt.Errorf("another scan is running (%s is locked)", path)
		}
		return nil, err
	}
	return func() { f.Close() }, nil
}
