// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 noir017

//go:build unix

package lock

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// File takes an exclusive lock so that overlapping runs (a slow scan still
// going when cron fires the next one, or a second executor) fail fast.
func File(path string) (unlock func(), err error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, fmt.Errorf("another nasbutler process holds %s", path)
		}
		return nil, err
	}
	return func() { f.Close() }, nil
}
