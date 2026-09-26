// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 noir017

//go:build linux

package fsx

import (
	"errors"
	"os"
	"syscall"
)

// OpenRead opens a file read-only without following a final symlink and,
// where the kernel allows it (file owner or CAP_FOWNER), without updating
// its access time: cataloging should leave no trace on the files.
func OpenRead(p string) (*os.File, error) {
	flags := syscall.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC
	fd, err := syscall.Open(p, flags|syscall.O_NOATIME, 0)
	if errors.Is(err, syscall.EPERM) {
		fd, err = syscall.Open(p, flags, 0)
	}
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: p, Err: err}
	}
	return os.NewFile(uintptr(fd), p), nil
}
