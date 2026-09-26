// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 noir017

//go:build linux

package fsx

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// RenameNoReplace moves a file within one filesystem and fails with an
// error wrapping os.ErrExist if the destination exists. The check and the
// move are one atomic step (renameat2 RENAME_NOREPLACE); filesystems that
// lack it get link+unlink, which is just as unable to overwrite. Moving
// across filesystems fails (EXDEV): nothing is ever copied.
func RenameNoReplace(from, to string) error {
	err := unix.Renameat2(unix.AT_FDCWD, from, unix.AT_FDCWD, to, unix.RENAME_NOREPLACE)
	if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOSYS) {
		return linkUnlink(from, to)
	}
	if err != nil {
		return &os.LinkError{Op: "rename", Old: from, New: to, Err: err}
	}
	return nil
}
