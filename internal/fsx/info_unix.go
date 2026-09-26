// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 noir017

//go:build unix

package fsx

import (
	"io/fs"
	"syscall"
)

// Inode returns the file's inode number, or 0 if unknown.
func Inode(info fs.FileInfo) int64 {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return int64(st.Ino)
	}
	return 0
}

// Dev returns the id of the filesystem holding the file, or 0 if unknown.
func Dev(info fs.FileInfo) uint64 {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Dev)
	}
	return 0
}
