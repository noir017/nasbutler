// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 noir017

//go:build !unix

package fsx

import "io/fs"

// Inode is unknown outside Unix.
func Inode(fs.FileInfo) int64 { return 0 }

// Dev is unknown outside Unix.
func Dev(fs.FileInfo) uint64 { return 0 }
