// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 noir017

//go:build !linux

package fsx

import "os"

// OpenRead opens a file read-only. Only the Linux build refuses symlinks
// and avoids access-time updates; other platforms are for development.
func OpenRead(p string) (*os.File, error) { return os.Open(p) }
