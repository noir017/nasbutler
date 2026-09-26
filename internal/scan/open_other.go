// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 noir017

//go:build !linux

package scan

import "os"

// openRead opens a file read-only. Only the Linux build refuses symlinks
// and avoids access-time updates; other platforms are for development.
func openRead(p string) (*os.File, error) { return os.Open(p) }
