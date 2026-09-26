// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 noir017

//go:build !unix

package scan

import "io/fs"

func inode(fs.FileInfo) int64 { return 0 }
