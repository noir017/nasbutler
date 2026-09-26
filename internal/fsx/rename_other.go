// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 noir017

//go:build !linux

package fsx

// RenameNoReplace moves a file without ever replacing an existing one.
// Outside Linux it always uses link+unlink.
func RenameNoReplace(from, to string) error { return linkUnlink(from, to) }
