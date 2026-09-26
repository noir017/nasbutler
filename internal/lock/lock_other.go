// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 noir017

//go:build !unix

package lock

// File is a no-op outside Unix; nasbutler targets Linux.
func File(string) (func(), error) { return func() {}, nil }
