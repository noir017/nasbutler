// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 noir017

// Package fsx holds the few filesystem primitives nasbutler relies on for
// safety: opening files without following symlinks or touching access
// times, and renaming without ever replacing an existing file.
package fsx
