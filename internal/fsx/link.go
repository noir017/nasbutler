// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 noir017

package fsx

import "os"

// linkUnlink moves a file by hard-linking it to the destination (which
// fails if the destination exists) and then removing the old name.
func linkUnlink(from, to string) error {
	if err := os.Link(from, to); err != nil {
		return err
	}
	return os.Remove(from)
}
