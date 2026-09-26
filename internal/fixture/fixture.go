// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 noir017

// Package fixture builds a small, deliberately messy directory tree for
// tests: duplicates, personal data, secrets, hidden and opaque areas.
package fixture

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Values that must never reach an agent, in any form.
var (
	Phone       = "13812345678"
	CNID        = "11010519491231002X"
	SKToken     = "sk-" + strings.Repeat("0f9e8d7c", 4)
	EnvPassword = "supersecret1"
	// SecretName is part of a directory name inside a secret directory.
	SecretName = "SENTINELNAME"
	// HiddenName names a file under a hidden directory.
	HiddenName = "diary-HIDDENNAME"
)

// Rules to use with the tree.
var (
	Hidden = []string{"/private"}
	Opaque = []string{"/backup"}
)

// Build creates the tree under a temp dir and returns its root.
func Build(t testing.TB) string {
	t.Helper()
	root := t.TempDir()
	big := bytes.Repeat([]byte("0123456789abcdef"), 200<<10/16) // 200 KiB
	bigDiff := append([]byte{}, big...)
	bigDiff[len(bigDiff)/2] ^= 0xFF // same size, head and tail: only a full hash tells them apart
	kdbx := append([]byte{0x03, 0xD9, 0xA2, 0x9A, 0x67, 0xFB, 0x4B, 0xB5}, make([]byte, 64)...)

	files := map[string][]byte{
		"photos/2024/IMG_20240101_123045.jpg":      []byte("jpeg-bytes-A"),
		"photos/2024/copy/IMG_20240101_123045.jpg": []byte("jpeg-bytes-A"),
		"photos/2024/Thumbs.db":                    []byte("junk"),
		"photos/2023/big.mp4":                      big,
		"photos/2023/big-copy.mp4":                 big,
		"photos/2023/big-diff.mp4":                 bigDiff,
		"docs/contacts.txt":                        []byte("张三 " + Phone + "\n"),
		"docs/notes.md":                            []byte("nothing sensitive here\n"),
		"docs/empty.txt":                           {},
		"docs/ID_" + CNID + ".jpg":                 []byte("scan of an id card"),
		"docs/api.txt":                             []byte("key: " + SKToken + "\n"),
		// A directory named after a phone number: plans must still be able
		// to address it through its pseudonym.
		"clients/" + Phone + "/invoice.pdf": []byte("%PDF-1.4 invoice"),
		"app/.env":                          []byte("DB_PASSWORD=" + EnvPassword + "\n"),
		"vault/renamed.dat":                 kdbx,
		"Phone Backup/WeChat Files/wxid_" + SecretName + "/Msg/chat.db": []byte("messages"),
		"private/" + HiddenName + ".txt":                                []byte("dear diary"),
		"backup/server1/etc/app.conf":                                   []byte("password = \"" + EnvPassword + "\"\n"),
		"backup/server1/data.bin":                                       []byte("0123456789"),
		// "中文.txt" in GBK, as old Chinese Windows systems wrote names.
		"docs/\xd6\xd0\xce\xc4.txt": []byte("gbk named"),
	}
	for rel, data := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// A symlink out of the root must never be followed.
	if err := os.Symlink("/etc/passwd", filepath.Join(root, "docs", "link")); err != nil {
		t.Fatal(err)
	}
	return root
}

// Forbidden lists strings no agent-facing output may contain.
func Forbidden(root string) []string {
	return []string{Phone, CNID, SKToken, EnvPassword, SecretName, HiddenName, "WeChat Files", root}
}
