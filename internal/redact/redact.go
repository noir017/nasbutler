// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 noir017

// Package redact replaces sensitive values with keyed pseudonyms.
//
// A pseudonym is "[label#xxxxxxxx]", where the hex part is an HMAC of the
// normalised value under a key that never leaves the server. The same value
// always maps to the same pseudonym, so an agent can tell that thirty files
// mention one phone number without learning the number.
package redact

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"

	"github.com/noir017/nasbutler/internal/detect"
)

const keySize = 32

// Redactor holds the pseudonym key.
type Redactor struct {
	key []byte
}

// New returns a Redactor using key.
func New(key []byte) *Redactor { return &Redactor{key: key} }

// LoadOrCreateKey reads the key at path, creating a random one (mode 0600)
// if the file does not exist. Losing the key only renumbers pseudonyms.
func LoadOrCreateKey(path string) ([]byte, error) {
	key, err := os.ReadFile(path)
	if err == nil {
		if len(key) != keySize {
			return nil, fmt.Errorf("pseudonym key %s: want %d bytes, got %d", path, keySize, len(key))
		}
		return key, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	key = make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	if _, err := f.Write(key); err != nil {
		f.Close()
		return nil, err
	}
	return key, f.Close()
}

// Token returns the pseudonym for value under label.
func (r *Redactor) Token(label, value string) string {
	m := hmac.New(sha256.New, r.key)
	m.Write([]byte(label))
	m.Write([]byte{0})
	m.Write([]byte(value))
	return "[" + label + "#" + hex.EncodeToString(m.Sum(nil))[:8] + "]"
}

// String replaces every sensitive value in s and reports how many it found.
func (r *Redactor) String(s string) (string, int) {
	b := []byte(s)
	fs := detect.Find(b)
	if len(fs) == 0 {
		return s, 0
	}
	var sb strings.Builder
	last := 0
	for _, f := range fs {
		sb.Write(b[last:f.Start])
		sb.WriteString(r.Token(f.Type.Label(), f.Normalize(b)))
		last = f.End
	}
	sb.Write(b[last:])
	return sb.String(), len(fs)
}

// JSON redacts every string (object keys included) inside a JSON object or
// array, leaving numbers alone: a 13,812,345,678-byte file must keep its
// size. Anything else — a bare scalar, trailing data — is an error, so the
// caller falls back to redacting the whole text as a string rather than
// letting a bare number through or silently dropping the tail.
func (r *Redactor) JSON(doc []byte) ([]byte, int, error) {
	trimmed := bytes.TrimSpace(doc)
	if len(trimmed) == 0 || (trimmed[0] != '{' && trimmed[0] != '[') {
		return nil, 0, errors.New("not a JSON object or array")
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, 0, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, 0, errors.New("trailing data after JSON value")
	}
	n := 0
	v = r.walk(v, &n)
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, 0, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), n, nil
}

func (r *Redactor) walk(v any, n *int) any {
	switch x := v.(type) {
	case string:
		s, k := r.String(x)
		*n += k
		return s
	case []any:
		for i := range x {
			x[i] = r.walk(x[i], n)
		}
		return x
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			rk, c := r.String(k)
			*n += c
			out[rk] = r.walk(val, n)
		}
		return out
	}
	return v
}
