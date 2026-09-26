// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 noir017

// Package detect finds sensitive values in bytes: personal identifiers
// (Chinese ID numbers, mobile numbers, bank cards, e-mail addresses) and
// credentials (private keys, API tokens, password assignments).
//
// Detectors report positions and types only. Callers must never persist or
// return the matched values themselves.
package detect

import (
	"bytes"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Level orders how much of a file an agent may learn about.
type Level int

const (
	// Normal files expose their metadata and (redacted) names.
	Normal Level = iota
	// Personal files contain personal identifiers; names are redacted.
	Personal
	// Secret files hold credentials or live in a secret container; their
	// names are replaced wholesale by a pseudonym.
	Secret
)

func (l Level) String() string {
	switch l {
	case Personal:
		return "personal"
	case Secret:
		return "secret"
	default:
		return "normal"
	}
}

// ParseLevel is the inverse of Level.String.
func ParseLevel(s string) (Level, bool) {
	switch s {
	case "normal":
		return Normal, true
	case "personal":
		return Personal, true
	case "secret":
		return Secret, true
	}
	return Normal, false
}

// Type names a kind of sensitive value.
type Type string

const (
	CNID       Type = "cn_id"
	CNMobile   Type = "cn_mobile"
	BankCard   Type = "bank_card"
	Email      Type = "email"
	PrivateKey Type = "private_key"
	APIToken   Type = "api_token"
	Credential Type = "credential"
	// KeyStore is reported by Sniff for binary password databases.
	KeyStore Type = "keystore"
)

// Types lists every Type in a stable order, for reports.
var Types = []Type{CNID, CNMobile, BankCard, Email, PrivateKey, APIToken, Credential, KeyStore}

// Level is the file level implied by one finding of this type.
func (t Type) Level() Level {
	switch t {
	case CNID, CNMobile, BankCard, Email:
		return Personal
	default:
		return Secret
	}
}

// Label is the short tag used in pseudonyms, e.g. "[phone#1a2b3c4d]".
func (t Type) Label() string {
	switch t {
	case CNID:
		return "cn-id"
	case CNMobile:
		return "phone"
	case BankCard:
		return "bank-card"
	case Email:
		return "email"
	case PrivateKey:
		return "private-key"
	case APIToken:
		return "token"
	case KeyStore:
		return "keystore"
	default:
		return "credential"
	}
}

// Finding locates one sensitive value: b[Start:End].
type Finding struct {
	Type       Type
	Start, End int
}

// Normalize maps equivalent spellings of a value to one form, so that
// "138 1234 5678" and "13812345678" share a pseudonym.
func (f Finding) Normalize(b []byte) string {
	v := b[f.Start:f.End]
	switch f.Type {
	case CNID, CNMobile, BankCard:
		var sb strings.Builder
		for _, c := range v {
			if isDigit(c) || c == 'X' || c == 'x' {
				sb.WriteByte(upper(c))
			}
		}
		s := sb.String()
		if f.Type == CNMobile && len(s) > 11 {
			s = s[len(s)-11:] // drop the 86 / 0086 country prefix
		}
		return s
	case Email:
		return strings.ToLower(string(v))
	}
	return string(v)
}

// MaxLevel is the highest level implied by the findings.
func MaxLevel(fs []Finding) Level {
	l := Normal
	for _, f := range fs {
		if fl := f.Type.Level(); fl > l {
			l = fl
		}
	}
	return l
}

var (
	spacedMobile = regexp.MustCompile(`1[3-9]\d[ -]\d{4}[ -]\d{4}`)
	spacedCard   = regexp.MustCompile(`\d{4}(?:[ -]\d{4}){3}(?:[ -]?\d{1,3})?`)
	email        = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,24}`)

	privateKey = regexp.MustCompile(`-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----|PuTTY-User-Key-File-\d+:`)

	tokens = []*regexp.Regexp{
		regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
		regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,}\b`),
		regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{22,}\b`),
		regexp.MustCompile(`\bxox[abposr]-[A-Za-z0-9-]{10,}`),
		regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}`),
		regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`),
		// Telegram bot tokens: <bot id>:<35 chars>.
		regexp.MustCompile(`\b\d{8,10}:[A-Za-z0-9_-]{35}\b`),
	}
	// "sk-" keys (OpenAI, Anthropic, DeepSeek, one-api style gateways) are
	// checked by skKeyOK, because a bare pattern also matches prose such as
	// "sk-learn-tutorial-notes".
	skKey = regexp.MustCompile(`\bsk-[A-Za-z0-9_\-]{20,}`)

	quotedCredential = regexp.MustCompile(`(?i)(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key)["']?\s*[:=]\s*["']([^"'\s]{6,})["']`)
	envCredential    = regexp.MustCompile(`(?m)^[ \t]*(?:export[ \t]+)?[A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|APIKEY)[A-Z0-9_]*[ \t]*=[ \t]*([^\s#'"]{6,})`)
)

// Find returns the sensitive values in b, sorted by position and without
// overlaps (on overlap the earlier, then longer, finding wins).
func Find(b []byte) []Finding {
	var fs []Finding
	fs = findDigitRuns(b, fs)
	for _, loc := range spacedMobile.FindAllIndex(b, -1) {
		if digitBounded(b, loc[0], loc[1]) {
			fs = append(fs, Finding{CNMobile, loc[0], loc[1]})
		}
	}
	for _, loc := range spacedCard.FindAllIndex(b, -1) {
		if digitBounded(b, loc[0], loc[1]) && validCard(digitsOf(b[loc[0]:loc[1]])) {
			fs = append(fs, Finding{BankCard, loc[0], loc[1]})
		}
	}
	for _, loc := range email.FindAllIndex(b, -1) {
		if !fileLikeTLD(b[loc[0]:loc[1]]) {
			fs = append(fs, Finding{Email, loc[0], loc[1]})
		}
	}
	for _, loc := range privateKey.FindAllIndex(b, -1) {
		fs = append(fs, Finding{PrivateKey, loc[0], loc[1]})
	}
	for _, re := range tokens {
		for _, loc := range re.FindAllIndex(b, -1) {
			fs = append(fs, Finding{APIToken, loc[0], loc[1]})
		}
	}
	for _, loc := range skKey.FindAllIndex(b, -1) {
		if skKeyOK(b[loc[0]+3 : loc[1]]) {
			fs = append(fs, Finding{APIToken, loc[0], loc[1]})
		}
	}
	for _, re := range []*regexp.Regexp{quotedCredential, envCredential} {
		for _, m := range re.FindAllSubmatchIndex(b, -1) {
			if !placeholderValue(b[m[2]:m[3]]) {
				fs = append(fs, Finding{Credential, m[2], m[3]})
			}
		}
	}
	return dedupe(fs)
}

// FindString is Find for strings.
func FindString(s string) []Finding { return Find([]byte(s)) }

// Sniff recognises binary password databases by their magic bytes.
func Sniff(head []byte) (Type, bool) {
	// KeePass 2.x (kdbx) and 1.x (kdb).
	if bytes.HasPrefix(head, []byte{0x03, 0xD9, 0xA2, 0x9A, 0x67, 0xFB, 0x4B, 0xB5}) ||
		bytes.HasPrefix(head, []byte{0x03, 0xD9, 0xA2, 0x9A, 0x65, 0xFB, 0x4B, 0xB5}) {
		return KeyStore, true
	}
	return "", false
}

// findDigitRuns classifies maximal runs of ASCII digits by length. Working on
// whole runs gives digit boundaries for free: a 20-digit camera timestamp is
// never mistaken for the bank card hiding in its first 16 digits.
func findDigitRuns(b []byte, fs []Finding) []Finding {
	for i := 0; i < len(b); {
		if !isDigit(b[i]) {
			i++
			continue
		}
		s := i
		for i < len(b) && isDigit(b[i]) {
			i++
		}
		e := i
		n := e - s
		run := string(b[s:e])
		switch {
		case n == 17 && e < len(b) && (b[e] == 'X' || b[e] == 'x') && !(e+1 < len(b) && isAlnum(b[e+1])):
			if validCNID(run + "X") {
				fs = append(fs, Finding{CNID, s, e + 1})
				i = e + 1
			}
		case n == 18 && validCNID(run):
			fs = append(fs, Finding{CNID, s, e})
		case n == 11 && mobilePrefix(run):
			fs = append(fs, Finding{CNMobile, s, e})
		case n == 13 && strings.HasPrefix(run, "86") && mobilePrefix(run[2:]),
			n == 15 && strings.HasPrefix(run, "0086") && mobilePrefix(run[4:]):
			fs = append(fs, Finding{CNMobile, s, e})
		case n >= 15 && n <= 19 && validCard(run):
			fs = append(fs, Finding{BankCard, s, e})
		}
	}
	return fs
}

func mobilePrefix(s string) bool {
	return len(s) == 11 && s[0] == '1' && s[1] >= '3' && s[1] <= '9'
}

var cnidWeights = [17]int{7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2}

// validCNID checks an 18-character resident ID number (GB 11643): region,
// birth date and the mod-11 check character.
func validCNID(s string) bool {
	if len(s) != 18 || s[0] < '1' || s[0] > '8' {
		return false
	}
	for i := 0; i < 17; i++ {
		if !isDigit(s[i]) {
			return false
		}
	}
	y, m, d := atoi(s[6:10]), atoi(s[10:12]), atoi(s[12:14])
	if y < 1900 || y > time.Now().Year() || m < 1 || m > 12 || d < 1 {
		return false
	}
	if t := time.Date(y, time.Month(m), d, 0, 0, 0, 0, time.UTC); t.Day() != d {
		return false // e.g. February 30th
	}
	sum := 0
	for i := 0; i < 17; i++ {
		sum += int(s[i]-'0') * cnidWeights[i]
	}
	return upper(s[17]) == "10X98765432"[sum%11]
}

// validCard checks issuer prefix and length before the Luhn checksum. The
// prefix check matters: one in ten random digit strings passes Luhn, and
// date-like runs ("2024…") start with digits no card network issues.
func validCard(d string) bool {
	n := len(d)
	if n < 15 || n > 19 {
		return false
	}
	p2, p4 := atoi(d[:2]), atoi(d[:4])
	ok := false
	switch {
	case d[0] == '4':
		ok = n == 16 || n == 19
	case p2 >= 51 && p2 <= 55, p4 >= 2221 && p4 <= 2720:
		ok = n == 16
	case p2 == 34 || p2 == 37:
		ok = n == 15
	case p2 == 62, p2 == 65, p4 == 6011, p4 >= 3528 && p4 <= 3589:
		ok = n >= 16
	}
	return ok && luhn(d)
}

func luhn(d string) bool {
	sum := 0
	for i := 0; i < len(d); i++ {
		v := int(d[len(d)-1-i] - '0')
		if i%2 == 1 {
			v *= 2
			if v > 9 {
				v -= 9
			}
		}
		sum += v
	}
	return sum%10 == 0
}

// skKeyOK accepts the part after "sk-" when it contains a long unbroken
// run with a digit in it, as real keys do and hyphenated prose does not.
func skKeyOK(rest []byte) bool {
	run, hasDigit := 0, false
	for _, c := range rest {
		if isAlnum(c) || c == '_' {
			run++
			if isDigit(c) {
				hasDigit = true
			}
			if run >= 20 && hasDigit {
				return true
			}
			continue
		}
		run, hasDigit = 0, false
	}
	return false
}

// fileLikeTLD rejects "addresses" that are really asset names such as
// "icon@2x.png", which the e-mail pattern otherwise accepts.
func fileLikeTLD(m []byte) bool {
	tld := strings.ToLower(string(m[bytes.LastIndexByte(m, '.')+1:]))
	switch tld {
	case "png", "jpg", "jpeg", "gif", "svg", "webp", "bmp", "ico", "pdf", "txt", "md",
		"js", "css", "json", "html", "htm", "xml", "zip", "mp3", "mp4", "mov", "avi", "mkv":
		return true
	}
	return false
}

func placeholderValue(v []byte) bool {
	s := strings.ToLower(string(v))
	if strings.HasPrefix(s, "$") || strings.HasPrefix(s, "<") || strings.Contains(s, "{{") || strings.Contains(s, "${") {
		return true
	}
	for _, p := range []string{"xxxx", "****", "change", "your", "example", "placeholder", "dummy", "redacted"} {
		if strings.Contains(s, p) {
			return true
		}
	}
	return false
}

func dedupe(fs []Finding) []Finding {
	if len(fs) < 2 {
		return fs
	}
	sort.Slice(fs, func(i, j int) bool {
		if fs[i].Start != fs[j].Start {
			return fs[i].Start < fs[j].Start
		}
		return fs[i].End > fs[j].End
	})
	out := fs[:1]
	for _, f := range fs[1:] {
		if f.Start >= out[len(out)-1].End {
			out = append(out, f)
		}
	}
	return out
}

func digitBounded(b []byte, s, e int) bool {
	return (s == 0 || !isDigit(b[s-1])) && (e == len(b) || !isDigit(b[e]))
}

func digitsOf(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		if isDigit(c) {
			sb.WriteByte(c)
		}
	}
	return sb.String()
}

func atoi(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		n = n*10 + int(s[i]-'0')
	}
	return n
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isAlnum(c byte) bool {
	return isDigit(c) || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func upper(c byte) byte {
	if c >= 'a' && c <= 'z' {
		return c - 'a' + 'A'
	}
	return c
}
