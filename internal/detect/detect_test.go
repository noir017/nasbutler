// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 noir017

package detect

import (
	"strings"
	"testing"
)

// withCNIDCheck appends the GB 11643 check character to 17 digits.
func withCNIDCheck(p string) string {
	sum := 0
	for i := 0; i < 17; i++ {
		sum += int(p[i]-'0') * cnidWeights[i]
	}
	return p + string("10X98765432"[sum%11])
}

// withLuhn appends the Luhn check digit.
func withLuhn(p string) string {
	for d := byte('0'); d <= '9'; d++ {
		if luhn(p + string(d)) {
			return p + string(d)
		}
	}
	panic("unreachable")
}

func types(fs []Finding) []Type {
	var ts []Type
	for _, f := range fs {
		ts = append(ts, f.Type)
	}
	return ts
}

func TestFind(t *testing.T) {
	id := withCNIDCheck("11010519900307123")
	idX := "11010519491231002X" // widely published sample with an X check character
	card := withLuhn("622202123456789")
	// Built at runtime so that the repository never contains a string that
	// secret scanners would flag.
	ghToken := "gh" + "p_" + strings.Repeat("a1B2", 9)
	skToken := "sk-" + strings.Repeat("0f9e8d7c", 4)

	cases := []struct {
		name string
		in   string
		want []Type
	}{
		{"cn id", "身份证号 " + id + " 已登记", []Type{CNID}},
		{"cn id with X", "scan_" + idX + ".jpg", []Type{CNID}},
		{"cn id bad checksum", id[:17] + string("0123456789"[(strings.IndexByte("0123456789", id[17])+1)%10]), nil},
		{"cn id bad date", withCNIDCheck("11010519900230123"), nil},
		{"mobile", "电话13812345678", []Type{CNMobile}},
		{"mobile with country code", "+8613812345678", []Type{CNMobile}},
		{"mobile spaced", "138 1234 5678", []Type{CNMobile}},
		{"not mobile: second digit", "12812345678", nil},
		{"not mobile: 12 digits", "138123456789", nil},
		{"camera timestamp", "IMG_20240101_123045.jpg", nil},
		{"unix millis", "1700000000000", nil},
		{"long timestamp run", "ch01_20240101123045678901.dav", nil},
		{"bank card", "卡号" + card, []Type{BankCard}},
		{"visa spaced", "4111 1111 1111 1111", []Type{BankCard}},
		{"luhn failure", "4111111111111112", nil},
		{"email", "mail me: Some.One@Example.com.", []Type{Email}},
		{"asset name is not email", "icon@2x.png", nil},
		{"private key", "-----BEGIN OPENSSH PRIVATE KEY-----\nabc", []Type{PrivateKey}},
		{"aws key", "id=AKIAIOSFODNN7EXAMPLE", []Type{APIToken}},
		{"github token", "token " + ghToken, []Type{APIToken}},
		{"sk key", "OPENAI=" + skToken, []Type{APIToken}},
		{"sk prose", "sk-learn-tutorial-notes-for-beginners", nil},
		{"quoted credential", `password = "hunter22"`, []Type{Credential}},
		{"json credential", `{"api_key": "abcdef123"}`, []Type{Credential}},
		{"env credential", "DB_PASSWORD=s3cretvalue\n", []Type{Credential}},
		{"env placeholder", "DB_PASSWORD=${DB_PASS}\n", nil},
		{"quoted placeholder", `password: "changeme123"`, nil},
		{"two findings", "13812345678 and a@b.cn", []Type{CNMobile, Email}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := types(FindString(c.in))
			if strings.Join(toStrings(got), ",") != strings.Join(toStrings(c.want), ",") {
				t.Fatalf("Find(%q) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

func toStrings(ts []Type) []string {
	var s []string
	for _, t := range ts {
		s = append(s, string(t))
	}
	return s
}

func TestFindSpansCoverValue(t *testing.T) {
	in := `password = "hunter22"`
	fs := FindString(in)
	if len(fs) != 1 || in[fs[0].Start:fs[0].End] != "hunter22" {
		t.Fatalf("credential span = %+v, want the value only", fs)
	}
}

func TestNormalize(t *testing.T) {
	for _, in := range []string{"13812345678", "138 1234 5678", "+8613812345678", "008613812345678"} {
		fs := FindString(in)
		if len(fs) != 1 {
			t.Fatalf("Find(%q) = %v", in, fs)
		}
		if got := fs[0].Normalize([]byte(in)); got != "13812345678" {
			t.Errorf("Normalize(%q) = %q", in, got)
		}
	}
	in := "A@Example.COM"
	if got := FindString(in)[0].Normalize([]byte(in)); got != "a@example.com" {
		t.Errorf("email Normalize = %q", got)
	}
}

func TestSniff(t *testing.T) {
	kdbx := []byte{0x03, 0xD9, 0xA2, 0x9A, 0x67, 0xFB, 0x4B, 0xB5, 0, 0}
	if typ, ok := Sniff(kdbx); !ok || typ != KeyStore {
		t.Fatalf("Sniff(kdbx) = %v, %v", typ, ok)
	}
	if _, ok := Sniff([]byte("hello")); ok {
		t.Fatal("Sniff(text) reported a keystore")
	}
}

func TestLevels(t *testing.T) {
	if MaxLevel(nil) != Normal {
		t.Fatal("no findings must be normal")
	}
	if MaxLevel([]Finding{{Type: Email}}) != Personal {
		t.Fatal("email must be personal")
	}
	if MaxLevel([]Finding{{Type: Email}, {Type: Credential}}) != Secret {
		t.Fatal("credential must be secret")
	}
	for _, l := range []Level{Normal, Personal, Secret} {
		if got, ok := ParseLevel(l.String()); !ok || got != l {
			t.Fatalf("ParseLevel(%q) = %v, %v", l.String(), got, ok)
		}
	}
}
