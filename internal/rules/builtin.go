// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 noir017

package rules

// BuiltinSecret are secret rules that are always on. A directory match makes
// everything beneath it secret. Bump Version when editing this list.
var BuiltinSecret = []string{
	// Credential and key stores.
	".ssh", ".gnupg", ".aws", ".kube", ".docker", ".password-store",
	"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
	"*.pem", "*.key", "*.p12", "*.pfx", "*.jks", "*.keystore", "*.ovpn", "*.ppk",
	"*.kdbx", "*.kdb", "*.keychain", "*.keychain-db", "*.opvault", "*.1pif",
	".env", ".env.*", ".netrc", ".git-credentials", ".pgpass", ".htpasswd",
	"credentials.json", "**/etc/shadow",

	// Chat history.
	"wechat files", "xwechat_files", "micromsg", "com.tencent.mm",
	"tencent files", "com.tencent.mobileqq", "msg3.0.db", "enmicromsg.db",
	"tdata", "chatexport_*",

	// Browser profile secrets. "Cookies" is only matched inside a profile,
	// so that a folder of cookie recipes stays visible.
	"login data", "login data-journal", "web data", "key4.db", "logins.json",
	"**/default/cookies", "**/profile */cookies", "**/network/cookies",

	// Cryptocurrency wallets.
	"wallet.dat", "keystore", "electrum",
}
