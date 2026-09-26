// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 noir017

// Package kind sorts files into coarse categories by extension, name and,
// when the extension says nothing, by their leading bytes.
package kind

import (
	"net/http"
	"strings"
)

// Kind is a coarse file category.
type Kind string

const (
	Image      Kind = "image"
	Video      Kind = "video"
	Audio      Kind = "audio"
	Document   Kind = "document"
	Text       Kind = "text"
	Code       Kind = "code"
	Archive    Kind = "archive"
	DiskImage  Kind = "disk_image"
	Database   Kind = "database"
	Executable Kind = "executable"
	Font       Kind = "font"
	// Junk is leftovers that are safe cleanup candidates: temp files,
	// partial downloads, OS metadata.
	Junk  Kind = "junk"
	Empty Kind = "empty"
	Other Kind = "other"
)

var byExt = map[string]Kind{}

func init() {
	add := func(k Kind, exts string) {
		for _, e := range strings.Fields(exts) {
			byExt[e] = k
		}
	}
	add(Image, "jpg jpeg png gif bmp webp heic heif tif tiff avif jxl psd svg ico raw cr2 cr3 nef arw dng orf rw2 raf srw")
	// "ts" is here as MPEG transport stream, the common case on a NAS with
	// camera footage; Refine reclassifies TypeScript by its content.
	add(Video, "mp4 m4v mov avi mkv wmv flv f4v webm ts m2ts mts 3gp rmvb rm vob asf mpg mpeg ogv mxf dav 264 h264 265 h265 hevc")
	add(Audio, "mp3 wav flac aac m4a ogg opus wma ape amr aiff aif alac mid midi")
	add(Document, "pdf doc docx xls xlsx ppt pptx odt ods odp rtf wps et dps pages numbers epub mobi azw3 djvu chm vsd vsdx xmind")
	add(Text, "txt md markdown csv tsv log json jsonl xml yaml yml toml ini conf cfg properties srt ass vtt html htm rst tex org")
	add(Code, "go py js mjs cjs jsx tsx java kt kts scala c h cc cpp hpp cs rs rb php swift sh bash zsh fish ps1 bat cmd sql lua pl r vue css scss less dart gradle")
	add(Archive, "zip rar 7z tar gz tgz bz2 tbz2 xz txz zst lz4 lzma z cab")
	add(DiskImage, "iso img vmdk vdi vhd vhdx qcow2 dmg gho wim")
	add(Database, "db sqlite sqlite3 mdb accdb dbf frm ibd")
	add(Executable, "exe msi dll so dylib apk ipa deb rpm appimage jar")
	add(Font, "ttf otf woff woff2 ttc")
	add(Junk, "tmp temp part crdownload download partial swp swo")
}

var junkNames = map[string]bool{".ds_store": true, "thumbs.db": true, "desktop.ini": true, ".localized": true}

// Ext returns the lower-case extension of name without the dot.
func Ext(name string) string {
	i := strings.LastIndexByte(name, '.')
	if i < 0 || i == len(name)-1 {
		return ""
	}
	return strings.ToLower(name[i+1:])
}

// Guess classifies a file from its name and size. known is false when the
// name says nothing and the leading bytes should be consulted via Refine.
func Guess(name string, size int64) (k Kind, known bool) {
	lower := strings.ToLower(name)
	if junkNames[lower] || strings.HasPrefix(name, "~$") || strings.HasPrefix(name, "._") || strings.HasSuffix(name, "~") {
		return Junk, true
	}
	if size == 0 {
		return Empty, true
	}
	k, known = byExt[Ext(name)]
	if !known {
		return Other, false
	}
	return k, true
}

// NeedsHead reports whether the leading bytes are worth reading: to classify
// an unknown file, to check a text file for secrets, or to tell MPEG-TS from
// TypeScript. Media and archives are skipped to spare the disk a seek each.
func NeedsHead(name string, k Kind, known bool) bool {
	if !known {
		return true
	}
	switch k {
	case Text, Code, Database, Other:
		return true
	}
	return Ext(name) == "ts"
}

// Refine updates a guess using the file's leading bytes and returns the
// sniffed MIME type.
func Refine(name string, k Kind, known bool, head []byte) (Kind, string) {
	mime := http.DetectContentType(head)
	if Ext(name) == "ts" {
		if len(head) > 0 && head[0] == 0x47 { // MPEG-TS sync byte
			return Video, "video/mp2t"
		}
		if strings.HasPrefix(mime, "text/") {
			return Code, mime
		}
		return k, mime
	}
	if known {
		return k, mime
	}
	switch {
	case strings.HasPrefix(mime, "image/"):
		return Image, mime
	case strings.HasPrefix(mime, "video/"):
		return Video, mime
	case strings.HasPrefix(mime, "audio/"):
		return Audio, mime
	case mime == "application/pdf":
		return Document, mime
	case strings.HasPrefix(mime, "text/"), mime == "application/json":
		return Text, mime
	case mime == "application/zip", mime == "application/x-gzip", mime == "application/x-rar-compressed", mime == "application/x-7z-compressed":
		return Archive, mime
	}
	return Other, mime
}

// TextLike reports whether a file's content should be scanned for secrets.
func TextLike(k Kind, mime string) bool {
	if k == Text || k == Code {
		return true
	}
	return strings.HasPrefix(mime, "text/") || mime == "application/json"
}
