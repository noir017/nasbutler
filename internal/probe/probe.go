// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 noir017

// Package probe reads technical media properties with ffprobe.
//
// Only an allow-list of fields is decoded: container, duration, bit rate,
// and per-stream codec, resolution and frame rate. Tags are never read,
// because they carry titles, device serials and GPS positions.
package probe

import (
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Timeout bounds one ffprobe run.
const Timeout = 20 * time.Second

// Stream is one elementary stream.
type Stream struct {
	Type   string `json:"type"`
	Codec  string `json:"codec,omitempty"`
	Width  int    `json:"width,omitempty"`
	Height int    `json:"height,omitempty"`
	FPS    string `json:"fps,omitempty"`
}

// Media describes a media file.
type Media struct {
	Format      string   `json:"format,omitempty"`
	DurationSec float64  `json:"duration_sec,omitempty"`
	BitRate     int64    `json:"bit_rate,omitempty"`
	Streams     []Stream `json:"streams,omitempty"`
}

// ErrFailed hides ffprobe's own messages, which quote the file path.
var ErrFailed = errors.New("media probe failed")

// Available reports whether the ffprobe binary can be found.
func Available(bin string) bool {
	if bin == "" {
		return false
	}
	_, err := exec.LookPath(bin)
	return err == nil
}

// Run probes the file at the absolute path abs.
func Run(ctx context.Context, bin, abs string) (*Media, error) {
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()
	// The "file:" prefix and protocol allow-list stop names such as
	// "http:x" or "concat:a|b" from being read as other protocols.
	out, err := exec.CommandContext(ctx, bin,
		"-v", "error", "-hide_banner", "-protocol_whitelist", "file",
		"-print_format", "json",
		"-show_entries", "format=format_name,duration,bit_rate:stream=codec_type,codec_name,width,height,avg_frame_rate",
		"-i", "file:"+abs).Output()
	if err != nil {
		return nil, ErrFailed
	}
	return parse(out)
}

func parse(out []byte) (*Media, error) {
	var raw struct {
		Streams []struct {
			CodecType string `json:"codec_type"`
			CodecName string `json:"codec_name"`
			Width     int    `json:"width"`
			Height    int    `json:"height"`
			FrameRate string `json:"avg_frame_rate"`
		} `json:"streams"`
		Format struct {
			FormatName string `json:"format_name"`
			Duration   string `json:"duration"`
			BitRate    string `json:"bit_rate"`
		} `json:"format"`
	}
	if err := json.Unmarshal(out, &raw); err != nil {
		return nil, ErrFailed
	}
	m := &Media{Format: raw.Format.FormatName}
	m.DurationSec, _ = strconv.ParseFloat(raw.Format.Duration, 64)
	m.BitRate, _ = strconv.ParseInt(raw.Format.BitRate, 10, 64)
	for _, s := range raw.Streams {
		st := Stream{Type: s.CodecType, Codec: s.CodecName}
		if s.CodecType == "video" {
			st.Width, st.Height, st.FPS = s.Width, s.Height, fps(s.FrameRate)
		}
		m.Streams = append(m.Streams, st)
	}
	return m, nil
}

// fps renders ffprobe's rational frame rate ("30000/1001") as "29.97".
func fps(r string) string {
	num, den, ok := strings.Cut(r, "/")
	n, err1 := strconv.ParseFloat(num, 64)
	d, err2 := strconv.ParseFloat(den, 64)
	if !ok || err1 != nil || err2 != nil || d == 0 || n == 0 {
		return ""
	}
	return strconv.FormatFloat(n/d, 'f', -1, 64)
}
