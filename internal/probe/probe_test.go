// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 noir017

package probe

import (
	"strings"
	"testing"
)

func TestParseAllowList(t *testing.T) {
	out := []byte(`{
		"streams": [
			{"codec_type": "video", "codec_name": "hevc", "width": 2560, "height": 1440, "avg_frame_rate": "30000/1001",
			 "tags": {"location": "+31.2304+121.4737/"}},
			{"codec_type": "audio", "codec_name": "aac", "avg_frame_rate": "0/0"}
		],
		"format": {"format_name": "mov,mp4,m4a,3gp,3g2,mj2", "duration": "600.040000", "bit_rate": "4000123",
		           "tags": {"title": "private title", "com.apple.quicktime.location.ISO6709": "+31.2304+121.4737/"}}
	}`)
	m, err := parse(out)
	if err != nil {
		t.Fatal(err)
	}
	if m.DurationSec != 600.04 || m.BitRate != 4000123 || len(m.Streams) != 2 {
		t.Fatalf("parse = %+v", m)
	}
	if v := m.Streams[0]; v.Codec != "hevc" || v.Width != 2560 || v.FPS != "29.97002997002997" {
		t.Errorf("video stream = %+v", v)
	}
	if a := m.Streams[1]; a.Codec != "aac" || a.FPS != "" || a.Width != 0 {
		t.Errorf("audio stream = %+v", a)
	}
}

func TestParseNeverKeepsTags(t *testing.T) {
	m, _ := parse([]byte(`{"format": {"tags": {"title": "secret-title"}}}`))
	if strings.Contains(strings.ToLower(m.Format), "secret") {
		t.Fatal("tags leaked into the result")
	}
}

func TestFailureHidesDetails(t *testing.T) {
	if _, err := parse([]byte("/data/private/file.mp4: Invalid data")); err != ErrFailed {
		t.Fatalf("err = %v", err)
	}
}
