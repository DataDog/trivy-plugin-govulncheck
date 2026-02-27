// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026-present Datadog, Inc.

package main

import (
	"testing"
)

func TestParseImagePathSpec(t *testing.T) {
	// Valid digest is 64 hex chars; use a short one for test - name.ParseReference accepts it in some versions
	sha := "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	tests := []struct {
		spec      string
		wantImage string
		wantPath  string
		wantErr   bool
	}{
		{"tianon/gosu:latest:usr/local/bin/gosu", "tianon/gosu:latest", "usr/local/bin/gosu", false},
		{"docker.io/library/busybox:1.36:bin/busybox", "docker.io/library/busybox:1.36", "bin/busybox", false},
		{"myreg.io/img:tag:path/to/file", "myreg.io/img:tag", "path/to/file", false},
		{"no-colon", "", "", true},
		{"only:", "", "", true},
		{":only", "", "", true},
		{"img:path", "img", "path", false},
		// image_url@sha256:xxxx:path
		{"myreg.io/img@" + sha + ":usr/bin/app", "myreg.io/img@" + sha, "usr/bin/app", false},
		// image_url:tag@sha256:xxxx:path
		{"myreg.io/img:v1@" + sha + ":usr/bin/app", "myreg.io/img:v1@" + sha, "usr/bin/app", false},
		// path with colon (parser finds valid ref from left)
		{"myreg.io/img:tag:path/with:colons", "myreg.io/img:tag", "path/with:colons", false},
	}
	for _, tt := range tests {
		t.Run(tt.spec, func(t *testing.T) {
			gotImage, gotPath, err := ParseImagePathSpec(tt.spec)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseImagePathSpec() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && (gotImage != tt.wantImage || gotPath != tt.wantPath) {
				t.Errorf("ParseImagePathSpec() = %q, %q, want %q, %q", gotImage, gotPath, tt.wantImage, tt.wantPath)
			}
		})
	}
}

func TestExportFileFromImageSpec_parseErrors(t *testing.T) {
	// Only test parse errors; actual export requires network and an image.
	for _, input := range []string{"", "nospace", "image:path"} {
		err := ExportFileFromImageSpec(input)
		if err == nil {
			t.Errorf("ExportFileFromImageSpec(%q) expected error", input)
		}
	}
}
