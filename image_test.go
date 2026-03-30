// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026-present Datadog, Inc.

package main

import (
	"archive/tar"
	"bytes"
	"errors"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
)

func TestErrIsSymlinkLoop(t *testing.T) {
	if !errIsSymlinkLoop(syscall.ELOOP) {
		t.Fatal("expected syscall.ELOOP to be recognized")
	}
	wrapped := &os.PathError{Op: "open", Path: "/x", Err: syscall.ELOOP}
	if !errIsSymlinkLoop(wrapped) {
		t.Fatal("expected PathError wrapping ELOOP to be recognized")
	}
	if errIsSymlinkLoop(os.ErrNotExist) {
		t.Fatal("expected unrelated error to be false")
	}
}

// discardLogOutput silences package log during tests that exercise skipDueToSymlinkLoop.
func discardLogOutput(t *testing.T) {
	t.Helper()
	prev := log.Writer()
	log.SetOutput(io.Discard)
	t.Cleanup(func() { log.SetOutput(prev) })
}

// writeTestTar builds a tar stream from ordered (header, body) pairs. Body is
// ignored unless header.Typeflag is tar.TypeReg or tar.TypeRegA.
func writeTestTar(t *testing.T, entries []struct {
	hdr  *tar.Header
	body []byte
}) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		hdr := *e.hdr
		switch hdr.Typeflag {
		case tar.TypeDir:
			hdr.Size = 0
		case tar.TypeSymlink:
			hdr.Size = 0
		case tar.TypeReg, tar.TypeRegA:
			hdr.Size = int64(len(e.body))
		}
		if err := tw.WriteHeader(&hdr); err != nil {
			t.Fatalf("WriteHeader %q: %v", hdr.Name, err)
		}
		if hdr.Typeflag == tar.TypeReg || hdr.Typeflag == tar.TypeRegA {
			if len(e.body) > 0 {
				if _, err := tw.Write(e.body); err != nil {
					t.Fatalf("Write body %q: %v", hdr.Name, err)
				}
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return &buf
}

// TestExtractTarToDir_skipsELOOPRegularFile verifies that a regular file under a
// circular symlink is skipped, the tar stream stays aligned (large payload
// drained), and later entries still extract.
func TestExtractTarToDir_skipsELOOPRegularFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("circular symlink ELOOP behavior is Unix-specific")
	}
	discardLogOutput(t)

	dir := t.TempDir()
	payload := bytes.Repeat([]byte("z"), 8192)
	buf := writeTestTar(t, []struct {
		hdr  *tar.Header
		body []byte
	}{
		{hdr: &tar.Header{Name: "ssl", Mode: 0o755, Typeflag: tar.TypeDir}},
		{hdr: &tar.Header{Name: "ssl/a", Mode: 0o777, Typeflag: tar.TypeSymlink, Linkname: "b"}},
		{hdr: &tar.Header{Name: "ssl/b", Mode: 0o777, Typeflag: tar.TypeSymlink, Linkname: "a"}},
		{hdr: &tar.Header{Name: "ssl/a/trouble.bin", Mode: 0o644, Typeflag: tar.TypeReg}, body: payload},
		{hdr: &tar.Header{Name: "ok/after.txt", Mode: 0o644, Typeflag: tar.TypeReg}, body: []byte("recovered")},
	})

	if err := extractTarToDir(buf, dir); err != nil {
		t.Fatalf("extractTarToDir: %v", err)
	}

	bad := filepath.Join(dir, "ssl", "a", "trouble.bin")
	_, err := os.Lstat(bad)
	if err == nil {
		t.Fatalf("expected skipped file not to be present at %q", bad)
	}
	// Resolution hits the a<->b loop (ELOOP); the path is not a normal missing file.
	if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, syscall.ELOOP) {
		t.Fatalf("unexpected lstat %q: %v", bad, err)
	}

	got, err := os.ReadFile(filepath.Join(dir, "ok", "after.txt"))
	if err != nil {
		t.Fatalf("read ok/after.txt: %v", err)
	}
	if string(got) != "recovered" {
		t.Fatalf("after.txt = %q, want recovered", got)
	}
}

// TestExtractTarToDir_skipsELOOPMkdirAll verifies that mkdir under a symlink
// loop is skipped without aborting extraction.
func TestExtractTarToDir_skipsELOOPMkdirAll(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("circular symlink ELOOP behavior is Unix-specific")
	}
	discardLogOutput(t)

	dir := t.TempDir()
	buf := writeTestTar(t, []struct {
		hdr  *tar.Header
		body []byte
	}{
		{hdr: &tar.Header{Name: "loop", Mode: 0o755, Typeflag: tar.TypeDir}},
		{hdr: &tar.Header{Name: "loop/x", Mode: 0o777, Typeflag: tar.TypeSymlink, Linkname: "y"}},
		{hdr: &tar.Header{Name: "loop/y", Mode: 0o777, Typeflag: tar.TypeSymlink, Linkname: "x"}},
		{hdr: &tar.Header{Name: "loop/x/deep", Mode: 0o755, Typeflag: tar.TypeDir}},
		{hdr: &tar.Header{Name: "tail.txt", Mode: 0o644, Typeflag: tar.TypeReg}, body: []byte("tail")},
	})

	if err := extractTarToDir(buf, dir); err != nil {
		t.Fatalf("extractTarToDir: %v", err)
	}

	deep := filepath.Join(dir, "loop", "x", "deep")
	if _, err := os.Stat(deep); err == nil {
		t.Fatalf("expected deep dir under loop not to be created, got %q", deep)
	}

	got, err := os.ReadFile(filepath.Join(dir, "tail.txt"))
	if err != nil {
		t.Fatalf("read tail.txt: %v", err)
	}
	if string(got) != "tail" {
		t.Fatalf("tail.txt = %q", got)
	}
}

// TestExtractTarToDir_skipsELOOPSymlink verifies os.Symlink ELOOP is skipped
// (e.g. link target path resolution hits a loop).
func TestExtractTarToDir_skipsELOOPSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("circular symlink ELOOP behavior is Unix-specific")
	}
	discardLogOutput(t)

	dir := t.TempDir()
	// a -> b, b -> a, then third link c -> a/b/../c (or c -> a) can hit ELOOP on create.
	buf := writeTestTar(t, []struct {
		hdr  *tar.Header
		body []byte
	}{
		{hdr: &tar.Header{Name: "m", Mode: 0o755, Typeflag: tar.TypeDir}},
		{hdr: &tar.Header{Name: "m/a", Mode: 0o777, Typeflag: tar.TypeSymlink, Linkname: "b"}},
		{hdr: &tar.Header{Name: "m/b", Mode: 0o777, Typeflag: tar.TypeSymlink, Linkname: "a"}},
		{hdr: &tar.Header{Name: "m/c", Mode: 0o777, Typeflag: tar.TypeSymlink, Linkname: "a/c"}},
		{hdr: &tar.Header{Name: "final.txt", Mode: 0o644, Typeflag: tar.TypeReg}, body: []byte("ok")},
	})

	if err := extractTarToDir(buf, dir); err != nil {
		t.Fatalf("extractTarToDir: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(dir, "final.txt"))
	if err != nil {
		t.Fatalf("read final.txt: %v", err)
	}
	if string(got) != "ok" {
		t.Fatalf("final.txt = %q", got)
	}
}

// TestExtractTarToDir_plainTarStillWorks is a sanity check unrelated to ELOOP.
func TestExtractTarToDir_plainTarStillWorks(t *testing.T) {
	dir := t.TempDir()
	buf := writeTestTar(t, []struct {
		hdr  *tar.Header
		body []byte
	}{
		{hdr: &tar.Header{Name: "bin", Mode: 0o755, Typeflag: tar.TypeDir}},
		{hdr: &tar.Header{Name: "bin/app", Mode: 0o755, Typeflag: tar.TypeReg}, body: []byte("elf")},
	})

	if err := extractTarToDir(buf, dir); err != nil {
		t.Fatalf("extractTarToDir: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "bin", "app"))
	if err != nil || string(b) != "elf" {
		t.Fatalf("bin/app: %v, %q", err, b)
	}
}
