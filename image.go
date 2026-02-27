// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026-present Datadog, Inc.

package main

import (
	"archive/tar"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// extractImageFromTarPath loads the container image from a local tar path (e.g. from
// "trivy image --input image.tar") and extracts its filesystem to a temporary directory.
// Returns the temp dir path, a cleanup function, and an error.
func extractImageFromTarPath(tarPath string) (string, func(), error) {
	img, err := crane.Load(tarPath)
	if err != nil {
		return "", nil, fmt.Errorf("load image from tar: %w", err)
	}
	dir, err := os.MkdirTemp("", "trivy-govulncheck-image-*")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	pr, pw := io.Pipe()
	go func() {
		err := crane.Export(img, pw)
		_ = pw.CloseWithError(err)
	}()
	if err := extractTarToDir(pr, dir); err != nil {
		pr.Close()
		cleanup()
		return "", nil, fmt.Errorf("extract image: %w", err)
	}
	_ = pr.Close()
	return dir, cleanup, nil
}

// extractImageToTemp pulls the container image and extracts its filesystem to a
// temporary directory using go-containerregistry (crane.Export for layer merging, then tar extraction).
// Returns the temp dir path, a cleanup function, and an error.
//
// TODO: Avoid dual download when used after trivy image — we cannot use Trivy's
// image cache today, so the same image may be pulled twice per run. Explore
// reusing Trivy's extracted layers or a shared cache (e.g. OCI layout on disk).
func extractImageToTemp(imageRef string) (string, func(), error) {
	dir, err := os.MkdirTemp("", "trivy-govulncheck-image-*")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { _ = os.RemoveAll(dir) }

	ref, err := name.ParseReference(imageRef)
	if err != nil {
		cleanup()
		return "", nil, fmt.Errorf("parse image reference: %w", err)
	}
	img, err := remote.Image(ref)
	if err != nil {
		cleanup()
		return "", nil, fmt.Errorf("pull image: %w", err)
	}
	pr, pw := io.Pipe()
	go func() {
		err := crane.Export(img, pw)
		_ = pw.CloseWithError(err)
	}()
	if err := extractTarToDir(pr, dir); err != nil {
		pr.Close()
		cleanup()
		return "", nil, fmt.Errorf("extract image: %w", err)
	}
	_ = pr.Close()
	return dir, cleanup, nil
}

// extractTarToDir extracts a tar stream to dir, handling OCI whiteout entries.
// Whiteout: entries named .wh.<path> mean remove <path>; .wh..wh..opq means opaque dir.
func extractTarToDir(r io.Reader, dir string) error {
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		entryName := filepath.Clean(hdr.Name)
		if entryName == "" || strings.Contains(entryName, "..") {
			continue
		}
		target := filepath.Join(dir, entryName)
		if !strings.HasPrefix(filepath.Clean(target), filepath.Clean(dir)+string(filepath.Separator)) && target != filepath.Clean(dir) {
			continue // path traversal
		}
		switch {
		case strings.HasPrefix(filepath.Base(entryName), ".wh."):
			// Whiteout: remove the target path
			if filepath.Base(entryName) == ".wh..wh..opq" {
				// Opaque dir: remove contents of parent dir (we skip recreating for simplicity)
				parent := filepath.Dir(target)
				if parent != dir {
					_ = os.RemoveAll(parent)
				}
			} else {
				removal := filepath.Join(filepath.Dir(target), strings.TrimPrefix(filepath.Base(entryName), ".wh."))
				_ = os.RemoveAll(removal)
			}
		case hdr.Typeflag == tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil && !os.IsExist(err) {
				return err
			}
		case hdr.Typeflag == tar.TypeReg || hdr.Typeflag == tar.TypeRegA:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil && !os.IsExist(err) {
				return err
			}
			f, err := os.Create(target)
			if err != nil {
				return err
			}
			size := hdr.Size
			if size < 0 {
				size = 0
			}
			if _, err := io.CopyN(f, tr, size); err != nil {
				f.Close()
				return err
			}
			if err := f.Chmod(os.FileMode(hdr.Mode) & 0o777); err != nil {
				f.Close()
				return err
			}
			f.Close()
		case hdr.Typeflag == tar.TypeSymlink:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil && !os.IsExist(err) {
				return err
			}
			_ = os.Remove(target)
			if err := os.Symlink(hdr.Linkname, target); err != nil {
				return err
			}
		}
	}
	return nil
}

// resolveBinaryPath resolves target (relative to basePath, the extracted image root) to an absolute path.
// If target is a single component (e.g. "gosu") and basePath/target does not exist, the extracted root
// is searched for a file with that name (Trivy may report only the binary name for gobinary results).
func resolveBinaryPath(target, basePath string) (string, error) {
	target = filepath.Clean(target)
	if basePath == "" {
		return "", fmt.Errorf("image root not available (plugin only supports trivy image): %s", target)
	}
	joined := filepath.Join(basePath, target)
	if info, err := os.Stat(joined); err == nil && !info.IsDir() {
		return joined, nil
	}
	// Target may be just the binary name (e.g. "gosu"); search for it under basePath
	if !strings.Contains(target, string(filepath.Separator)) {
		var found string
		_ = filepath.WalkDir(basePath, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			if filepath.Base(path) == target && found == "" {
				found = path
				return filepath.SkipAll
			}
			return nil
		})
		if found != "" {
			return found, nil
		}
	}
	return "", fmt.Errorf("binary not found: %s", joined)
}
