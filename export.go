// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026-present Datadog, Inc.

package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
)

// ExportFileFromImageSpec parses a single string "image_ref:path_inside_image local_path" and exports
// the file from the image to the local path. The first space separates the spec from the local path
// (so the local path may contain spaces). Example: "tianon/gosu:latest:usr/local/bin/gosu ./gosu"
func ExportFileFromImageSpec(specAndLocal string) error {
	specAndLocal = strings.TrimSpace(specAndLocal)
	idx := strings.Index(specAndLocal, " ")
	if idx < 0 {
		return fmt.Errorf("input must be image_ref:path_inside_image local_path (missing space)")
	}
	spec := strings.TrimSpace(specAndLocal[:idx])
	localPath := strings.TrimSpace(specAndLocal[idx+1:])
	if spec == "" || localPath == "" {
		return fmt.Errorf("input must be image_ref:path_inside_image local_path (empty part)")
	}
	imageRef, pathInImage, err := ParseImagePathSpec(spec)
	if err != nil {
		return err
	}
	return ExportFileFromImage(imageRef, pathInImage, localPath)
}

// ParseImagePathSpec parses a spec string "image_ref:path_inside_image" into the image reference and
// the path to the file inside the image. The image ref may contain colons (e.g. tag, or digest as in
// image@sha256:hex), so we use go-containerregistry's name.ParseReference to find the longest valid
// ref from the left; the remainder after the separating colon is the path. Supports image_url:tag,
// image_url@sha256:xxxx, and image_url:tag@sha256:xxxx formats.
func ParseImagePathSpec(spec string) (imageRef, pathInImage string, err error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return "", "", fmt.Errorf("spec must be image_ref:path_inside_image (empty)")
	}
	// Collect all colon positions so we can try splitting at each (right to left).
	// The image ref can contain colons (tag, or "sha256:" in a digest), so we must
	// find the colon that separates ref from path by validating with the reference parser.
	var colons []int
	for i := 0; i < len(spec); i++ {
		if spec[i] == ':' {
			colons = append(colons, i)
		}
	}
	if len(colons) == 0 {
		return "", "", fmt.Errorf("spec must be image_ref:path_inside_image (missing ':')")
	}
	// Try from rightmost colon leftward so we get the longest valid ref (path may contain colons).
	for j := len(colons) - 1; j >= 0; j-- {
		idx := colons[j]
		candidateRef := strings.TrimSpace(spec[:idx])
		candidatePath := strings.TrimSpace(spec[idx+1:])
		if candidateRef == "" || candidatePath == "" {
			continue
		}
		if _, err := name.ParseReference(candidateRef); err != nil {
			continue
		}
		pathInImage = filepath.Clean(candidatePath)
		if pathInImage == "." || strings.HasPrefix(pathInImage, "..") {
			return "", "", fmt.Errorf("path_inside_image must not be . or escape root")
		}
		return candidateRef, pathInImage, nil
	}
	return "", "", fmt.Errorf("spec must be image_ref:path_inside_image (no valid image reference found)")
}

// ExportFileFromImage extracts a single file from a container image to a local path for analysis.
// imageRef is the image reference (e.g. "tianon/gosu:latest"); pathInImage is the path to the file
// inside the image (e.g. "usr/local/bin/gosu"); localPath is the destination path on the host.
// Parent directories of localPath are created if needed.
func ExportFileFromImage(imageRef, pathInImage, localPath string) error {
	pathInImage = filepath.Clean(pathInImage)
	if pathInImage == "." || strings.HasPrefix(pathInImage, "..") {
		return fmt.Errorf("path_inside_image must not be . or escape root")
	}
	extracted, cleanup, err := extractImageToTemp(imageRef)
	if err != nil {
		return err
	}
	defer cleanup()
	src := filepath.Join(extracted, pathInImage)
	info, err := os.Stat(src)
	if err != nil {
		return fmt.Errorf("file not found in image %q at %q: %w", imageRef, pathInImage, err)
	}
	if info.IsDir() {
		return fmt.Errorf("path in image is a directory, not a file: %s", pathInImage)
	}
	if !pathUnderRoot(src, extracted) {
		return fmt.Errorf("path escapes image root: %s", pathInImage)
	}
	if err := os.MkdirAll(filepath.Dir(localPath), 0o755); err != nil {
		return fmt.Errorf("create destination dir: %w", err)
	}
	return copyFile(src, localPath, info.Mode())
}

// pathUnderRoot reports whether path is under root (or equal to root). Used for path traversal checks.
func pathUnderRoot(path, root string) bool {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return false
	}
	return absPath == absRoot || strings.HasPrefix(absPath, absRoot+string(filepath.Separator))
}

// copyFile copies a regular file from src to dst, preserving mode.
func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Chmod(mode & 0o777)
}
