// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026-present Datadog, Inc.

package main

import (
	"fmt"
	"net/url"
	"unicode"
)

// validateVulnDBURL ensures vulnDBURL is a safe, well-formed URL with an allowed scheme (file, https, http).
// Uses the standard library net/url for parsing and validation (the usual Go approach); rejects control
// characters and restricts scheme to file, https, and http only.
func validateVulnDBURL(vulnDBURL string) error {
	if vulnDBURL == "" {
		return nil
	}
	for _, r := range vulnDBURL {
		if r == 0 || r == '\n' || r == '\r' || unicode.IsControl(r) {
			return fmt.Errorf("vuln-db URL contains invalid control character")
		}
	}
	u, err := url.Parse(vulnDBURL)
	if err != nil {
		return fmt.Errorf("vuln-db URL parse failed: %w", err)
	}
	switch u.Scheme {
	case "file", "https", "http":
		// allowed
	default:
		return fmt.Errorf("vuln-db URL scheme must be file, https, or http, got %q", u.Scheme)
	}
	return nil
}

// validateBinaryPath ensures binaryPath does not contain characters that could break command invocation.
func validateBinaryPath(binaryPath string) error {
	if binaryPath == "" {
		return fmt.Errorf("binary path is empty")
	}
	for _, r := range binaryPath {
		if r == 0 || r == '\n' || r == '\r' || unicode.IsControl(r) {
			return fmt.Errorf("binary path contains invalid control character")
		}
	}
	return nil
}
