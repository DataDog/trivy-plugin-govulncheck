// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026-present Datadog, Inc.

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

// pluginVersion is set at build time via -ldflags "-X main.pluginVersion=0.1.3" to match plugin.yaml.
var pluginVersion = "dev"

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	verbose := flag.Bool("v", false, "Log when a Go binary is skipped (path not found or govulncheck failed)")
	vulnDB := flag.String("vuln-db", "", "Go vulnerability database URL (file://, https://, or http://). If set, govulncheck uses this instead of vuln.go.dev (no network calls for file://). Pin a version by serving or extracting vulndb.zip (see https://go.dev/security/vuln/database)")
	exportSpec := flag.String("export", "", "Export a file from an image: 'image_ref:path_inside_image local_path' (e.g. tianon/gosu:latest:usr/local/bin/gosu ./gosu). When set, runs export and exits; no stdin report.")
	gobinaryTargets := flag.String("gobinary-targets", "", "Comma-separated list of go binary paths to scan (e.g. usr/local/bin/gosu,gosu). If set, only these targets are scanned; other go binaries in the report are left unchanged.")
	flag.Parse()

	if *exportSpec != "" {
		return ExportFileFromImageSpec(*exportSpec)
	}

	var report types.Report
	if err := json.NewDecoder(os.Stdin).Decode(&report); err != nil {
		return fmt.Errorf("decode trivy report: %w", err)
	}

	// Plugin only supports "trivy image" output. Extract the image to a temp dir to run govulncheck on Go binaries.
	// When ArtifactName is a path to a tar file (e.g. "trivy image --input image.tar"), load from that file.
	// Otherwise treat it as an image reference and pull via go-containerregistry.
	var resolvedBasePath string
	if report.ArtifactType == ftypes.TypeContainerImage && report.ArtifactName != "" {
		artifactName := report.ArtifactName
		if info, err := os.Stat(artifactName); err == nil && !info.IsDir() {
			extracted, cleanup, err := extractImageFromTarPath(artifactName)
			if err != nil {
				if *verbose {
					log.Printf("govulncheck plugin: could not extract image from tar %q: %v", artifactName, err)
				}
			} else {
				defer cleanup()
				resolvedBasePath = extracted
			}
		} else {
			extracted, cleanup, err := extractImageToTemp(artifactName)
			if err != nil {
				if *verbose {
					log.Printf("govulncheck plugin: could not extract image %q: %v", artifactName, err)
				}
			} else {
				defer cleanup()
				resolvedBasePath = extracted
			}
		}
	}
	if resolvedBasePath == "" && *verbose && reportHasGobinaryVulns(&report) {
		log.Printf("govulncheck plugin: no image root (ArtifactType=%q, ArtifactName=%q); skipping Go binary filtering", report.ArtifactType, report.ArtifactName)
	}

	allowedTargets := parseGobinaryTargets(*gobinaryTargets)
	var loggedDBInfo bool
	for i := range report.Results {
		result := &report.Results[i]
		if result.Type != ftypes.GoBinary {
			continue
		}
		if len(result.Vulnerabilities) == 0 {
			continue
		}
		if len(allowedTargets) > 0 && !targetInAllowedList(result.Target, allowedTargets) {
			continue
		}
		binPath, err := resolveBinaryPath(result.Target, resolvedBasePath)
		if err != nil {
			if *verbose {
				log.Printf("govulncheck plugin: skip %q: %v", result.Target, err)
			}
			continue
		}
		dbInfo, confirmedIDs, consideredIDs, err := runGovulncheck(context.Background(), binPath, *vulnDB)
		if err != nil {
			if *verbose {
				log.Printf("govulncheck plugin: skip %q (govulncheck failed): %v", result.Target, err)
			}
			continue
		}
		if dbInfo != nil && dbInfo.DB != "" && !loggedDBInfo {
			msg := fmt.Sprintf("govulncheck plugin: vulnerability DB %s", dbInfo.DB)
			if dbInfo.DBLastModified != "" {
				msg += fmt.Sprintf(" (last modified: %s)", dbInfo.DBLastModified)
			}
			log.Print(msg)
			loggedDBInfo = true
		}
		if *verbose {
			log.Printf("govulncheck plugin: %q → %d confirmed, %d considered (of %d Trivy vulns)", result.Target, len(confirmedIDs), len(consideredIDs), len(result.Vulnerabilities))
		}
		filterVulnerabilities(result, confirmedIDs, consideredIDs, dbInfo, govulncheckVersion(), pluginVersion)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		return fmt.Errorf("encode report: %w", err)
	}
	return nil
}

// reportHasGobinaryVulns returns true if the report has at least one Go binary result with vulnerabilities.
func reportHasGobinaryVulns(report *types.Report) bool {
	for _, r := range report.Results {
		if r.Type == ftypes.GoBinary && len(r.Vulnerabilities) > 0 {
			return true
		}
	}
	return false
}

// parseGobinaryTargets returns a slice of trimmed, non-empty paths from a comma-separated list.
func parseGobinaryTargets(csv string) []string {
	if csv == "" {
		return nil
	}
	var out []string
	for _, s := range strings.Split(csv, ",") {
		s = strings.TrimSpace(s)
		if s != "" {
			out = append(out, filepath.ToSlash(filepath.Clean(s)))
		}
	}
	return out
}

// targetInAllowedList returns true if target matches any entry in allowed (exact match, or target path ends with the allowed path).
func targetInAllowedList(target string, allowed []string) bool {
	target = filepath.ToSlash(filepath.Clean(target))
	for _, a := range allowed {
		if target == a {
			return true
		}
		// Match when target path ends with the allowed path (e.g. "usr/local/bin/gosu" matches "gosu" or "bin/gosu")
		if strings.HasSuffix(target, "/"+a) {
			return true
		}
	}
	return false
}
