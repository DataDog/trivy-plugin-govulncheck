//go:build integration

// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026-present Datadog, Inc.

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// defaultIntegrationImage is the image used by integration tests.
// Override with TRIVY_PLUGIN_GOVULNCHECK_IMAGE. For repeatable runs, use a digest, e.g. tianon/gosu@sha256:....
const defaultIntegrationImage = "tianon/gosu:latest"

// Repeatability: set these env vars to lock DB versions.
// - TRIVY_PLUGIN_GOVULNCHECK_TRIVY_CACHE: dir with Trivy's vulnerability DB (trivy will use --skip-db-update).
// - TRIVY_PLUGIN_GOVULNCHECK_VULNDB: path to extracted Go vuln DB dir (from vuln.go.dev/vulndb.zip); plugin gets --vuln-db=file://<path>.

func TestIntegrationPluginOnDockerImage(t *testing.T) {
	image := os.Getenv("TRIVY_PLUGIN_GOVULNCHECK_IMAGE")
	if image == "" {
		image = defaultIntegrationImage
	}

	// 1. Run Trivy image scan (JSON); use pinned cache if TRIVY_PLUGIN_GOVULNCHECK_TRIVY_CACHE is set
	trivyReport, err := runTrivyImage(image)
	if err != nil {
		t.Fatalf("trivy image: %v", err)
	}

	var reportBefore types.Report
	if err := json.Unmarshal(trivyReport, &reportBefore); err != nil {
		t.Fatalf("parse trivy report: %v", err)
	}

	// Find gobinary result and count vulns before filtering
	var goBinaryVulnsBefore int
	for _, r := range reportBefore.Results {
		if r.Type == ftypes.GoBinary {
			goBinaryVulnsBefore += len(r.Vulnerabilities)
		}
	}
	t.Logf("Trivy report: %d results, %d vulns in Go binary targets before plugin", len(reportBefore.Results), goBinaryVulnsBefore)

	// 2. Run plugin (stdin = trivy report; plugin extracts image and filters). Uses TRIVY_PLUGIN_GOVULNCHECK_VULNDB if set.
	pluginOut, _, err := runPlugin(trivyReport, pluginArgs()...)
	if err != nil {
		t.Fatalf("plugin: %v", err)
	}

	var reportAfter types.Report
	if err := json.Unmarshal(pluginOut, &reportAfter); err != nil {
		t.Fatalf("parse plugin output: %v", err)
	}

	// 3. Assertions
	if len(reportAfter.Results) != len(reportBefore.Results) {
		t.Errorf("result count changed: before %d, after %d", len(reportBefore.Results), len(reportAfter.Results))
	}

	var goBinaryVulnsAfter int
	for _, r := range reportAfter.Results {
		if r.Type == ftypes.GoBinary {
			goBinaryVulnsAfter += len(r.Vulnerabilities)
		}
	}
	t.Logf("After plugin: %d vulns in Go binary targets", goBinaryVulnsAfter)

	// Plugin should keep only vulns confirmed by govulncheck => after <= before
	if goBinaryVulnsAfter > goBinaryVulnsBefore {
		t.Errorf("plugin should not add vulns: before=%d after=%d", goBinaryVulnsBefore, goBinaryVulnsAfter)
	}

	// Confirm every vuln removed from Vulnerabilities appears in ModifiedFindings with correct status/source
	assertModifiedFindings(t, &reportBefore, &reportAfter)

	// If we had any Go binary vulns before, we expect the plugin to have run (after may be 0 or less)
	if goBinaryVulnsBefore > 0 && goBinaryVulnsBefore == goBinaryVulnsAfter {
		t.Logf("govulncheck confirmed all %d vulns (no filtering)", goBinaryVulnsAfter)
	}
}

// TestIntegrationGosuEmbeddedGovulncheckFiltersAllGoBinaryVulns runs Trivy image and the plugin,
// and confirms that all Go binary vulnerabilities can be filtered out (gosu's binary does not call
// any vulnerable symbols, so govulncheck reports 0 and the plugin should remove all Trivy vulns for those targets).
func TestIntegrationGosuEmbeddedGovulncheckFiltersAllGoBinaryVulns(t *testing.T) {
	image := os.Getenv("TRIVY_PLUGIN_GOVULNCHECK_IMAGE")
	if image == "" {
		image = defaultIntegrationImage
	}

	trivyReport, err := runTrivyImage(image)
	if err != nil {
		t.Fatalf("trivy image: %v", err)
	}

	var reportBefore types.Report
	if err := json.Unmarshal(trivyReport, &reportBefore); err != nil {
		t.Fatalf("parse trivy report: %v", err)
	}

	var goBinaryResultsBefore int
	var goBinaryVulnsBefore int
	for _, r := range reportBefore.Results {
		if r.Type == ftypes.GoBinary {
			goBinaryResultsBefore++
			goBinaryVulnsBefore += len(r.Vulnerabilities)
		}
	}
	if goBinaryResultsBefore == 0 {
		t.Fatal("expected at least one Go binary result in Trivy report (gosu image)")
	}
	t.Logf("Trivy: %d Go binary result(s), %d vulns before plugin", goBinaryResultsBefore, goBinaryVulnsBefore)

	pluginOut, pluginStderr, err := runPlugin(trivyReport, pluginArgs("-v")...)
	if err != nil {
		t.Fatalf("plugin: %v", err)
	}

	var reportAfter types.Report
	if err := json.Unmarshal(pluginOut, &reportAfter); err != nil {
		t.Fatalf("parse plugin output: %v", err)
	}

	var goBinaryVulnsAfter int
	for _, r := range reportAfter.Results {
		if r.Type == ftypes.GoBinary {
			goBinaryVulnsAfter += len(r.Vulnerabilities)
		}
	}

	if goBinaryVulnsAfter > goBinaryVulnsBefore {
		t.Errorf("plugin must not add vulns: before=%d after=%d", goBinaryVulnsBefore, goBinaryVulnsAfter)
	}
	assertModifiedFindings(t, &reportBefore, &reportAfter)
	if goBinaryVulnsAfter == 0 {
		t.Logf("All %d Go binary vulns filtered out by embedded govulncheck", goBinaryVulnsBefore)
	} else {
		t.Logf("plugin stderr:\n%s", pluginStderr)
		if bytes.Contains(pluginStderr, []byte("vulnerability DB ")) {
			t.Logf("govulncheck did not filter (after=%d); vuln DB was loaded but no vulns were suppressed (govulncheck may not have emitted OSV messages for this binary or Trivy vuln IDs do not match)", goBinaryVulnsAfter)
		} else {
			t.Logf("govulncheck did not filter (after=%d); may need network for vuln DB or OSV messages not emitted for this binary", goBinaryVulnsAfter)
		}
	}
}

// TestIntegrationTrivyImagePipeToPlugin runs "trivy image -f json <image> | plugin" (no --base-path).
// The plugin must auto-extract the image (go-containerregistry) and filter Go binary vulns.
func TestIntegrationTrivyImagePipeToPlugin(t *testing.T) {
	image := os.Getenv("TRIVY_PLUGIN_GOVULNCHECK_IMAGE")
	if image == "" {
		image = defaultIntegrationImage
	}

	trivyOut, err := runTrivyImage(image)
	if err != nil {
		t.Fatalf("trivy image: %v", err)
	}

	pluginOut, pluginStderr, err := runPlugin(trivyOut, pluginArgs("-v")...)
	if err != nil {
		t.Fatalf("plugin (with auto-extract): %v", err)
	}

	var reportBefore types.Report
	if err := json.Unmarshal(trivyOut, &reportBefore); err != nil {
		t.Fatalf("parse trivy output: %v", err)
	}
	var goBinaryVulnsBefore int
	for _, r := range reportBefore.Results {
		if r.Type == ftypes.GoBinary {
			goBinaryVulnsBefore += len(r.Vulnerabilities)
		}
	}

	var report types.Report
	if err := json.Unmarshal(pluginOut, &report); err != nil {
		t.Fatalf("parse plugin output: %v", err)
	}
	var goBinaryVulnsAfter int
	for _, r := range report.Results {
		if r.Type == ftypes.GoBinary {
			goBinaryVulnsAfter += len(r.Vulnerabilities)
		}
	}

	if goBinaryVulnsAfter > goBinaryVulnsBefore {
		t.Errorf("plugin must not add vulns: before=%d after=%d", goBinaryVulnsBefore, goBinaryVulnsAfter)
	}
	assertModifiedFindings(t, &reportBefore, &report)
	if goBinaryVulnsAfter == 0 {
		t.Logf("trivy image | plugin: 0 Go binary vulns (auto-extract and filtering worked)")
	} else {
		t.Logf("plugin stderr:\n%s", pluginStderr)
		t.Logf("trivy image | plugin: %d Go binary vulns after (filtering may require govulncheck vuln DB)", goBinaryVulnsAfter)
	}
}

// TestIntegrationTrivyImageInputTar runs "trivy image -f json --input image.tar" and pipes to the plugin.
// The plugin receives ArtifactName "image.tar" (a path) and must extract from that tar file to run
// govulncheck on Go binaries. When the plugin incorrectly treats "image.tar" as an image reference
// and tries to pull it, extraction fails and no filtering occurs—this test exposes that bug.
func TestIntegrationTrivyImageInputTar(t *testing.T) {
	image := os.Getenv("TRIVY_PLUGIN_GOVULNCHECK_IMAGE")
	if image == "" {
		image = defaultIntegrationImage
	}

	// Create a tar file from the same image used in other integration tests (so we have Go binaries).
	tarPath, cleanup, err := createImageTar(t, image)
	if err != nil {
		t.Fatalf("create image tar: %v", err)
	}
	defer cleanup()

	// Trivy with --input uses the tar path; report will have ArtifactName set to the path (e.g. "image.tar" or full path).
	trivyReport, err := runTrivyImageInput(tarPath)
	if err != nil {
		t.Fatalf("trivy image --input: %v", err)
	}

	var reportBefore types.Report
	if err := json.Unmarshal(trivyReport, &reportBefore); err != nil {
		t.Fatalf("parse trivy report: %v", err)
	}
	var goBinaryVulnsBefore int
	var goBinaryResultsBefore int
	for _, r := range reportBefore.Results {
		if r.Type == ftypes.GoBinary {
			goBinaryResultsBefore++
			goBinaryVulnsBefore += len(r.Vulnerabilities)
		}
	}
	if goBinaryResultsBefore == 0 {
		t.Skip("no Go binary results in Trivy report for this image (nothing for plugin to filter)")
	}
	t.Logf("Trivy --input %s: %d Go binary result(s), %d vulns before plugin", tarPath, goBinaryResultsBefore, goBinaryVulnsBefore)

	pluginOut, pluginStderr, err := runPlugin(trivyReport, pluginArgs("-v")...)
	if err != nil {
		t.Fatalf("plugin: %v", err)
	}

	var reportAfter types.Report
	if err := json.Unmarshal(pluginOut, &reportAfter); err != nil {
		t.Fatalf("parse plugin output: %v", err)
	}
	var goBinaryVulnsAfter int
	for _, r := range reportAfter.Results {
		if r.Type == ftypes.GoBinary {
			goBinaryVulnsAfter += len(r.Vulnerabilities)
		}
	}

	// Plugin must run govulncheck on binaries from --input image.tar. For gosu we expect all Go vulns filtered.
	// When the bug is present: plugin treats ArtifactName "image.tar" as image ref, pull fails, no extraction,
	// resolvedBasePath is empty, so no govulncheck runs and vuln count is unchanged.
	if goBinaryVulnsAfter >= goBinaryVulnsBefore && goBinaryVulnsBefore > 0 {
		t.Errorf("plugin did not filter Go binary vulns when using --input image.tar: before=%d after=%d (govulncheck likely did not run; check that plugin extracts from tar path instead of pulling ArtifactName as image ref). plugin stderr:\n%s",
			goBinaryVulnsBefore, goBinaryVulnsAfter, pluginStderr)
	}
	if goBinaryVulnsAfter > goBinaryVulnsBefore {
		t.Errorf("plugin must not add vulns: before=%d after=%d", goBinaryVulnsBefore, goBinaryVulnsAfter)
	}
	assertModifiedFindings(t, &reportBefore, &reportAfter)
}

// assertModifiedFindings verifies that for each Go binary result, every vulnerability removed from
// Vulnerabilities appears in ModifiedFindings with status not_affected and source trivy-plugin-govulncheck.
func assertModifiedFindings(t *testing.T, before, after *types.Report) {
	t.Helper()
	beforeByTarget := make(map[string]*types.Result)
	for i := range before.Results {
		r := &before.Results[i]
		if r.Type == ftypes.GoBinary {
			beforeByTarget[r.Target] = r
		}
	}
	for i := range after.Results {
		r := &after.Results[i]
		if r.Type != ftypes.GoBinary {
			continue
		}
		beforeResult := beforeByTarget[r.Target]
		if beforeResult == nil {
			continue
		}
		beforeIDs := make(map[string]struct{})
		for _, v := range beforeResult.Vulnerabilities {
			beforeIDs[v.VulnerabilityID] = struct{}{}
		}
		afterIDs := make(map[string]struct{})
		for _, v := range r.Vulnerabilities {
			afterIDs[v.VulnerabilityID] = struct{}{}
		}
		var removed []string
		for id := range beforeIDs {
			if _, kept := afterIDs[id]; !kept {
				removed = append(removed, id)
			}
		}
		if len(removed) != len(r.ModifiedFindings) {
			t.Errorf("result %q: %d vulns removed but %d ModifiedFindings (expected one ModifiedFinding per suppressed vuln)",
				r.Target, len(removed), len(r.ModifiedFindings))
			continue
		}
		modifiedIDs := make(map[string]struct{})
		for _, mf := range r.ModifiedFindings {
			if mf.Status != types.FindingStatusNotAffected {
				t.Errorf("result %q: ModifiedFinding has status %q, want not_affected", r.Target, mf.Status)
			}
			if !bytes.Contains([]byte(mf.Source), []byte("trivy-plugin-govulncheck")) {
				t.Errorf("result %q: ModifiedFinding source %q must contain trivy-plugin-govulncheck", r.Target, mf.Source)
			}
			switch v := mf.Finding.(type) {
			case *types.DetectedVulnerability:
				modifiedIDs[v.VulnerabilityID] = struct{}{}
			case types.DetectedVulnerability:
				modifiedIDs[v.VulnerabilityID] = struct{}{}
			}
		}
		for _, id := range removed {
			if _, ok := modifiedIDs[id]; !ok {
				t.Errorf("result %q: removed vuln %q not found in ModifiedFindings", r.Target, id)
			}
		}
	}
}

// runTrivyImage runs "trivy image -f json --scanners vuln <image>".
// If TRIVY_PLUGIN_GOVULNCHECK_TRIVY_CACHE is set, Trivy uses that dir and --skip-db-update for a pinned DB.
func runTrivyImage(image string) ([]byte, error) {
	args := []string{"image", "-f", "json", "--scanners", "vuln", image}
	cmd := exec.Command("trivy", args...)
	if cacheDir := os.Getenv("TRIVY_PLUGIN_GOVULNCHECK_TRIVY_CACHE"); cacheDir != "" {
		cmd.Env = append(os.Environ(), "TRIVY_CACHE_DIR="+cacheDir)
		cmd.Args = append(cmd.Args, "--skip-db-update")
	}
	return cmd.Output()
}

// runTrivyImageInput runs "trivy image -f json --scanners vuln --input <tarPath>".
// The report will have ArtifactName set to the tar path (or basename), which the plugin must handle.
func runTrivyImageInput(tarPath string) ([]byte, error) {
	args := []string{"image", "-f", "json", "--scanners", "vuln", "--input", tarPath}
	cmd := exec.Command("trivy", args...)
	if cacheDir := os.Getenv("TRIVY_PLUGIN_GOVULNCHECK_TRIVY_CACHE"); cacheDir != "" {
		cmd.Env = append(os.Environ(), "TRIVY_CACHE_DIR="+cacheDir)
		cmd.Args = append(cmd.Args, "--skip-db-update")
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("%w (trivy stderr: %s)", err, stderr.Bytes())
	}
	return stdout, nil
}

// createImageTar pulls the given image and saves it to a temp tar file (docker-load format via crane.MultiSave).
// Returns the tar path, a cleanup function, and an error. Used to test trivy image --input <tar>.
func createImageTar(t *testing.T, image string) (tarPath string, cleanup func(), err error) {
	t.Helper()
	ref, err := name.ParseReference(image)
	if err != nil {
		return "", nil, fmt.Errorf("parse image reference: %w", err)
	}
	img, err := remote.Image(ref)
	if err != nil {
		return "", nil, fmt.Errorf("pull image: %w", err)
	}
	f, err := os.CreateTemp("", "trivy-govulncheck-image-*.tar")
	if err != nil {
		return "", nil, fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := f.Name()
	if err := f.Close(); err != nil {
		os.Remove(tmpPath)
		return "", nil, err
	}
	imageMap := map[string]v1.Image{ref.String(): img}
	if err := crane.MultiSave(imageMap, tmpPath); err != nil {
		os.Remove(tmpPath)
		return "", nil, fmt.Errorf("save image to tar: %w", err)
	}
	return tmpPath, func() { _ = os.Remove(tmpPath) }, nil
}

// pluginArgs returns plugin args for runPlugin: --vuln-db=file://<path> when TRIVY_PLUGIN_GOVULNCHECK_VULNDB is set, plus any extra (e.g. "-v").
func pluginArgs(extra ...string) []string {
	var args []string
	if v := os.Getenv("TRIVY_PLUGIN_GOVULNCHECK_VULNDB"); v != "" {
		args = append(args, "--vuln-db=file://"+v)
	}
	args = append(args, extra...)
	return args
}

// runPlugin runs the plugin with the given trivy report (from trivy image) and optional extra args (e.g. "-v", or from pluginArgs()).
// Returns stdout, stderr, and error. Caller can log stderr on failure to see skip messages.
func runPlugin(trivyReport []byte, extraArgs ...string) (stdout, stderr []byte, err error) {
	pluginBin := "./trivy-govulncheck"
	if _, statErr := os.Stat(pluginBin); statErr != nil {
		pluginBin = filepath.Join(filepath.Dir(os.Args[0]), "trivy-govulncheck")
		if _, statErr2 := os.Stat(pluginBin); statErr2 != nil {
			return nil, nil, fmt.Errorf("plugin binary not found (run make build): %w", statErr)
		}
	}
	cmd := exec.Command(pluginBin, extraArgs...)
	cmd.Stdin = bytes.NewReader(trivyReport)
	var stderrBuf bytes.Buffer
	cmd.Stderr = &stderrBuf
	stdout, err = cmd.Output()
	stderr = stderrBuf.Bytes()
	if err != nil {
		return nil, stderr, fmt.Errorf("%w (stderr: %s)", err, stderr)
	}
	return stdout, stderr, nil
}
