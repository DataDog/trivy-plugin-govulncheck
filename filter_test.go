// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026-present Datadog, Inc.

package main

import (
	"testing"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestVulnerabilityConfirmed(t *testing.T) {
	confirmed := map[string]struct{}{
		"GO-2024-1234": {},
		"CVE-2023-9999": {},
	}
	tests := []struct {
		name string
		v    *types.DetectedVulnerability
		want bool
	}{
		{
			name: "VulnerabilityID match",
			v:    &types.DetectedVulnerability{VulnerabilityID: "GO-2024-1234"},
			want: true,
		},
		{
			name: "VendorIDs match",
			v:    &types.DetectedVulnerability{VulnerabilityID: "X", VendorIDs: []string{"CVE-2023-9999"}},
			want: true,
		},
		{
			name: "No match",
			v:    &types.DetectedVulnerability{VulnerabilityID: "CVE-0000-0000"},
			want: false,
		},
		{
			name: "Case insensitive match",
			v:    &types.DetectedVulnerability{VulnerabilityID: "go-2024-1234"},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := vulnerabilityMatchesSet(tt.v, confirmed); got != tt.want {
				t.Errorf("vulnerabilityMatchesSet() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFilterVulnerabilities(t *testing.T) {
	// Not considered by govulncheck (empty considered) = keep all in Vulnerabilities, do not suppress
	result := &types.Result{
		Target: "bin/app",
		Type:   ftypes.GoBinary,
		Vulnerabilities: []types.DetectedVulnerability{
			{VulnerabilityID: "CVE-2024-0001"},
			{VulnerabilityID: "GO-2024-1234"},
		},
	}
	filterVulnerabilities(result, map[string]struct{}{}, map[string]struct{}{}, nil, "v0.0.0", "test")
	if len(result.Vulnerabilities) != 2 {
		t.Errorf("expected 2 vulns when none considered (no false negative), got %d", len(result.Vulnerabilities))
	}
	if len(result.ModifiedFindings) != 0 {
		t.Errorf("expected 0 modified when none considered, got %d", len(result.ModifiedFindings))
	}

	// Considered but not confirmed = suppress (move to ModifiedFindings)
	result.ModifiedFindings = nil
	result.Vulnerabilities = []types.DetectedVulnerability{
		{VulnerabilityID: "CVE-2024-0001"},
		{VulnerabilityID: "GO-2024-1234"},
	}
	considered := map[string]struct{}{"CVE-2024-0001": {}, "GO-2024-1234": {}}
	filterVulnerabilities(result, map[string]struct{}{}, considered, nil, "v0.0.0", "test")
	if len(result.Vulnerabilities) != 0 {
		t.Errorf("expected 0 vulns when all considered but none confirmed, got %d", len(result.Vulnerabilities))
	}
	if len(result.ModifiedFindings) != 2 {
		t.Errorf("expected 2 modified (suppressed) findings, got %d", len(result.ModifiedFindings))
	}

	// One confirmed, one considered but not confirmed = keep one vuln, one suppressed
	result.ModifiedFindings = nil
	result.Vulnerabilities = []types.DetectedVulnerability{
		{VulnerabilityID: "CVE-2024-0001"},
		{VulnerabilityID: "GO-2024-1234"},
	}
	filterVulnerabilities(result, map[string]struct{}{"GO-2024-1234": {}}, considered, nil, "v0.0.0", "test")
	if len(result.Vulnerabilities) != 1 || result.Vulnerabilities[0].VulnerabilityID != "GO-2024-1234" {
		t.Errorf("expected 1 vuln GO-2024-1234, got %d: %v", len(result.Vulnerabilities), result.Vulnerabilities)
	}
	if len(result.ModifiedFindings) != 1 || result.ModifiedFindings[0].Status != types.FindingStatusNotAffected {
		t.Errorf("expected 1 modified finding with status not_affected, got %d: %v", len(result.ModifiedFindings), result.ModifiedFindings)
	}
}
