// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026-present Datadog, Inc.

package main

import (
	"testing"
)

// TestParseGovulncheckOpenVEX verifies we parse govulncheck -format openvex output using go-vex.
// Confirmed = status "called"; considered = all vuln IDs (name + aliases) from every statement.
func TestParseGovulncheckOpenVEX(t *testing.T) {
	// OpenVEX doc: one vuln considered only (not_affected), one vuln confirmed (called).
	input := []byte(`{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "version": 1,
  "statements": [
    {
      "vulnerability": {"name": "GO-2024-1234", "aliases": ["CVE-2024-1234"]},
      "products": [{"@id": "pkg:go/binary"}],
      "status": "not_affected",
      "justification": "vulnerable_code_not_present"
    },
    {
      "vulnerability": {"name": "GO-2024-5678"},
      "products": [{"@id": "pkg:go/binary"}],
      "status": "called"
    }
  ]
}`)
	dbInfo, confirmed, considered, err := parseGovulncheckOpenVEX(input, "")
	if err != nil {
		t.Fatalf("parseGovulncheckOpenVEX: %v", err)
	}
	if dbInfo != nil {
		t.Errorf("expected nil dbInfo when vulnDBURL is empty, got %+v", dbInfo)
	}
	if len(considered) != 3 {
		t.Errorf("expected 3 considered (GO-2024-1234, CVE-2024-1234, GO-2024-5678), got %d: %v", len(considered), considered)
	}
	if _, ok := considered["GO-2024-1234"]; !ok {
		t.Error("considered missing GO-2024-1234")
	}
	if _, ok := considered["CVE-2024-1234"]; !ok {
		t.Error("considered missing CVE-2024-1234")
	}
	if _, ok := considered["GO-2024-5678"]; !ok {
		t.Error("considered missing GO-2024-5678")
	}
	if len(confirmed) != 1 {
		t.Errorf("expected 1 confirmed (GO-2024-5678), got %d: %v", len(confirmed), confirmed)
	}
	if _, ok := confirmed["GO-2024-5678"]; !ok {
		t.Error("confirmed missing GO-2024-5678")
	}

	// Status not "called" => not confirmed
	noCalled := []byte(`{"@context":"https://openvex.dev/ns/v0.2.0","version":1,"statements":[{"vulnerability":{"name":"GO-2024-0000"},"products":[{"@id":"x"}],"status":"not_affected","justification":"vulnerable_code_not_present"}]}`)
	_, confNoCalled, _, err := parseGovulncheckOpenVEX(noCalled, "")
	if err != nil {
		t.Fatalf("parseGovulncheckOpenVEX(noCalled): %v", err)
	}
	if len(confNoCalled) != 0 {
		t.Errorf("statements without status called should not be confirmed, got %d: %v", len(confNoCalled), confNoCalled)
	}
}

func TestParseGovulncheckOpenVEX_dbInfo(t *testing.T) {
	// When vulnDBURL is passed, dbInfo should be set with that URL (OpenVEX output does not contain DB metadata).
	input := []byte(`{"@context":"https://openvex.dev/ns/v0.2.0","version":1,"statements":[]}`)
	dbInfo, _, _, err := parseGovulncheckOpenVEX(input, "https://vuln.go.dev")
	if err != nil {
		t.Fatalf("parseGovulncheckOpenVEX: %v", err)
	}
	if dbInfo == nil {
		t.Fatal("expected non-nil dbInfo when vulnDBURL is set")
	}
	if dbInfo.DB != "https://vuln.go.dev" {
		t.Errorf("DB = %q, want https://vuln.go.dev", dbInfo.DB)
	}
}

func TestFormatPluginSource(t *testing.T) {
	// No dbInfo: source is plugin and govulncheck version only (empty version becomes "unknown")
	if got := formatPluginSource("0.1.1", "", nil); got != "trivy-plugin-govulncheck 0.1.1 (govulncheck unknown)" {
		t.Errorf("formatPluginSource(nil) = %q", got)
	}
	// With dbInfo: source includes vuln DB and last modified
	dbInfo := &govulncheckDBInfo{DB: "https://vuln.go.dev", DBLastModified: "2024-01-15T12:00:00Z"}
	got := formatPluginSource("0.1.1", "v1.0.0", dbInfo)
	if got != "trivy-plugin-govulncheck 0.1.1 (govulncheck v1.0.0) (vuln DB: https://vuln.go.dev, last modified: 2024-01-15T12:00:00Z)" {
		t.Errorf("formatPluginSource(dbInfo) = %q", got)
	}
	// DB only, no last modified
	dbInfo2 := &govulncheckDBInfo{DB: "file:///opt/vulndb"}
	if got := formatPluginSource("test", "v1.0.0", dbInfo2); got != "trivy-plugin-govulncheck test (govulncheck v1.0.0) (vuln DB: file:///opt/vulndb)" {
		t.Errorf("formatPluginSource(dbInfo2) = %q", got)
	}
}
