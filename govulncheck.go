// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026-present Datadog, Inc.

package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"runtime/debug"

	"github.com/openvex/go-vex/pkg/vex"
	"golang.org/x/vuln/scan"
)

// govulncheckDBInfo is the config message from govulncheck (DB source and last-modified). Used for
// parsing the "config" JSON and for logging / ModifiedFindings source.
// When using OpenVEX output we set DB from the -db flag when provided; last-modified may be empty.
type govulncheckDBInfo struct {
	DB             string `json:"db,omitempty"`
	DBLastModified string `json:"db_last_modified,omitempty"`
}

// runGovulncheck runs govulncheck via golang.org/x/vuln/scan (compiled into the plugin).
// vulnDBURL is optional; if non-empty, govulncheck is run with -db <vulnDBURL> (no network when file://).
// Returns dbInfo (DB source and last-modified from govulncheck config, may be nil), confirmedIDs, consideredIDs, or error.
func runGovulncheck(ctx context.Context, binaryPath string, vulnDBURL string) (dbInfo *govulncheckDBInfo, confirmedIDs, consideredIDs map[string]struct{}, err error) {
	if err := validateVulnDBURL(vulnDBURL); err != nil {
		return nil, nil, nil, err
	}
	if err := validateBinaryPath(binaryPath); err != nil {
		return nil, nil, nil, err
	}
	var stdout bytes.Buffer
	args := []string{"-format", "openvex", "-mode", "binary"}
	if vulnDBURL != "" {
		args = append(args, "-db", vulnDBURL)
	}
	args = append(args, binaryPath)
	// Validating the vulnerability database URL and binary path before running govulncheck to avoid command injection.
	// no-dd-sa:go-security/command-injection
	cmd := scan.Command(ctx, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, nil, nil, err
	}
	if err := cmd.Wait(); err != nil {
		return nil, nil, nil, err
	}
	info, confirmed, considered, err := parseGovulncheckOpenVEX(stdout.Bytes(), vulnDBURL)
	if err != nil {
		return nil, nil, nil, err
	}
	return info, confirmed, considered, nil
}

// parseGovulncheckOpenVEX parses govulncheck -format openvex output using the OpenVEX standard.
// Confirmed = vulns with status "called" (vulnerable code actually used). Considered = all vuln IDs
// (Name + Aliases) from every statement. When vulnDBURL is non-empty, dbInfo.DB is set to it
// (last_modified is not present in OpenVEX output).
func parseGovulncheckOpenVEX(data []byte, vulnDBURL string) (dbInfo *govulncheckDBInfo, confirmedIDs, consideredIDs map[string]struct{}, err error) {
	confirmed := make(map[string]struct{})
	considered := make(map[string]struct{})
	doc, err := vex.Parse(data)
	if err != nil {
		return nil, nil, nil, err
	}
	if vulnDBURL != "" {
		dbInfo = &govulncheckDBInfo{DB: vulnDBURL}
	}
	for i := range doc.Statements {
		s := &doc.Statements[i]
		v := &s.Vulnerability
		// Considered: every vuln ID mentioned (name + aliases)
		if v.Name != "" {
			considered[string(v.Name)] = struct{}{}
		}
		if v.ID != "" {
			considered[v.ID] = struct{}{}
		}
		for _, a := range v.Aliases {
			if a != "" {
				considered[string(a)] = struct{}{}
			}
		}
		// Confirmed: only when govulncheck reports status "called" (vulnerable code in binary call graph)
		if string(s.Status) == "called" {
			if v.Name != "" {
				confirmed[string(v.Name)] = struct{}{}
			}
			if v.ID != "" {
				confirmed[v.ID] = struct{}{}
			}
			for _, a := range v.Aliases {
				if a != "" {
					confirmed[string(a)] = struct{}{}
				}
			}
		}
	}
	return dbInfo, confirmed, considered, nil
}

// formatPluginSource returns the source string for ModifiedFindings, including vuln DB when available.
func formatPluginSource(pluginVer string, govulnVersion string, dbInfo *govulncheckDBInfo) string {
	if govulnVersion == "" {
		govulnVersion = "unknown"
	}
	s := fmt.Sprintf("trivy-plugin-govulncheck %s (govulncheck %s)", pluginVer, govulnVersion)
	if dbInfo != nil && dbInfo.DB != "" {
		s += fmt.Sprintf(" (vuln DB: %s", dbInfo.DB)
		if dbInfo.DBLastModified != "" {
			s += fmt.Sprintf(", last modified: %s", dbInfo.DBLastModified)
		}
		s += ")"
	}
	return s
}

// govulncheckVersion returns the version of golang.org/x/vuln (govulncheck) from build info, or "unknown".
func govulncheckVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	for _, d := range info.Deps {
		if d.Path == "golang.org/x/vuln" {
			if d.Version != "" {
				return d.Version
			}
			return "unknown"
		}
	}
	return "unknown"
}
