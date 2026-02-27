// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026-present Datadog, Inc.

package main

import (
	"strings"

	"github.com/aquasecurity/trivy/pkg/types"
)

// filterVulnerabilities keeps vulns that govulncheck reported as used (confirmedIDs).
// Only move to ModifiedFindings when govulncheck considered the vuln (in DB, applicable to binary)
// but did not report it as used — i.e. symbol not in call graph. If the vuln is not in consideredIDs,
// govulncheck did not have it in its DB or it didn't apply; leave it as an active finding to avoid false negatives.
func filterVulnerabilities(result *types.Result, confirmedIDs, consideredIDs map[string]struct{}, dbInfo *govulncheckDBInfo, govulnVersion, pluginVer string) {
	source := formatPluginSource(pluginVer, govulnVersion, dbInfo)
	filtered := result.Vulnerabilities[:0]
	for _, v := range result.Vulnerabilities {
		considered := vulnerabilityMatchesSet(&v, consideredIDs)
		confirmed := vulnerabilityMatchesSet(&v, confirmedIDs)
		if considered && !confirmed {
			// govulncheck considered this vuln but did not confirm (symbol not used) → suppress
			vCopy := v
			result.ModifiedFindings = append(result.ModifiedFindings, types.NewModifiedFinding(
				&vCopy,
				types.FindingStatusNotAffected,
				"vulnerable symbol not used in binary",
				source,
			))
		} else {
			// confirmed, or not considered by govulncheck → keep as active finding
			filtered = append(filtered, v)
		}
	}
	result.Vulnerabilities = filtered
}

// vulnerabilityMatchesSet returns true if the finding's VulnerabilityID, any VendorID, or
// any case-insensitive OSV alias matches an ID in the set (e.g. confirmed or considered IDs from govulncheck).
func vulnerabilityMatchesSet(v *types.DetectedVulnerability, ids map[string]struct{}) bool {
	if _, ok := ids[v.VulnerabilityID]; ok {
		return true
	}
	for _, id := range v.VendorIDs {
		if _, ok := ids[id]; ok {
			return true
		}
	}
	idUpper := strings.ToUpper(v.VulnerabilityID)
	for osvID := range ids {
		if strings.ToUpper(osvID) == idUpper {
			return true
		}
	}
	return false
}
