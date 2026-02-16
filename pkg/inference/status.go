// SPDX-FileCopyrightText: 2026 Bonial International GmbH
// SPDX-License-Identifier: Apache-2.0

package inference

import (
	"strings"

	"github.com/openvex/go-vex/pkg/vex"
)

// InferenceResult holds the derived VEX fields from a statement.
type InferenceResult struct {
	Status          vex.Status
	Justification   vex.Justification
	ActionStatement string
	ImpactStatement string
}

type rule struct {
	keywords      []string
	status        vex.Status
	justification vex.Justification
}

var rules = []rule{
	{
		keywords:      []string{"not present", "not installed", "component not present"},
		status:        vex.StatusNotAffected,
		justification: vex.ComponentNotPresent,
	},
	{
		keywords:      []string{"not reachable", "not in execute path", "dead code"},
		status:        vex.StatusNotAffected,
		justification: vex.VulnerableCodeNotInExecutePath,
	},
	{
		keywords:      []string{"cannot be controlled", "not exploitable"},
		status:        vex.StatusNotAffected,
		justification: vex.VulnerableCodeCannotBeControlledByAdversary,
	},
	{
		keywords:      []string{"mitigated", "mitigation", "compensating control"},
		status:        vex.StatusNotAffected,
		justification: vex.InlineMitigationsAlreadyExist,
	},
	{
		keywords: []string{"fixed", "patched", "upgraded", "resolved"},
		status:   vex.StatusFixed,
	},
	{
		keywords: []string{"investigating", "under review", "evaluating"},
		status:   vex.StatusUnderInvestigation,
	},
}

// InferStatus derives VEX status fields from a .trivyignore.yaml statement.
// Pattern matching is case-insensitive. First matching rule wins.
// Default: affected with "Risk accepted." action statement.
func InferStatus(statement string) InferenceResult {
	lower := strings.ToLower(statement)

	for _, r := range rules {
		for _, kw := range r.keywords {
			if strings.Contains(lower, kw) {
				result := InferenceResult{
					Status:        r.status,
					Justification: r.justification,
				}
				if r.status == vex.StatusNotAffected {
					result.ImpactStatement = statement
				}
				return result
			}
		}
	}

	action := "Risk accepted."
	if statement != "" {
		action = "Risk accepted. " + statement
	}
	return InferenceResult{
		Status:          vex.StatusAffected,
		ActionStatement: action,
	}
}
