// SPDX-FileCopyrightText: 2026 Bonial International GmbH
// SPDX-License-Identifier: Apache-2.0

package inference

import (
	"testing"

	"github.com/openvex/go-vex/pkg/vex"
)

func TestInferStatus(t *testing.T) {
	tests := []struct {
		name        string
		statement   string
		wantStatus  vex.Status
		wantJustify vex.Justification
		wantAction  string
		wantImpact  string
	}{
		{
			name:        "component not present",
			statement:   "Component not present in our runtime image",
			wantStatus:  vex.StatusNotAffected,
			wantJustify: vex.ComponentNotPresent,
			wantImpact:  "Component not present in our runtime image",
		},
		{
			name:        "not installed",
			statement:   "Package is not installed in production",
			wantStatus:  vex.StatusNotAffected,
			wantJustify: vex.ComponentNotPresent,
			wantImpact:  "Package is not installed in production",
		},
		{
			name:        "not compiled in",
			statement:   "Feature is not compiled in for our build",
			wantStatus:  vex.StatusNotAffected,
			wantJustify: vex.VulnerableCodeNotPresent,
			wantImpact:  "Feature is not compiled in for our build",
		},
		{
			name:        "feature disabled",
			statement:   "Vulnerable feature disabled at build time",
			wantStatus:  vex.StatusNotAffected,
			wantJustify: vex.VulnerableCodeNotPresent,
			wantImpact:  "Vulnerable feature disabled at build time",
		},
		{
			name:        "excluded from build",
			statement:   "Module excluded from build via linker flag",
			wantStatus:  vex.StatusNotAffected,
			wantJustify: vex.VulnerableCodeNotPresent,
			wantImpact:  "Module excluded from build via linker flag",
		},
		{
			name:        "not reachable",
			statement:   "Code is not reachable from any entry point",
			wantStatus:  vex.StatusNotAffected,
			wantJustify: vex.VulnerableCodeNotInExecutePath,
			wantImpact:  "Code is not reachable from any entry point",
		},
		{
			name:        "dead code",
			statement:   "This is dead code, never executed",
			wantStatus:  vex.StatusNotAffected,
			wantJustify: vex.VulnerableCodeNotInExecutePath,
			wantImpact:  "This is dead code, never executed",
		},
		{
			name:        "not exploitable",
			statement:   "Vulnerability is not exploitable in our config",
			wantStatus:  vex.StatusNotAffected,
			wantJustify: vex.VulnerableCodeCannotBeControlledByAdversary,
			wantImpact:  "Vulnerability is not exploitable in our config",
		},
		{
			name:        "cannot be controlled",
			statement:   "Input cannot be controlled by adversary",
			wantStatus:  vex.StatusNotAffected,
			wantJustify: vex.VulnerableCodeCannotBeControlledByAdversary,
			wantImpact:  "Input cannot be controlled by adversary",
		},
		{
			name:        "mitigated",
			statement:   "Mitigated by WAF rules",
			wantStatus:  vex.StatusNotAffected,
			wantJustify: vex.InlineMitigationsAlreadyExist,
			wantImpact:  "Mitigated by WAF rules",
		},
		{
			name:        "compensating control",
			statement:   "Compensating control in place via network segmentation",
			wantStatus:  vex.StatusNotAffected,
			wantJustify: vex.InlineMitigationsAlreadyExist,
			wantImpact:  "Compensating control in place via network segmentation",
		},
		{
			name:       "fixed",
			statement:  "Fixed in latest patch release",
			wantStatus: vex.StatusFixed,
		},
		{
			name:       "patched",
			statement:  "Already patched upstream",
			wantStatus: vex.StatusFixed,
		},
		{
			name:       "upgraded",
			statement:  "Upgraded to non-vulnerable version",
			wantStatus: vex.StatusFixed,
		},
		{
			name:       "resolved",
			statement:  "Issue resolved via dependency update",
			wantStatus: vex.StatusFixed,
		},
		{
			name:       "investigating",
			statement:  "Currently investigating impact",
			wantStatus: vex.StatusUnderInvestigation,
		},
		{
			name:       "under review",
			statement:  "Under review by security team",
			wantStatus: vex.StatusUnderInvestigation,
		},
		{
			name:       "evaluating",
			statement:  "Evaluating whether this applies",
			wantStatus: vex.StatusUnderInvestigation,
		},
		{
			name:       "default — risk accepted with statement",
			statement:  "Risk accepted per JIRA-123",
			wantStatus: vex.StatusAffected,
			wantAction: "Risk accepted. Risk accepted per JIRA-123",
		},
		{
			name:       "default — risk accepted empty statement",
			statement:  "",
			wantStatus: vex.StatusAffected,
			wantAction: "Risk accepted.",
		},
		{
			name:        "case insensitive — NOT PRESENT",
			statement:   "Component is NOT PRESENT",
			wantStatus:  vex.StatusNotAffected,
			wantJustify: vex.ComponentNotPresent,
			wantImpact:  "Component is NOT PRESENT",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := InferStatus(tt.statement)

			if result.Status != tt.wantStatus {
				t.Errorf("status: got %q, want %q", result.Status, tt.wantStatus)
			}
			if result.Justification != tt.wantJustify {
				t.Errorf("justification: got %q, want %q", result.Justification, tt.wantJustify)
			}
			if result.ActionStatement != tt.wantAction {
				t.Errorf("action: got %q, want %q", result.ActionStatement, tt.wantAction)
			}
			if result.ImpactStatement != tt.wantImpact {
				t.Errorf("impact: got %q, want %q", result.ImpactStatement, tt.wantImpact)
			}
		})
	}
}

func TestInferStatus_FirstMatchWins(t *testing.T) {
	result := InferStatus("Component not present but also mitigated")
	if result.Status != vex.StatusNotAffected {
		t.Errorf("expected not_affected, got %s", result.Status)
	}
	if result.Justification != vex.ComponentNotPresent {
		t.Errorf("expected component_not_present, got %s", result.Justification)
	}
}
