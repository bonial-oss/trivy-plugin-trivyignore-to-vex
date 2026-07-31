// SPDX-FileCopyrightText: 2026 Bonial International GmbH
// SPDX-License-Identifier: Apache-2.0

package vexgen

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/bonial-oss/trivy-plugin-trivyignore-to-vex/pkg/types"
	govex "github.com/openvex/go-vex/pkg/vex"
)

func TestGenerate_BasicStatement(t *testing.T) {
	entries := []types.IgnoreEntry{
		{
			ID:        "CVE-2023-1234",
			Statement: "Component not present in our image",
		},
	}
	opts := Options{
		Author:  "test-author",
		Product: "pkg:oci/my-image",
	}

	doc, err := Generate(entries, opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if doc.Author != "test-author" {
		t.Errorf("expected author test-author, got %s", doc.Author)
	}
	if len(doc.Statements) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(doc.Statements))
	}

	stmt := doc.Statements[0]
	if stmt.Vulnerability.ID != "https://nvd.nist.gov/vuln/detail/CVE-2023-1234" {
		t.Errorf("expected vulnerability ID https://nvd.nist.gov/vuln/detail/CVE-2023-1234, got %s", stmt.Vulnerability.ID)
	}
	if stmt.Status != govex.StatusNotAffected {
		t.Errorf("expected not_affected, got %s", stmt.Status)
	}
	if stmt.Justification != govex.ComponentNotPresent {
		t.Errorf("expected component_not_present, got %s", stmt.Justification)
	}
	if stmt.ImpactStatement != "Statement:\nComponent not present in our image" {
		t.Errorf("unexpected impact statement: %q", stmt.ImpactStatement)
	}
}

func TestGenerate_AffectedDefault(t *testing.T) {
	entries := []types.IgnoreEntry{
		{
			ID:        "CVE-2023-5678",
			Statement: "Risk accepted per JIRA-123",
		},
	}
	opts := Options{Author: "test-author"}

	doc, err := Generate(entries, opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	stmt := doc.Statements[0]
	if stmt.Status != govex.StatusAffected {
		t.Errorf("expected affected, got %s", stmt.Status)
	}
	if stmt.ActionStatement != "Risk accepted.\nStatement:\nRisk accepted per JIRA-123" {
		t.Errorf("unexpected action statement: %q", stmt.ActionStatement)
	}
}

func TestGenerate_SkipsExpiredEntries(t *testing.T) {
	entries := []types.IgnoreEntry{
		{
			ID:        "CVE-2023-1111",
			Statement: "Still valid",
		},
		{
			ID:        "CVE-2023-2222",
			Statement: "Expired entry",
			ExpiredAt: "2020-01-01",
		},
	}
	opts := Options{Author: "test-author"}

	doc, err := Generate(entries, opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(doc.Statements) != 1 {
		t.Fatalf("expected 1 statement (expired should be skipped), got %d", len(doc.Statements))
	}
	if string(doc.Statements[0].Vulnerability.Name) != "CVE-2023-1111" {
		t.Errorf("expected CVE-2023-1111, got %s", doc.Statements[0].Vulnerability.Name)
	}
}

func TestGenerate_KeepsFutureExpiry(t *testing.T) {
	entries := []types.IgnoreEntry{
		{
			ID:        "CVE-2023-3333",
			Statement: "Valid until far future",
			ExpiredAt: "2099-12-31",
		},
	}
	opts := Options{Author: "test-author"}

	doc, err := Generate(entries, opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(doc.Statements) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(doc.Statements))
	}
}

func TestGenerate_NoProduct(t *testing.T) {
	entries := []types.IgnoreEntry{
		{ID: "CVE-2023-1234", Statement: "Not present"},
	}
	opts := Options{Author: "test-author"}

	doc, err := Generate(entries, opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(doc.Statements[0].Products) != 0 {
		t.Errorf("expected no products when product is not specified, got %d", len(doc.Statements[0].Products))
	}
}

func TestGenerate_WithProduct(t *testing.T) {
	entries := []types.IgnoreEntry{
		{ID: "CVE-2023-1234", Statement: "Not present"},
	}
	opts := Options{
		Author:  "test-author",
		Product: "pkg:oci/my-image@sha256:abc123",
	}

	doc, err := Generate(entries, opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(doc.Statements[0].Products) != 1 {
		t.Fatalf("expected 1 product, got %d", len(doc.Statements[0].Products))
	}
	if doc.Statements[0].Products[0].ID != "pkg:oci/my-image@sha256:abc123" {
		t.Errorf("unexpected product ID: %s", doc.Statements[0].Products[0].ID)
	}
}

func TestGenerate_EmptyEntries(t *testing.T) {
	doc, err := Generate(nil, Options{Author: "test-author"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(doc.Statements) != 0 {
		t.Errorf("expected 0 statements, got %d", len(doc.Statements))
	}
}

func TestGenerate_MalformedExpiredAt(t *testing.T) {
	entries := []types.IgnoreEntry{
		{
			ID:        "CVE-2023-4444",
			Statement: "Has bad date",
			ExpiredAt: "not-a-date",
		},
	}
	opts := Options{Author: "test-author"}

	doc, err := Generate(entries, opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Malformed date should be treated as not expired (entry included)
	if len(doc.Statements) != 1 {
		t.Fatalf("expected 1 statement (malformed date = not expired), got %d", len(doc.Statements))
	}
}

func TestGenerate_DocumentMetadata(t *testing.T) {
	doc, err := Generate(nil, Options{Author: "security-team"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.HasPrefix(doc.ID, "urn:uuid:") {
		t.Errorf("expected document ID to start with urn:uuid:, got %s", doc.ID)
	}
	if doc.Context != "https://openvex.dev/ns/v0.2.0" {
		t.Errorf("unexpected context: %s", doc.Context)
	}
	if doc.Author != "security-team" {
		t.Errorf("unexpected author: %s", doc.Author)
	}
	if doc.AuthorRole != "" {
		t.Errorf("expected empty role (omitted) when no AuthorRole is provided, got: %s", doc.AuthorRole)
	}
	if doc.Version != 1 {
		t.Errorf("expected version 1, got %d", doc.Version)
	}
	if doc.Timestamp == nil {
		t.Error("expected non-nil timestamp")
	}
	if time.Since(*doc.Timestamp) > 5*time.Second {
		t.Errorf("timestamp too far in the past: %v", doc.Timestamp)
	}
}

func TestGenerate_AuthorRoleVerbatim(t *testing.T) {
	doc, err := Generate(nil, Options{Author: "team", AuthorRole: "Component Owner"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if doc.AuthorRole != "Component Owner" {
		t.Errorf("expected Component Owner, got %q", doc.AuthorRole)
	}
}

func TestGenerate_DocIDBackstageURL(t *testing.T) {
	doc, err := Generate(nil, Options{
		Author:          "team",
		BackstageURL:    "https://backstage.example.com",
		EntityKind:      "component",
		EntityNamespace: "default",
		EntityName:      "my-service",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	prefix := "https://backstage.example.com/catalog/default/component/my-service#vex-"
	if !strings.HasPrefix(doc.ID, prefix) {
		t.Errorf("expected doc ID to start with %q, got %q", prefix, doc.ID)
	}
}

func TestGenerate_DocIDBackstageURLTrimsTrailingSlash(t *testing.T) {
	doc, err := Generate(nil, Options{
		Author:          "team",
		BackstageURL:    "https://backstage.example.com/",
		EntityKind:      "component",
		EntityNamespace: "default",
		EntityName:      "my-service",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	prefix := "https://backstage.example.com/catalog/default/component/my-service#vex-"
	if !strings.HasPrefix(doc.ID, prefix) {
		t.Errorf("expected doc ID to start with %q, got %q", prefix, doc.ID)
	}
}

func TestGenerate_DocIDFallsBackToUUIDWhenPartial(t *testing.T) {
	// BackstageURL set but no entity fields → fall back to urn:uuid.
	doc, err := Generate(nil, Options{
		Author:       "team",
		BackstageURL: "https://backstage.example.com",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(doc.ID, "urn:uuid:") {
		t.Errorf("expected urn:uuid fallback when entity fields missing, got %q", doc.ID)
	}
}

func TestGenerate_PurlsAsSubcomponentsWithProduct(t *testing.T) {
	entries := []types.IgnoreEntry{
		{
			ID:        "CVE-2025-25290",
			Statement: "not reachable",
			PURLs:     []string{"pkg:npm/%40octokit/request"},
		},
	}
	doc, err := Generate(entries, Options{
		Author:  "team",
		Product: "pkg:oci/my-image@sha256:abc",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(doc.Statements) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(doc.Statements))
	}
	stmt := doc.Statements[0]
	if len(stmt.Products) != 1 {
		t.Fatalf("expected 1 product, got %d", len(stmt.Products))
	}
	if len(stmt.Products[0].Subcomponents) != 1 {
		t.Fatalf("expected 1 subcomponent, got %d", len(stmt.Products[0].Subcomponents))
	}
	subPurl := stmt.Products[0].Subcomponents[0].Identifiers[govex.PURL]
	if subPurl != "pkg:npm/%40octokit/request" {
		t.Errorf("unexpected subcomponent purl: %s", subPurl)
	}
	// prose "Affected PURLs:" section should NOT appear when subcomponents are emitted structurally
	if strings.Contains(stmt.ImpactStatement, "Affected PURLs:") {
		t.Errorf("did not expect Affected PURLs: prose when product is set, got: %s", stmt.ImpactStatement)
	}
	// but the Statement: section should still contain the original statement
	if !strings.Contains(stmt.ImpactStatement, "Statement:\nnot reachable") {
		t.Errorf("expected Statement: section with original statement, got: %s", stmt.ImpactStatement)
	}
}

func TestGenerate_PurlsAsProseWithoutProduct(t *testing.T) {
	entries := []types.IgnoreEntry{
		{
			ID:        "CVE-2025-25290",
			Statement: "not reachable",
			PURLs:     []string{"pkg:npm/%40octokit/request", "pkg:npm/other"},
		},
	}
	doc, err := Generate(entries, Options{Author: "team"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	stmt := doc.Statements[0]
	if len(stmt.Products) != 0 {
		t.Errorf("expected no products when --product not set, got %d", len(stmt.Products))
	}
	// not_affected → sections go into impact_statement
	want := "Affected PURLs:\n  - pkg:npm/%40octokit/request\n  - pkg:npm/other\nStatement:\nnot reachable"
	if stmt.ImpactStatement != want {
		t.Errorf("unexpected impact_statement:\ngot:  %q\nwant: %q", stmt.ImpactStatement, want)
	}
}

func TestGenerate_PathsNotEmittedInOutput(t *testing.T) {
	// Post-delta: paths are parsed from .trivyignore.yaml but never surface in
	// the emitted VEX (VEX has no file-path scoping concept; paths don't
	// identify what's shipped). This test pins that behavior.
	entries := []types.IgnoreEntry{
		{
			ID:        "CVE-2023-1234",
			Statement: "not reachable",
			Paths:     []string{"src/foo.js", "src/bar.js"},
		},
	}
	doc, err := Generate(entries, Options{Author: "team"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	stmt := doc.Statements[0]
	if strings.Contains(stmt.ImpactStatement, "src/foo.js") ||
		strings.Contains(stmt.ImpactStatement, "src/bar.js") ||
		strings.Contains(stmt.ImpactStatement, "Affected paths") {
		t.Errorf("expected paths to not surface in impact_statement, got: %q", stmt.ImpactStatement)
	}
}

func TestGenerate_ExpiresAtSection(t *testing.T) {
	entries := []types.IgnoreEntry{
		{
			ID:        "CVE-2023-3333",
			Statement: "not reachable",
			ExpiredAt: "2099-12-31",
		},
	}
	doc, err := Generate(entries, Options{Author: "team"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	stmt := doc.Statements[0]
	want := "Expires at: 2099-12-31\nStatement:\nnot reachable"
	if stmt.ImpactStatement != want {
		t.Errorf("unexpected impact_statement:\ngot:  %q\nwant: %q", stmt.ImpactStatement, want)
	}
}

func TestGenerate_SectionOrderingAllPresent(t *testing.T) {
	// Verify the fixed section ordering: Risk accepted. → Expires at: →
	// Affected PURLs: → Statement:
	entries := []types.IgnoreEntry{
		{
			ID:        "CVE-2023-8888",
			Statement: "Living with this one",
			ExpiredAt: "2099-12-31",
			PURLs:     []string{"pkg:npm/foo"},
		},
	}
	doc, err := Generate(entries, Options{Author: "team"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	stmt := doc.Statements[0]
	// This entry falls through to affected (no inference keywords matched).
	if stmt.Status != govex.StatusAffected {
		t.Fatalf("expected affected, got %s", stmt.Status)
	}
	want := "Risk accepted.\nExpires at: 2099-12-31\nAffected PURLs:\n  - pkg:npm/foo\nStatement:\nLiving with this one"
	if stmt.ActionStatement != want {
		t.Errorf("unexpected action_statement:\ngot:  %q\nwant: %q", stmt.ActionStatement, want)
	}
}

func TestGenerate_EmptyStatementOmitsStatementSection(t *testing.T) {
	// affected + empty statement → action_statement is just "Risk accepted." —
	// no dangling "Statement:" label.
	entries := []types.IgnoreEntry{
		{
			ID:        "CVE-2023-7777",
			Statement: "",
		},
	}
	doc, err := Generate(entries, Options{Author: "team"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	stmt := doc.Statements[0]
	if stmt.ActionStatement != "Risk accepted." {
		t.Errorf("expected action_statement = %q, got %q", "Risk accepted.", stmt.ActionStatement)
	}
}

func TestGenerate_NotAffectedNoRiskAcceptedPrefix(t *testing.T) {
	// not_affected statements must not carry the "Risk accepted." prefix —
	// that leader is only for affected.
	entries := []types.IgnoreEntry{
		{
			ID:        "CVE-2023-6666",
			Statement: "not reachable",
		},
	}
	doc, err := Generate(entries, Options{Author: "team"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	stmt := doc.Statements[0]
	if stmt.Status != govex.StatusNotAffected {
		t.Fatalf("expected not_affected, got %s", stmt.Status)
	}
	if strings.HasPrefix(stmt.ImpactStatement, "Risk accepted.") {
		t.Errorf("not_affected impact_statement must not lead with 'Risk accepted.', got: %q", stmt.ImpactStatement)
	}
}

func TestGenerate_FixedStatusRoutesToStatusNotes(t *testing.T) {
	entries := []types.IgnoreEntry{
		{
			ID:        "CVE-2023-5555",
			Statement: "Fixed in v2.0",
			ExpiredAt: "2099-12-31",
		},
	}
	doc, err := Generate(entries, Options{Author: "team"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	stmt := doc.Statements[0]
	if stmt.Status != govex.StatusFixed {
		t.Fatalf("expected fixed, got %s", stmt.Status)
	}
	// fixed → sections go into status_notes (not impact/action)
	if stmt.ImpactStatement != "" {
		t.Errorf("expected empty impact_statement for fixed status, got: %q", stmt.ImpactStatement)
	}
	if stmt.ActionStatement != "" {
		t.Errorf("expected empty action_statement for fixed status, got: %q", stmt.ActionStatement)
	}
	want := "Expires at: 2099-12-31\nStatement:\nFixed in v2.0"
	if stmt.StatusNotes != want {
		t.Errorf("unexpected status_notes:\ngot:  %q\nwant: %q", stmt.StatusNotes, want)
	}
}

func TestGenerate_WarningsWriter_CapturesPurlsWithoutProduct(t *testing.T) {
	entries := []types.IgnoreEntry{
		{
			ID:        "CVE-2025-25290",
			Statement: "not reachable",
			PURLs:     []string{"pkg:npm/foo"},
		},
		{
			ID:        "CVE-2025-25291",
			Statement: "not reachable",
			PURLs:     []string{"pkg:npm/bar"},
		},
	}
	var buf bytes.Buffer
	_, err := Generate(entries, Options{Author: "team", WarningsWriter: &buf})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := buf.String()
	if !strings.Contains(got, "2 .trivyignore.yaml entries have `purls`") {
		t.Errorf("expected count-of-2 warning, got: %q", got)
	}
	if !strings.Contains(got, "Pass --product") {
		t.Errorf("expected suggestion to pass --product, got: %q", got)
	}
}

func TestGenerate_WarningsWriter_DiscardSuppresses(t *testing.T) {
	entries := []types.IgnoreEntry{
		{
			ID:        "CVE-2025-25290",
			Statement: "not reachable",
			PURLs:     []string{"pkg:npm/foo"},
			ExpiredAt: "not-a-date", // triggers the malformed-date warning too
		},
	}
	_, err := Generate(entries, Options{Author: "team", WarningsWriter: io.Discard})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// If io.Discard didn't route through the writer, this test would show up
	// in the test runner's captured stderr. The assertion is implicit: no
	// panic, no error, and (visually) no noise in the test output.
}

// TestGenerate_RoleOmittedFromJSONWhenEmpty is a defensive test that pins our
// FR-3.3 "omit role when no signal" contract to the upstream go-vex library's
// `json:"role,omitempty"` tag on Metadata.AuthorRole. If a future go-vex
// release drops the omitempty tag, we would silently start emitting
// `"role": ""` in every doc lacking a role signal — spec-legal but misleading.
// This test catches that regression at `go mod tidy` time.
func TestGenerate_RoleOmittedFromJSONWhenEmpty(t *testing.T) {
	doc, err := Generate(nil, Options{Author: "Unknown"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if doc.AuthorRole != "" {
		t.Fatalf("test invariant broken: AuthorRole should be empty in Options with no role signal, got %q", doc.AuthorRole)
	}

	var buf bytes.Buffer
	if err := doc.ToJSON(&buf); err != nil {
		t.Fatalf("failed to serialize VEX: %v", err)
	}

	var m map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if v, has := m["role"]; has {
		t.Errorf("expected `role` to be omitted from JSON when AuthorRole is empty, found role=%v.\n"+
			"This likely means the upstream go-vex library dropped the `json:\"role,omitempty\"` tag on "+
			"Metadata.AuthorRole. Our FR-3.3 \"omit role when no signal\" contract depends on that tag; "+
			"pin the go-vex version or implement a custom marshaler in pkg/vex to restore the behavior.",
			v)
	}
}

func TestGenerate_WarningsWriter_MalformedDate(t *testing.T) {
	entries := []types.IgnoreEntry{
		{
			ID:        "CVE-2023-4444",
			Statement: "Has bad date",
			ExpiredAt: "not-a-date",
		},
	}
	var buf bytes.Buffer
	_, err := Generate(entries, Options{Author: "team", WarningsWriter: &buf})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := buf.String()
	if !strings.Contains(got, "CVE-2023-4444") {
		t.Errorf("expected malformed-date warning to name the entry, got: %q", got)
	}
	if !strings.Contains(got, "not-a-date") {
		t.Errorf("expected malformed-date warning to include the bad value, got: %q", got)
	}
}

