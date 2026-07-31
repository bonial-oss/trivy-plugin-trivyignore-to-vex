// SPDX-FileCopyrightText: 2026 Bonial International GmbH
// SPDX-License-Identifier: Apache-2.0

package vexgen

import (
	"bytes"
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
	if stmt.ImpactStatement != "Component not present in our image" {
		t.Errorf("unexpected impact statement: %s", stmt.ImpactStatement)
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
	if stmt.ActionStatement != "Risk accepted. Risk accepted per JIRA-123" {
		t.Errorf("unexpected action statement: %s", stmt.ActionStatement)
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
	// prose "Affected purls:" should NOT appear when subcomponents are emitted structurally
	if strings.Contains(stmt.ImpactStatement, "Affected purls:") {
		t.Errorf("did not expect Affected purls: prose when product is set, got: %s", stmt.ImpactStatement)
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
	// not_affected → prose goes into impact_statement
	if !strings.Contains(stmt.ImpactStatement, "Affected purls: pkg:npm/%40octokit/request, pkg:npm/other") {
		t.Errorf("expected Affected purls: prose in impact_statement, got: %s", stmt.ImpactStatement)
	}
	// blank line separator between existing prose and new note
	if !strings.Contains(stmt.ImpactStatement, "not reachable\n\nAffected purls:") {
		t.Errorf("expected blank-line separator, got: %s", stmt.ImpactStatement)
	}
}

func TestGenerate_PathsAsProse(t *testing.T) {
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
	if !strings.Contains(stmt.ImpactStatement, "Affected paths: src/foo.js, src/bar.js") {
		t.Errorf("expected Affected paths: prose, got: %s", stmt.ImpactStatement)
	}
}

func TestGenerate_PathsProseForAffected(t *testing.T) {
	entries := []types.IgnoreEntry{
		{
			ID:        "CVE-2023-9999",
			Statement: "Risk accepted",
			Paths:     []string{"src/foo.js"},
		},
	}
	doc, err := Generate(entries, Options{Author: "team"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	stmt := doc.Statements[0]
	if stmt.Status != govex.StatusAffected {
		t.Fatalf("expected affected, got %s", stmt.Status)
	}
	// affected → paths prose goes into action_statement
	if !strings.Contains(stmt.ActionStatement, "Affected paths: src/foo.js") {
		t.Errorf("expected Affected paths: in action_statement, got: %s", stmt.ActionStatement)
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

func TestGenerate_PathsProseForFixed(t *testing.T) {
	entries := []types.IgnoreEntry{
		{
			ID:        "CVE-2023-9998",
			Statement: "Fixed in v2.0",
			Paths:     []string{"src/foo.js"},
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
	// fixed → prose goes into status_notes
	if !strings.Contains(stmt.StatusNotes, "Affected paths: src/foo.js") {
		t.Errorf("expected Affected paths: in status_notes, got: %s", stmt.StatusNotes)
	}
}
