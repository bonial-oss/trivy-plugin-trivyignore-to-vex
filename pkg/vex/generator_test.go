// SPDX-FileCopyrightText: 2026 Bonial International GmbH
// SPDX-License-Identifier: Apache-2.0

package vexgen

import (
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
	if doc.AuthorRole != "Document Creator" {
		t.Errorf("unexpected role: %s", doc.AuthorRole)
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
