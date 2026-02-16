// SPDX-FileCopyrightText: 2026 Bonial International GmbH
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"testing"
)

func TestParseTrivyignoreYAML(t *testing.T) {
	entries, err := ParseFile("../../testdata/trivyignore_sample.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(entries) != 5 {
		t.Fatalf("expected 5 entries, got %d", len(entries))
	}

	if entries[0].ID != "CVE-2023-1234" {
		t.Errorf("expected CVE-2023-1234, got %s", entries[0].ID)
	}
	if entries[0].Statement != "Component not present in our runtime image" {
		t.Errorf("unexpected statement: %s", entries[0].Statement)
	}

	if entries[2].ExpiredAt != "2020-01-01" {
		t.Errorf("expected expired_at 2020-01-01, got %s", entries[2].ExpiredAt)
	}

	if len(entries[3].Paths) != 1 || entries[3].Paths[0] != "usr/lib/libfoo.so" {
		t.Errorf("unexpected paths: %v", entries[3].Paths)
	}
	if len(entries[3].PURLs) != 1 || entries[3].PURLs[0] != "pkg:deb/debian/libfoo" {
		t.Errorf("unexpected purls: %v", entries[3].PURLs)
	}
}

func TestParseTrivyignoreYAML_FileNotFound(t *testing.T) {
	_, err := ParseFile("nonexistent.yaml")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestParseTrivyignoreYAML_InvalidYAML(t *testing.T) {
	_, err := ParseBytes([]byte("not: [valid: yaml: content"))
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestParseTrivyignoreYAML_Empty(t *testing.T) {
	entries, err := ParseBytes([]byte("vulnerabilities: []"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(entries))
	}
}
