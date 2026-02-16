// SPDX-FileCopyrightText: 2026 Bonial International GmbH
// SPDX-License-Identifier: Apache-2.0

package catalog

import (
	"testing"
)

func TestReadCatalogInfo(t *testing.T) {
	info, err := ReadFile("../../testdata/catalog_info_sample.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if info.Metadata.Name != "my-service" {
		t.Errorf("expected name my-service, got %s", info.Metadata.Name)
	}
	if info.Spec.Owner != "platform-team" {
		t.Errorf("expected owner platform-team, got %s", info.Spec.Owner)
	}
}

func TestReadCatalogInfo_FileNotFound(t *testing.T) {
	_, err := ReadFile("nonexistent.yaml")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestReadCatalogInfo_Owner(t *testing.T) {
	info, err := ReadFile("../../testdata/catalog_info_sample.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Owner() != "platform-team" {
		t.Errorf("expected owner platform-team, got %s", info.Owner())
	}
}

func TestReadCatalogInfo_Name(t *testing.T) {
	info, err := ReadFile("../../testdata/catalog_info_sample.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Name() != "my-service" {
		t.Errorf("expected name my-service, got %s", info.Name())
	}
}
