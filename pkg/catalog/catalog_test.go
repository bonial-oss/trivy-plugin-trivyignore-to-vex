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

func TestReadCatalogInfo_Kind(t *testing.T) {
	info, err := ReadFile("../../testdata/catalog_info_sample.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Kind != "Component" {
		t.Errorf("expected kind Component, got %s", info.Kind)
	}
}

func TestReadCatalogInfo_NamespaceDefault(t *testing.T) {
	info, err := ReadFile("../../testdata/catalog_info_sample.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Namespace() != "default" {
		t.Errorf("expected default namespace, got %s", info.Namespace())
	}
}

func TestNamespaceExplicit(t *testing.T) {
	info := &CatalogInfo{
		Metadata: CatalogMetadata{Namespace: "platform"},
	}
	if info.Namespace() != "platform" {
		t.Errorf("expected platform, got %s", info.Namespace())
	}
}

func TestParseOwnerRef(t *testing.T) {
	tests := []struct {
		name string
		ref  string
		want EntityRef
	}{
		{
			name: "bare name defaults to group/default",
			ref:  "platform-team",
			want: EntityRef{Kind: "group", Namespace: "default", Name: "platform-team"},
		},
		{
			name: "kind-prefixed",
			ref:  "user:alice",
			want: EntityRef{Kind: "user", Namespace: "default", Name: "alice"},
		},
		{
			name: "namespace-prefixed",
			ref:  "platform/team-a",
			want: EntityRef{Kind: "group", Namespace: "platform", Name: "team-a"},
		},
		{
			name: "fully qualified",
			ref:  "group:platform/team-a",
			want: EntityRef{Kind: "group", Namespace: "platform", Name: "team-a"},
		},
		{
			name: "user with namespace",
			ref:  "user:security/alice",
			want: EntityRef{Kind: "user", Namespace: "security", Name: "alice"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseOwnerRef(tc.ref)
			if got != tc.want {
				t.Errorf("ParseOwnerRef(%q) = %+v, want %+v", tc.ref, got, tc.want)
			}
		})
	}
}

func TestResolveOwner(t *testing.T) {
	info, err := ReadFile("../../testdata/catalog_info_sample.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := EntityRef{Kind: "group", Namespace: "default", Name: "platform-team"}
	got := info.ResolveOwner()
	if got != want {
		t.Errorf("ResolveOwner() = %+v, want %+v", got, want)
	}
}
