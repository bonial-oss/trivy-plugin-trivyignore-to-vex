// SPDX-FileCopyrightText: 2026 Bonial International GmbH
// SPDX-License-Identifier: Apache-2.0

package catalog

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// DefaultNamespace is the Backstage default namespace when metadata.namespace is absent.
const DefaultNamespace = "default"

// DefaultOwnerKind is the Backstage default kind when an owner reference has no kind prefix.
const DefaultOwnerKind = "group"

// CatalogInfo represents the relevant fields from a Backstage catalog-info.yaml.
type CatalogInfo struct {
	Kind     string          `yaml:"kind"`
	Metadata CatalogMetadata `yaml:"metadata"`
	Spec     CatalogSpec     `yaml:"spec"`
}

// CatalogMetadata holds the metadata section.
type CatalogMetadata struct {
	Name      string `yaml:"name"`
	Namespace string `yaml:"namespace"`
}

// CatalogSpec holds the spec section.
type CatalogSpec struct {
	Owner string `yaml:"owner"`
}

// EntityRef holds a resolved Backstage entity reference (kind, namespace, name).
type EntityRef struct {
	Kind      string
	Namespace string
	Name      string
}

// Owner returns the spec.owner value (raw string).
func (c *CatalogInfo) Owner() string {
	return c.Spec.Owner
}

// Name returns the metadata.name value.
func (c *CatalogInfo) Name() string {
	return c.Metadata.Name
}

// Namespace returns metadata.namespace, defaulting to "default" when absent.
func (c *CatalogInfo) Namespace() string {
	if c.Metadata.Namespace == "" {
		return DefaultNamespace
	}
	return c.Metadata.Namespace
}

// ResolveOwner parses spec.owner as a Backstage entity reference.
// See ParseOwnerRef for the accepted formats and defaults.
func (c *CatalogInfo) ResolveOwner() EntityRef {
	return ParseOwnerRef(c.Spec.Owner)
}

// ParseOwnerRef parses a Backstage owner reference string.
//
// Accepted formats:
//   - "<name>"                          → kind=DefaultOwnerKind, namespace=DefaultNamespace, name=<name>
//   - "<kind>:<name>"                   → kind=<kind>, namespace=DefaultNamespace, name=<name>
//   - "<namespace>/<name>"              → kind=DefaultOwnerKind, namespace=<namespace>, name=<name>
//   - "<kind>:<namespace>/<name>"       → kind=<kind>, namespace=<namespace>, name=<name>
//
// Non-Backstage-shaped values (e.g. IRIs like "mailto:alice@example.com") are
// parsed the same way — callers wanting to emit those verbatim should use the
// --author CLI override rather than depending on this parser.
func ParseOwnerRef(ref string) EntityRef {
	kind := DefaultOwnerKind
	namespace := DefaultNamespace
	name := ref

	if idx := strings.Index(name, ":"); idx >= 0 {
		kind = name[:idx]
		name = name[idx+1:]
	}
	if idx := strings.Index(name, "/"); idx >= 0 {
		namespace = name[:idx]
		name = name[idx+1:]
	}

	return EntityRef{Kind: kind, Namespace: namespace, Name: name}
}

// ReadFile reads and parses a catalog-info.yaml file.
func ReadFile(path string) (*CatalogInfo, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	var info CatalogInfo
	if err := yaml.Unmarshal(data, &info); err != nil {
		return nil, fmt.Errorf("parsing catalog-info.yaml: %w", err)
	}

	return &info, nil
}
