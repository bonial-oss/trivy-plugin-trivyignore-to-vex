// SPDX-FileCopyrightText: 2026 Bonial International GmbH
// SPDX-License-Identifier: Apache-2.0

package catalog

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// CatalogInfo represents the relevant fields from a Backstage catalog-info.yaml.
type CatalogInfo struct {
	Metadata CatalogMetadata `yaml:"metadata"`
	Spec     CatalogSpec     `yaml:"spec"`
}

// CatalogMetadata holds the metadata section.
type CatalogMetadata struct {
	Name string `yaml:"name"`
}

// CatalogSpec holds the spec section.
type CatalogSpec struct {
	Owner string `yaml:"owner"`
}

// Owner returns the spec.owner value.
func (c *CatalogInfo) Owner() string {
	return c.Spec.Owner
}

// Name returns the metadata.name value.
func (c *CatalogInfo) Name() string {
	return c.Metadata.Name
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
