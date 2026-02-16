// SPDX-FileCopyrightText: 2026 Bonial International GmbH
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"fmt"
	"os"

	"github.com/bonial-oss/trivy-plugin-trivyignore-to-vex/pkg/types"
	"gopkg.in/yaml.v3"
)

// ParseFile reads and parses a .trivyignore.yaml file from disk.
func ParseFile(path string) ([]types.IgnoreEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	return ParseBytes(data)
}

// ParseBytes parses .trivyignore.yaml content from a byte slice.
func ParseBytes(data []byte) ([]types.IgnoreEntry, error) {
	var file types.TrivyignoreFile
	if err := yaml.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("parsing YAML: %w", err)
	}
	return file.Vulnerabilities, nil
}
