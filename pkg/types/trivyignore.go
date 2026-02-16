// SPDX-FileCopyrightText: 2026 Bonial International GmbH
// SPDX-License-Identifier: Apache-2.0

package types

// TrivyignoreFile represents the structure of a .trivyignore.yaml file.
type TrivyignoreFile struct {
	Vulnerabilities []IgnoreEntry `yaml:"vulnerabilities"`
}

// IgnoreEntry represents a single entry in the vulnerabilities section.
type IgnoreEntry struct {
	ID        string   `yaml:"id"`
	Statement string   `yaml:"statement"`
	Paths     []string `yaml:"paths"`
	PURLs     []string `yaml:"purls"`
	ExpiredAt string   `yaml:"expired_at"`
}
