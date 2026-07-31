// SPDX-FileCopyrightText: 2026 Bonial International GmbH
// SPDX-License-Identifier: Apache-2.0

package vexgen

import "testing"

func TestVulnerabilityIRI(t *testing.T) {
	tests := []struct {
		name string
		id   string
		want string
	}{
		{
			name: "CVE routes to NVD",
			id:   "CVE-2025-25290",
			want: "https://nvd.nist.gov/vuln/detail/CVE-2025-25290",
		},
		{
			name: "GHSA routes to GitHub advisories",
			id:   "GHSA-w5hq-g745-h8pq",
			want: "https://github.com/advisories/GHSA-w5hq-g745-h8pq",
		},
		{
			name: "GO routes to pkg.go.dev vuln",
			id:   "GO-2024-1234",
			want: "https://pkg.go.dev/vuln/GO-2024-1234",
		},
		{
			name: "RUSTSEC routes to rustsec.org",
			id:   "RUSTSEC-2024-0001",
			want: "https://rustsec.org/advisories/RUSTSEC-2024-0001",
		},
		{
			name: "PYSEC routes to OSV",
			id:   "PYSEC-2024-1",
			want: "https://osv.dev/vulnerability/PYSEC-2024-1",
		},
		{
			name: "OSV routes to OSV",
			id:   "OSV-2024-1",
			want: "https://osv.dev/vulnerability/OSV-2024-1",
		},
		{
			name: "unknown prefix returns empty",
			id:   "NPMSA-2024-1",
			want: "",
		},
		{
			name: "bare string returns empty",
			id:   "some-vulnerability",
			want: "",
		},
		{
			name: "empty ID returns empty",
			id:   "",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := vulnerabilityIRI(tt.id)
			if got != tt.want {
				t.Errorf("vulnerabilityIRI(%q) = %q, want %q", tt.id, got, tt.want)
			}
		})
	}
}
