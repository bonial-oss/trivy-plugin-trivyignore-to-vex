// SPDX-FileCopyrightText: 2026 Bonial International GmbH
// SPDX-License-Identifier: Apache-2.0

package vexgen

import "strings"

// vulnerabilityIRI returns a canonical IRI for the given vulnerability
// identifier based on its prefix. Returns an empty string when the prefix is
// unknown — callers should assign this to `Vulnerability.ID` unconditionally
// (the field has `omitempty`, so empty values are dropped from the JSON
// output; `vulnerability.name` is what carries the identifier per FR-1.2).
//
// Prefix routing table:
//
//	CVE-*     → https://nvd.nist.gov/vuln/detail/<ID>
//	GHSA-*    → https://github.com/advisories/<ID>
//	GO-*      → https://pkg.go.dev/vuln/<ID>
//	RUSTSEC-* → https://rustsec.org/advisories/<ID>
//	PYSEC-*   → https://osv.dev/vulnerability/<ID>
//	OSV-*     → https://osv.dev/vulnerability/<ID>
//	other     → "" (caller omits @id)
//
// New prefixes can be added here without breaking callers — unknown prefixes
// silently degrade to the "omit @id" fallback.
func vulnerabilityIRI(id string) string {
	switch {
	case strings.HasPrefix(id, "CVE-"):
		return "https://nvd.nist.gov/vuln/detail/" + id
	case strings.HasPrefix(id, "GHSA-"):
		return "https://github.com/advisories/" + id
	case strings.HasPrefix(id, "GO-"):
		return "https://pkg.go.dev/vuln/" + id
	case strings.HasPrefix(id, "RUSTSEC-"):
		return "https://rustsec.org/advisories/" + id
	case strings.HasPrefix(id, "PYSEC-"):
		return "https://osv.dev/vulnerability/" + id
	case strings.HasPrefix(id, "OSV-"):
		return "https://osv.dev/vulnerability/" + id
	default:
		return ""
	}
}
