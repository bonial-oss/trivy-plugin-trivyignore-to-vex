// SPDX-FileCopyrightText: 2026 Bonial International GmbH
// SPDX-License-Identifier: Apache-2.0

package vexgen

import (
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/bonial-oss/trivy-plugin-trivyignore-to-vex/pkg/inference"
	"github.com/bonial-oss/trivy-plugin-trivyignore-to-vex/pkg/types"
	govex "github.com/openvex/go-vex/pkg/vex"
)

// generateUUID generates a UUID v4 string using crypto/rand.
func generateUUID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating UUID: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}

// Options configures VEX document generation. All fields are resolved to
// their final values by the caller; Generate does not perform derivation.
type Options struct {
	// Author is the resolved document author. Emitted verbatim as `author`.
	Author string

	// AuthorRole is the resolved document author role. Empty → field omitted.
	AuthorRole string

	// Product is the resolved --product value. Sole source of products[].@id.
	// Empty means no product identifier is available; statements are emitted
	// without a products array (spec-legal per OpenVEX v0.2).
	Product string

	// BackstageURL, EntityKind, EntityNamespace, EntityName together enable
	// the Backstage-URL document @id form. When ALL FOUR are set, the doc @id
	// is `<BackstageURL>/catalog/<EntityNamespace>/<EntityKind>/<EntityName>#vex-<uuid>`;
	// otherwise the doc @id falls back to `urn:uuid:<uuid>`.
	BackstageURL    string
	EntityKind      string
	EntityNamespace string
	EntityName      string

	// WarningsWriter is where non-fatal warnings ("expired_at malformed",
	// "purls without --product") are written. When nil, defaults to os.Stderr.
	// Set to io.Discard to suppress warnings (used by --quiet in the CLI).
	// Errors that accompany a returned error value are NOT written here — they
	// remain the caller's responsibility.
	WarningsWriter io.Writer
}

// Generate creates an OpenVEX document from .trivyignore.yaml entries.
// Entries with expired_at dates in the past are skipped.
func Generate(entries []types.IgnoreEntry, opts Options) (*govex.VEX, error) {
	now := time.Now().UTC()

	warnings := opts.WarningsWriter
	if warnings == nil {
		warnings = os.Stderr
	}

	uuid, err := generateUUID()
	if err != nil {
		return nil, err
	}

	doc := govex.New()
	doc.ID = composeDocID(uuid, opts)
	doc.Author = opts.Author
	doc.AuthorRole = opts.AuthorRole
	doc.Timestamp = &now
	doc.Version = 1
	doc.Statements = []govex.Statement{}

	hasProduct := opts.Product != ""
	purlsWithoutProductCount := 0

	for _, entry := range entries {
		expired, malformed := isExpired(entry.ExpiredAt, now)
		if malformed {
			fmt.Fprintf(warnings, "Warning: %s has unparseable expired_at value %q, treating as not expired\n", entry.ID, entry.ExpiredAt)
		}
		if expired {
			continue
		}

		result := inference.InferStatus(entry.Statement)

		stmt := govex.Statement{
			Vulnerability: govex.Vulnerability{
				ID:   vulnerabilityIRI(entry.ID),
				Name: govex.VulnerabilityID(entry.ID),
			},
			Status:        result.Status,
			Justification: result.Justification,
		}

		if hasProduct {
			product := govex.Product{
				Component: govex.Component{ID: opts.Product},
			}
			for _, purl := range entry.PURLs {
				product.Subcomponents = append(product.Subcomponents, govex.Subcomponent{
					Component: govex.Component{
						Identifiers: map[govex.IdentifierType]string{
							govex.PURL: purl,
						},
					},
				})
			}
			stmt.Products = []govex.Product{product}
		} else if len(entry.PURLs) > 0 {
			purlsWithoutProductCount++
		}

		text := buildStatementText(entry, result.Status, hasProduct)
		setStatementText(&stmt, text)

		doc.Statements = append(doc.Statements, stmt)
	}

	if purlsWithoutProductCount > 0 {
		fmt.Fprintf(warnings,
			"Warning: %d .trivyignore.yaml entries have `purls` but no `--product` was provided.\n"+
				"Subcomponent information will not appear in the emitted VEX document.\n"+
				"Pass --product to preserve purl-to-subcomponent mapping.\n",
			purlsWithoutProductCount)
	}

	return &doc, nil
}

// composeDocID returns the OpenVEX document @id.
// Backstage-URL form when all four EntityKind/Namespace/Name and BackstageURL are set;
// urn:uuid form otherwise. The kind segment is lowercased to match Backstage's
// URL convention (kinds in YAML are typically PascalCase; the router is
// case-insensitive but the canonical URL form is lowercase).
func composeDocID(uuid string, opts Options) string {
	if opts.BackstageURL != "" && opts.EntityKind != "" && opts.EntityNamespace != "" && opts.EntityName != "" {
		return fmt.Sprintf("%s/catalog/%s/%s/%s#vex-%s",
			strings.TrimRight(opts.BackstageURL, "/"),
			opts.EntityNamespace,
			strings.ToLower(opts.EntityKind),
			opts.EntityName,
			uuid,
		)
	}
	return "urn:uuid:" + uuid
}

// buildStatementText composes the statement's text field as a section-based
// multi-line string. Sections are emitted only when their source data is
// present, in this fixed order:
//
//  1. "Risk accepted."  — only for affected status
//  2. "Expires at: <yyyy-mm-dd>"  — when entry.ExpiredAt is non-empty
//  3. "Affected PURLs:\n  - <purl>..."  — when purls present AND no --product
//  4. "Statement:\n<original statement>"  — when entry.Statement is non-empty
//
// Sections are joined by single "\n". The routing of the resulting string to
// impact_statement / action_statement / status_notes happens in setStatementText.
func buildStatementText(entry types.IgnoreEntry, status govex.Status, hasProduct bool) string {
	var sections []string

	if status == govex.StatusAffected {
		sections = append(sections, "Risk accepted.")
	}

	if entry.ExpiredAt != "" {
		sections = append(sections, "Expires at: "+entry.ExpiredAt)
	}

	if len(entry.PURLs) > 0 && !hasProduct {
		lines := []string{"Affected PURLs:"}
		for _, purl := range entry.PURLs {
			lines = append(lines, "  - "+purl)
		}
		sections = append(sections, strings.Join(lines, "\n"))
	}

	if stmt := strings.TrimRight(entry.Statement, "\n"); stmt != "" {
		sections = append(sections, "Statement:\n"+stmt)
	}

	return strings.Join(sections, "\n")
}

// setStatementText routes the composed text field to the appropriate govex
// Statement slot based on status:
//   - not_affected                → impact_statement
//   - affected                    → action_statement
//   - fixed / under_investigation → status_notes
//
// An empty text is not routed anywhere (the field stays zero-valued and
// omitempty will drop it from the JSON output).
func setStatementText(stmt *govex.Statement, text string) {
	if text == "" {
		return
	}
	switch stmt.Status {
	case govex.StatusNotAffected:
		stmt.ImpactStatement = text
	case govex.StatusAffected:
		stmt.ActionStatement = text
	default:
		stmt.StatusNotes = text
	}
}

// isExpired returns true if the expired_at date is in the past.
// The second return value indicates whether the date was malformed.
func isExpired(expiredAt string, now time.Time) (bool, bool) {
	if expiredAt == "" {
		return false, false
	}
	t, err := time.Parse("2006-01-02", expiredAt)
	if err != nil {
		return false, true // not expired, but malformed
	}
	return t.Before(now), false
}
