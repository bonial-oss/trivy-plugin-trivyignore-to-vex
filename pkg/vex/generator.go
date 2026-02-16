// SPDX-FileCopyrightText: 2026 Bonial International GmbH
// SPDX-License-Identifier: Apache-2.0

package vexgen

import (
	"crypto/rand"
	"fmt"
	"time"

	"github.com/bonial-oss/trivy-plugin-trivyignore-to-vex/pkg/inference"
	"github.com/bonial-oss/trivy-plugin-trivyignore-to-vex/pkg/types"
	govex "github.com/openvex/go-vex/pkg/vex"
)

// generateUUID generates a UUID v4 string using crypto/rand.
func generateUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// Options configures VEX document generation.
type Options struct {
	Author  string
	Product string
}

// Generate creates an OpenVEX document from .trivyignore.yaml entries.
// Entries with expired_at dates in the past are skipped.
func Generate(entries []types.IgnoreEntry, opts Options) (*govex.VEX, error) {
	now := time.Now().UTC()

	doc := govex.New()
	doc.ID = "urn:uuid:" + generateUUID()
	doc.Author = opts.Author
	doc.AuthorRole = "Document Creator"
	doc.Timestamp = &now
	doc.Version = 1
	doc.Statements = []govex.Statement{}

	for _, entry := range entries {
		if isExpired(entry.ExpiredAt, now) {
			continue
		}

		result := inference.InferStatus(entry.Statement)

		stmt := govex.Statement{
			Vulnerability: govex.Vulnerability{
				ID:   "https://nvd.nist.gov/vuln/detail/" + entry.ID,
				Name: govex.VulnerabilityID(entry.ID),
			},
			Status:          result.Status,
			Justification:   result.Justification,
			ImpactStatement: result.ImpactStatement,
			ActionStatement: result.ActionStatement,
		}

		if opts.Product != "" {
			stmt.Products = []govex.Product{
				{Component: govex.Component{ID: opts.Product}},
			}
		}

		doc.Statements = append(doc.Statements, stmt)
	}

	return &doc, nil
}

// isExpired returns true if the expired_at date is in the past.
func isExpired(expiredAt string, now time.Time) bool {
	if expiredAt == "" {
		return false
	}
	t, err := time.Parse("2006-01-02", expiredAt)
	if err != nil {
		return false
	}
	return t.Before(now)
}
