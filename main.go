// SPDX-FileCopyrightText: 2026 Bonial International GmbH
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/bonial-oss/trivy-plugin-trivyignore-to-vex/pkg/catalog"
	"github.com/bonial-oss/trivy-plugin-trivyignore-to-vex/pkg/parser"
	vexgen "github.com/bonial-oss/trivy-plugin-trivyignore-to-vex/pkg/vex"
)

var version = "dev"

// backstageURLEnvVar is the environment variable consulted when --backstage-url
// is not provided (FR-6.7 — COULD priority).
const backstageURLEnvVar = "TRIVYIGNORE_VEX_BACKSTAGE_URL"

func main() {
	os.Exit(run())
}

func run() int {
	var (
		input        string
		output       string
		product      string
		author       string
		authorRole   string
		catalogP     string
		noCatalog    bool
		backstageURL string
		showVer      bool
	)

	flag.StringVar(&input, "i", ".trivyignore.yaml", "Path to .trivyignore.yaml")
	flag.StringVar(&input, "input", ".trivyignore.yaml", "Path to .trivyignore.yaml")
	flag.StringVar(&output, "o", "", "Output file (default: stdout)")
	flag.StringVar(&output, "output", "", "Output file (default: stdout)")
	flag.StringVar(&product, "p", "", "Product identifier (purl or image ref)")
	flag.StringVar(&product, "product", "", "Product identifier (purl or image ref)")
	flag.StringVar(&author, "author", "", "VEX document author (overrides derivation from catalog-info.yaml)")
	flag.StringVar(&authorRole, "author-role", "", "VEX document author role (overrides derivation; empty when no source available)")
	flag.StringVar(&catalogP, "catalog", "catalog-info.yaml", "Path to Backstage catalog-info.yaml")
	flag.BoolVar(&noCatalog, "no-catalog", false, "Skip reading catalog-info.yaml")
	flag.StringVar(&backstageURL, "backstage-url", "", "Backstage instance host URL (e.g. https://backstage.example.com). Enables Backstage-URL doc @id and author. Env fallback: "+backstageURLEnvVar)
	flag.BoolVar(&showVer, "v", false, "Print version")
	flag.BoolVar(&showVer, "version", false, "Print version")
	flag.Parse()

	if showVer {
		fmt.Println("trivyignore-to-vex " + version)
		return 0
	}

	// Env fallback for --backstage-url (FR-6.7).
	if backstageURL == "" {
		backstageURL = os.Getenv(backstageURLEnvVar)
	}

	// Read catalog-info.yaml if not skipped. Missing/unreadable file is
	// silently ignored (FR-3.2 fallback to Unknown handles this case).
	var info *catalog.CatalogInfo
	if !noCatalog {
		if i, err := catalog.ReadFile(catalogP); err == nil {
			info = i
		}
	}

	// Resolve author (FR-3.2 fallback chain).
	authorFromOwner := false
	if author == "" && info != nil && info.Owner() != "" {
		owner := info.ResolveOwner()
		if backstageURL != "" {
			author = fmt.Sprintf("%s/catalog/%s/%s/%s",
				strings.TrimRight(backstageURL, "/"),
				owner.Namespace,
				strings.ToLower(owner.Kind),
				owner.Name,
			)
		} else {
			author = fmt.Sprintf("%s:%s/%s", owner.Kind, owner.Namespace, owner.Name)
		}
		authorFromOwner = true
	}
	if author == "" {
		author = "Unknown"
	}

	// Resolve author role (FR-3.3 + FR-6.9).
	if authorRole == "" && authorFromOwner {
		if info != nil && info.Kind != "" {
			authorRole = info.Kind + " Owner"
		} else {
			authorRole = "Owner"
		}
	}

	// Resolve entity fields for doc @id composition (FR-6.8).
	var entityKind, entityNamespace, entityName string
	if info != nil {
		entityKind = info.Kind
		entityNamespace = info.Namespace()
		entityName = info.Name()
	}

	// Check if input file exists/readable.
	if _, err := os.Stat(input); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}

	// Parse input.
	entries, err := parser.ParseFile(input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 2
	}

	// Generate VEX document.
	opts := vexgen.Options{
		Author:          author,
		AuthorRole:      authorRole,
		Product:         product,
		BackstageURL:    backstageURL,
		EntityKind:      entityKind,
		EntityNamespace: entityNamespace,
		EntityName:      entityName,
	}
	doc, err := vexgen.Generate(entries, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating VEX: %v\n", err)
		return 2
	}

	// Write output.
	if output != "" {
		f, err := os.Create(output)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating output file: %v\n", err)
			return 1
		}
		defer f.Close()
		if err := doc.ToJSON(f); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing VEX: %v\n", err)
			return 1
		}
	} else {
		if err := doc.ToJSON(os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing VEX: %v\n", err)
			return 1
		}
	}

	return 0
}
