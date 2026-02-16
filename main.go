// SPDX-FileCopyrightText: 2026 Bonial International GmbH
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/bonial-oss/trivy-plugin-trivyignore-to-vex/pkg/catalog"
	"github.com/bonial-oss/trivy-plugin-trivyignore-to-vex/pkg/parser"
	vexgen "github.com/bonial-oss/trivy-plugin-trivyignore-to-vex/pkg/vex"
)

var version = "dev"

func main() {
	os.Exit(run())
}

func run() int {
	var (
		input     string
		output    string
		product   string
		author    string
		catalogP  string
		noCatalog bool
		showVer   bool
	)

	flag.StringVar(&input, "i", ".trivyignore.yaml", "Path to .trivyignore.yaml")
	flag.StringVar(&input, "input", ".trivyignore.yaml", "Path to .trivyignore.yaml")
	flag.StringVar(&output, "o", "", "Output file (default: stdout)")
	flag.StringVar(&output, "output", "", "Output file (default: stdout)")
	flag.StringVar(&product, "p", "", "Product identifier (purl or image ref)")
	flag.StringVar(&product, "product", "", "Product identifier (purl or image ref)")
	flag.StringVar(&author, "author", "", "VEX document author (overrides catalog-info)")
	flag.StringVar(&catalogP, "catalog", "catalog-info.yaml", "Path to catalog-info.yaml")
	flag.BoolVar(&noCatalog, "no-catalog", false, "Skip reading catalog-info.yaml")
	flag.BoolVar(&showVer, "v", false, "Print version")
	flag.BoolVar(&showVer, "version", false, "Print version")
	flag.Parse()

	if showVer {
		fmt.Println("trivyignore-to-vex " + version)
		return 0
	}

	// Read catalog-info.yaml for defaults
	if !noCatalog && author == "" {
		if info, err := catalog.ReadFile(catalogP); err == nil {
			author = info.Owner()
		}
	}
	if author == "" {
		author = "Unknown"
	}

	// Check if file exists/readable
	if _, err := os.Stat(input); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}

	// Parse input
	entries, err := parser.ParseFile(input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 2
	}

	// Generate VEX document
	opts := vexgen.Options{
		Author:  author,
		Product: product,
	}
	doc, err := vexgen.Generate(entries, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating VEX: %v\n", err)
		return 2
	}

	// Write output
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
