// SPDX-FileCopyrightText: 2026 Bonial International GmbH
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestCLI_StdoutOutput(t *testing.T) {
	buildBinary(t)

	cmd := exec.Command("./trivyignore-to-vex",
		"-i", "testdata/trivyignore_integration.yaml",
		"--author", "test-author",
		"--product", "pkg:oci/my-image",
		"--no-catalog",
	)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		t.Fatalf("command failed: %v\nstderr: %s", err, stderr.String())
	}

	var doc map[string]interface{}
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v\noutput: %s", err, stdout.String())
	}

	if doc["author"] != "test-author" {
		t.Errorf("expected author test-author, got %v", doc["author"])
	}

	statements, ok := doc["statements"].([]interface{})
	if !ok {
		t.Fatalf("statements is not an array: %v", doc["statements"])
	}

	// Should have 2 statements (3rd entry is expired)
	if len(statements) != 2 {
		t.Fatalf("expected 2 statements, got %d", len(statements))
	}
}

func TestCLI_FileOutput(t *testing.T) {
	buildBinary(t)

	outFile := t.TempDir() + "/output.json"
	cmd := exec.Command("./trivyignore-to-vex",
		"-i", "testdata/trivyignore_integration.yaml",
		"-o", outFile,
		"--author", "test-author",
		"--no-catalog",
	)

	if err := cmd.Run(); err != nil {
		t.Fatalf("command failed: %v", err)
	}

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("could not read output file: %v", err)
	}

	var doc map[string]interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("output file is not valid JSON: %v", err)
	}
}

func TestCLI_MissingInput(t *testing.T) {
	buildBinary(t)

	cmd := exec.Command("./trivyignore-to-vex",
		"-i", "nonexistent.yaml",
		"--no-catalog",
	)
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected error for missing input file")
	}

	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("expected ExitError, got %T", err)
	}
	if exitErr.ExitCode() != 1 {
		t.Errorf("expected exit code 1, got %d", exitErr.ExitCode())
	}
}

func TestCLI_InvalidYAML(t *testing.T) {
	buildBinary(t)

	tmpFile := t.TempDir() + "/invalid.yaml"
	if err := os.WriteFile(tmpFile, []byte(":::invalid yaml{{{"), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	cmd := exec.Command("./trivyignore-to-vex",
		"-i", tmpFile,
		"--no-catalog",
	)
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected error for invalid YAML input")
	}

	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("expected ExitError, got %T", err)
	}
	if exitErr.ExitCode() != 2 {
		t.Errorf("expected exit code 2, got %d", exitErr.ExitCode())
	}
}

func TestCLI_Version(t *testing.T) {
	buildBinary(t)

	cmd := exec.Command("./trivyignore-to-vex", "-v")
	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	if err := cmd.Run(); err != nil {
		t.Fatalf("command failed: %v", err)
	}

	if stdout.Len() == 0 {
		t.Error("expected version output")
	}
}

func TestCLI_AuthorRoleOverride(t *testing.T) {
	buildBinary(t)

	cmd := exec.Command("./trivyignore-to-vex",
		"-i", "testdata/trivyignore_integration.yaml",
		"--author", "team",
		"--author-role", "Security Team",
		"--no-catalog",
	)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		t.Fatalf("command failed: %v\nstderr: %s", err, stderr.String())
	}

	var doc map[string]interface{}
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if doc["role"] != "Security Team" {
		t.Errorf("expected role Security Team, got %v", doc["role"])
	}
}

func TestCLI_RoleOmittedWhenNoSignal(t *testing.T) {
	buildBinary(t)

	cmd := exec.Command("./trivyignore-to-vex",
		"-i", "testdata/trivyignore_integration.yaml",
		"--author", "team",
		"--no-catalog",
	)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	if err := cmd.Run(); err != nil {
		t.Fatalf("command failed: %v", err)
	}

	var doc map[string]interface{}
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if _, hasRole := doc["role"]; hasRole {
		t.Errorf("expected role to be omitted when no signal, got: %v", doc["role"])
	}
}

func TestCLI_BackstageURLComposesDocIDAndAuthor(t *testing.T) {
	buildBinary(t)

	cmd := exec.Command("./trivyignore-to-vex",
		"-i", "testdata/trivyignore_integration.yaml",
		"--catalog", "testdata/catalog_info_sample.yaml",
		"--backstage-url", "https://backstage.example.com",
	)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		t.Fatalf("command failed: %v\nstderr: %s", err, stderr.String())
	}

	var doc map[string]interface{}
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	// Doc @id should be Backstage URL form (lowercase kind in URL).
	wantIDPrefix := "https://backstage.example.com/catalog/default/component/my-service#vex-"
	if id, _ := doc["@id"].(string); !strings.HasPrefix(id, wantIDPrefix) {
		t.Errorf("expected @id to start with %q, got %q", wantIDPrefix, id)
	}

	// Author should be Backstage-URL form of owner.
	wantAuthor := "https://backstage.example.com/catalog/default/group/platform-team"
	if doc["author"] != wantAuthor {
		t.Errorf("expected author %q, got %v", wantAuthor, doc["author"])
	}

	// Role should be kind-derived ("Component Owner").
	if doc["role"] != "Component Owner" {
		t.Errorf("expected role Component Owner, got %v", doc["role"])
	}
}

func TestCLI_CatalogWithoutBackstageURLDerivesEntityRefAuthor(t *testing.T) {
	buildBinary(t)

	cmd := exec.Command("./trivyignore-to-vex",
		"-i", "testdata/trivyignore_integration.yaml",
		"--catalog", "testdata/catalog_info_sample.yaml",
	)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	if err := cmd.Run(); err != nil {
		t.Fatalf("command failed: %v", err)
	}

	var doc map[string]interface{}
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	// Author falls back to canonical entity ref (no Backstage URL to compose against).
	wantAuthor := "group:default/platform-team"
	if doc["author"] != wantAuthor {
		t.Errorf("expected author %q, got %v", wantAuthor, doc["author"])
	}

	// Doc @id should still be urn:uuid (partial Backstage config = no Backstage URL doc @id).
	id, _ := doc["@id"].(string)
	if !strings.HasPrefix(id, "urn:uuid:") {
		t.Errorf("expected urn:uuid @id without --backstage-url, got %q", id)
	}
}

func TestCLI_BackstageURLFromEnv(t *testing.T) {
	buildBinary(t)

	cmd := exec.Command("./trivyignore-to-vex",
		"-i", "testdata/trivyignore_integration.yaml",
		"--catalog", "testdata/catalog_info_sample.yaml",
	)
	cmd.Env = append(os.Environ(), "TRIVYIGNORE_VEX_BACKSTAGE_URL=https://backstage.example.com")
	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	if err := cmd.Run(); err != nil {
		t.Fatalf("command failed: %v", err)
	}

	var doc map[string]interface{}
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	wantIDPrefix := "https://backstage.example.com/catalog/default/component/my-service#vex-"
	if id, _ := doc["@id"].(string); !strings.HasPrefix(id, wantIDPrefix) {
		t.Errorf("expected @id from env-supplied backstage URL, got %q", id)
	}
}

func buildBinary(t *testing.T) {
	t.Helper()
	cmd := exec.Command("go", "build", "-o", "trivyignore-to-vex", ".")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}
}
